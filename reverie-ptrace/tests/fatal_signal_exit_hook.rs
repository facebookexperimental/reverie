/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `GlobalTool::on_fatal_signal_exit` runs once for each thread of a process
//! that a core-dumping signal ends, while the thread is held at its exit stop,
//! and never for a thread that exits any other way, including one that
//! seccomp kills while its process lives on. Nothing in these tests reaps a
//! held guest's memory, so the hook here expects to read it; a real consumer
//! must tolerate a failed or short read.
//!
//! Every guest sets its soft `RLIMIT_CORE` to 1 first, when its hard limit
//! allows. The kernel refuses to write a core at that limit, whether
//! `core_pattern` names a file or a pipe, so no guest leaves a core on the host
//! and every core-dumped flag is false. Under a hard limit of 0 the guest
//! cannot raise its soft limit, and the flag then depends on `core_pattern` (a
//! pipe helper still receives the core), so the tests check the flag only when
//! the limit was 1. The kernel runs its core dump step at either limit.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Mutex;

use reverie::ExitStatus;
use reverie::FatalSignalExit;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::Signal;
use reverie::Tool;
use reverie_ptrace::testing::test_fn_with_config;

const BEFORE: &[u8; 16] = b"written-pre-fork";
const DYING: &[u8; 16] = b"written-by-guest";

/// A page the test process allocates before the guest is forked from it, so
/// the guest has it at the same address.
fn shared_page() -> usize {
    let page = Box::leak(Box::new([0u8; 4096]));
    page[..BEFORE.len()].copy_from_slice(BEFORE);
    page.as_ptr() as usize
}

/// The hard `RLIMIT_CORE` of this process, which a forked guest inherits.
fn hard_core_limit() -> libc::rlim_t {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    limit.rlim_max
}

/// Keeps the kernel from writing a core for this guest, when the hard limit
/// allows; see the module doc.
fn refuse_host_core() {
    let hard = hard_core_limit();
    if hard >= 1 {
        let limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: hard,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
    }
}

/// Asserts that `status` is death by `signal`, with the core-dumped flag
/// clear whenever the guest could refuse a core.
fn assert_killed_by(status: ExitStatus, signal: Signal) {
    match status {
        ExitStatus::Signaled(actual, dumped) => {
            assert_eq!(actual, signal, "{status:?}");
            if hard_core_limit() >= 1 {
                assert!(!dumped, "the guest dumped core at limit 1: {status:?}");
            }
        }
        _ => panic!("expected death by {signal:?}, got {status:?}"),
    }
}

/// Writes `bytes` to the start of the shared page, for the hook to read back.
unsafe fn mark(page: usize, bytes: &[u8]) {
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), page as *mut u8, bytes.len()) };
}

/// The calling thread's ID, as the first four bytes the hook will read.
fn tid_mark() -> [u8; 4] {
    unsafe { libc::gettid() }.to_ne_bytes()
}

/// Faults by writing to address 8, which is never mapped.
fn segfault() -> ! {
    unsafe { std::ptr::dangling_mut::<u64>().write_volatile(1) };
    unreachable!("the write above faults")
}

#[derive(Debug)]
struct Seen {
    tid: Pid,
    signal: Signal,
    status: ExitStatus,
    dumping: bool,
    failed_run: bool,
    rip: u64,
    /// The guest's bytes at the page, read through `/proc/<tid>/mem` from
    /// inside the hook.
    page: Vec<u8>,
}

impl Seen {
    fn marked_tid(&self) -> i32 {
        i32::from_ne_bytes(self.page[..4].try_into().unwrap())
    }
}

#[derive(Default)]
struct FatalLog {
    page: usize,
    seen: Mutex<Vec<Seen>>,
}

#[reverie::global_tool]
impl GlobalTool for FatalLog {
    type Request = ();
    type Response = ();
    type Config = usize;

    async fn init_global_state(page: &usize) -> Self {
        Self {
            page: *page,
            ..Self::default()
        }
    }

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}

    fn on_fatal_signal_exit(&self, exit: &FatalSignalExit) {
        let mut bytes = vec![0; DYING.len()];
        let mem = File::open(format!("/proc/{}/mem", exit.tid.as_raw()))
            .expect("the dying thread's memory should still be open");
        mem.read_exact_at(&mut bytes, self.page as u64)
            .expect("the dying thread's memory should still be mapped");
        self.seen.lock().unwrap().push(Seen {
            tid: exit.tid,
            signal: exit.signal,
            status: exit.status,
            dumping: exit.dumping,
            failed_run: exit.deadline.is_some(),
            rip: exit.regs.rip,
            page: bytes,
        });
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FatalLogTool;

#[reverie::tool]
impl Tool for FatalLogTool {
    type GlobalState = FatalLog;
    type ThreadState = ();
}

fn run(guest: impl FnOnce(usize)) -> (ExitStatus, Vec<Seen>) {
    let page = shared_page();
    let (output, log) = test_fn_with_config::<FatalLogTool, _>(
        || {
            refuse_host_core();
            guest(page)
        },
        page,
        true,
    )
    .expect("the guest should run");
    (output.status, log.seen.into_inner().unwrap())
}

#[test]
fn a_segfault_is_offered_once_with_its_memory_still_mapped() {
    let (status, seen) = run(|page| {
        unsafe { mark(page, DYING) };
        segfault()
    });
    assert_killed_by(status, Signal::SIGSEGV);
    assert_eq!(seen.len(), 1, "{seen:?}");
    let seen = &seen[0];
    assert_eq!(seen.signal, Signal::SIGSEGV);
    assert_eq!(seen.status, status);
    assert!(seen.dumping, "the faulting thread ran the core dump step");
    assert!(!seen.failed_run);
    assert!(seen.tid.as_raw() > 0);
    assert_ne!(seen.rip, 0);
    assert_eq!(
        seen.page,
        DYING,
        "the hook read {:?}, not what the guest wrote before it died",
        String::from_utf8_lossy(&seen.page)
    );
}

#[test]
fn an_abort_is_offered() {
    let (status, seen) = run(|_| std::process::abort());
    assert_killed_by(status, Signal::SIGABRT);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].signal, Signal::SIGABRT);
    assert!(seen[0].dumping);
}

#[test]
fn signals_that_dump_no_core_and_ordinary_exits_are_not_offered() {
    let (status, seen) = run(|_| unsafe {
        libc::kill(libc::getpid(), libc::SIGTERM);
    });
    assert_eq!(status, ExitStatus::Signaled(Signal::SIGTERM, false));
    assert!(seen.is_empty(), "{seen:?}");

    let (status, seen) = run(|_| unsafe { libc::_exit(3) });
    assert_eq!(status, ExitStatus::Exited(3));
    assert!(seen.is_empty(), "{seen:?}");
}

/// Each thread of the dying process is offered once, all with the same
/// signal, and only the thread that faulted is the dumping one.
#[test]
fn every_thread_of_a_multithreaded_crash_is_offered_and_one_is_dumping() {
    let (status, seen) = run(|page| {
        let started = std::sync::Arc::new(std::sync::Barrier::new(4));
        for _ in 0..3 {
            let started = started.clone();
            std::thread::spawn(move || {
                started.wait();
                loop {
                    std::thread::park();
                }
            });
        }
        started.wait();
        unsafe { mark(page, &tid_mark()) };
        segfault()
    });
    assert_killed_by(status, Signal::SIGSEGV);
    assert_eq!(seen.len(), 4, "{seen:#?}");
    let mut tids: Vec<_> = seen.iter().map(|seen| seen.tid).collect();
    tids.sort();
    tids.dedup();
    assert_eq!(tids.len(), 4, "a thread was offered twice: {seen:#?}");
    for seen in &seen {
        assert_eq!(seen.signal, Signal::SIGSEGV);
        assert!(!seen.failed_run);
        if !seen.dumping {
            // A thread the dump step held reaches its exit stop with the
            // signal it was sent, never with the core-dumped flag.
            assert_eq!(seen.status, ExitStatus::Signaled(Signal::SIGSEGV, false));
        }
    }
    let dumping: Vec<_> = seen.iter().filter(|seen| seen.dumping).collect();
    assert_eq!(dumping.len(), 1, "{seen:#?}");
    assert_eq!(dumping[0].status, status, "{seen:#?}");
    assert_eq!(
        dumping[0].tid.as_raw(),
        dumping[0].marked_tid(),
        "the dumping thread is not the one that faulted"
    );
}

/// A forked child's crash is offered with the child's own memory, and the
/// parent goes on to exit normally.
#[test]
fn a_forked_child_crash_is_offered_with_its_own_memory() {
    let (status, seen) = run(|page| unsafe {
        let child = libc::fork();
        if child == 0 {
            mark(page, &tid_mark());
            segfault();
        }
        let mut wstatus = 0;
        assert_eq!(libc::waitpid(child, &mut wstatus, 0), child);
        let ok = libc::WIFSIGNALED(wstatus) && libc::WTERMSIG(wstatus) == libc::SIGSEGV;
        libc::_exit(if ok { 0 } else { 1 });
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(seen.len(), 1, "{seen:#?}");
    assert_killed_by(seen[0].status, Signal::SIGSEGV);
    assert!(seen[0].dumping);
    assert_eq!(
        seen[0].tid.as_raw(),
        seen[0].marked_tid(),
        "the hook read memory that is not the child's"
    );
}

/// `SECCOMP_RET_KILL_THREAD` ends one thread of a multithreaded process
/// with SIGSYS, a core-dumping signal number, without a fatal signal to the
/// process, which then exits normally. That thread is not offered.
#[test]
fn a_thread_seccomp_kills_while_its_process_lives_on_is_not_offered() {
    let (status, seen) = run(|_| {
        std::thread::spawn(|| unsafe {
            // Kill the thread on getppid, allow every other syscall.
            let filter = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_getppid as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_KILL_THREAD,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut _,
            };
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            let installed = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &program as *const libc::sock_fprog,
            );
            assert_eq!(installed, 0);
            libc::syscall(libc::SYS_getppid);
        });
        // The killed thread never returns, so wait for it to leave the
        // thread list rather than joining it.
        while std::fs::read_dir("/proc/self/task").unwrap().count() > 1 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        unsafe { libc::_exit(7) };
    });
    assert_eq!(status, ExitStatus::Exited(7));
    assert!(
        seen.is_empty(),
        "offered a thread of a process that went on to exit normally: {seen:#?}"
    );
}
