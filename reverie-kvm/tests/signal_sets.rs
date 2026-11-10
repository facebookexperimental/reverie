/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::signal_sets` on a KVM guest is the executor's own signal state,
//! for any live thread of the run, and it is what Linux shows in that
//! thread's `status` file: the same C guest, run natively, reads
//! `/proc/<tid>/status` at the points where the KVM run asks the Tool. The
//! points cover a pending signal for the thread and for the process, ignored
//! and caught actions, a full mask, a handler's mask, another thread's sets
//! asked from each side, and another process: a child asking about its
//! parent, the parent asking about the child's two threads. An exited child,
//! as a zombie (Linux still shows its sets, with state `Z`) and once reaped,
//! is `ESRCH`, and so is a number no task has. Two differences are the
//! executor's: it refuses real-time signals, so the guest's two `sigqueue`
//! calls fail and no real-time signal is pending; and it keeps no waiting
//! state, so a thread waiting in `sigtimedwait` shows its own mask, where
//! Linux shows that mask without the signals it waits for.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
use reverie::Errno;
use reverie::Error;
use reverie::FactError;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::SignalSets;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_kvm::KvmBackend;

/// The first argument of the guest's `tuxcall` that asks for a fact
/// (`ASK` in the fixture).
const ASK: u64 = 0x7369_6773_6574;

// The fixture's numbered points.
const SELF_PENDING: u64 = 1;
const SHARED_PENDING: u64 = 2;
const ACTIONS: u64 = 3;
const REALTIME: u64 = 4;
const FULL_MASK: u64 = 5;
const IN_HANDLER: u64 = 6;
const AFTER_HANDLER: u64 = 7;
const SIBLING: u64 = 8;
const LEADER_FROM_SIBLING: u64 = 9;
const CHILD_READS_PARENT: u64 = 10;
const PARENT_READS_CHILD: u64 = 11;
const CHILD_SIBLING: u64 = 12;
const ZOMBIE_CHILD: u64 = 13;
const REAPED_CHILD: u64 = 14;
const NO_TASK: u64 = 15;
const ZERO: u64 = 16;
const NEGATIVE: u64 = 17;
const WAITING: u64 = 18;
const POINTS: u64 = 18;

type Fact = Result<SignalSets, FactError>;

/// The facts the Tool read, by the guest's point number.
#[derive(Default)]
struct FactLog(Mutex<BTreeMap<u64, (i32, Fact)>>);

#[reverie::global_tool]
impl GlobalTool for FactLog {
    type Request = (u64, i32, Fact);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) {
        let (point, tid, fact) = request;
        let previous = self.0.lock().unwrap().insert(point, (tid, fact));
        assert!(previous.is_none(), "point {point} asked twice");
    }
}

#[derive(Default)]
struct FactTool;

#[reverie::tool]
impl Tool for FactTool {
    type GlobalState = FactLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::tuxcall].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (_, args) = syscall.into_parts();
        if args.arg0 as u64 != ASK {
            return Ok(guest.inject(syscall).await?);
        }
        let (tid, point) = (args.arg1 as i32, args.arg2 as u64);
        let fact = guest.signal_sets(Pid::from_raw(tid));
        guest.send_rpc((point, tid, fact)).await;
        Ok(0)
    }
}

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-kvm-signal-sets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn bit(signal: libc::c_int) -> u64 {
    1 << (signal - 1)
}

/// What the native run read at one point: the state letter and the five
/// sets, or the errno of the read.
type Native = Result<(char, SignalSets), i32>;

/// The points the native run's standard output lists, after its two lines
/// of call results.
fn native_points(stdout: &str) -> BTreeMap<u64, Native> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("point "))
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let point = fields[0].parse().unwrap();
            let read = match fields[1..] {
                ["errno", errno] => Err(errno.parse().unwrap()),
                [state, pending, shared, blocked, ignored, caught] => {
                    let set = |text| u64::from_str_radix(text, 16).unwrap();
                    Ok((
                        state.parse().unwrap(),
                        SignalSets::new(
                            set(pending),
                            set(shared),
                            set(blocked),
                            set(ignored),
                            set(caught),
                        ),
                    ))
                }
                _ => panic!("native point line {line:?}"),
            };
            (point, read)
        })
        .collect()
}

#[test]
fn a_kvm_guest_reports_the_signal_sets_linux_shows() {
    Kvm::new().expect("signal sets test requires usable /dev/kvm");
    let directory = Directory::new();
    let source = directory.0.join("signal_sets.c");
    let executable = directory.0.join("signal_sets");
    std::fs::write(&source, include_str!("fixtures/signal_sets.c")).unwrap();
    let compiled = std::process::Command::new("/usr/bin/gcc")
        .args(["-O2", "-std=c11", "-pthread", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "gcc: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let native = std::process::Command::new(&executable)
        .arg("native")
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(native.status.success(), "native: {native:?}");
    let native_stdout = String::from_utf8(native.stdout).unwrap();
    // SIGSTOP's action cannot change (EINVAL); both real-time signals queue.
    assert!(
        native_stdout.starts_with(&format!("sigstop {}\nsigqueue 0 0 taken 2\n", libc::EINVAL)),
        "{native_stdout}"
    );
    let native = native_points(&native_stdout);
    assert_eq!(native.len() as u64, POINTS, "{native_stdout}");

    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap()],
            &[],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<FactTool>((), true))
            .unwrap();
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    // The executor refuses real-time signals (ENOSYS), so nothing queues.
    let mut expected = format!(
        "sigstop {}\nsigqueue {} {} taken 0\n",
        libc::EINVAL,
        libc::ENOSYS,
        libc::ENOSYS
    );
    for point in 1..=POINTS {
        expected.push_str(&format!("point {point} asked\n"));
    }
    assert_eq!(String::from_utf8_lossy(&stdout), expected);
    let facts = log.0.into_inner().unwrap();
    assert_eq!(facts.len() as u64, POINTS, "{facts:?}");
    let fact = |point: u64| match facts[&point].1 {
        Ok(sets) => sets,
        Err(error) => panic!("point {point}: {error:?}"),
    };

    // Where the executor holds what Linux holds, the fact is Linux's sets,
    // for a live thread in either process.
    let linux = |point: u64| match native[&point] {
        Ok((state, sets)) => {
            assert_ne!(state, 'Z', "native point {point}");
            sets
        }
        Err(errno) => panic!("native point {point}: errno {errno}"),
    };
    for point in [
        SELF_PENDING,
        SHARED_PENDING,
        ACTIONS,
        FULL_MASK,
        IN_HANDLER,
        AFTER_HANDLER,
        SIBLING,
        LEADER_FROM_SIBLING,
        CHILD_READS_PARENT,
        PARENT_READS_CHILD,
        CHILD_SIBLING,
    ] {
        assert_eq!(fact(point), linux(point), "point {point}");
    }

    // The sets those points show, spelled out.
    let (usr1, usr2) = (bit(libc::SIGUSR1), bit(libc::SIGUSR2));
    let actions = (bit(libc::SIGHUP), usr2);
    let expect = |pending, shared, blocked, (ignored, caught): (u64, u64)| {
        SignalSets::new(pending, shared, blocked, ignored, caught)
    };
    assert_eq!(fact(SELF_PENDING), expect(usr1, 0, usr1, (0, 0)));
    assert_eq!(fact(SHARED_PENDING), expect(0, usr2, usr2, (0, 0)));
    assert_eq!(fact(ACTIONS), expect(0, 0, 0, actions));
    // Every signal but SIGKILL and SIGSTOP, which the kernel leaves out, and
    // glibc's two internal ones, which sigfillset leaves out.
    let full = !(bit(libc::SIGKILL) | bit(libc::SIGSTOP) | bit(32) | bit(33));
    assert_eq!(fact(FULL_MASK), expect(0, 0, full, actions));
    // The mask at delivery, the handler's sa_mask and its own signal.
    let pipe = bit(libc::SIGPIPE);
    assert_eq!(
        fact(IN_HANDLER),
        expect(0, 0, pipe | bit(libc::SIGWINCH) | usr2, actions)
    );
    assert_eq!(fact(AFTER_HANDLER), expect(0, 0, pipe, actions));
    // glibc's first pthread_create installs a handler for its internal
    // signal 33, which it uses to change every thread's IDs.
    let caught = (bit(libc::SIGHUP), usr1 | usr2 | bit(33));
    assert_eq!(
        fact(SIBLING),
        expect(usr1, 0, usr1 | bit(libc::SIGINT), caught)
    );
    assert_eq!(fact(LEADER_FROM_SIBLING), expect(0, 0, 0, caught));
    // The child inherits the actions and adds SIGINT's SIG_IGN. While it has
    // one thread, SIGTERM is pending for its process and SIGUSR2 for that
    // thread; it takes SIGTERM before it makes its second thread, which
    // queues SIGQUIT to itself.
    let (term, quit) = (bit(libc::SIGTERM), bit(libc::SIGQUIT));
    let child_actions = (bit(libc::SIGHUP) | bit(libc::SIGINT), usr1 | usr2 | bit(33));
    assert_eq!(fact(CHILD_READS_PARENT), expect(0, 0, 0, caught));
    assert_eq!(
        fact(PARENT_READS_CHILD),
        expect(usr2, term, usr2 | term, child_actions)
    );
    assert_eq!(fact(CHILD_SIBLING), expect(quit, 0, quit, child_actions));
    // The sibling's sets were asked about by the leader, and the leader's by
    // the sibling; the parent's by the child, and the child's threads' by the
    // parent.
    assert_ne!(facts[&SIBLING].0, facts[&LEADER_FROM_SIBLING].0);
    assert_eq!(facts[&LEADER_FROM_SIBLING].0, facts[&SELF_PENDING].0);
    assert_eq!(facts[&CHILD_READS_PARENT].0, facts[&SELF_PENDING].0);
    assert_ne!(facts[&PARENT_READS_CHILD].0, facts[&CHILD_SIBLING].0);
    assert_eq!(facts[&ZOMBIE_CHILD].0, facts[&PARENT_READS_CHILD].0);
    assert_eq!(facts[&REAPED_CHILD].0, facts[&PARENT_READS_CHILD].0);

    // Linux queued the real-time signal twice for the process and shows it
    // once; the executor refused both, and shows the rest of Linux's sets.
    let realtime = bit(libc::SIGRTMIN());
    assert_eq!(linux(REALTIME), expect(0, realtime, realtime, actions));
    assert_eq!(fact(REALTIME), expect(0, 0, realtime, actions));

    // A thread waiting in sigtimedwait for SIGUSR1, with SIGUSR1 and SIGUSR2
    // blocked: while it sleeps, Linux's mask is its own without SIGUSR1. The
    // executor answers the call at once (EAGAIN, and the thread asks again),
    // so the fact is the thread's own mask.
    assert!(
        matches!(native[&WAITING], Ok(('S', _))),
        "{:?}",
        native[&WAITING]
    );
    assert_eq!(linux(WAITING), expect(0, 0, usr2, caught));
    assert_eq!(fact(WAITING), expect(0, 0, usr1 | usr2, caught));
    assert_ne!(facts[&WAITING].0, facts[&SELF_PENDING].0);

    // The exited child: Linux still shows a zombie's sets, with state `Z`;
    // the fact, for a thread that has exited, is ESRCH, reaped or not.
    assert!(
        matches!(native[&ZOMBIE_CHILD], Ok(('Z', _))),
        "{:?}",
        native[&ZOMBIE_CHILD]
    );
    for point in [ZOMBIE_CHILD, REAPED_CHILD, NO_TASK, ZERO, NEGATIVE] {
        assert_eq!(
            facts[&point].1,
            Err(FactError::Errno(Errno::ESRCH)),
            "point {point}"
        );
    }
    for point in [REAPED_CHILD, NO_TASK, ZERO, NEGATIVE] {
        assert_eq!(native[&point], Err(libc::ENOENT), "native point {point}");
    }
    assert_eq!(
        [facts[&NO_TASK].0, facts[&ZERO].0, facts[&NEGATIVE].0],
        [i32::MAX, 0, -1]
    );
}
