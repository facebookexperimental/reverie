/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::signal_sets` on a traced guest is the kernel's own five signal
//! sets for the thread named, in any process the tracer traces: a pending
//! signal for the thread and for the process, ignored and caught actions, a
//! real-time signal queued twice, a full mask, a handler's mask, another
//! thread's sets asked from each side, another process (a child asking
//! about its parent, the parent asking about the child's two threads), and
//! a thread waiting in `sigtimedwait`, whose mask while it sleeps is its own
//! without the signals it waits for. An exited child, as a zombie and once
//! reaped, a host task the tracer does not trace (the guest's own parent,
//! the tracer, and init), and a number no task has are `ESRCH`.
//!
//! The guest asks at numbered points with `tuxcall`, which Linux does not
//! implement; the tool answers it, and records the fact it read then.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::mpsc;

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

/// The first argument of a guest's `tuxcall` that asks for a fact.
const ASK: u64 = 0x7369_6773_6574;

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
const HOST_PARENT: u64 = 15;
const INIT: u64 = 16;
const NO_TASK: u64 = 17;
const ZERO: u64 = 18;
const NEGATIVE: u64 = 19;
/// A task this process traces outside the session
/// (`a_task_traced_outside_the_session_is_esrch`).
const BYSTANDER: u64 = 20;
const WAITING: u64 = 21;

type Fact = Result<SignalSets, FactError>;

/// The facts the tool read, by the guest's point number.
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

fn bit(signal: libc::c_int) -> u64 {
    1 << (signal - 1)
}

/// Asks the tool for thread `tid`'s signal sets at `point`.
fn ask(point: u64, tid: i32) {
    // SAFETY: tuxcall takes no pointers; only the tool answers it.
    unsafe { libc::syscall(libc::SYS_tuxcall, ASK, tid as libc::c_long, point) };
}

fn gettid() -> i32 {
    // SAFETY: gettid takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn check(result: libc::c_long, what: &str) -> libc::c_long {
    assert!(result >= 0, "{what}: {}", std::io::Error::last_os_error());
    result
}

/// The raw `rt_sigprocmask`: the kernel, not glibc, decides what a mask
/// may hold.
fn set_mask(how: libc::c_int, mask: u64) {
    // SAFETY: the kernel reads eight bytes of `mask` and writes nothing.
    check(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                how,
                &mask as *const u64,
                std::ptr::null_mut::<u64>(),
                8,
            )
        },
        "rt_sigprocmask",
    );
}

/// `rt_sigaction(signal, handler)` with `mask` as its `sa_mask`; glibc's
/// own restorer, as `sigaction(3)` installs it.
fn act(signal: libc::c_int, handler: libc::sighandler_t, mask: u64) -> libc::c_long {
    // SAFETY: sigaction is plain data; an all-zero value is valid.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    // SAFETY: the set is a valid sigset_t.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signal in 1..=64 {
        if mask & bit(signal) != 0 {
            // SAFETY: as above.
            unsafe { libc::sigaddset(&mut action.sa_mask, signal) };
        }
    }
    // SAFETY: action is a valid sigaction value the call only reads.
    let result = unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
    if result == 0 {
        0
    } else {
        -(std::io::Error::last_os_error().raw_os_error().unwrap() as libc::c_long)
    }
}

/// Takes one pending instance of `signal`, which the caller blocks.
fn take(signal: libc::c_int) -> libc::c_int {
    // SAFETY: the set is a valid sigset_t and the timeout a valid timespec.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        libc::sigtimedwait(&set, std::ptr::null_mut(), &zero)
    }
}

/// Waits up to a minute for `signal`, which the caller blocks.
fn wait_for(signal: libc::c_int) -> libc::c_int {
    // SAFETY: the set is a valid sigset_t and the timeout a valid timespec.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        let patience = libc::timespec {
            tv_sec: 60,
            tv_nsec: 0,
        };
        libc::sigtimedwait(&set, std::ptr::null_mut(), &patience)
    }
}

/// Waits until thread `tid` sleeps in `rt_sigtimedwait`: its state `S`, and
/// the call it is in, the first field of `/proc/<tid>/syscall`, that one.
fn await_sigtimedwait(tid: i32) {
    let call = libc::SYS_rt_sigtimedwait.to_string();
    for _ in 0..10_000 {
        let syscall = std::fs::read_to_string(format!("/proc/{tid}/syscall")).unwrap();
        let status = std::fs::read_to_string(format!("/proc/{tid}/status")).unwrap();
        if syscall.split(' ').next() == Some(call.as_str()) && status.contains("\nState:\tS") {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("thread {tid} never slept in rt_sigtimedwait");
}

fn tgkill(pid: i32, tid: i32, signal: libc::c_int) {
    // SAFETY: tgkill takes no pointers.
    check(
        unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, signal) },
        "tgkill",
    );
}

extern "C" fn on_signal(_signal: libc::c_int) {
    ask(IN_HANDLER, gettid());
}

extern "C" fn on_other(_signal: libc::c_int) {}

/// Starts from no handler, no ignored signal and an empty mask, whatever the
/// test process left: a fork keeps both.
fn reset() {
    for signal in 1..=64 {
        if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            continue;
        }
        // The kernel's struct: handler, flags, restorer, mask.
        let action = [libc::SIG_DFL as u64, 0, 0, 0];
        // SAFETY: the kernel reads the 32-byte action and writes nothing.
        check(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    signal,
                    action.as_ptr(),
                    std::ptr::null_mut::<u64>(),
                    8,
                )
            },
            "rt_sigaction",
        );
    }
    set_mask(libc::SIG_SETMASK, 0);
}

/// The guest: every point in order, as the KVM backend's fixture runs them.
fn guest() {
    reset();
    // SAFETY: getpid takes no arguments.
    let pid = unsafe { libc::getpid() };
    let tid = gettid();
    let (usr1, usr2) = (libc::SIGUSR1, libc::SIGUSR2);

    set_mask(libc::SIG_BLOCK, bit(usr1));
    tgkill(pid, tid, usr1);
    ask(SELF_PENDING, tid);
    assert_eq!(take(usr1), usr1);
    set_mask(libc::SIG_UNBLOCK, bit(usr1));

    set_mask(libc::SIG_BLOCK, bit(usr2));
    // SAFETY: kill takes no pointers.
    check(unsafe { libc::kill(pid, usr2) } as libc::c_long, "kill");
    ask(SHARED_PENDING, tid);
    assert_eq!(take(usr2), usr2);
    set_mask(libc::SIG_UNBLOCK, bit(usr2));

    assert_eq!(act(libc::SIGHUP, libc::SIG_IGN, 0), 0);
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    assert_eq!(act(usr2, handler, bit(libc::SIGWINCH)), 0);
    assert_eq!(act(libc::SIGCHLD, libc::SIG_DFL, 0), 0);
    assert_eq!(
        act(libc::SIGSTOP, libc::SIG_IGN, 0),
        -(libc::EINVAL as libc::c_long)
    );
    ask(ACTIONS, tid);

    let realtime = libc::SIGRTMIN();
    set_mask(libc::SIG_BLOCK, bit(realtime));
    for _ in 0..2 {
        // SAFETY: sigqueue takes the value by copy.
        let value = libc::sigval {
            sival_ptr: std::ptr::null_mut(),
        };
        check(
            unsafe { libc::sigqueue(pid, realtime, value) } as libc::c_long,
            "sigqueue",
        );
    }
    ask(REALTIME, tid);
    assert_eq!(take(realtime), realtime);
    assert_eq!(take(realtime), realtime);
    assert_eq!(take(realtime), -1);
    set_mask(libc::SIG_UNBLOCK, bit(realtime));

    set_mask(libc::SIG_SETMASK, u64::MAX);
    ask(FULL_MASK, tid);
    set_mask(libc::SIG_SETMASK, 0);

    set_mask(libc::SIG_BLOCK, bit(libc::SIGPIPE));
    tgkill(pid, tid, usr2);
    ask(AFTER_HANDLER, tid);
    set_mask(libc::SIG_UNBLOCK, bit(libc::SIGPIPE));

    let other = on_other as extern "C" fn(libc::c_int) as libc::sighandler_t;
    assert_eq!(act(usr1, other, 0), 0);
    let (ready_sender, ready) = mpsc::channel();
    let (release, release_receiver) = mpsc::channel::<()>();
    let sibling = std::thread::spawn(move || {
        set_mask(libc::SIG_SETMASK, bit(usr1) | bit(libc::SIGINT));
        ready_sender.send(gettid()).unwrap();
        release_receiver.recv().unwrap();
        // The leader now waits for this thread; ask about it.
        ask(LEADER_FROM_SIBLING, tid);
        assert_eq!(take(usr1), usr1);
    });
    let sibling_tid = ready.recv().unwrap();
    tgkill(pid, sibling_tid, usr1);
    ask(SIBLING, sibling_tid);
    release.send(()).unwrap();
    sibling.join().unwrap();

    // Another process: a child asks about this process while it waits, and
    // this process asks about the child's two threads while they wait, then
    // about the child as a zombie and once it is reaped.
    let (child_ready, child_release) = (pipe(), pipe());
    // SAFETY: this process has one thread; the child runs on its own copy.
    let child = unsafe { libc::fork() };
    if child == 0 {
        run_child(pid, child_ready, child_release);
    }
    check(child as libc::c_long, "fork");
    close(child_ready[1]);
    close(child_release[0]);
    assert_eq!(receive(child_ready[0]), child);
    ask(PARENT_READS_CHILD, child);
    send(child_release[1], 0);
    let second = receive(child_ready[0]);
    ask(CHILD_SIBLING, second);
    send(child_release[1], 0);
    // Exited, not reaped: wait without reaping.
    // SAFETY: siginfo_t is plain data; an all-zero value is valid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: info is writable.
    check(
        unsafe {
            libc::waitid(
                libc::P_PID,
                child as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        } as libc::c_long,
        "waitid",
    );
    ask(ZOMBIE_CHILD, child);
    let mut status = 0;
    // SAFETY: status is writable.
    check(
        unsafe { libc::waitpid(child, &mut status, 0) } as libc::c_long,
        "waitpid",
    );
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    ask(REAPED_CHILD, child);

    // A thread waiting in sigtimedwait for SIGUSR1, with SIGUSR1 and SIGUSR2
    // blocked, asked about while it sleeps there.
    let (waiter_ready, waiter_ready_receiver) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        set_mask(libc::SIG_SETMASK, bit(usr1) | bit(usr2));
        waiter_ready.send(gettid()).unwrap();
        assert_eq!(wait_for(usr1), usr1);
    });
    let waiter_tid = waiter_ready_receiver.recv().unwrap();
    await_sigtimedwait(waiter_tid);
    ask(WAITING, waiter_tid);
    tgkill(pid, waiter_tid, usr1);
    waiter.join().unwrap();

    // Host tasks the tracer does not trace: this guest's own parent, the
    // tracer's process, and init. Then numbers that name no task.
    // SAFETY: getppid takes no arguments.
    ask(HOST_PARENT, unsafe { libc::getppid() });
    ask(INIT, 1);
    ask(NO_TASK, i32::MAX);
    ask(ZERO, 0);
    ask(NEGATIVE, -1);
}

fn pipe() -> [i32; 2] {
    let mut fds = [0; 2];
    // SAFETY: fds has room for two descriptors.
    check(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } as libc::c_long,
        "pipe2",
    );
    fds
}

fn close(fd: i32) {
    // SAFETY: the descriptor is this guest's own.
    check(unsafe { libc::close(fd) } as libc::c_long, "close");
}

fn send(fd: i32, value: i32) {
    let bytes = value.to_ne_bytes();
    // SAFETY: bytes is a live four-byte buffer.
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), 4) };
    assert_eq!(written, 4, "{}", std::io::Error::last_os_error());
}

fn receive(fd: i32) -> i32 {
    let mut bytes = [0u8; 4];
    // SAFETY: bytes is a live four-byte buffer.
    let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), 4) };
    assert_eq!(read, 4, "{}", std::io::Error::last_os_error());
    i32::from_ne_bytes(bytes)
}

/// The child process, in two phases while the parent asks about it. First,
/// with one thread: SIGINT ignored, SIGUSR2 pending for that thread and
/// SIGTERM for the process, both blocked, and a question about the parent.
/// Then, with SIGTERM taken, a second thread with SIGQUIT pending. It exits
/// holding the first thread's SIGUSR2.
fn run_child(parent: i32, ready: [i32; 2], release: [i32; 2]) -> ! {
    close(ready[0]);
    close(release[1]);
    assert_eq!(act(libc::SIGINT, libc::SIG_IGN, 0), 0);
    set_mask(libc::SIG_SETMASK, bit(libc::SIGUSR2) | bit(libc::SIGTERM));
    // SAFETY: getpid takes no arguments.
    let pid = unsafe { libc::getpid() };
    tgkill(pid, gettid(), libc::SIGUSR2);
    // SAFETY: kill takes no pointers.
    check(
        unsafe { libc::kill(pid, libc::SIGTERM) } as libc::c_long,
        "kill",
    );
    ask(CHILD_READS_PARENT, parent);
    send(ready[1], pid);
    receive_byte(release[0]);

    assert_eq!(take(libc::SIGTERM), libc::SIGTERM);
    let (thread_ready, thread_ready_receiver) = mpsc::channel();
    let (thread_release, thread_release_receiver) = mpsc::channel::<()>();
    let second = std::thread::spawn(move || {
        set_mask(libc::SIG_SETMASK, bit(libc::SIGQUIT));
        // SAFETY: getpid takes no arguments.
        tgkill(unsafe { libc::getpid() }, gettid(), libc::SIGQUIT);
        thread_ready.send(gettid()).unwrap();
        thread_release_receiver.recv().unwrap();
    });
    send(ready[1], thread_ready_receiver.recv().unwrap());
    receive_byte(release[0]);
    thread_release.send(()).unwrap();
    second.join().unwrap();
    // SAFETY: _exit ends the child.
    unsafe { libc::_exit(0) }
}

fn receive_byte(fd: i32) {
    receive(fd);
}

#[test]
fn a_traced_guest_reports_its_threads_signal_sets() {
    let log = reverie_ptrace::testing::check_fn::<FactTool, _>(guest);
    let facts = log.0.into_inner().unwrap();
    assert_eq!(facts.len(), 20, "{facts:?}");
    let fact = |point: u64| match facts[&point].1 {
        Ok(sets) => sets,
        Err(error) => panic!("point {point}: {error:?}"),
    };
    let (usr1, usr2) = (bit(libc::SIGUSR1), bit(libc::SIGUSR2));
    let actions = (bit(libc::SIGHUP), usr2);
    let expect = |pending, shared, blocked, (ignored, caught): (u64, u64)| {
        SignalSets::new(pending, shared, blocked, ignored, caught)
    };
    assert_eq!(fact(SELF_PENDING), expect(usr1, 0, usr1, (0, 0)));
    assert_eq!(fact(SHARED_PENDING), expect(0, usr2, usr2, (0, 0)));
    assert_eq!(fact(ACTIONS), expect(0, 0, 0, actions));
    // Queued twice for the process, shown once.
    let realtime = bit(libc::SIGRTMIN());
    assert_eq!(fact(REALTIME), expect(0, realtime, realtime, actions));
    // Every signal but SIGKILL and SIGSTOP, which the kernel leaves out.
    let full = !(bit(libc::SIGKILL) | bit(libc::SIGSTOP));
    assert_eq!(fact(FULL_MASK), expect(0, 0, full, actions));
    let pipe = bit(libc::SIGPIPE);
    assert_eq!(
        fact(IN_HANDLER),
        expect(0, 0, pipe | bit(libc::SIGWINCH) | usr2, actions)
    );
    assert_eq!(fact(AFTER_HANDLER), expect(0, 0, pipe, actions));
    let caught = (bit(libc::SIGHUP), usr1 | usr2);
    assert_eq!(
        fact(SIBLING),
        expect(usr1, 0, usr1 | bit(libc::SIGINT), caught)
    );
    assert_eq!(fact(LEADER_FROM_SIBLING), expect(0, 0, 0, caught));
    assert_ne!(facts[&SIBLING].0, facts[&LEADER_FROM_SIBLING].0);
    assert_eq!(facts[&LEADER_FROM_SIBLING].0, facts[&SELF_PENDING].0);
    // The child inherits the actions and adds SIGINT's SIG_IGN; while it has
    // one thread, SIGTERM is pending for its process and SIGUSR2 for that
    // thread, and its second thread has SIGQUIT pending.
    let (term, quit) = (bit(libc::SIGTERM), bit(libc::SIGQUIT));
    let child_actions = (bit(libc::SIGHUP) | bit(libc::SIGINT), usr1 | usr2);
    assert_eq!(fact(CHILD_READS_PARENT), expect(0, 0, 0, caught));
    assert_eq!(
        fact(PARENT_READS_CHILD),
        expect(usr2, term, usr2 | term, child_actions)
    );
    assert_eq!(fact(CHILD_SIBLING), expect(quit, 0, quit, child_actions));
    assert_eq!(facts[&CHILD_READS_PARENT].0, facts[&SELF_PENDING].0);
    assert_ne!(facts[&PARENT_READS_CHILD].0, facts[&CHILD_SIBLING].0);
    assert_eq!(facts[&ZOMBIE_CHILD].0, facts[&PARENT_READS_CHILD].0);
    assert_eq!(facts[&REAPED_CHILD].0, facts[&PARENT_READS_CHILD].0);
    // While the waiter sleeps in sigtimedwait, its mask without SIGUSR1.
    assert_eq!(fact(WAITING), expect(0, 0, usr2, caught));
    assert_ne!(facts[&WAITING].0, facts[&SELF_PENDING].0);
    for point in [
        ZOMBIE_CHILD,
        REAPED_CHILD,
        HOST_PARENT,
        INIT,
        NO_TASK,
        ZERO,
        NEGATIVE,
    ] {
        assert_eq!(
            facts[&point].1,
            Err(FactError::Errno(Errno::ESRCH)),
            "point {point}"
        );
    }
    // The guest's parent is the tracer's process, a host task that exists.
    assert_eq!(facts[&HOST_PARENT].0, std::process::id() as i32);
}

/// A task a thread of this process traces, but that is no guest of the
/// session, is ESRCH: the session's own record of its tasks decides, not
/// only the kernel's word that a tracer of ours traces the task. The
/// bystander is a child of this test process that this thread traces.
#[test]
fn a_task_traced_outside_the_session_is_esrch() {
    // SAFETY: the child only pauses until it is killed.
    let bystander = unsafe { libc::fork() };
    if bystander == 0 {
        loop {
            // SAFETY: pause takes no arguments.
            unsafe { libc::pause() };
        }
    }
    check(bystander as libc::c_long, "fork");
    // SAFETY: the bystander is this process's own child; PTRACE_SEIZE leaves
    // it running.
    let seized = unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            bystander,
            std::ptr::null_mut::<libc::c_void>(),
            0 as libc::c_long,
        )
    };
    let log = (seized == 0).then(|| {
        reverie_ptrace::testing::check_fn::<FactTool, _>(move || ask(BYSTANDER, bystander))
    });
    // SAFETY: the bystander is this process's own child.
    unsafe { libc::kill(bystander, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: status is writable.
    let reaped = unsafe { libc::waitpid(bystander, &mut status, 0) };
    assert_eq!(
        seized,
        0,
        "PTRACE_SEIZE: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(reaped, bystander);
    let facts = log.unwrap().0.into_inner().unwrap();
    assert_eq!(
        facts[&BYSTANDER],
        (bystander, Err(FactError::Errno(Errno::ESRCH)))
    );
}
