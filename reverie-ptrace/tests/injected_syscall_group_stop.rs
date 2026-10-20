/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A syscall that a tool injects through Reverie's private page must report
//! the kernel's result exactly once, even when a job-control group stop lands
//! on the injecting thread around the single step.
//!
//! Under `PTRACE_TRACEME` a group stop is reported with the stop signal and no
//! event, so it looks like a signal-delivery stop. When another thread
//! initiates a group stop while the injected `syscall` executes, Linux checks
//! `JOBCTL_STOP_PENDING` in `get_signal` before it dequeues the step SIGTRAP
//! queued by `syscall_exit_work`, so the tracer sees the stop signal with RIP
//! already past the private `syscall` instruction and the kernel's result in
//! RAX. The injection must neither overwrite that completed result with
//! `-ERESTARTSYS` (re-executing the syscall through a restart) nor leave the
//! guest a raw restart code.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Signal;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::Fork;
use reverie::syscalls::Getpid;
use reverie::syscalls::Getppid;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Ppoll;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::RtTgsigqueueinfo;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::Sysno;
use reverie::syscalls::Tgkill;
#[cfg(target_arch = "x86_64")]
use reverie::syscalls::Vfork;
use reverie_ptrace::testing::test_fn;
use serde::Deserialize;
use serde::Serialize;

/// The guest dups its pipe's write end here; a zero-length write to this
/// descriptor is the marker the tool replaces with a one-byte write.
const PROBE_FD: i32 = 900;
/// A zero-length write to this descriptor is replaced with
/// `rt_tgsigqueueinfo(self, self, SIGSYS, buf)`, where `buf` is the marker's
/// buffer holding a guest-prepared siginfo.
const SIGQUEUE_FD: i32 = 901;
/// A zero-length write to this descriptor is replaced with
/// `rt_sigprocmask(SIG_UNBLOCK, buf, NULL)`.
const UNBLOCK_FD: i32 = 902;
/// Like `UNBLOCK_FD`, followed by an injected `getpid` whose result the tool
/// returns to the guest.
const UNBLOCK_THEN_GETPID_FD: i32 = 903;
/// Set by a test to run `UNBLOCK_THEN_GETPID_FD`'s `getpid` with the
/// tracer's soft `RLIMIT_NOFILE` at 0, so no descriptor can be opened during
/// it; the limit is restored when it returns.
static GETPID_WITHOUT_DESCRIPTORS: AtomicBool = AtomicBool::new(false);
/// A zero-length write to this descriptor is replaced with
/// `ppoll(NULL, 0, &buf.timeout, &buf.mask, 8)` for a `PpollArgs` at `buf`.
const PPOLL_FD: i32 = 904;
/// Like `PPOLL_FD`, followed by an injected `getpid` whose result the tool
/// returns to the guest.
const PPOLL_THEN_GETPID_FD: i32 = 905;
/// A zero-length write to this descriptor is replaced with `getppid`.
const GETPPID_FD: i32 = 906;
/// Like `PPOLL_FD`, but the tool returns 0 to the guest instead of the
/// `ppoll` result, so the guest's syscall is not restarted.
const PPOLL_THEN_ZERO_FD: i32 = 907;
/// For an `UnblockThenTrapArgs` at `buf`: `rt_sigprocmask(SIG_UNBLOCK,
/// &buf.set, NULL)`, then `getpid`, then `rt_tgsigqueueinfo(self, self,
/// SIGTRAP, &buf.info)`, each reported; the tool returns the last result.
const UNBLOCK_GETPID_THEN_TRAP_FD: i32 = 908;
/// `rt_sigprocmask(SIG_UNBLOCK, buf, NULL)`, then `getpid`, then `fork`, each
/// reported; the tool returns 0 to the guest.
const UNBLOCK_GETPID_FORK_THEN_ZERO_FD: i32 = 909;
/// `ExecInSignalHook` keeps `buf`, an `ExecArgs`, for its signal hook.
const EXEC_ARGS_FD: i32 = 910;
/// `tgkill(self, self, SIGSTOP)`, then `getpid`, each reported; the tool
/// returns the `getpid` result. The `tgkill` is skipped, and the `i32` at
/// `buf` left alone, once that `i32` is nonzero; the tool sets it to 1 when
/// it injects the `tgkill`, so a restarted marker sends no second SIGSTOP.
const SIGSTOP_THEN_GETPID_FD: i32 = 911;
/// For a `TimedSleepArgs` at `buf`: `setitimer(ITIMER_REAL, &buf.timer,
/// NULL)`, then `nanosleep(&buf.sleep, NULL)`, then `getpid`, each reported;
/// the tool returns the `nanosleep` result.
const TIMED_SLEEP_THEN_GETPID_FD: i32 = 912;
/// As `EXEC_ARGS_FD`, and the replacement program's post-exec callback ends
/// with `tail_inject(getpid)`.
const EXEC_ARGS_TAIL_AFTER_EXEC_FD: i32 = 913;
/// `TrapBeforeGetppid` leaves the tracer without descriptors at a
/// zero-length write here (`tracer_without_descriptors`) until its injected
/// `getppid` returns; the tool returns 0 to the guest.
const NO_DESCRIPTORS_FD: i32 = 914;

/// Guest memory for the injected `ppoll`.
#[repr(C)]
struct PpollArgs {
    mask: libc::sigset_t,
    timeout: libc::timespec,
}
/// Guest memory for `TIMED_SLEEP_THEN_GETPID_FD`.
#[repr(C)]
struct TimedSleepArgs {
    timer: libc::itimerval,
    sleep: libc::timespec,
}
/// Guest memory for `UNBLOCK_GETPID_THEN_TRAP_FD`.
#[repr(C)]
struct UnblockThenTrapArgs {
    set: libc::sigset_t,
    info: libc::siginfo_t,
}
const MARKERS: usize = 1500;

#[derive(Debug, Deserialize, Serialize)]
enum Report {
    Injected(Result<i64, i32>),
    Signal(i32),
    Timer,
    Rdtsc,
    /// The guest's original syscall number and return register at a stop.
    Regs(i64, i64),
}

#[derive(Default)]
struct Log {
    injected: Mutex<Vec<Result<i64, i32>>>,
    signals: Mutex<Vec<i32>>,
    regs: Mutex<Vec<(i64, i64)>>,
    timers: AtomicUsize,
    rdtscs: AtomicUsize,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Report;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        match report {
            Report::Injected(result) => self.injected.lock().unwrap().push(result),
            Report::Signal(signal) => self.signals.lock().unwrap().push(signal),
            Report::Timer => {
                self.timers.fetch_add(1, Ordering::Relaxed);
            }
            Report::Rdtsc => {
                self.rdtscs.fetch_add(1, Ordering::Relaxed);
            }
            Report::Regs(orig_syscall, ret) => self.regs.lock().unwrap().push((orig_syscall, ret)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplaceMarker;

#[reverie::tool]
impl Tool for ReplaceMarker {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        Ok(Some(signal))
    }
}

/// The marker replacements shared by `ReplaceMarker` and
/// `InjectInFirstSignalHook`.
async fn replace_marker<T, G>(guest: &mut G, syscall: Syscall) -> Result<i64, Error>
where
    T: Tool<GlobalState = Log>,
    G: Guest<T>,
{
    match syscall {
        Syscall::Write(write) if write.fd() == PROBE_FD && write.len() == 0 => {
            // A different syscall from the pending one: this takes the
            // private_inject -> untraced_syscall path.
            let result = guest.inject(write.with_len(1)).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        Syscall::Write(write) if write.fd() == SIGQUEUE_FD && write.len() == 0 => {
            let siginfo = write.buf().and_then(|buf| AddrMut::from_raw(buf.as_raw()));
            let result = guest
                .inject(
                    RtTgsigqueueinfo::new()
                        .with_tgid(guest.pid().as_raw())
                        .with_tid(guest.tid().as_raw())
                        .with_sig(libc::SIGSYS)
                        .with_siginfo(siginfo),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        Syscall::Write(write)
            if (write.fd() == UNBLOCK_FD || write.fd() == UNBLOCK_THEN_GETPID_FD)
                && write.len() == 0 =>
        {
            let set = write.buf().and_then(|buf| Addr::from_raw(buf.as_raw()));
            let result = guest
                .inject(
                    RtSigprocmask::new()
                        .with_how(libc::SIG_UNBLOCK)
                        .with_set(set)
                        .with_oldset(None)
                        .with_sigsetsize(8),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            if write.fd() == UNBLOCK_FD {
                return Ok(result?);
            }
            let limited = GETPID_WITHOUT_DESCRIPTORS.load(Ordering::Relaxed);
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if limited {
                // SAFETY: both calls only read or set this process's limit.
                unsafe {
                    assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
                    let lowered = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: limit.rlim_max,
                    };
                    assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lowered), 0);
                }
            }
            let result = guest.inject(Getpid::new()).await;
            if limited {
                // SAFETY: restores the limit read above.
                unsafe { assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0) };
            }
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        Syscall::Write(write)
            if (write.fd() == PPOLL_FD
                || write.fd() == PPOLL_THEN_GETPID_FD
                || write.fd() == PPOLL_THEN_ZERO_FD)
                && write.len() == 0 =>
        {
            let base = write.buf().map_or(0, |buf| buf.as_raw());
            let result = guest
                .inject(
                    Ppoll::new()
                        .with_fds(None)
                        .with_nfds(0)
                        .with_timeout(AddrMut::from_raw(
                            base + std::mem::offset_of!(PpollArgs, timeout),
                        ))
                        .with_sigmask(Addr::from_raw(base))
                        .with_sigsetsize(8),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            if write.fd() == PPOLL_FD {
                return Ok(result?);
            }
            if write.fd() == PPOLL_THEN_ZERO_FD {
                return Ok(0);
            }
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        Syscall::Write(write) if write.fd() == SIGSTOP_THEN_GETPID_FD && write.len() == 0 => {
            let sent = write
                .buf()
                .and_then(|buf| AddrMut::<i32>::from_raw(buf.as_raw()))
                .ok_or(Errno::EFAULT)?;
            if guest.memory().read_value(sent)? == 0 {
                guest.memory().write_value(sent, &1)?;
                let result = guest
                    .inject(
                        Tgkill::new()
                            .with_tgid(guest.pid().as_raw())
                            .with_tid(guest.tid().as_raw())
                            .with_sig(libc::SIGSTOP),
                    )
                    .await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
            }
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        Syscall::Write(write) if write.fd() == TIMED_SLEEP_THEN_GETPID_FD && write.len() == 0 => {
            let base = write.buf().map_or(0, |buf| buf.as_raw());
            let timer = Syscall::from_raw(
                Sysno::setitimer,
                SyscallArgs::new(
                    libc::ITIMER_REAL as usize,
                    base + std::mem::offset_of!(TimedSleepArgs, timer),
                    0,
                    0,
                    0,
                    0,
                ),
            );
            let sleep = Syscall::from_raw(
                Sysno::nanosleep,
                SyscallArgs::new(
                    base + std::mem::offset_of!(TimedSleepArgs, sleep),
                    0,
                    0,
                    0,
                    0,
                    0,
                ),
            );
            let mut slept = Ok(0);
            for (i, syscall) in [timer, sleep, Getpid::new().into()].into_iter().enumerate() {
                let result = guest.inject(syscall).await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                if i == 1 {
                    slept = result;
                }
            }
            Ok(slept?)
        }
        Syscall::Write(write) if write.fd() == GETPPID_FD && write.len() == 0 => {
            let result = guest.inject(Getppid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        Syscall::Write(write)
            if write.fd() == UNBLOCK_GETPID_FORK_THEN_ZERO_FD && write.len() == 0 =>
        {
            let set = write.buf().and_then(|buf| Addr::from_raw(buf.as_raw()));
            let result = guest
                .inject(
                    RtSigprocmask::new()
                        .with_how(libc::SIG_UNBLOCK)
                        .with_set(set)
                        .with_oldset(None)
                        .with_sigsetsize(8),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            let result = guest.inject(Fork::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(0)
        }
        Syscall::Write(write) if write.fd() == UNBLOCK_GETPID_THEN_TRAP_FD && write.len() == 0 => {
            let base = write.buf().map_or(0, |buf| buf.as_raw());
            let result = guest
                .inject(
                    RtSigprocmask::new()
                        .with_how(libc::SIG_UNBLOCK)
                        .with_set(Addr::from_raw(base))
                        .with_oldset(None)
                        .with_sigsetsize(8),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            let result = guest
                .inject(
                    RtTgsigqueueinfo::new()
                        .with_tgid(guest.pid().as_raw())
                        .with_tid(guest.tid().as_raw())
                        .with_sig(libc::SIGTRAP)
                        .with_siginfo(AddrMut::from_raw(
                            base + std::mem::offset_of!(UnblockThenTrapArgs, info),
                        )),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            Ok(result?)
        }
        other => Ok(guest.inject(other).await?),
    }
}

/// Like `ReplaceMarker`, but the first signal hook on each thread injects a
/// `getpid`, reported, before passing the signal through.
#[derive(Clone, Copy, Debug, Default)]
struct InjectInFirstSignalHook;

#[reverie::tool]
impl Tool for InjectInFirstSignalHook {
    type GlobalState = Log;
    /// Signal hooks run on this thread so far.
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        *guest.thread_state_mut() += 1;
        if *guest.thread_state_mut() == 1 {
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// Like `InjectInFirstSignalHook`, but the first signal hook injects `fork`.
#[derive(Clone, Copy, Debug, Default)]
struct ForkInFirstSignalHook;

#[reverie::tool]
impl Tool for ForkInFirstSignalHook {
    type GlobalState = Log;
    /// Signal hooks run on this thread so far.
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        *guest.thread_state_mut() += 1;
        if *guest.thread_state_mut() == 1 {
            let result = guest.inject(Fork::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// Guest memory naming the program `ExecInSignalHook` executes.
#[repr(C)]
struct ExecArgs {
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
}

/// Keeps the `ExecArgs` a zero-length write to `EXEC_ARGS_FD` or
/// `EXEC_ARGS_TAIL_AFTER_EXEC_FD` names, and executes them from the signal
/// hook of the next SIGUSR2. In any program, `geteuid` is replaced with
/// `getpid`; other markers are replaced as by `ReplaceMarker`.
#[derive(Clone, Copy, Debug, Default)]
struct ExecInSignalHook;

#[reverie::tool]
impl Tool for ExecInSignalHook {
    type GlobalState = Log;
    /// The address of the kept `ExecArgs`, and whether the post-exec
    /// callback ends with `tail_inject(getpid)`.
    type ThreadState = (usize, bool);

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription.syscall(Sysno::geteuid);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Write(write)
                if (write.fd() == EXEC_ARGS_FD || write.fd() == EXEC_ARGS_TAIL_AFTER_EXEC_FD)
                    && write.len() == 0 =>
            {
                *guest.thread_state_mut() = (
                    write.buf().map_or(0, |buf| buf.as_raw()),
                    write.fd() == EXEC_ARGS_TAIL_AFTER_EXEC_FD,
                );
                Ok(0)
            }
            Syscall::Geteuid(_) => guest.tail_inject(Getpid::new()).await,
            other => replace_marker(guest, other).await,
        }
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        if !guest.thread_state_mut().1 {
            return Ok(());
        }
        guest.tail_inject(Getpid::new()).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        let base = guest.thread_state_mut().0;
        if signal == Signal::SIGUSR2 && base != 0 {
            let field = |offset: usize| base + offset;
            let mut args = [0usize; 3];
            for (i, offset) in [
                std::mem::offset_of!(ExecArgs, path),
                std::mem::offset_of!(ExecArgs, argv),
                std::mem::offset_of!(ExecArgs, envp),
            ]
            .into_iter()
            .enumerate()
            {
                let addr = Addr::<usize>::from_raw(field(offset)).ok_or(Errno::EFAULT)?;
                args[i] = guest.memory().read_value(addr)?;
            }
            let execve = Syscall::from_raw(
                Sysno::execve,
                SyscallArgs::new(args[0], args[1], args[2], 0, 0, 0),
            );
            // Returns only if the exec fails.
            let result = guest.inject(execve).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// Guest outcome, printed on stdout as one whitespace-separated line.
#[derive(Debug, Default)]
struct Outcome {
    markers: usize,
    returned_one: usize,
    other_returns: Vec<i64>,
    bytes: usize,
}

fn drain(read_fd: i32) -> usize {
    let mut total = 0;
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is a valid writable buffer of the given length.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return total;
        }
        total += n as usize;
    }
}

fn guest() {
    static STOP: AtomicBool = AtomicBool::new(false);

    // SAFETY: plain libc calls on owned descriptors.
    let read_fd = unsafe {
        // A job-control stop signal is discarded in an orphaned process group.
        // Leading a new group whose parent (the tracer) is in another group of
        // the same session keeps SIGTSTP's default action a real stop.
        assert_eq!(libc::setpgid(0, 0), 0);
        let mut fds = [0; 2];
        assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK), 0);
        assert_eq!(libc::dup2(fds[1], PROBE_FD), PROBE_FD);
        libc::close(fds[1]);
        fds[0]
    };

    extern "C" fn stop_repeatedly(_: *mut libc::c_void) -> *mut libc::c_void {
        while !STOP.load(Ordering::Relaxed) {
            // SAFETY: raise has no memory-safety preconditions. SIGTSTP keeps
            // its default (stop) disposition, so delivering it initiates a
            // group stop that reaches the marker thread.
            unsafe { libc::raise(libc::SIGTSTP) };
        }
        std::ptr::null_mut()
    }
    // The guest is a fork of the multithreaded test process, so a lock another
    // test thread held at the fork stays held here forever. `std::thread`
    // takes std's stack-overflow `thread_info` lock when the thread starts and
    // again when it exits, and a guest that inherited it held hangs in
    // `join`. A raw pthread takes no std lock.
    let mut stopper: libc::pthread_t = 0;
    // SAFETY: stop_repeatedly has the pthread start-routine signature and
    // captures nothing; stopper is written before it is joined below.
    assert_eq!(
        unsafe {
            libc::pthread_create(
                &mut stopper,
                std::ptr::null(),
                stop_repeatedly,
                std::ptr::null_mut(),
            )
        },
        0
    );

    let mut outcome = Outcome {
        markers: MARKERS,
        ..Default::default()
    };
    let byte = 0x5au8;
    for _ in 0..MARKERS {
        // SAFETY: a zero-length write from a valid buffer.
        let ret = unsafe { libc::syscall(libc::SYS_write, PROBE_FD, &byte as *const u8, 0usize) };
        if ret == 1 {
            outcome.returned_one += 1;
        } else {
            outcome.other_returns.push(ret);
        }
        outcome.bytes += drain(read_fd);
    }
    STOP.store(true, Ordering::Relaxed);
    // SAFETY: stopper is a joinable thread created above and joined once.
    assert_eq!(
        unsafe { libc::pthread_join(stopper, std::ptr::null_mut()) },
        0
    );
    outcome.bytes += drain(read_fd);
    let others: Vec<String> = outcome.other_returns.iter().map(i64::to_string).collect();
    println!(
        "{} {} {} {}",
        outcome.markers,
        outcome.returned_one,
        outcome.bytes,
        others.join(",")
    );
}

fn parse_outcome(line: &str) -> Outcome {
    let mut fields = line.split(' ');
    let mut number = || {
        fields
            .next()
            .expect("outcome field")
            .parse()
            .expect("count")
    };
    let markers = number();
    let returned_one = number();
    let bytes = number();
    let other_returns = line
        .splitn(4, ' ')
        .nth(3)
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("return value"))
        .collect();
    Outcome {
        markers,
        returned_one,
        other_returns,
        bytes,
    }
}

#[test]
fn injected_syscall_completed_before_group_stop_reports_its_result_once() {
    let (output, log) = test_fn::<ReplaceMarker, _>(guest).expect("run group-stop guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let outcome = parse_outcome(stdout.trim());
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    let tstp = signals.iter().filter(|&&s| s == libc::SIGTSTP).count();
    let restarted = injected
        .iter()
        .filter(|result| matches!(result, Err(errno) if *errno == Errno::ERESTARTSYS.into_raw()))
        .count();
    eprintln!(
        "PROBE markers={} returned_one={} bytes={} injections={} restarted={} sigtstp_reports={} other_returns={:?}",
        outcome.markers,
        outcome.returned_one,
        outcome.bytes,
        injected.len(),
        restarted,
        tstp,
        outcome.other_returns,
    );
    assert!(tstp > 0, "the stopper thread never raised SIGTSTP");
    // Only the stopper thread receives SIGTSTP itself; the marker thread sees
    // nothing but group stops, which a restarted ptraced tracee ignores. No
    // injection may therefore be reported as interrupted or be repeated.
    assert_eq!(restarted, 0, "a group stop is not a signal delivery");
    assert_eq!(injected.len(), MARKERS, "each marker is injected once");
    assert_eq!(outcome.returned_one, MARKERS, "{outcome:?}");
    assert_eq!(
        outcome.bytes, MARKERS,
        "each marker must write exactly once"
    );
}

static SIGSYS_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_sigsys(_signal: libc::c_int) {
    SIGSYS_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// A synchronous-class signal (positive `si_code`) that the injected syscall
/// queues to its own thread is dequeued ahead of the step SIGTRAP, so the
/// tracer sees a genuine signal-delivery stop with RIP past the private
/// `syscall` and the completed result in RAX. The kernel under plain
/// execution returns that result and then runs the handler once; it must not
/// turn the completed syscall into `-ERESTARTSYS` (which, without
/// `SA_RESTART`, surfaces as `EINTR`) or run it twice.
#[test]
fn injected_syscall_completed_before_signal_delivery_keeps_its_result() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = count_sigsys as *const () as usize;
        // No SA_RESTART: a restarted-by-signal syscall would report EINTR.
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()),
            0
        );
        let mut info: libc::siginfo_t = std::mem::zeroed();
        info.si_signo = libc::SIGSYS;
        // A positive si_code classifies the queued signal as synchronous,
        // which Linux dequeues ahead of other pending signals.
        info.si_code = 1;
        let ret = libc::syscall(
            libc::SYS_write,
            SIGQUEUE_FD,
            &mut info as *mut libc::siginfo_t,
            0usize,
        );
        let calls = SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed);
        println!("{ret} {calls}");
    })
    .expect("run sigqueue guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!("PROBE sigqueue signals={:?}", *signals);
    eprintln!(
        "PROBE sigqueue guest={} injected={:?}",
        stdout.trim(),
        *injected
    );
    assert_eq!(
        *injected,
        vec![Ok(0)],
        "the injected syscall runs once and succeeds"
    );
    assert_eq!(
        stdout.trim(),
        "0 1",
        "guest sees success and one handler run"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGSYS],
        "the signal reaches the tool like any other signal delivery"
    );
}

static SIGSEGV_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_sigsegv(_signal: libc::c_int) {
    SIGSEGV_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

static SIGUSR1_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_sigusr1(_signal: libc::c_int) {
    SIGUSR1_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Installs `handler` for `signal` without `SA_RESTART`.
///
/// # Safety
/// Replaces the process-wide disposition of `signal`.
unsafe fn install_counter(signal: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as *const () as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
    }
}

/// Blocks `signals` and returns the set.
///
/// # Safety
/// Changes the calling thread's signal mask.
unsafe fn block(signals: &[libc::c_int]) -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &signal in signals {
            libc::sigaddset(&mut set, signal);
        }
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                &set as *const libc::sigset_t,
                0usize,
                8usize
            ),
            0
        );
        set
    }
}

/// Queues `signal` to the calling thread with `si_code`.
///
/// # Safety
/// Sends a signal to the calling thread.
unsafe fn queue_to_self(signal: libc::c_int, si_code: libc::c_int) {
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        info.si_signo = signal;
        info.si_code = si_code;
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_tgsigqueueinfo,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                signal,
                &mut info as *mut libc::siginfo_t,
            ),
            0
        );
    }
}

/// Two synchronous-class signals (positive `si_code`) queued while blocked
/// and unblocked by one injected `rt_sigprocmask` are both dequeued ahead of
/// the step SIGTRAP, one stop each, with RIP past the private `syscall`.
/// Linux under plain execution returns 0 and runs both handlers once (checked
/// with the same guest body run untraced: "0 1 1"). Holding them in the
/// single `pending_signal` slot delivered only the second one ("0 0 1").
#[test]
fn injected_syscall_completed_before_two_signal_deliveries_delivers_both() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        install_counter(libc::SIGSEGV, count_sigsegv);
        let set = block(&[libc::SIGSYS, libc::SIGSEGV]);
        queue_to_self(libc::SIGSYS, 1);
        queue_to_self(libc::SIGSEGV, 1);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        println!(
            "{ret} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            SIGSEGV_HANDLER_CALLS.load(Ordering::Relaxed)
        );
    })
    .expect("run two-signal guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE two-signal guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(*injected, vec![Ok(0)], "the unblock runs once and succeeds");
    assert_eq!(
        stdout.trim(),
        "0 1 1",
        "guest sees success and each handler runs once"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGSYS, libc::SIGSEGV],
        "both signals reach the tool, in queue order"
    );
}

/// A signal that becomes deliverable before an injected `syscall` executes
/// interrupts it: Reverie reports `ERESTARTSYS` and delivers the signal at
/// the next resume, where the kernel turns the restart into `EINTR` because
/// the handler lacks `SA_RESTART`. SIGUSR1 queued by `tgkill` is not
/// synchronous-class, so the unblock's own step SIGTRAP is dequeued first and
/// the signal stops the following `getpid` before its `syscall`.
///
/// That stop takes the signal out of the kernel's queue into
/// `pending_signal`; the Tool must still be told about it before the resume
/// delivers it, or a Tool that acts on signals never sees this one
/// (https://github.com/rrnewton/hermit/issues/3468: Hermit's
/// `--sigint-instakill` missed a SIGINT that interrupted an injected stdin
/// read).
#[test]
fn signal_pending_before_injected_syscall_interrupts_it() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGUSR1, count_sigusr1);
        let set = block(&[libc::SIGUSR1]);
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGUSR1
            ),
            0
        );
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        let errno = *libc::__errno_location();
        println!(
            "{ret} {errno} {}",
            SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed)
        );
    })
    .expect("run interrupted-injection guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE interrupted guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; the signal interrupts getpid before it runs"
    );
    assert_eq!(
        stdout.trim(),
        format!("-1 {} 1", libc::EINTR),
        "guest sees EINTR and one handler run"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGUSR1],
        "the held signal is reported to the tool once before it is delivered"
    );
}

/// `ppoll` swaps in a temporary signal mask and leaves the kernel to restore
/// the saved one after signal handling. When the temporary mask unblocks a
/// pending synchronous-class signal, `ppoll` returns `-ERESTARTNOHAND` and
/// the signal is dequeued ahead of the step SIGTRAP. Returning it to the
/// kernel queue by masking it through ptrace would discard the saved mask, so
/// SIGSYS would stay unblocked after the call. Untraced Linux prints
/// "-1 4 1 1": EINTR, one handler run, SIGSYS blocked again.
#[test]
fn injected_mask_swapping_syscall_keeps_the_saved_mask() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        block(&[libc::SIGSYS]);
        queue_to_self(libc::SIGSYS, 1);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        let errno = *libc::__errno_location();
        let mut current: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                0usize,
                &mut current as *mut libc::sigset_t,
                8usize
            ),
            0
        );
        println!(
            "{ret} {errno} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            libc::sigismember(&current, libc::SIGSYS)
        );
    })
    .expect("run ppoll guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    eprintln!(
        "PROBE ppoll guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        *injected,
        vec![Err(Errno::ERESTARTNOHAND.into_raw())],
        "ppoll is interrupted by the signal its mask unblocks"
    );
    assert_eq!(
        stdout.trim(),
        format!("-1 {} 1 1", libc::EINTR),
        "guest sees EINTR, one handler run, and its saved mask restored"
    );
}

static SIGBUS_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_sigbus(_signal: libc::c_int) {
    SIGBUS_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Returns whether `signal` is in the calling thread's signal mask.
///
/// # Safety
/// Reads the calling thread's signal mask.
unsafe fn is_blocked(signal: libc::c_int) -> libc::c_int {
    unsafe {
        let mut current: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                0usize,
                &mut current as *mut libc::sigset_t,
                8usize
            ),
            0
        );
        libc::sigismember(&current, signal)
    }
}

/// Linux's `dequeue_synchronous_signal` returns the first queued
/// synchronous-class entry (positive `si_code`) without consulting the mask
/// whenever some unblocked synchronous signal is pending, and the step
/// SIGTRAP always is. So a signal the guest keeps blocked can stop the
/// injected step after its `syscall` completed. Returning it to the kernel
/// queue must leave the guest's mask alone: unmasking it at the end of the
/// step would unblock a signal the guest itself blocked.
///
/// Oracle: the same guest body under `strace -f` prints "0 0 1 1" (a tracer
/// resuming a blocked signal has `ptrace_signal` requeue it, so its handler
/// does not run, and SIGBUS stays blocked). Untraced Linux prints "0 1 1 1";
/// no ptrace tracer can match its SIGBUS handler count.
#[test]
fn guest_blocked_signal_dequeued_after_injected_syscall_stays_blocked() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGBUS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGBUS, count_sigbus);
        install_counter(libc::SIGSEGV, count_sigsegv);
        block(&[libc::SIGBUS, libc::SIGSEGV]);
        queue_to_self(libc::SIGBUS, 1);
        queue_to_self(libc::SIGSEGV, 1);
        let mut unblock: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut unblock);
        libc::sigaddset(&mut unblock, libc::SIGSEGV);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_FD,
            &unblock as *const libc::sigset_t,
            0usize,
        );
        println!(
            "{ret} {} {} {}",
            SIGBUS_HANDLER_CALLS.load(Ordering::Relaxed),
            SIGSEGV_HANDLER_CALLS.load(Ordering::Relaxed),
            is_blocked(libc::SIGBUS)
        );
    })
    .expect("run guest-blocked signal guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE guest-blocked guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(*injected, vec![Ok(0)], "the unblock runs once and succeeds");
    assert_eq!(
        stdout.trim(),
        "0 0 1 1",
        "success, SIGBUS still blocked and not run, SIGSEGV run once (strace oracle)"
    );
    // The requeued SIGBUS sits ahead of SIGSEGV, so the same quirk dequeues
    // it once more at the next resume: the tool sees it (as `strace -f` does)
    // and its requeue leaves it blocked, then SIGSEGV is delivered.
    assert_eq!(
        *signals,
        vec![libc::SIGBUS, libc::SIGSEGV],
        "the still-blocked SIGBUS is reported and requeued, then SIGSEGV delivered"
    );
}

/// The mask-swapping variant: an injected `ppoll` whose temporary mask keeps
/// SIGBUS blocked but unblocks SIGSYS, both queued with a positive `si_code`.
/// SIGBUS is dequeued first, still blocked; it must be requeued rather than
/// held, or it occupies the single hold slot and SIGSYS then fails the step
/// closed.
///
/// Oracle: the same guest body under `strace -f` prints "-1 4 1 0 1 1"
/// (EINTR, SIGSYS handler once, SIGBUS handler never, both blocked again
/// once `ppoll` restores the saved mask). Untraced Linux prints
/// "-1 4 1 1 1 1".
#[test]
fn injected_mask_swapping_syscall_requeues_a_signal_its_mask_blocks() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGBUS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        install_counter(libc::SIGBUS, count_sigbus);
        block(&[libc::SIGBUS, libc::SIGSYS]);
        queue_to_self(libc::SIGBUS, 1);
        queue_to_self(libc::SIGSYS, 1);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        libc::sigaddset(&mut args.mask, libc::SIGBUS);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        let errno = *libc::__errno_location();
        println!(
            "{ret} {errno} {} {} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            SIGBUS_HANDLER_CALLS.load(Ordering::Relaxed),
            is_blocked(libc::SIGBUS),
            is_blocked(libc::SIGSYS)
        );
    })
    .expect("run ppoll guest-blocked guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE ppoll-blocked guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        *injected,
        vec![Err(Errno::ERESTARTNOHAND.into_raw())],
        "ppoll is interrupted by the signal its mask unblocks"
    );
    assert_eq!(
        stdout.trim(),
        format!("-1 {} 1 0 1 1", libc::EINTR),
        "EINTR, SIGSYS run once, SIGBUS never run, saved mask restored (strace oracle)"
    );
    assert!(
        !signals.contains(&libc::SIGBUS),
        "the still-blocked SIGBUS is never delivered: {signals:?}"
    );
}

/// Two synchronous-class signals requeued after an injected `rt_sigprocmask`
/// completes are pending again before the callback's next injected
/// `syscall` (`getpid`), which is therefore reported as interrupted. Both
/// handlers still run exactly once and the guest sees EINTR.
///
/// This is not native Linux, where both handlers run between the two
/// syscalls and `getpid` succeeds; untraced the same guest body prints the
/// pid. The signal that stops `getpid` before its `syscall` (SIGSYS) is
/// held in the single `pending_signal` slot, and SIGSEGV is then delivered
/// from the kernel queue.
///
/// Known gaps pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the interrupted `getpid` and the signal parked in the single slot; and
/// the held SIGSYS reaches the guest unreported, as on main, because SIGSEGV
/// is still pending: a hook injecting for SIGSYS would have its own step
/// take SIGSEGV into the occupied slot
/// (`held_signal_is_not_reported_while_another_signal_is_pending`).
#[test]
fn requeued_signals_interrupt_the_next_injected_syscall() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        install_counter(libc::SIGSEGV, count_sigsegv);
        let set = block(&[libc::SIGSYS, libc::SIGSEGV]);
        queue_to_self(libc::SIGSYS, 1);
        queue_to_self(libc::SIGSEGV, 1);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        let errno = *libc::__errno_location();
        println!(
            "{ret} {errno} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            SIGSEGV_HANDLER_CALLS.load(Ordering::Relaxed)
        );
    })
    .expect("run requeue-then-interrupt guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE requeue-interrupt guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; a requeued signal interrupts getpid before it runs"
    );
    assert_eq!(
        stdout.trim(),
        format!("-1 {} 1 1", libc::EINTR),
        "guest sees EINTR and each handler run once"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGSEGV],
        "SIGSYS bypasses the tool through pending_signal (known gap)"
    );
}

/// An injected `ppoll` whose temporary mask unblocks two pending
/// synchronous-class signals. Both are dequeued ahead of the step SIGTRAP, one
/// stop each. The first is held for delivery at the guest's syscall site and
/// the step stops there, leaving the second (and the step SIGTRAP) queued in
/// the kernel: holding both would need a second hold slot, and returning the
/// second to the queue by masking it would discard `ppoll`'s saved mask.
///
/// Oracle: untraced Linux and `strace -f` both print "-1 4 1 1 1 1" (EINTR,
/// each handler once, both blocked again once the saved mask is restored).
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the held SIGSYS reaches the guest through the `pending_signal` slot
/// unreported, because `ppoll`'s saved mask is still to be restored and
/// SIGSEGV is still pending when the resume delivers it; only SIGSEGV,
/// delivered from the kernel queue, is reported to the tool.
#[test]
fn injected_mask_swapping_syscall_holds_the_first_of_two_unblocked_signals() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        install_counter(libc::SIGSEGV, count_sigsegv);
        block(&[libc::SIGSYS, libc::SIGSEGV]);
        queue_to_self(libc::SIGSYS, 1);
        queue_to_self(libc::SIGSEGV, 1);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        let errno = *libc::__errno_location();
        println!(
            "{ret} {errno} {} {} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            SIGSEGV_HANDLER_CALLS.load(Ordering::Relaxed),
            is_blocked(libc::SIGSYS),
            is_blocked(libc::SIGSEGV)
        );
    })
    .expect("run ppoll two-signal guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE ppoll-two guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        *injected,
        vec![Err(Errno::ERESTARTNOHAND.into_raw())],
        "ppoll is interrupted by the signals its mask unblocks"
    );
    assert_eq!(
        stdout.trim(),
        format!("-1 {} 1 1 1 1", libc::EINTR),
        "EINTR, each handler run once, saved mask restored (native and strace oracle)"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGSEGV],
        "the held SIGSYS bypasses the tool (known gap); SIGSEGV is reported"
    );
}

/// After a held signal stops the step of an injected `ppoll`, that step's
/// SIGTRAP is still queued. The same callback's next injection (`getpid`)
/// meets it before its own `syscall` executes; it must be discarded rather
/// than read as that step's completion, which would report RAX (the syscall
/// number, 39) for a `getpid` that never ran.
///
/// Known gaps pinned here, tracked in TaskGraph
/// `reverie_pending_signal_single_slot`: resuming the second step lets the
/// kernel restore `ppoll`'s saved mask before the held SIGSYS is delivered,
/// so it is requeued blocked and its handler never runs. Untraced, the same
/// callback would return the pid after one SIGSYS handler run.
///
/// Because the restored mask blocks SIGSYS at the final resume, the kernel
/// requeues it instead of delivering it, so it is not reported to the tool:
/// a report here would claim a delivery that did not happen, and the tool
/// would see the signal a second time once the guest unblocks it.
#[test]
fn injection_after_a_held_signal_discards_the_stale_step_trap() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        block(&[libc::SIGSYS]);
        queue_to_self(libc::SIGSYS, 1);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_THEN_GETPID_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        println!(
            "{} {} {} {}",
            ret == libc::getpid() as i64,
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            is_blocked(libc::SIGSYS),
            ret
        );
    })
    .expect("run ppoll-then-getpid guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE ppoll-getpid guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(injected.len(), 2, "{:?}", *injected);
    assert_eq!(
        injected[0],
        Err(Errno::ERESTARTNOHAND.into_raw()),
        "ppoll is interrupted by the signal its mask unblocks"
    );
    assert_ne!(
        injected[1],
        Ok(libc::SYS_getpid),
        "the stale step SIGTRAP was read as getpid's completion"
    );
    let fields: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(
        fields[..3],
        ["true", "0", "1"],
        "getpid ran and returned the pid; SIGSYS stays pending and blocked (known gap)"
    );
    assert_eq!(
        *signals,
        Vec::<i32>::new(),
        "the requeued, still-blocked SIGSYS is not reported as delivered"
    );
}

/// Whether `signal` is pending for the calling thread.
///
/// # Safety
/// Plain libc calls on a local set.
unsafe fn is_pending(signal: libc::c_int) -> libc::c_int {
    unsafe {
        let mut pending: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigpending,
                &mut pending as *mut libc::sigset_t,
                8usize
            ),
            0
        );
        libc::sigismember(&pending, signal)
    }
}

/// Unblocks `signal` for the calling thread.
///
/// # Safety
/// Changes the calling thread's signal mask.
unsafe fn unblock(signal: libc::c_int) {
    unsafe { unblock_returning(signal, 0) }
}

/// As `unblock`, but checks that the unblock returns `ret`.
///
/// A signal the unblock lets through stops the guest at its delivery stop
/// as the unblock returns. A hook that injects there leaves its last
/// injection's return value in the guest's return register, so the unblock
/// returns that value instead of 0. Main leaks the injected result this way
/// (<https://github.com/rrnewton/reverie/issues/892>); tests that pin the
/// leak pass the leaked value as `ret`, and a fix flips those pins to 0.
///
/// # Safety
/// Changes the calling thread's signal mask.
unsafe fn unblock_returning(signal: libc::c_int, ret: libc::c_long) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_UNBLOCK,
                &set as *const libc::sigset_t,
                0usize,
                8usize
            ),
            ret
        );
    }
}

/// The held SIGSYS of `injected_mask_swapping_syscall_keeps_the_saved_mask`,
/// with a signal hook that injects `getpid` before passing a signal through.
/// The guest's result is `ppoll`'s, and nothing restarts it. The outcome is
/// the non-injecting `ReplaceMarker`'s: untraced Linux and that test print
/// "-1 4 1 1 0 1": EINTR, one handler run, SIGSYS blocked again and no
/// longer pending, and no second handler run once it is unblocked.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// as in `injected_mask_swapping_syscall_keeps_the_saved_mask`, the held
/// SIGSYS is passed on without a report while `ppoll`'s restore of its
/// saved mask is pending, so the hook never runs.
#[test]
fn signal_hook_injecting_after_a_held_signal_keeps_the_guest_result() {
    let (output, log) = test_fn::<InjectInFirstSignalHook, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        block(&[libc::SIGSYS]);
        queue_to_self(libc::SIGSYS, 1);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        let errno = *libc::__errno_location();
        let calls = SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed);
        let blocked = is_blocked(libc::SIGSYS);
        let pending = is_pending(libc::SIGSYS);
        unblock(libc::SIGSYS);
        println!(
            "{ret} {errno} {calls} {blocked} {pending} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            libc::getpid()
        );
    })
    .expect("run signal-hook injection guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE hook-inject-held guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        fields,
        format!("-1 {} 1 1 0 1", libc::EINTR),
        "guest sees EINTR, one handler run, and SIGSYS blocked and not pending"
    );
    assert_ne!(pid, 0);
    let restart = Err(Errno::ERESTARTNOHAND.into_raw());
    assert_eq!(
        *injected,
        vec![restart],
        "ppoll is interrupted; no hook runs (known gap)"
    );
    assert_eq!(
        *signals,
        Vec::<i32>::new(),
        "the held SIGSYS is not reported (known gap)"
    );
}

/// As `signal_hook_injecting_after_a_held_signal_keeps_the_guest_result`, but
/// the tool returns 0 for the guest's syscall, so nothing restarts it. SIGSYS
/// is delivered before the guest's syscall returns, and is blocked again
/// afterwards. The guest's outcome is the one it has under the
/// non-injecting `ReplaceMarker`, run here too: "0 1 1 0 1". The held SIGSYS
/// is not reported, as there (known gap,
/// https://github.com/rrnewton/reverie/issues/845).
#[test]
fn signal_hook_injecting_after_a_held_signal_delivers_it_as_without_the_injection() {
    fn guest() {
        // SAFETY: plain libc calls on this thread's signal state and on
        // buffers that outlive each call.
        unsafe {
            SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGSYS, count_sigsys);
            block(&[libc::SIGSYS]);
            queue_to_self(libc::SIGSYS, 1);
            let mut args: PpollArgs = std::mem::zeroed();
            libc::sigemptyset(&mut args.mask);
            args.timeout.tv_sec = 5;
            let ret = libc::syscall(
                libc::SYS_write,
                PPOLL_THEN_ZERO_FD,
                &mut args as *mut PpollArgs,
                0usize,
            );
            let calls = SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed);
            let blocked = is_blocked(libc::SIGSYS);
            let pending = is_pending(libc::SIGSYS);
            unblock(libc::SIGSYS);
            println!(
                "{ret} {calls} {blocked} {pending} {} {}",
                SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
                libc::getpid()
            );
        }
    }
    let (plain, _) = test_fn::<ReplaceMarker, _>(guest).expect("run non-injecting guest");
    let (output, log) =
        test_fn::<InjectInFirstSignalHook, _>(guest).expect("run signal-hook injection guest");
    for output in [&plain, &output] {
        assert_eq!(
            output.status,
            ExitStatus::Exited(0),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let plain = String::from_utf8_lossy(&plain.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE hook-inject-held-zero guest={} plain={} injected={:?} signals={:?}",
        stdout.trim(),
        plain.trim(),
        *injected,
        *signals
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    let (plain_fields, _) = plain.trim().rsplit_once(' ').expect("guest pid");
    assert_eq!(
        plain_fields, "0 1 1 0 1",
        "without the hook's injection SIGSYS runs its handler during the marker"
    );
    assert_eq!(
        fields, plain_fields,
        "the hook's injection does not change the guest's outcome"
    );
    assert_ne!(pid, 0);
    assert_eq!(
        *injected,
        vec![Err(Errno::ERESTARTNOHAND.into_raw())],
        "ppoll is interrupted; no hook runs (known gap)"
    );
    assert_eq!(
        *signals,
        Vec::<i32>::new(),
        "the held SIGSYS is not reported (known gap)"
    );
}

/// The ordinary signal route with the same hook: the guest's own `ppoll`,
/// whose temporary mask lets a pending SIGSYS through, is not intercepted.
/// Untraced Linux prints "-1 4 1 1 0 1".
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the hook's `getpid` lets the kernel restore the saved mask, which blocks
/// SIGSYS, so SIGSYS is requeued, and the guest keeps the hook's `getpid`
/// result, as in `always_injecting_hook_requeues_at_a_delivery_stop`.
/// SIGSYS is reported again, and handled, when the guest unblocks it.
#[test]
fn signal_hook_injecting_at_a_delivery_stop_requeues_its_signal() {
    let (output, log) = test_fn::<InjectInFirstSignalHook, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        block(&[libc::SIGSYS]);
        queue_to_self(libc::SIGSYS, 1);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        let errno = *libc::__errno_location();
        let calls = SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed);
        let blocked = is_blocked(libc::SIGSYS);
        let pending = is_pending(libc::SIGSYS);
        unblock(libc::SIGSYS);
        println!(
            "{ret} {errno} {calls} {blocked} {pending} {} {}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            libc::getpid()
        );
    })
    .expect("run signal-hook injection guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE hook-inject-ordinary guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    let (ret, fields) = fields.split_once(' ').expect("guest result");
    let (_errno, fields) = fields.split_once(' ').expect("guest errno");
    assert_eq!(
        (ret, fields),
        (pid.to_string().as_str(), "0 1 1 1"),
        "guest sees the hook's getpid, no handler run, and SIGSYS blocked and pending until unblocked (known gap)"
    );
    assert_eq!(*injected, vec![Ok(pid)], "the hook's getpid runs once");
    assert_eq!(
        *signals,
        vec![libc::SIGSYS, libc::SIGSYS],
        "SIGSYS is reported at its delivery stop and again after the unblock (known gap)"
    );
}

/// A held SIGTSTP with its default (stop) disposition, as in
/// `signal_pending_before_injected_syscall_interrupts_it`. Resuming with it
/// starts a group stop, which the tracer sees as a second SIGTSTP stop
/// without siginfo. That stop is a consequence of the one delivery the tool
/// was told about, so the tool is not told again. A restarted ptraced tracee
/// does not honor the stop; the interrupted marker restarts and its
/// injections run again, the `getpid` now returning the pid.
#[test]
fn held_default_action_stop_signal_is_reported_once() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        // As in `guest`: a stop signal is discarded in an orphaned group.
        assert_eq!(libc::setpgid(0, 0), 0);
        let set = block(&[libc::SIGTSTP]);
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGTSTP
            ),
            0
        );
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        println!("{ret} {}", libc::getpid());
    })
    .expect("run held stop-signal guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE held-sigtstp guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let (ret, pid) = stdout.trim().split_once(' ').expect("guest output");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(ret, pid.to_string(), "the restarted marker returns the pid");
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(0), Ok(pid)],
        "SIGTSTP interrupts getpid; the restarted marker runs both injections"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGTSTP],
        "one SIGTSTP is reported once, not again at its group stop"
    );
}

/// `held_default_action_stop_signal_is_reported_once` with a blocked SIGURG
/// also pending, so the held SIGTSTP is passed on unreported
/// (`check_held_signal_with_another_pending`). The group stop its delivery
/// starts is then reported instead, as on main, where every group stop was
/// reported: the Tool sees the one SIGTSTP once.
#[test]
fn held_stop_signal_passed_unreported_is_reported_at_its_group_stop() {
    let (output, log) = test_fn_bounded::<ReplaceMarker, _>(
        || unsafe {
            // As in `guest`: a stop signal is discarded in an orphaned group.
            assert_eq!(libc::setpgid(0, 0), 0);
            block(&[libc::SIGURG]);
            let set = block(&[libc::SIGTSTP]);
            for signal in [libc::SIGURG, libc::SIGTSTP] {
                assert_eq!(
                    libc::syscall(
                        libc::SYS_tgkill,
                        libc::getpid(),
                        libc::syscall(libc::SYS_gettid),
                        signal
                    ),
                    0
                );
            }
            let ret = libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            println!("{ret} {}", libc::getpid());
        },
        "held stop signal passed unreported",
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE held-sigtstp-unreported guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let (ret, pid) = stdout.trim().split_once(' ').expect("guest output");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(ret, pid.to_string(), "the restarted marker returns the pid");
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(0), Ok(pid)],
        "SIGTSTP interrupts getpid; the restarted marker runs both injections"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGTSTP],
        "the SIGTSTP passed on unreported is reported once, at its group stop"
    );
}

/// SIGSTOP sent by an injected `tgkill` is not synchronous-class, so, as
/// SIGUSR1 in `signal_pending_before_injected_syscall_interrupts_it`, the
/// `tgkill`'s step SIGTRAP is dequeued first and SIGSTOP stops the following
/// `getpid` before its `syscall`, which holds it. It is resumed without a
/// report, as the tracer never reports SIGSTOP to the tool: the resume starts
/// a group stop, which a ptraced tracee does not honor once restarted. The
/// interrupted marker restarts, sends no second SIGSTOP, and its `getpid`
/// now returns the pid.
#[test]
fn held_sigstop_is_not_reported() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        let mut sent: i32 = 0;
        let ret = libc::syscall(
            libc::SYS_write,
            SIGSTOP_THEN_GETPID_FD,
            &mut sent as *mut i32,
            0usize,
        );
        println!("{ret} {}", libc::getpid());
    })
    .expect("run held-SIGSTOP guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE held-sigstop guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let (ret, pid) = stdout.trim().split_once(' ').expect("guest pid");
    assert_eq!(ret, pid, "the guest gets the getpid result");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(pid)],
        "tgkill succeeds, SIGSTOP interrupts getpid before it runs, and the restarted marker's getpid runs"
    );
    assert_eq!(*signals, Vec::<i32>::new(), "SIGSTOP is not reported");
}

/// The ordinary route of a default-action SIGTSTP: its delivery stop is
/// reported, and the group stop that follows the delivery is not.
#[test]
fn default_action_stop_signal_is_reported_once() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        assert_eq!(libc::setpgid(0, 0), 0);
        assert_eq!(libc::raise(libc::SIGTSTP), 0);
        println!("resumed");
    })
    .expect("run stop-signal guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE sigtstp guest={} signals={:?}",
        stdout.trim(),
        *signals
    );
    assert_eq!(stdout.trim(), "resumed");
    assert_eq!(
        *signals,
        vec![libc::SIGTSTP],
        "one SIGTSTP is reported once, not again at its group stop"
    );
}

/// A guest may queue itself a SIGTRAP whose `si_code` is that of a syscall
/// stop (`SIGTRAP | 0x80`). Here SIGUSR1 is held as in
/// `signal_pending_before_injected_syscall_interrupts_it`, and the callback's
/// third injection queues such a SIGTRAP, which Linux dequeues ahead of the
/// step SIGTRAP: the injection ends at a genuine signal-delivery stop whose
/// siginfo reads like a syscall stop. Resuming from it delivers the held
/// SIGUSR1, so the tool must be told about SIGUSR1 first.
#[test]
fn held_signal_is_reported_at_a_delivery_stop_with_syscall_stop_siginfo() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGUSR1, count_sigusr1);
        let mut args: UnblockThenTrapArgs = std::mem::zeroed();
        args.set = block(&[libc::SIGUSR1]);
        args.info.si_signo = libc::SIGTRAP;
        args.info.si_code = libc::SIGTRAP | 0x80;
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGUSR1
            ),
            0
        );
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_GETPID_THEN_TRAP_FD,
            &mut args as *mut UnblockThenTrapArgs,
            0usize,
        );
        println!("{ret} {}", SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed));
    })
    .expect("run syscall-stop siginfo guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE trap-siginfo guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(0)],
        "SIGUSR1 interrupts getpid; the SIGTRAP is queued"
    );
    assert_eq!(
        stdout.trim(),
        "0 1",
        "the guest sees the last result and SIGUSR1's handler runs once"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGUSR1],
        "the held SIGUSR1 is reported once before it is delivered"
    );
}

#[cfg(target_arch = "x86_64")]
static SECCOMP_TRAPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static SECCOMP_CODE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
#[cfg(target_arch = "x86_64")]
static SECCOMP_SYSCALL: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
#[cfg(target_arch = "x86_64")]
static SECCOMP_RAX_SEEN: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// A SIGSYS handler emulating a seccomp-trapped syscall: records `si_code`,
/// `si_syscall` and the RAX it finds, then makes the syscall return 4242.
#[cfg(target_arch = "x86_64")]
extern "C" fn emulate_trapped_syscall(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: the kernel passes a valid siginfo and ucontext to an
    // SA_SIGINFO handler. For SIGSYS the siginfo union holds `_sigsys`
    // (`void *_call_addr; int _syscall; unsigned _arch;`) at offset 16.
    unsafe {
        let syscall = *(info.cast::<u8>().add(24).cast::<i32>());
        let gregs = &mut (*context.cast::<libc::ucontext_t>()).uc_mcontext.gregs;
        SECCOMP_CODE.store((*info).si_code as i64, Ordering::Relaxed);
        SECCOMP_SYSCALL.store(syscall as i64, Ordering::Relaxed);
        SECCOMP_RAX_SEEN.store(gregs[libc::REG_RAX as usize], Ordering::Relaxed);
        gregs[libc::REG_RAX as usize] = 4242;
    }
    SECCOMP_TRAPS.fetch_add(1, Ordering::Relaxed);
}

/// Loads a seccomp filter that traps `getppid` (`SECCOMP_RET_TRAP`) and
/// allows everything else, with `emulate_trapped_syscall` as the SIGSYS
/// handler.
///
/// # Safety
/// Replaces the process-wide SIGSYS disposition and restricts the calling
/// thread's syscalls for the rest of its life.
#[cfg(target_arch = "x86_64")]
unsafe fn trap_getppid() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = emulate_trapped_syscall as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()),
            0
        );
        let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let filter = [
            // seccomp_data.nr is at offset 0.
            statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            statement(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                libc::SYS_getppid as u32,
                0,
                1,
            ),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_TRAP, 0, 0),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog
            ),
            0
        );
    }
}

/// Prints the last trapped syscall's return value and what the handler saw.
#[cfg(target_arch = "x86_64")]
fn print_seccomp_trap(ret: i64) {
    println!(
        "{ret} {} {} {} {}",
        SECCOMP_TRAPS.load(Ordering::Relaxed),
        SECCOMP_CODE.load(Ordering::Relaxed),
        SECCOMP_SYSCALL.load(Ordering::Relaxed),
        SECCOMP_RAX_SEEN.load(Ordering::Relaxed)
    );
}

/// A seccomp `SECCOMP_RET_TRAP` filter the guest installed can trap a syscall
/// the tool injects. The kernel does not execute it: it rolls RAX back to the
/// syscall number and raises SIGSYS (`si_code` `SYS_SECCOMP`) with RIP already
/// past the private `syscall`, ahead of the step SIGTRAP. The tool must be
/// told the syscall did not run (`ENOSYS`), not handed the leftover syscall
/// number as a success, and the guest's SIGSYS handler must still run.
///
/// The first line is the in-place control, the same guest calling `getppid`
/// itself: the handler sees `si_code` 1, `si_syscall` 110 and RAX 110, and
/// the call returns the handler's 4242. In the injected case the handler
/// sees the `-ENOSYS` the tool returned instead of 110 (seccomp(2) leaves
/// that register architecture-dependent), and its 4242 is again the result.
#[cfg(target_arch = "x86_64")]
#[test]
fn injected_syscall_trapped_by_guest_seccomp_reports_enosys() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        trap_getppid();
        print_seccomp_trap(libc::syscall(libc::SYS_getppid));
        let ret = libc::syscall(libc::SYS_write, GETPPID_FD, std::ptr::null::<u8>(), 0usize);
        print_seccomp_trap(ret);
    })
    .expect("run seccomp-trap guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE seccomp-trap guest={:?} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        *injected,
        vec![Err(libc::ENOSYS)],
        "the trapped getppid did not run"
    );
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        [
            format!("4242 1 1 {} {}", libc::SYS_getppid, libc::SYS_getppid),
            format!("4242 2 1 {} {}", libc::SYS_getppid, -libc::ENOSYS),
        ],
        "in place and injected, the guest's SIGSYS handler emulates getppid once"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGSYS, libc::SIGSYS],
        "each SIGSYS reaches the tool"
    );
}

/// How a guest disposes of a requeued SIGBUS without its delivery.
#[derive(Clone, Copy)]
enum Consume {
    /// `rt_sigtimedwait`, which the tool does not intercept.
    Sigtimedwait,
    /// A switch to `SIG_IGN` and back, which discards the pending signal.
    Ignore,
}

/// Leaves a SIGBUS the tool was told about pending, consumes it as `consume`
/// says, and prints the `UNBLOCK_FD` marker's result, SIGSEGV's handler runs,
/// and whether SIGBUS was pending before and after.
///
/// This is `guest_blocked_signal_dequeued_after_injected_syscall_stays_blocked`:
/// SIGBUS and SIGSEGV are queued blocked with a positive `si_code`, and the
/// marker unblocks SIGSEGV only. Linux's synchronous dequeue takes the
/// still-blocked SIGBUS at a delivery stop, which is reported to the tool,
/// and resuming it requeues it because it is blocked. SIGSEGV is then
/// delivered.
///
/// # Safety
/// Changes the calling thread's signal state.
unsafe fn requeue_then_consume(consume: Consume) -> String {
    unsafe {
        SIGBUS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGBUS, count_sigbus);
        install_counter(libc::SIGSEGV, count_sigsegv);
        block(&[libc::SIGBUS, libc::SIGSEGV]);
        queue_to_self(libc::SIGBUS, 1);
        queue_to_self(libc::SIGSEGV, 1);
        let mut segv: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut segv);
        libc::sigaddset(&mut segv, libc::SIGSEGV);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_FD,
            &segv as *const libc::sigset_t,
            0usize,
        );
        let before = is_pending(libc::SIGBUS);
        match consume {
            Consume::Sigtimedwait => {
                let mut bus: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut bus);
                libc::sigaddset(&mut bus, libc::SIGBUS);
                let mut info: libc::siginfo_t = std::mem::zeroed();
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                assert_eq!(
                    libc::syscall(
                        libc::SYS_rt_sigtimedwait,
                        &bus as *const libc::sigset_t,
                        &mut info as *mut libc::siginfo_t,
                        &timeout as *const libc::timespec,
                        8usize,
                    ),
                    libc::SIGBUS as libc::c_long
                );
            }
            Consume::Ignore => {
                assert_ne!(libc::signal(libc::SIGBUS, libc::SIG_IGN), libc::SIG_ERR);
                install_counter(libc::SIGBUS, count_sigbus);
            }
        }
        format!(
            "{ret} {} {before} {}",
            SIGSEGV_HANDLER_CALLS.load(Ordering::Relaxed),
            is_pending(libc::SIGBUS)
        )
    }
}

/// How the guest sends itself the second SIGBUS after its requeued first one
/// was consumed.
#[derive(Clone, Copy)]
enum Resend {
    /// `kill`, after no intercepted syscall.
    Kill,
    /// `rt_tgsigqueueinfo` with the siginfo the first SIGBUS was queued with,
    /// which its requeue kept, after no intercepted syscall, so that the
    /// siginfo's contents cannot tell it from the requeued instance.
    Lookalike,
    /// As `Lookalike`, after an intercepted `getppid` marker.
    LookalikeAfterSyscall,
}

/// Sends the calling thread SIGBUS as `resend` says.
///
/// # Safety
/// Sends a signal to the calling thread, which must be the leader.
unsafe fn resend_sigbus(resend: Resend) {
    unsafe {
        if let Resend::Kill = resend {
            assert_eq!(libc::kill(libc::getpid(), libc::SIGBUS), 0);
            return;
        }
        if let Resend::LookalikeAfterSyscall = resend {
            libc::syscall(libc::SYS_write, GETPPID_FD, std::ptr::null::<u8>(), 0usize);
        }
        queue_to_self(libc::SIGBUS, 1);
    }
}

/// The SIGBUS requeued after the tool was told about it is consumed without
/// a delivery. A later SIGBUS that the guest sends itself as `resend` says is
/// a different instance, which the tool has not seen: it is reported on its
/// ordinary delivery when the guest unblocks it, and the handler runs once,
/// for the second SIGBUS.
///
/// The first phase depends on the tracer: only a tracer's requeue leaves a
/// SIGBUS for `requeue_then_consume` to consume. Untraced Linux delivers the
/// first SIGBUS, so its `rt_sigtimedwait` fails with EAGAIN. Untraced Linux is the
/// oracle for the second send alone: with no SIGBUS pending, it runs the
/// handler once.
fn consumed_requeue_then_resend_is_reported(consume: Consume, resend: Resend) {
    let (output, log) = test_fn::<ReplaceMarker, _>(move || unsafe {
        let first = requeue_then_consume(consume);
        resend_sigbus(resend);
        unblock(libc::SIGBUS);
        println!("{first} {}", SIGBUS_HANDLER_CALLS.load(Ordering::Relaxed));
    })
    .expect("run consumed-requeue guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE consumed-requeue guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        stdout.trim(),
        "0 1 1 0 1",
        "SIGSEGV runs once; the requeued SIGBUS is pending, then consumed; the second runs the handler once"
    );
    let mut expected = vec![Ok(0)];
    if let Resend::LookalikeAfterSyscall = resend {
        expected.push(Ok(std::process::id() as i64));
    }
    assert_eq!(*injected, expected, "the unblock runs once and succeeds");
    assert_eq!(
        *signals,
        vec![libc::SIGBUS, libc::SIGSEGV, libc::SIGBUS],
        "the tool sees each SIGBUS once, and SIGSEGV"
    );
}

#[test]
fn requeue_consumed_by_sigtimedwait_does_not_hide_a_later_signal() {
    consumed_requeue_then_resend_is_reported(Consume::Sigtimedwait, Resend::Kill);
}

#[test]
fn requeue_discarded_by_sig_ign_does_not_hide_a_later_signal() {
    consumed_requeue_then_resend_is_reported(Consume::Ignore, Resend::Kill);
}

/// The second SIGBUS's siginfo cannot tell it from the requeued instance (see
/// `Resend::Lookalike`), and no intercepted syscall passes between the
/// consumption and the lookalike; it is still a separate instance, which the
/// tool sees.
#[test]
fn requeue_consumed_by_sigtimedwait_does_not_hide_a_lookalike_signal() {
    consumed_requeue_then_resend_is_reported(Consume::Sigtimedwait, Resend::Lookalike);
}

/// As `consumed_requeue_then_resend_is_reported`, but the second SIGBUS is
/// held by the injected `ppoll` of another marker, whose temporary mask lets
/// it through, and reported before the resume that delivers it. As there,
/// untraced Linux is the oracle for the second send alone: a `ppoll` with
/// that SIGBUS pending returns EINTR, and the handler runs once.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// after the lookalike's marker syscall, the held SIGBUS is passed on
/// without a report, as in `injected_mask_swapping_syscall_keeps_the_saved_mask`.
/// The guest's outcome is still Linux's.
fn consumed_requeue_then_held(resend: Resend) {
    let (output, log) = test_fn::<ReplaceMarker, _>(move || unsafe {
        let first = requeue_then_consume(Consume::Sigtimedwait);
        resend_sigbus(resend);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        let errno = *libc::__errno_location();
        println!(
            "{first} {ret} {errno} {} {}",
            SIGBUS_HANDLER_CALLS.load(Ordering::Relaxed),
            is_pending(libc::SIGBUS),
        );
    })
    .expect("run consumed-requeue guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE consumed-requeue-held guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        stdout.trim(),
        format!("0 1 1 0 -1 {} 1 0", libc::EINTR),
        "the second SIGBUS interrupts the ppoll marker and runs the handler once"
    );
    let mut expected = vec![Ok(0)];
    if let Resend::LookalikeAfterSyscall = resend {
        expected.push(Ok(std::process::id() as i64));
    }
    expected.push(Err(Errno::ERESTARTNOHAND.into_raw()));
    assert_eq!(
        *injected, expected,
        "the unblock succeeds and the ppoll is interrupted"
    );
    let mut expected = vec![libc::SIGBUS, libc::SIGSEGV];
    if !matches!(resend, Resend::LookalikeAfterSyscall) {
        expected.push(libc::SIGBUS);
    }
    assert_eq!(
        *signals, expected,
        "the tool sees each SIGBUS once, and SIGSEGV; a held lookalike is not reported (known gap)"
    );
}

#[test]
fn consumed_requeue_does_not_hide_a_later_held_signal() {
    consumed_requeue_then_held(Resend::Kill);
}

#[test]
fn consumed_requeue_then_held_lookalike_is_delivered_unreported() {
    consumed_requeue_then_held(Resend::LookalikeAfterSyscall);
}

/// Writes `line` to stdout with `writev` and exits with `exit_group`,
/// neither of which the tools intercept, so no callback follows.
///
/// # Safety
/// Ends the process.
unsafe fn print_and_exit_unintercepted(line: &str) -> ! {
    unsafe {
        let iov = libc::iovec {
            iov_base: line.as_ptr() as *mut libc::c_void,
            iov_len: line.len(),
        };
        assert_eq!(libc::writev(1, &iov, 1), line.len() as isize);
        libc::syscall(libc::SYS_exit_group, 0);
        unreachable!("exit_group returned");
    }
}

/// One injected `rt_sigprocmask` unblocks two pending signals. SIGSYS,
/// queued with a positive `si_code`, is dequeued ahead of the step SIGTRAP
/// and held. SIGUSR1, sent by `tgkill`, is not synchronous-class and stays
/// queued. The hook for SIGSYS injects `getpid`, and SIGUSR1 stops that step
/// before its `syscall`, so SIGUSR1 is held while the callback for SIGSYS is
/// still running. The guest then exits without another intercepted syscall,
/// so no later callback could hand SIGUSR1 back. On untraced Linux the
/// unblock returns 0 and delivers both, each handler running once.
///
/// Known gap pinned here: SIGUSR1 stays in the tracer's single hold slot,
/// which nothing resumes from, so it is never reported or delivered
/// (https://github.com/rrnewton/reverie/issues/845). Also pinned: the
/// unblock's own result is `SYS_getpid`, the number of the hook's
/// injection, which SIGUSR1 interrupted before its `syscall`. Main leaks the
/// injection's register state into the guest's result here
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips this pin
/// to 0.
#[test]
fn signal_held_by_a_signal_hook_injection_is_not_delivered() {
    let (output, log) = test_fn::<InjectInFirstSignalHook, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        install_counter(libc::SIGUSR1, count_sigusr1);
        let set = block(&[libc::SIGSYS, libc::SIGUSR1]);
        queue_to_self(libc::SIGSYS, 1);
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGUSR1
            ),
            0
        );
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        print_and_exit_unintercepted(&format!(
            "{ret} {} {} {}\n",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
            SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed),
            libc::getpid()
        ));
    })
    .expect("run hook-held signal guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE hook-held guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let (fields, _pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    // Main leaks the injection's syscall number into the unblock's result;
    // see https://github.com/rrnewton/reverie/issues/892. A fix flips this
    // pin to "0 1 0".
    assert_eq!(
        fields,
        format!("{} 1 0", libc::SYS_getpid),
        "the unblock returns the hook's getpid number (known leak) and SIGSYS runs its handler; SIGUSR1 never does (known gap)"
    );
    assert_eq!(
        *injected,
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; SIGUSR1 interrupts the hook's getpid before it runs"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGSYS],
        "SIGUSR1, left in the hold slot, never reaches the tool (known gap)"
    );
}

/// The program `requeued_signal_survives_a_nonleader_exec` executes. It
/// prints whether SIGBUS is blocked and pending, installs a handler,
/// unblocks SIGBUS, and prints the handler's run count and the PID.
const UNBLOCK_SIGBUS_PY: &std::ffi::CStr = c"import os, signal
runs = []
blocked = int(signal.SIGBUS in signal.pthread_sigmask(signal.SIG_BLOCK, []))
pending = int(signal.SIGBUS in signal.sigpending())
signal.signal(signal.SIGBUS, lambda *_: runs.append(1))
signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGBUS])
print(blocked, pending, len(runs), os.getpid())
";

/// A worker thread's blocked SIGBUS is reported to the tool and requeued on
/// the worker's private queue, as in `requeue_then_consume`, and SIGSEGV is
/// delivered. The worker then executes another program, which takes the
/// leader's TID and keeps the worker's private queue, and that program
/// unblocks SIGBUS, whose handler then runs once.
///
/// The tool is told about SIGBUS three times. Once before the exec; once
/// after it, as the new program's initialization injects syscalls whose step
/// SIGTRAP lets Linux's synchronous dequeue take the still-blocked SIGBUS at
/// the next resume (it is requeued again, as `strace -f` sees it); and once
/// for its delivery. The new program runs in the same process: its PID is
/// the TGID the leader printed before the exec.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// one received SIGBUS should be reported once. The record that keeps a
/// requeued signal from being reported again covers only its later capture
/// by an injection's step, not ordinary delivery stops, and the exec
/// takeover clears it; main reports SIGBUS three times too.
#[test]
fn requeued_signal_survives_a_nonleader_exec() {
    extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: plain libc calls on this thread's signal state and on
        // buffers that outlive each call.
        unsafe {
            block(&[libc::SIGBUS, libc::SIGSEGV]);
            queue_to_self(libc::SIGBUS, 1);
            queue_to_self(libc::SIGSEGV, 1);
            let mut segv: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut segv);
            libc::sigaddset(&mut segv, libc::SIGSEGV);
            let ret = libc::syscall(
                libc::SYS_write,
                UNBLOCK_FD,
                &segv as *const libc::sigset_t,
                0usize,
            );
            assert_eq!(ret, 0);
            assert_eq!(SIGSEGV_HANDLER_CALLS.load(Ordering::Relaxed), 1);
            let path = c"/usr/bin/python3";
            let argv = [
                c"python3".as_ptr(),
                c"-c".as_ptr(),
                UNBLOCK_SIGBUS_PY.as_ptr(),
                std::ptr::null(),
            ];
            let envp = [std::ptr::null()];
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(3);
        }
    }
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSEGV, count_sigsegv);
        println!("{}", libc::getpid());
        let mut thread: libc::pthread_t = 0;
        assert_eq!(
            libc::pthread_create(&mut thread, std::ptr::null(), worker, std::ptr::null_mut()),
            0
        );
        // The worker's exec ends this thread.
        libc::pthread_join(thread, std::ptr::null_mut());
        libc::_exit(4);
    })
    .expect("run nonleader-exec guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE nonleader-exec guest={} injected={:?} signals={:?} stderr={}",
        stdout.trim(),
        *injected,
        *signals,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (tgid, program) = stdout.trim().split_once('\n').expect("two lines");
    let (fields, pid) = program.rsplit_once(' ').expect("program pid");
    assert_eq!(
        fields, "1 1 1",
        "SIGBUS stays blocked and pending across the exec, then runs the handler once"
    );
    assert_eq!(pid, tgid, "the program runs in the guest's process");
    assert_eq!(*injected, vec![Ok(0)], "the unblock runs once and succeeds");
    assert_eq!(
        *signals,
        vec![libc::SIGBUS, libc::SIGSEGV, libc::SIGBUS, libc::SIGBUS],
        "SIGBUS is reported before and after the exec, each time requeued, and when it is delivered"
    );
}

/// A held SIGUSR1 (as in `signal_pending_before_injected_syscall_interrupts_it`)
/// stays held while the same callback injects `fork`, and the callback
/// returns 0. The child's dispatch steps the parent to a signal-delivery stop
/// (its step SIGTRAP), from which the final resume delivers SIGUSR1 without
/// another stop, so it is reported before that resume.
#[test]
fn held_signal_is_reported_after_a_fork_injection() {
    let (output, log) = test_fn::<ReplaceMarker, _>(|| unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGUSR1, count_sigusr1);
        // The child's exit SIGCHLD stays pending rather than stopping the
        // parent at a time that depends on the child.
        block(&[libc::SIGCHLD]);
        let set = block(&[libc::SIGUSR1]);
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGUSR1
            ),
            0
        );
        let pid = libc::getpid();
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_GETPID_FORK_THEN_ZERO_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        if libc::getpid() != pid {
            libc::_exit(0);
        }
        let calls = SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed);
        let mut status = 0;
        let child = libc::waitpid(-1, &mut status, 0);
        println!("{ret} {calls} {child} {status}");
    })
    .expect("run held-fork guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE held-fork guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    let fields: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(injected.len(), 3, "unblock, getpid and fork are injected");
    let Ok(child) = injected[2] else {
        panic!("fork failed: {:?}", injected[2]);
    };
    assert_eq!(
        injected[..2],
        [Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; SIGUSR1 interrupts getpid before it runs"
    );
    assert_eq!(
        fields,
        ["0", "1", &child.to_string(), "0"],
        "the guest sees 0, runs the handler once, and reaps the forked child"
    );
    assert_eq!(
        *signals,
        vec![libc::SIGUSR1],
        "the held signal is reported once before it is delivered"
    );
}

/// `signal_hook_injecting_after_a_held_signal_keeps_the_guest_result` with a hook
/// that injects `fork`: the guest's interrupted `ppoll` keeps its
/// `-ERESTARTNOHAND`, which SIGSYS's delivery turns into EINTR. Untraced
/// Linux prints "-1 4 1 1 0 1".
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// as there, the held SIGSYS is passed on without a report, so the hook
/// never forks and the guest has no child to reap.
#[test]
fn signal_hook_forking_after_a_held_signal_keeps_the_guest_result() {
    let (output, log) = test_fn::<ForkInFirstSignalHook, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        block(&[libc::SIGSYS, libc::SIGCHLD]);
        queue_to_self(libc::SIGSYS, 1);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        libc::sigaddset(&mut args.mask, libc::SIGCHLD);
        args.timeout.tv_sec = 5;
        let pid = libc::getpid();
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        if libc::getpid() != pid {
            libc::_exit(0);
        }
        let errno = *libc::__errno_location();
        print_fork_hook_outcome(ret, errno);
    })
    .expect("run signal-hook fork guest");
    let (fields, child) = check_fork_hook_outcome(&output, &log, "hook-fork-held");
    assert_eq!(
        fields,
        format!("-1 {} 1 1 0 1", libc::EINTR),
        "guest sees EINTR, one handler run, and SIGSYS blocked and not pending"
    );
    assert_eq!(child, -1, "no hook forks, so there is no child (known gap)");
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Err(Errno::ERESTARTNOHAND.into_raw())],
        "ppoll is interrupted; no hook runs (known gap)"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        Vec::<i32>::new(),
        "the held SIGSYS is not reported (known gap)"
    );
}

/// `signal_hook_injecting_at_a_delivery_stop_requeues_its_signal` with a hook
/// that injects `fork`. Untraced Linux prints "-1 4 1 1 0 1".
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// as there, SIGSYS is requeued and the guest's `ppoll` returns the hook's
/// result, here the child's PID.
#[test]
fn signal_hook_forking_at_a_delivery_stop_requeues_its_signal() {
    let (output, log) = test_fn::<ForkInFirstSignalHook, _>(|| unsafe {
        SIGSYS_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSYS, count_sigsys);
        block(&[libc::SIGSYS, libc::SIGCHLD]);
        queue_to_self(libc::SIGSYS, 1);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let pid = libc::getpid();
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        if libc::getpid() != pid {
            libc::_exit(0);
        }
        let errno = *libc::__errno_location();
        print_fork_hook_outcome(ret, errno);
    })
    .expect("run signal-hook fork guest");
    let (fields, child) = check_fork_hook_outcome(&output, &log, "hook-fork-ordinary");
    assert!(child > 0, "the guest reaps the hook's child");
    let (ret, fields) = fields.split_once(' ').expect("guest result");
    let (_errno, fields) = fields.split_once(' ').expect("guest errno");
    assert_eq!(
        (ret, fields),
        (child.to_string().as_str(), "0 1 1 1"),
        "guest sees the child's PID, no handler run, and SIGSYS blocked and pending until unblocked (known gap)"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(child)],
        "the hook's fork runs once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGSYS, libc::SIGSYS],
        "SIGSYS is reported at its delivery stop and again after the unblock (known gap)"
    );
}

/// Prints a fork-hook guest's syscall result, errno, SIGSYS handler runs,
/// SIGSYS blocked and pending, handler runs after unblocking, and the child
/// it reaped.
///
/// # Safety
/// Changes the calling thread's signal mask and reaps a child.
unsafe fn print_fork_hook_outcome(ret: libc::c_long, errno: libc::c_int) {
    unsafe {
        let calls = SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed);
        let blocked = is_blocked(libc::SIGSYS);
        let pending = is_pending(libc::SIGSYS);
        unblock(libc::SIGSYS);
        let mut status = 0;
        let child = libc::waitpid(-1, &mut status, 0);
        println!(
            "{ret} {errno} {calls} {blocked} {pending} {} {child}",
            SIGSYS_HANDLER_CALLS.load(Ordering::Relaxed),
        );
    }
}

/// Checks that the guest exited cleanly, and returns
/// `print_fork_hook_outcome`'s line without its last field, and that field:
/// the reaped child, or -1 if there was none.
fn check_fork_hook_outcome(
    output: &reverie::process::Output,
    log: &Log,
    probe: &str,
) -> (String, i64) {
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    let (fields, child) = stdout.trim().rsplit_once(' ').expect("reaped child");
    (fields.to_string(), child.parse().expect("reaped child"))
}

/// Like `InjectInFirstSignalHook`, but the first signal hook injects `vfork`.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Default)]
struct VforkInFirstSignalHook;

#[cfg(target_arch = "x86_64")]
#[reverie::tool]
impl Tool for VforkInFirstSignalHook {
    type GlobalState = Log;
    /// Signal hooks run on this thread so far.
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        *guest.thread_state_mut() += 1;
        if *guest.thread_state_mut() == 1 {
            let result = guest.inject(Vfork::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// Makes the syscall `nr(a0, a1, a2)` and returns its raw result. A child that
/// a signal hook's `vfork` starts right after the `syscall` instruction shares
/// the stack of its parent, which stays suspended until the child exits; it
/// exits at once, writing no memory.
///
/// # Safety
/// Makes an arbitrary syscall.
#[cfg(target_arch = "x86_64")]
unsafe fn syscall_exiting_a_vfork_child(nr: libc::c_long, a0: i64, a1: i64, a2: i64) -> i64 {
    let pid = unsafe { libc::getpid() } as i64;
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            "mov r12, rax",
            "mov eax, {getpid}",
            "syscall",
            "cmp rax, r13",
            "je 2f",
            "mov eax, {exit}",
            "xor edi, edi",
            "syscall",
            "2:",
            getpid = const libc::SYS_getpid,
            exit = const libc::SYS_exit,
            inout("rax") nr => _,
            inout("rdi") a0 => _,
            in("rsi") a1,
            in("rdx") a2,
            in("r13") pid,
            out("r12") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Checks a vfork-hook guest's line, `{ret} {handler runs} {reaped child}
/// {status}`, and the injections after `before`, and that the hook saw
/// SIGUSR1 once. `ret` is the guest's expected result, or `None` where the
/// guest gets the hook's vfork child PID instead: main leaks an ordinary
/// signal callback's injected result into the guest's syscall
/// (<https://github.com/rrnewton/reverie/issues/892>).
#[cfg(target_arch = "x86_64")]
fn check_vfork_hook_outcome(
    output: &reverie::process::Output,
    log: &Log,
    probe: &str,
    ret: Option<i64>,
    before: &[Result<i64, i32>],
) {
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE {probe} guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(injected.len(), before.len() + 1, "{:?}", *injected);
    assert_eq!(injected[..before.len()], *before);
    let Ok(child) = injected[before.len()] else {
        panic!("vfork failed: {:?}", injected[before.len()]);
    };
    let fields: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(
        fields,
        [
            &ret.unwrap_or(child).to_string(),
            "1",
            &child.to_string(),
            "0"
        ],
        "the guest gets its result (or, where ret is None, the leaked child PID), runs the SIGUSR1 handler once, and reaps the hook's child"
    );
    assert_eq!(*signals, vec![libc::SIGUSR1], "the hook sees SIGUSR1 once");
}

/// A held SIGUSR1 (as in `signal_pending_before_injected_syscall_interrupts_it`)
/// is reported to a hook that injects `vfork`. The parent's step after the
/// child's exit ends at the vfork-done event stop, which drops a signal passed
/// on resume; the injection steps on to the step trap, so the final resume
/// still delivers SIGUSR1.
#[cfg(target_arch = "x86_64")]
#[test]
fn held_signal_is_delivered_after_a_signal_hook_vfork() {
    let (output, log) = test_fn::<VforkInFirstSignalHook, _>(|| unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGUSR1, count_sigusr1);
        // The child's exit SIGCHLD stays pending rather than stopping the
        // parent at a time that depends on the child.
        block(&[libc::SIGCHLD]);
        let set = block(&[libc::SIGUSR1]);
        assert_eq!(
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGUSR1
            ),
            0
        );
        let ret = syscall_exiting_a_vfork_child(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD as i64,
            &set as *const libc::sigset_t as i64,
            0,
        );
        let calls = SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed);
        let mut status = 0;
        let child = libc::waitpid(-1, &mut status, 0);
        println!("{ret} {calls} {child} {status}");
    })
    .expect("run held-vfork guest");
    check_vfork_hook_outcome(
        &output,
        &log,
        "held-vfork",
        Some(-(libc::EINTR as i64)),
        &[Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
    );
}

/// As `held_signal_is_delivered_after_a_signal_hook_vfork`, but SIGUSR1 is
/// reported at its own signal-delivery stop, after the guest's `tgkill`.
/// Untraced Linux returns 0 from `tgkill`. Pinned: the guest's `tgkill`
/// returns the hook's vfork child PID. Main leaks the injected result here
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips this pin
/// to `Some(0)`.
#[cfg(target_arch = "x86_64")]
#[test]
fn signal_is_delivered_after_a_signal_hook_vfork_at_its_delivery_stop() {
    let (output, log) = test_fn::<VforkInFirstSignalHook, _>(|| unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGUSR1, count_sigusr1);
        block(&[libc::SIGCHLD]);
        let ret = syscall_exiting_a_vfork_child(
            libc::SYS_tgkill,
            libc::getpid() as i64,
            libc::syscall(libc::SYS_gettid),
            libc::SIGUSR1 as i64,
        );
        let calls = SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed);
        let mut status = 0;
        let child = libc::waitpid(-1, &mut status, 0);
        println!("{ret} {calls} {child} {status}");
    })
    .expect("run delivery-stop vfork guest");
    // Main leaks the hook's vfork result into tgkill's; see
    // https://github.com/rrnewton/reverie/issues/892. A fix flips this to Some(0).
    check_vfork_hook_outcome(&output, &log, "delivery-vfork", None, &[]);
}

/// A signal hook executes another program. The replacement program's
/// `geteuid`, which the tool replaces with `getpid`, gets the PID: the
/// callback that injected the exec never resumed, and nothing of it, notably
/// that a signal callback was running (a held-signal callback's injections
/// keep the guest's return register), outlives it.
#[test]
fn exec_from_a_signal_hook_ends_the_callback() {
    let (output, log) = test_fn::<ExecInSignalHook, _>(|| unsafe {
        let path = c"/usr/bin/id";
        let argv = [c"id".as_ptr(), c"-u".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        let args = ExecArgs {
            path: path.as_ptr(),
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
        };
        libc::syscall(
            libc::SYS_write,
            EXEC_ARGS_FD,
            &args as *const ExecArgs,
            0usize,
        );
        use std::io::Write;
        println!("{}", libc::getpid());
        std::io::stdout().flush().unwrap();
        libc::kill(libc::getpid(), libc::SIGUSR2);
        // Reached only if the hook did not execute the program.
        libc::_exit(3);
    })
    .expect("run exec-from-hook guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE exec-hook guest={:?} injected={:?} signals={:?} stderr={}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 2, "the guest's PID, then id's output");
    assert_eq!(
        lines[1], lines[0],
        "id's geteuid, replaced with getpid, returns the PID"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR2]);
    assert!(log.injected.lock().unwrap().is_empty(), "the exec succeeds");
}

/// As `exec_from_a_signal_hook_ends_the_callback`, but the hook that
/// executes the program is a held signal's: SIGUSR2, pending and blocked,
/// is unblocked by the guest's marker, and the marker's `getpid` holds it.
/// A held callback's injections keep the guest's return register; the
/// replacement program runs outside that callback, so its `geteuid`, which
/// the tool replaces with `getpid`, gets the PID and not the `-ENOSYS` the
/// skipped syscall left.
#[test]
fn exec_from_a_held_signal_hook_ends_the_callback() {
    let (output, log) = test_fn_bounded::<ExecInSignalHook, _>(
        || unsafe {
            let path = c"/usr/bin/id";
            let argv = [c"id".as_ptr(), c"-u".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            let args = ExecArgs {
                path: path.as_ptr(),
                argv: argv.as_ptr(),
                envp: envp.as_ptr(),
            };
            libc::syscall(
                libc::SYS_write,
                EXEC_ARGS_FD,
                &args as *const ExecArgs,
                0usize,
            );
            use std::io::Write;
            println!("{}", libc::getpid());
            std::io::stdout().flush().unwrap();
            let set = block(&[libc::SIGUSR2]);
            assert_eq!(libc::kill(libc::getpid(), libc::SIGUSR2), 0);
            libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            // Reached only if the hook did not execute the program.
            libc::_exit(3);
        },
        "exec from a held signal hook",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE held-exec-hook guest={:?} injected={:?} signals={:?} stderr={}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; SIGUSR2 interrupts getpid before it runs, and the exec succeeds"
    );
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 2, "the guest's PID, then id's output");
    assert_eq!(
        lines[1], lines[0],
        "id's geteuid, replaced with getpid, returns the PID"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR2]);
}

/// As `exec_from_a_held_signal_hook_ends_the_callback`, but the replacement
/// program's post-exec callback ends with `tail_inject(getpid)`, which ends
/// the held signal's callback that made the exec. A successful exec does not
/// return to the callback, so it cannot ask for the held SIGUSR2: as after an
/// ordinary signal callback's exec, the replacement, whose SIGUSR2 is no
/// longer caught, resumes with no signal instead of dying of it. Main has no
/// held callback, so this guest dies of SIGUSR2 there; the input it guards
/// is a guest whose own handler executes the program, which main resumes
/// with no signal.
#[test]
fn held_signal_is_not_delivered_after_its_hook_executes_a_program() {
    let (output, log) = test_fn_bounded::<ExecInSignalHook, _>(
        || unsafe {
            let path = c"/usr/bin/id";
            let argv = [c"id".as_ptr(), c"-u".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            let args = ExecArgs {
                path: path.as_ptr(),
                argv: argv.as_ptr(),
                envp: envp.as_ptr(),
            };
            libc::syscall(
                libc::SYS_write,
                EXEC_ARGS_TAIL_AFTER_EXEC_FD,
                &args as *const ExecArgs,
                0usize,
            );
            use std::io::Write;
            println!("{}", libc::getpid());
            std::io::stdout().flush().unwrap();
            let set = block(&[libc::SIGUSR2]);
            assert_eq!(libc::kill(libc::getpid(), libc::SIGUSR2), 0);
            libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            // Reached only if the hook did not execute the program.
            libc::_exit(3);
        },
        "held signal hook executing a program with a post-exec tail injection",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE held-exec-tail guest={:?} status={:?} injected={:?} signals={:?} stderr={}",
        stdout.trim(),
        output.status,
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; SIGUSR2 interrupts getpid before it runs, and the exec succeeds"
    );
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 2, "the guest's PID, then id's output");
    assert_eq!(
        lines[1], lines[0],
        "id's geteuid, replaced with getpid, returns the PID"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR2]);
}

/// How many callbacks `InjectInEverySignalHook` injects in, so that a guest
/// whose signal is never delivered still ends.
const HOOK_INJECTIONS: u64 = 100;

/// Like `ReplaceMarker`, but every signal hook on each thread, up to
/// `HOOK_INJECTIONS` of them, injects a `getpid`, reported, before passing
/// the signal through.
#[derive(Clone, Copy, Debug, Default)]
struct InjectInEverySignalHook;

#[reverie::tool]
impl Tool for InjectInEverySignalHook {
    type GlobalState = Log;
    /// Signal hooks run on this thread so far.
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        *guest.thread_state_mut() += 1;
        if *guest.thread_state_mut() <= HOOK_INJECTIONS {
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// The value `queue_value_to_self` sends.
const QUEUED_VALUE: usize = 77;

static RECORDED_CALLS: AtomicUsize = AtomicUsize::new(0);
static RECORDED_CODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static RECORDED_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static RECORDED_VALUE: AtomicUsize = AtomicUsize::new(0);

/// An `SA_SIGINFO` handler that counts its runs and records the last
/// siginfo's code, sender PID and value.
extern "C" fn record_siginfo(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    let (code, pid, value) = unsafe {
        (
            (*info).si_code,
            (*info).si_pid(),
            (*info).si_value().sival_ptr as usize,
        )
    };
    RECORDED_CODE.store(code, Ordering::Relaxed);
    RECORDED_PID.store(pid, Ordering::Relaxed);
    RECORDED_VALUE.store(value, Ordering::Relaxed);
    RECORDED_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Installs `record_siginfo` for `signal` without `SA_RESTART` and clears
/// what it recorded.
///
/// # Safety
/// Replaces the process-wide disposition of `signal`.
unsafe fn install_recorder(signal: libc::c_int) {
    RECORDED_CALLS.store(0, Ordering::Relaxed);
    RECORDED_CODE.store(0, Ordering::Relaxed);
    RECORDED_PID.store(0, Ordering::Relaxed);
    RECORDED_VALUE.store(0, Ordering::Relaxed);
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_siginfo as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
    }
}

/// Queues `signal` to the calling thread with `si_code`, this process as the
/// sender, and `QUEUED_VALUE`, as `sigqueue` does with `SI_QUEUE`.
///
/// # Safety
/// Sends a signal to the calling thread.
unsafe fn queue_value_to_self(signal: libc::c_int, si_code: libc::c_int) {
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        info.si_signo = signal;
        info.si_code = si_code;
        // `si_pid`, `si_uid` and `si_value` open the union after the three
        // ints.
        let fields = (&mut info as *mut libc::siginfo_t).cast::<u8>().add(16);
        fields.cast::<libc::pid_t>().write(libc::getpid());
        fields.add(4).cast::<libc::uid_t>().write(libc::getuid());
        fields.add(8).cast::<usize>().write(QUEUED_VALUE);
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_tgsigqueueinfo,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                signal,
                &mut info as *mut libc::siginfo_t,
            ),
            0
        );
    }
}

/// Prints a syscall's result and errno, what `record_siginfo` recorded
/// (runs, code, sender PID and value), whether `signal` is blocked and
/// pending, the runs after unblocking it, and the PID.
///
/// # Safety
/// Changes the calling thread's signal mask.
unsafe fn print_recorded(ret: libc::c_long, errno: libc::c_int, signal: libc::c_int) {
    unsafe { print_recorded_unblocking_to(ret, errno, signal, 0) }
}

/// As `print_recorded`, but checks that the unblock returns `unblocked`
/// (`unblock_returning`).
///
/// # Safety
/// Changes the calling thread's signal mask.
unsafe fn print_recorded_unblocking_to(
    ret: libc::c_long,
    errno: libc::c_int,
    signal: libc::c_int,
    unblocked: libc::c_long,
) {
    unsafe {
        let calls = RECORDED_CALLS.load(Ordering::Relaxed);
        let blocked = is_blocked(signal);
        let pending = is_pending(signal);
        unblock_returning(signal, unblocked);
        println!(
            "{ret} {errno} {calls} {} {} {} {blocked} {pending} {} {}",
            RECORDED_CODE.load(Ordering::Relaxed),
            RECORDED_PID.load(Ordering::Relaxed),
            RECORDED_VALUE.load(Ordering::Relaxed),
            RECORDED_CALLS.load(Ordering::Relaxed),
            libc::getpid()
        );
    }
}

/// Checks the guest's `print_recorded` line: `ret`, `errno` and the handler
/// running once, with the queued siginfo (`code`, the guest's PID and
/// `QUEUED_VALUE`), the signal blocked again and not pending, and no second
/// run. Returns the guest's PID.
fn check_recorded(
    output: &reverie::process::Output,
    probe: &str,
    log: &Log,
    ret_errno: &str,
    code: i32,
) -> i64 {
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        fields,
        format!("{ret_errno} 1 {code} {pid} {QUEUED_VALUE} 1 0 1"),
        "one handler run, with the queued code, sender and value; blocked again and not pending"
    );
    pid
}

/// Pins a known gap (<https://github.com/rrnewton/reverie/issues/845>) where
/// untraced Linux passes `check_recorded`: the hook injected while the
/// guest's mask-swapping syscall waited, the injection's step let the kernel
/// restore that syscall's saved mask, which blocks the signal, so the signal
/// was requeued instead of delivered. The guest's syscall returns `ret` (the
/// hook's last injection's return value, as on main) with no handler run, the
/// signal is still pending after it, and its handler runs once when the guest
/// unblocks it, with the queued siginfo. `ret` may name the guest's PID as
/// `{pid}`; `errno` is checked when the syscall fails. Returns the guest's PID.
fn check_requeued_known_gap(
    output: &reverie::process::Output,
    probe: &str,
    log: &Log,
    ret: &str,
    errno: Option<i32>,
    code: i32,
) -> i64 {
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    let fields: Vec<&str> = fields.split(' ').collect();
    assert_eq!(fields.len(), 9, "guest fields: {fields:?}");
    assert_eq!(
        fields[0],
        ret.replace("{pid}", &pid.to_string()),
        "the guest's syscall returns the hook's last injection's value (main leaks it, https://github.com/rrnewton/reverie/issues/892; a fix flips this pin)"
    );
    if let Some(errno) = errno {
        assert_eq!(fields[1], errno.to_string(), "errno");
    }
    assert_eq!(
        fields[2..].join(" "),
        format!("0 {code} {pid} {QUEUED_VALUE} 1 1 1"),
        "no handler run under the syscall; the signal is still pending and runs once, with the queued siginfo, when unblocked (known gap, https://github.com/rrnewton/reverie/issues/845)"
    );
    pid
}

/// The guest's own `ppoll`, with a 5-second timeout, whose temporary mask
/// lets a pending `signal` through, and a hook that injects at every
/// callback. Untraced Linux prints EINTR at once, one handler run with the
/// queued siginfo, and the signal blocked again.
///
/// Known gap (<https://github.com/rrnewton/reverie/issues/845>), pinned: the
/// injection's step lets the kernel restore `ppoll`'s saved mask, which
/// blocks `signal`, so passing it through requeues it. Restoring the guest's
/// return register would restart `ppoll`, which takes the signal again at
/// every callback, so the guest keeps the injection's return value instead,
/// as on main: `ppoll` returns the hook's getpid, `signal` stays pending,
/// and its handler runs when the guest unblocks it, after a second report.
/// The second report's getpid is likewise left in the guest's return
/// register, so the unblock returns the guest's pid. Main leaks the injected
/// result into both (<https://github.com/rrnewton/reverie/issues/892>); a
/// fix flips these pins.
///
/// `code` is the queued `si_code`: a positive one is synchronous-class, which
/// the kernel dequeues ahead of a step's SIGTRAP.
fn always_injecting_hook_requeues_at_a_delivery_stop(signal: libc::c_int, code: libc::c_int) {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(move || unsafe {
        install_recorder(signal);
        block(&[signal]);
        queue_value_to_self(signal, code);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        let errno = *libc::__errno_location();
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        print_recorded_unblocking_to(ret, errno, signal, libc::getpid() as libc::c_long);
    })
    .expect("run always-injecting hook guest");
    let pid =
        check_requeued_known_gap(&output, "always-inject-ordinary", &log, "{pid}", None, code);
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid), Ok(pid)],
        "the hook's getpid runs at each report"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![signal, signal],
        "the signal is reported at its delivery stop and again after the unblock (known gap)"
    );
}

#[test]
fn always_injecting_hook_requeues_a_signal_at_its_delivery_stop() {
    always_injecting_hook_requeues_at_a_delivery_stop(libc::SIGUSR1, libc::SI_QUEUE);
}

#[test]
fn always_injecting_hook_requeues_a_synchronous_signal_at_its_delivery_stop() {
    always_injecting_hook_requeues_at_a_delivery_stop(libc::SIGSYS, 1);
}

/// Loads a seccomp filter that answers `ppoll` with `action` and allows
/// everything else.
///
/// # Safety
/// Restricts the calling thread's syscalls for the rest of its life.
unsafe fn filter_ppoll(action: u32) {
    unsafe {
        let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let filter = [
            // seccomp_data.nr is at offset 0.
            statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            statement(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                libc::SYS_ppoll as u32,
                0,
                1,
            ),
            statement(libc::BPF_RET | libc::BPF_K, action, 0, 0),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog
            ),
            0
        );
    }
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but the guest's
/// mask-swapping syscall is `pselect6`, and a seccomp filter the guest
/// installed answers `ppoll`, which neither the guest nor the hook makes,
/// with `action`. Untraced Linux prints EINTR, one handler run with the
/// queued siginfo, and the signal blocked again. Pinned at the same known gap
/// (<https://github.com/rrnewton/reverie/issues/845>), including the unblock
/// that returns the guest's pid, which main leaks there
/// (<https://github.com/rrnewton/reverie/issues/892>; a fix flips that pin).
/// Reverie makes no syscall the guest did not, so the filter is never
/// consulted.
fn always_injecting_hook_requeues_under_a_guest_seccomp_filter(action: u32) {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(move || unsafe {
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        filter_ppoll(action);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let sigmask: [usize; 2] = [&mask as *const libc::sigset_t as usize, 8];
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(
            libc::SYS_pselect6,
            0usize,
            0usize,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            sigmask.as_ptr(),
        );
        let errno = *libc::__errno_location();
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        print_recorded_unblocking_to(ret, errno, libc::SIGUSR1, libc::getpid() as libc::c_long);
    })
    .expect("run seccomp-filtered always-injecting hook guest");
    let pid = check_requeued_known_gap(
        &output,
        "always-inject-seccomp",
        &log,
        "{pid}",
        None,
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid), Ok(pid)],
        "the hook's getpid runs at each report"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported at its delivery stop and again after the unblock (known gap)"
    );
}

#[test]
fn always_injecting_hook_requeues_when_the_guest_kills_on_ppoll() {
    always_injecting_hook_requeues_under_a_guest_seccomp_filter(libc::SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn always_injecting_hook_requeues_when_the_guest_fails_ppoll() {
    always_injecting_hook_requeues_under_a_guest_seccomp_filter(
        libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    );
}

#[test]
fn always_injecting_hook_requeues_when_the_guest_traps_ppoll() {
    always_injecting_hook_requeues_under_a_guest_seccomp_filter(libc::SECCOMP_RET_TRAP);
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but the guest
/// ignores SIGUSR1 (`SIG_IGN`) and `ppoll` times out after 100 ms. Linux
/// discards the signal when `ppoll` takes it, restarts `ppoll`, and it
/// returns 0 with the signal blocked again and not pending, and no handler.
/// Known gap (<https://github.com/rrnewton/reverie/issues/845>), pinned as
/// there: `ppoll` returns the hook's getpid at once, and the requeued signal
/// stays pending.
#[test]
fn always_injecting_hook_requeues_an_ignored_signal() {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(|| unsafe {
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        *libc::__errno_location() = 0;
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        let errno = *libc::__errno_location();
        println!(
            "{ret} {errno} {} {} {}",
            is_blocked(libc::SIGUSR1),
            is_pending(libc::SIGUSR1),
            libc::getpid()
        );
    })
    .expect("run ignored-signal always-injecting hook guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE always-inject-ignored guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        fields,
        format!("{pid} 0 1 1"),
        "ppoll returns the hook's getpid (main leaks it, https://github.com/rrnewton/reverie/issues/892); the signal is blocked and still pending (known gap, https://github.com/rrnewton/reverie/issues/845)"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid)],
        "the hook's getpid runs once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "the signal is reported once"
    );
}

/// The set `BlockInFirstSignalHook` blocks. A static, so the forked guest has
/// it at the same address.
static SIGUSR1_SET: u64 = 1 << (libc::SIGUSR1 - 1);

/// Like `ReplaceMarker`, but the first signal hook on each thread injects
/// `rt_sigprocmask(SIG_BLOCK, {SIGUSR1})`, reported, before passing the
/// signal through.
#[derive(Clone, Copy, Debug, Default)]
struct BlockInFirstSignalHook;

#[reverie::tool]
impl Tool for BlockInFirstSignalHook {
    type GlobalState = Log;
    /// Whether a signal hook has run on this thread.
    type ThreadState = bool;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if !std::mem::replace(guest.thread_state_mut(), true) {
            let set = Addr::from_raw(&SIGUSR1_SET as *const u64 as usize);
            let result = guest
                .inject(
                    RtSigprocmask::new()
                        .with_how(libc::SIG_BLOCK)
                        .with_set(set)
                        .with_oldset(None)
                        .with_sigsetsize(8),
                )
                .await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// A SIGUSR1 queued unblocked is delivered as `rt_tgsigqueueinfo` returns,
/// outside any mask-swapping syscall. The hook blocks it with an injected
/// `rt_sigprocmask` before passing it through, so Linux requeues it: the
/// handler does not run until the guest unblocks it, and then runs with the
/// queued siginfo.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// a signal its Tool blocks should be reported once, but the guest's own
/// unblock delivers it at an ordinary delivery stop, which reports it again,
/// as on main. (When an injection's step takes it instead,
/// `requeued_signal_recaptured_by_an_injection_is_not_reported_again`, it is
/// not.)
#[test]
fn signal_hook_blocking_its_signal_keeps_it_pending() {
    let (output, log) = test_fn::<BlockInFirstSignalHook, _>(|| unsafe {
        install_recorder(libc::SIGUSR1);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        print_recorded(0, 0, libc::SIGUSR1);
    })
    .expect("run hook-blocking guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE hook-blocks guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        fields,
        format!("0 0 0 {} {pid} {QUEUED_VALUE} 1 1 1", libc::SI_QUEUE),
        "no handler run while blocked and pending; one run with the queued siginfo once unblocked"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0)],
        "the hook's rt_sigprocmask runs once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported when delivered, and again once unblocked"
    );
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but the hook is
/// `BlockInFirstSignalHook`, whose first callback blocks SIGUSR1 with an
/// injected `rt_sigprocmask`, and `ppoll`'s saved mask also blocks it. The
/// injection leaves the mask equal to `ppoll`'s saved mask, as an injection's
/// restore would, but the hook wrote it, so Linux requeues the signal as
/// `signal_hook_blocking_its_signal_keeps_it_pending` does. The restarted
/// `ppoll` lets it through again, and the second callback passes it through
/// without injecting: it is reported twice, and the handler runs once.
///
/// Known gap (<https://github.com/rrnewton/reverie/issues/845>), pinned: as
/// in `always_injecting_hook_requeues_at_a_delivery_stop`, the guest keeps
/// the injection's return value, so `ppoll` returns 0 instead of restarting,
/// and the handler runs only when the guest unblocks SIGUSR1.
#[test]
fn signal_hook_blocking_its_signal_at_a_delivery_stop_requeues_it() {
    let (output, log) = test_fn::<BlockInFirstSignalHook, _>(|| unsafe {
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run hook-blocking ppoll guest");
    check_requeued_known_gap(
        &output,
        "hook-blocks-at-delivery-stop",
        &log,
        "0",
        None,
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0)],
        "the hook's rt_sigprocmask runs once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported when taken, and again after the unblock (known gap)"
    );
}

/// The guest's own `ppoll`, with no descriptors, a 5-second timeout and an
/// empty temporary mask.
///
/// # Safety
/// Changes the calling thread's signal mask while it waits.
unsafe fn ppoll_with_empty_mask() -> libc::c_long {
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        )
    }
}

/// Installs `handler` for `signal` with `flags`, and no `SA_RESTART`, after
/// `install_recorder` clears what `record_siginfo` recorded.
///
/// # Safety
/// Replaces the process-wide disposition of `signal`.
unsafe fn install_recorder_with(signal: libc::c_int, handler: usize, flags: libc::c_int) {
    unsafe {
        install_recorder(signal);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = libc::SA_SIGINFO | flags;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
    }
}

/// The mask a `record_frame_masks` handler ran under.
static RUN_MASK: AtomicU64 = AtomicU64::new(0);
/// The `uc_sigmask` of a `record_frame_masks` handler's signal frame.
static FRAME_SIGMASK: AtomicU64 = AtomicU64::new(0);
/// The x86_64 `uc_mcontext.gregs[REG_OLDMASK]` of a `record_frame_masks`
/// handler's signal frame; `uc_sigmask` again on architectures that save
/// the mask once.
static FRAME_OLDMASK: AtomicU64 = AtomicU64::new(0);

/// `record_siginfo`, which also records the mask the handler runs under and
/// the masks its signal frame saved.
extern "C" fn record_frame_masks(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    let mut mask = 0u64;
    // SAFETY: rt_sigprocmask with no new set only writes the 8-byte old set,
    // and the kernel passes a valid ucontext to an SA_SIGINFO handler.
    let (frame_sigmask, frame_oldmask) = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            0usize,
            &mut mask as *mut u64,
            8usize,
        );
        let context = context.cast::<libc::ucontext_t>();
        let frame_sigmask = std::ptr::addr_of!((*context).uc_sigmask)
            .cast::<u64>()
            .read();
        #[cfg(target_arch = "x86_64")]
        let frame_oldmask = (*context).uc_mcontext.gregs[libc::REG_OLDMASK as usize] as u64;
        #[cfg(not(target_arch = "x86_64"))]
        let frame_oldmask = frame_sigmask;
        (frame_sigmask, frame_oldmask)
    };
    RUN_MASK.store(mask, Ordering::Relaxed);
    FRAME_SIGMASK.store(frame_sigmask, Ordering::Relaxed);
    FRAME_OLDMASK.store(frame_oldmask, Ordering::Relaxed);
    record_siginfo(signal, info, context);
}

/// Prints the masks `record_frame_masks` recorded, on a line of their own:
/// the handler's, then the frame's two.
fn print_frame_masks() {
    println!(
        "{:#x} {:#x} {:#x}",
        RUN_MASK.load(Ordering::Relaxed),
        FRAME_SIGMASK.load(Ordering::Relaxed),
        FRAME_OLDMASK.load(Ordering::Relaxed)
    );
}

/// Splits `print_frame_masks`'s first line from the guest's output, and
/// returns it with the output that follows it.
fn split_frame_masks(output: reverie::process::Output) -> (String, reverie::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let (masks, rest) = stdout.split_once('\n').expect("frame masks line");
    (
        masks.to_owned(),
        reverie::process::Output {
            stdout: rest.as_bytes().to_vec(),
            ..output
        },
    )
}

/// The mask bit of `signal`.
const fn bit(signal: libc::c_int) -> u64 {
    1 << (signal - 1)
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, with SIGUSR1 and
/// SIGUSR2 blocked outside `ppoll`. Untraced Linux runs the handler under
/// `ppoll`'s empty mask plus SIGUSR1, and its frame saves the blocked pair in
/// both places x86_64 saves a mask: `uc_sigmask`, which `rt_sigreturn`
/// restores, and `uc_mcontext.gregs[REG_OLDMASK]`.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued as there, so the handler runs only when the guest
/// unblocks SIGUSR1 after `ppoll`, after the guest has printed the masks,
/// which are therefore empty. The unblock returns the hook's getpid: main
/// leaks the injected result there
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips that pin.
#[test]
fn always_injecting_hook_saves_the_mask_in_effect_in_every_frame_field() {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(|| unsafe {
        install_recorder_with(libc::SIGUSR1, record_frame_masks as *const () as usize, 0);
        block(&[libc::SIGUSR1, libc::SIGUSR2]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_frame_masks();
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        print_recorded_unblocking_to(ret, errno, libc::SIGUSR1, libc::getpid() as libc::c_long);
    })
    .expect("run frame-mask always-injecting hook guest");
    let (masks, output) = split_frame_masks(output);
    let pid = check_requeued_known_gap(
        &output,
        "always-inject-frame-masks",
        &log,
        "{pid}",
        None,
        libc::SI_QUEUE,
    );
    assert_eq!(
        masks, "0x0 0x0 0x0",
        "no handler has run when the guest prints the masks, before the unblock (known gap)"
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid), Ok(pid)]);
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1]
    );
}

/// As `always_injecting_hook_requeues_an_ignored_signal`, with SIGUSR2,
/// caught by `record_siginfo`, also queued and blocked outside `ppoll`. On
/// untraced Linux `ppoll` takes the lower SIGUSR1 first and discards it,
/// then takes SIGUSR2 under its empty mask: the handler runs once with the
/// queued siginfo, and `ppoll` returns EINTR at once.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the hook's `getpid` resumes SIGUSR1's delivery stop without a signal, so
/// the kernel takes SIGUSR2 before the `syscall` runs and the injection
/// reports ERESTARTSYS. SIGUSR2 is held by the callback's own injection and
/// stays in the tracer's single hold slot. `ppoll` does not restart: it
/// returns `SYS_getpid` at once, the number the interrupted injection left
/// in the guest's return register. Main leaks it there
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips that pin
/// to `ppoll` restarting and timing out with 0. The guest's next
/// intercepted syscall, the first line's
/// `write`, resumes its syscall stop with SIGUSR2, where Linux queues it
/// with a siginfo of its own (`SI_KERNEL`, no sender, no value). The
/// restored saved mask blocks it, so the handler runs, and the hook reports
/// it, only when the guest unblocks it; that report's getpid is left in the
/// unblock's return register. Main leaks the injected result there
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips that pin.
#[test]
fn signal_held_by_a_hook_injection_at_a_delivery_stop_misses_the_syscall() {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(|| unsafe {
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        install_recorder(libc::SIGUSR2);
        block(&[libc::SIGUSR1, libc::SIGUSR2]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        queue_value_to_self(libc::SIGUSR2, libc::SI_QUEUE);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        *libc::__errno_location() = 0;
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        let errno = *libc::__errno_location();
        println!("{}", is_pending(libc::SIGUSR1));
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        print_recorded_unblocking_to(ret, errno, libc::SIGUSR2, libc::getpid() as libc::c_long);
    })
    .expect("run ignored-then-caught always-injecting hook guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE hook-held-at-delivery-stop guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    // Main leaks the interrupted getpid's number into ppoll's result; see
    // https://github.com/rrnewton/reverie/issues/892. A fix flips this pin
    // to format!("0\n0 0 0 {} 0 0 1 1 1", libc::SI_KERNEL).
    assert_eq!(
        fields,
        format!("0\n{} 0 0 {} 0 0 1 1 1", libc::SYS_getpid, libc::SI_KERNEL),
        "SIGUSR1 was discarded; ppoll returns the leaked getpid number (known leak), and SIGUSR2 runs once unblocked, with a kernel siginfo"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Err(Errno::ERESTARTSYS.into_raw()), Ok(pid)],
        "SIGUSR2 interrupts the first getpid before it runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR2],
        "each signal is reported once"
    );
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but the handlers
/// of SIGUSR1 and SIGSEGV run on an alternate stack (`SA_ONSTACK`) the guest
/// cannot write, and SIGSEGV is blocked outside `ppoll` along with SIGUSR1.
/// Linux cannot build SIGUSR1's frame and forces a SIGSEGV, which `ppoll`'s
/// empty mask lets through. Its handler's frame fails the same way, so Linux
/// forces a SIGSEGV with the default action, and untraced Linux ends the
/// guest with SIGSEGV. A tracer sees a delivery stop for each of the three
/// signals. Delivering a SIGSEGV under the restored pair would instead
/// requeue it, and the guest would go on to print.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued as there, and is reported again when the guest
/// unblocks it before printing. Its frame then fails on the alternate stack,
/// and the one SIGSEGV Linux forces, with the default action, ends the guest.
#[test]
fn always_injecting_hook_lets_a_forced_sigsegv_end_the_guest() {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(|| unsafe {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &no_core), 0);
        let size = 1 << 16;
        let stack = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(stack, libc::MAP_FAILED);
        let alternate = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: size,
        };
        assert_eq!(libc::sigaltstack(&alternate, std::ptr::null_mut()), 0);
        for signal in [libc::SIGSEGV, libc::SIGUSR1] {
            install_recorder_with(
                signal,
                record_siginfo as *const () as usize,
                libc::SA_ONSTACK,
            );
        }
        block(&[libc::SIGUSR1, libc::SIGSEGV]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run unwritable-alternate-stack always-injecting hook guest");
    eprintln!(
        "PROBE always-inject-forced-sigsegv status={:?} guest={} injected={:?} signals={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert!(
        matches!(output.status, ExitStatus::Signaled(Signal::SIGSEGV, _)),
        "the forced SIGSEGV ends the guest: {:?}",
        output.status
    );
    assert!(output.stdout.is_empty(), "the guest prints nothing");
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1, libc::SIGSEGV],
        "SIGUSR1 at its delivery stop and again after the unblock, then the SIGSEGV Linux forced (known gap)"
    );
    assert_eq!(
        log.injected.lock().unwrap().len(),
        3,
        "the hook's getpid runs at each callback"
    );
}

/// Like `ReplaceMarker`, but the first signal hook on each thread injects a
/// `getpid`, reported, and requests a precise timer one retired conditional
/// branch away, before passing the signal through. Each timer event is
/// reported.
#[derive(Clone, Copy, Debug, Default)]
struct TimerInFirstSignalHook;

#[reverie::tool]
impl Tool for TimerInFirstSignalHook {
    type GlobalState = Log;
    /// Whether a signal hook has run on this thread.
    type ThreadState = bool;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if !std::mem::replace(guest.thread_state_mut(), true) {
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            guest
                .set_timer_precise(TimerSchedule::Rcbs(1))
                .expect("request a precise timer");
        }
        Ok(Some(signal))
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        guest.send_rpc(Report::Timer).await;
    }
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but the hook also
/// requests a timer so near that Reverie kicks it with its own SIGSTKFLT,
/// queued while the thread is still at the delivery stop. The timer fires
/// once, and the guest's signal is not lost.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the guest's signal is requeued as there, so it is reported again, and its
/// handler runs, when the guest unblocks it.
#[cfg(target_arch = "x86_64")]
#[test]
fn signal_hook_requesting_a_near_timer_requeues_its_signal_and_fires_once() {
    reverie_ptrace::ret_without_perf!();
    let (output, log) = test_fn::<TimerInFirstSignalHook, _>(|| unsafe {
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        let errno = *libc::__errno_location();
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run near-timer hook guest");
    let pid = check_requeued_known_gap(
        &output,
        "near-timer-hook",
        &log,
        "{pid}",
        None,
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid)],
        "the hook's getpid runs once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported at its delivery stop and again after the unblock (known gap)"
    );
    assert_eq!(
        log.timers.load(Ordering::Relaxed),
        1,
        "the timer fires once"
    );
}

/// The value of the sibling that `QueueSiblingInFirstSignalHook` queues.
const SIBLING_VALUE: usize = 88;

/// The siginfo of that sibling, which the guest fills in.
static mut SIBLING_INFO: libc::siginfo_t = unsafe { std::mem::zeroed() };

/// Like `ReplaceMarker`, but the first signal hook on each thread injects a
/// `getpid` and then an `rt_tgsigqueueinfo` that queues the same signal to the
/// thread again with `SIBLING_INFO`, both reported, before passing the signal
/// through. Every later signal hook suppresses its signal.
#[derive(Clone, Copy, Debug, Default)]
struct QueueSiblingInFirstSignalHook;

#[reverie::tool]
impl Tool for QueueSiblingInFirstSignalHook {
    type GlobalState = Log;
    /// Signal hooks run on this thread so far.
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        *guest.thread_state_mut() += 1;
        if *guest.thread_state() > 1 {
            return Ok(None);
        }
        let result = guest.inject(Getpid::new()).await;
        guest
            .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
            .await;
        let result = guest
            .inject(
                RtTgsigqueueinfo::new()
                    .with_tgid(guest.pid().as_raw())
                    .with_tid(guest.tid().as_raw())
                    .with_sig(signal as i32)
                    .with_siginfo(AddrMut::from_raw(&raw mut SIBLING_INFO as usize)),
            )
            .await;
        guest
            .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
            .await;
        Ok(Some(signal))
    }
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, with `signal`
/// queued with `QUEUED_VALUE`, but the hook's injections leave a sibling of
/// the same number, with `SIBLING_VALUE`, queued while `ppoll`'s saved mask
/// blocks it. The instance the hook was told about is delivered, with its
/// own siginfo, as the hook decided. The sibling stays pending until the
/// guest unblocks it, and its own delivery reaches the Tool, which
/// suppresses it, so the handler never sees `SIBLING_VALUE`. The sibling
/// does not merge with the delivered instance, which left the queue at its
/// delivery stop. (Real-time signals are not covered: a real-time signal
/// stop already fails `WaitStatus::from_raw` in safeptrace's waitid.)
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the instance the hook was told about is requeued, as in
/// `always_injecting_hook_requeues_at_a_delivery_stop`, onto the pending
/// sibling, and a standard signal does not queue twice, so it is lost.
/// `ppoll` returns the hook's last injection's 0, and the sibling's delivery
/// at the unblock reaches the Tool, which suppresses it: the handler never
/// runs.
fn sibling_queued_by_a_signal_hook_reaches_the_tool(signal: libc::c_int) {
    let (output, log) = test_fn::<QueueSiblingInFirstSignalHook, _>(move || unsafe {
        install_recorder(signal);
        block(&[signal]);
        queue_value_to_self(signal, libc::SI_QUEUE);
        let sibling = &raw mut SIBLING_INFO;
        (*sibling).si_signo = signal;
        (*sibling).si_code = libc::SI_QUEUE;
        let fields = sibling.cast::<u8>().add(16);
        fields.cast::<libc::pid_t>().write(libc::getpid());
        fields.add(4).cast::<libc::uid_t>().write(libc::getuid());
        fields.add(8).cast::<usize>().write(SIBLING_VALUE);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let timeout = libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let ret = libc::syscall(
            libc::SYS_ppoll,
            0usize,
            0usize,
            &timeout as *const libc::timespec,
            &mask as *const libc::sigset_t,
            8usize,
        );
        let errno = *libc::__errno_location();
        print_recorded(ret, errno, signal);
    })
    .expect("run sibling-queueing hook guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE sibling-{signal} guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    let (ret, fields) = fields.split_once(' ').expect("guest result");
    let (_errno, fields) = fields.split_once(' ').expect("guest errno");
    assert_eq!(
        (ret, fields),
        ("0", "0 0 0 0 1 1 0"),
        "ppoll returns the hook's 0 and no handler runs; the sibling pending, then suppressed (known gap)"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid), Ok(0)],
        "the hook's getpid and rt_tgsigqueueinfo run once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![signal, signal],
        "the first instance and the sibling are each reported once"
    );
}

#[test]
fn standard_sibling_queued_by_a_signal_hook_reaches_the_tool() {
    sibling_queued_by_a_signal_hook_reaches_the_tool(libc::SIGUSR1);
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but `signal` is
/// held by the `PPOLL_FD` marker's injected `ppoll`, and the guest's result
/// is that `ppoll`'s. Untraced Linux prints EINTR, one handler run with the
/// queued siginfo, and the signal blocked again.
///
/// Known gaps pinned here (https://github.com/rrnewton/reverie/issues/845),
/// both as on main: a SIGUSR1 is requeued as in
/// `always_injecting_hook_requeues_at_a_delivery_stop`, so the guest's
/// result is the hook's getpid, the signal is reported twice, and the
/// guest's unblock also returns the hook's getpid (main leaks the injected
/// result into both, <https://github.com/rrnewton/reverie/issues/892>; a fix
/// flips those pins). A
/// synchronous-class SIGSYS, which the kernel dequeues ahead of the step's
/// SIGTRAP, is passed on unreported: the guest sees what untraced Linux
/// prints, but the Tool never sees the signal.
fn always_injecting_hook_after_a_held_signal(signal: libc::c_int, code: libc::c_int) {
    let (output, log) = test_fn::<InjectInEverySignalHook, _>(move || unsafe {
        install_recorder(signal);
        block(&[signal]);
        queue_value_to_self(signal, code);
        let mut args: PpollArgs = std::mem::zeroed();
        libc::sigemptyset(&mut args.mask);
        args.timeout.tv_sec = 5;
        let ret = libc::syscall(
            libc::SYS_write,
            PPOLL_FD,
            &mut args as *mut PpollArgs,
            0usize,
        );
        let errno = *libc::__errno_location();
        // Main leaks the requeued SIGUSR1's second getpid into the unblock's
        // result; see https://github.com/rrnewton/reverie/issues/892. A fix
        // flips this to 0. The unreported SIGSYS runs no hook.
        let unblocked = if code > 0 {
            0
        } else {
            libc::getpid() as libc::c_long
        };
        print_recorded_unblocking_to(ret, errno, signal, unblocked);
    })
    .expect("run always-injecting hook guest");
    if code > 0 {
        let pid = check_recorded(
            &output,
            "always-inject-held",
            &log,
            &format!("-1 {}", libc::EINTR),
            code,
        );
        assert_ne!(pid, 0);
        assert_eq!(
            *log.injected.lock().unwrap(),
            vec![Err(Errno::ERESTARTNOHAND.into_raw())],
            "ppoll is interrupted; no hook runs (known gap)"
        );
        assert_eq!(
            *log.signals.lock().unwrap(),
            Vec::<i32>::new(),
            "the held signal is not reported (known gap)"
        );
    } else {
        let pid =
            check_requeued_known_gap(&output, "always-inject-held", &log, "{pid}", None, code);
        assert_eq!(
            *log.injected.lock().unwrap(),
            vec![Err(Errno::ERESTARTNOHAND.into_raw()), Ok(pid), Ok(pid)],
            "ppoll is interrupted, and the hook's getpid runs at each report"
        );
        assert_eq!(
            *log.signals.lock().unwrap(),
            vec![signal, signal],
            "the signal is reported twice (known gap)"
        );
    }
}

#[test]
fn always_injecting_hook_requeues_a_held_signal() {
    always_injecting_hook_after_a_held_signal(libc::SIGUSR1, libc::SI_QUEUE);
}

#[test]
fn always_injecting_hook_passes_a_held_synchronous_signal_unreported() {
    always_injecting_hook_after_a_held_signal(libc::SIGSYS, 1);
}

/// A SIGUSR1 queued blocked with `SI_QUEUE`, the guest as its sender and
/// `QUEUED_VALUE`, is unblocked by the `UNBLOCK_THEN_GETPID_FD` marker's
/// injected `rt_sigprocmask` and stops the following `getpid` before its
/// `syscall`, so it is held. Nothing blocks it again, so nothing requeues it.
/// The hook injects `getpid` before passing it through, so the final resume
/// is from that injection's stop, not from SIGUSR1's: the handler must still
/// see the queued siginfo, not one Linux makes up for a signal resumed from
/// another signal's stop (`SI_USER`, the tracer's PID, no value).
#[test]
fn held_signal_keeps_its_siginfo_after_a_signal_hook_injection() {
    let (output, log) = test_fn::<InjectInFirstSignalHook, _>(|| unsafe {
        install_recorder(libc::SIGUSR1);
        let set = block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        let errno = *libc::__errno_location();
        // Blocked again for `print_recorded`'s check.
        block(&[libc::SIGUSR1]);
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run held-siginfo guest");
    let pid = check_recorded(
        &output,
        "held-siginfo",
        &log,
        &format!("-1 {}", libc::EINTR),
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(pid)],
        "the unblock completes, SIGUSR1 interrupts getpid before it runs, and the hook's getpid runs"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
}

/// The ordinary route: the guest unblocks the SIGUSR1 of
/// `held_signal_keeps_its_siginfo_after_a_signal_hook_injection` itself,
/// with an `rt_sigprocmask` the tool does not intercept, and it is delivered
/// as that syscall returns. The hook's `getpid` must not cost it its siginfo.
/// Pinned: the unblock returns the hook's getpid, not 0. Main leaks the
/// injected result here (<https://github.com/rrnewton/reverie/issues/892>);
/// a fix flips this pin to 0.
#[test]
fn signal_keeps_its_siginfo_after_a_signal_hook_injection() {
    let (output, log) = test_fn::<InjectInFirstSignalHook, _>(|| unsafe {
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        unblock_returning(libc::SIGUSR1, libc::getpid() as libc::c_long);
        block(&[libc::SIGUSR1]);
        print_recorded(0, 0, libc::SIGUSR1);
    })
    .expect("run siginfo guest");
    let pid = check_recorded(&output, "ordinary-siginfo", &log, "0 0", libc::SI_QUEUE);
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid)],
        "the hook's getpid runs"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
}

/// Runs `f` as a guest on a new thread, whose tracer threads cannot write a
/// siginfo: `PTRACE_SETSIGINFO` fails with EACCES (a seccomp filter on the
/// thread, which the threads it creates inherit), and every other syscall
/// is allowed. Also returns that thread's ID, the tracer's.
#[cfg(target_arch = "x86_64")]
fn test_fn_without_setsiginfo<F: FnOnce() + Send + 'static>(
    f: F,
) -> (reverie::process::Output, Log, libc::pid_t) {
    test_fn_under_tracer_filter(
        Some((
            libc::PTRACE_SETSIGINFO,
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
        )),
        f,
    )
}

/// Runs `f` as a guest on a new thread under a seccomp filter, which the
/// threads it creates inherit. With `refused` as `(request, action)`, the
/// filter returns `action` for a `ptrace` of `request`; it allows every other
/// syscall. Also returns that thread's ID, the tracer's.
#[cfg(target_arch = "x86_64")]
fn test_fn_under_tracer_filter<F: FnOnce() + Send + 'static>(
    refused: Option<(u32, u32)>,
    f: F,
) -> (reverie::process::Output, Log, libc::pid_t) {
    test_tool_under_tracer_filter::<InjectInFirstSignalHook, _>(refused, f)
}

/// `test_fn_under_tracer_filter` with the tool `T`.
#[cfg(target_arch = "x86_64")]
fn test_tool_under_tracer_filter<T, F>(
    refused: Option<(u32, u32)>,
    f: F,
) -> (reverie::process::Output, Log, libc::pid_t)
where
    T: Tool<GlobalState = Log> + 'static,
    F: FnOnce() + Send + 'static,
{
    test_tool_under_tracer_filters::<T, F>(refused, &[], f)
}

/// `test_tool_under_tracer_filter` whose filter also returns `action` for
/// every syscall `nr` of `numbers`, whatever its arguments.
#[cfg(target_arch = "x86_64")]
fn test_tool_under_tracer_filters<T, F>(
    refused: Option<(u32, u32)>,
    numbers: &'static [(libc::c_long, u32)],
    f: F,
) -> (reverie::process::Output, Log, libc::pid_t)
where
    T: Tool<GlobalState = Log> + 'static,
    F: FnOnce() + Send + 'static,
{
    std::thread::spawn(move || {
        let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let allow = statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0);
        let mut filter = Vec::new();
        if refused.is_some() || !numbers.is_empty() {
            // seccomp_data.nr is at offset 0, and the low half of args[0] at 16.
            filter.push(statement(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                0,
                0,
                0,
            ));
        }
        for &(nr, action) in numbers {
            filter.push(statement(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                nr as u32,
                0,
                1,
            ));
            filter.push(statement(libc::BPF_RET | libc::BPF_K, action, 0, 0));
        }
        if let Some((request, action)) = refused {
            filter.extend([
                statement(
                    libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                    libc::SYS_ptrace as u32,
                    0,
                    3,
                ),
                statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 16, 0, 0),
                statement(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, request, 0, 1),
                statement(libc::BPF_RET | libc::BPF_K, action, 0, 0),
            ]);
        }
        filter.push(allow);
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: both calls restrict only this thread and the threads it
        // creates, which end with the test.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &program as *const libc::sock_fprog
                ),
                0
            );
        }
        // SAFETY: gettid has no preconditions.
        let tracer = unsafe { libc::gettid() };
        let (output, log) = test_fn::<T, _>(f).expect("run guest under a tracer filter");
        (output, log, tracer)
    })
    .join()
    .expect("tracer thread")
}

/// Checks the guest's `print_recorded` line when the queued siginfo could
/// not be written back: `ret`, `errno` and the handler running once, with
/// the siginfo Linux makes up (`SI_USER`, the `tracer` thread as sender, no
/// value), the signal blocked again and not pending, and no second run.
/// Returns the guest's PID.
#[cfg(target_arch = "x86_64")]
fn check_recorded_made_up(
    output: &reverie::process::Output,
    probe: &str,
    log: &Log,
    ret_errno: &str,
    tracer: libc::pid_t,
) -> i64 {
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} guest={} injected={:?} signals={:?} tracer={tracer}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fields: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(fields.len(), 10, "one print_recorded line");
    let pid: i64 = fields[9].parse().expect("guest pid");
    assert_eq!(
        fields[..5].join(" "),
        format!("{ret_errno} 1 {} {tracer}", libc::SI_USER),
        "one handler run, with Linux's made-up code and the tracer thread as sender"
    );
    assert_eq!(
        fields[5..9].join(" "),
        "0 1 0 1",
        "no value; blocked again and not pending; no second run"
    );
    pid
}

/// `signal_keeps_its_siginfo_after_a_signal_hook_injection` with a tracer
/// that cannot write the siginfo back. Main writes none, so the signal is
/// still delivered, once, with the siginfo Linux makes up, and the guest
/// exits 0.
#[cfg(target_arch = "x86_64")]
#[test]
fn signal_is_delivered_when_its_siginfo_cannot_be_written_back() {
    let (output, log, tracer) = test_fn_without_setsiginfo(|| unsafe {
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        unblock_returning(libc::SIGUSR1, libc::getpid() as libc::c_long);
        block(&[libc::SIGUSR1]);
        print_recorded(0, 0, libc::SIGUSR1);
    });
    let pid = check_recorded_made_up(&output, "ordinary-no-setsiginfo", &log, "0 0", tracer);
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid)],
        "the hook's getpid runs"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
}

/// `held_signal_keeps_its_siginfo_after_a_signal_hook_injection` with a
/// tracer that cannot write the siginfo back. Main reports no held signal
/// and resumes it from its own stop, so the handler sees the queued siginfo.
/// A held report would resume it from the hook's `getpid` stop with the
/// siginfo Linux makes up, so the signal is passed on unreported, as main
/// passes it, because the tracer thread is under a seccomp filter.
#[cfg(target_arch = "x86_64")]
#[test]
fn held_signal_keeps_its_siginfo_when_it_cannot_be_written_back() {
    let (output, log, _) = test_fn_without_setsiginfo(|| unsafe {
        install_recorder(libc::SIGUSR1);
        let set = block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        let errno = *libc::__errno_location();
        // Blocked again for `print_recorded`'s check.
        block(&[libc::SIGUSR1]);
        print_recorded(ret, errno, libc::SIGUSR1);
    });
    check_recorded(
        &output,
        "held-no-setsiginfo",
        &log,
        &format!("-1 {}", libc::EINTR),
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes, SIGUSR1 interrupts getpid before it runs, and no hook runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        Vec::<i32>::new(),
        "the held signal is passed on unreported, as on main"
    );
}

/// `held_signal_keeps_its_siginfo_after_a_signal_hook_injection` with a
/// tracer under a seccomp filter that allows every syscall. Its writes
/// succeed, but a filter that allows one need not allow the next, so the
/// signal is passed on unreported, as main passes every held signal, and the
/// handler sees the queued siginfo.
#[cfg(target_arch = "x86_64")]
#[test]
fn held_signal_is_passed_on_unreported_under_a_tracer_seccomp_filter() {
    let (output, log, _) = test_fn_under_tracer_filter(None, || unsafe {
        install_recorder(libc::SIGUSR1);
        let set = block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        let errno = *libc::__errno_location();
        // Blocked again for `print_recorded`'s check.
        block(&[libc::SIGUSR1]);
        print_recorded(ret, errno, libc::SIGUSR1);
    });
    check_recorded(
        &output,
        "held-allowing-filter",
        &log,
        &format!("-1 {}", libc::EINTR),
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes, SIGUSR1 interrupts getpid before it runs, and no hook runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        Vec::<i32>::new(),
        "the held signal is passed on unreported, as on main"
    );
}

/// Runs `test`, the body of the test `name`, in a child process of the test
/// binary, and requires it to pass within 60 s. A tracer filter that kills
/// the tracer's process would otherwise kill the test binary.
#[cfg(target_arch = "x86_64")]
fn in_child_process(name: &str, test: impl FnOnce()) {
    const ROLE: &str = "REVERIE_FILTERED_TRACER";
    if std::env::var(ROLE).as_deref() == Ok(name) {
        test();
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(ROLE, name)
        .spawn()
        .expect("start the filtered tracer");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for the filtered tracer") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the filtered tracer did not finish in 60 s");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(status.success(), "filtered tracer: {status}");
}

/// `held_signal_is_passed_on_unreported_under_a_tracer_seccomp_filter` with
/// a filter that kills the tracer's process at a `ptrace` of `request`,
/// which main does not make for this guest. The guest must run as on main.
#[cfg(target_arch = "x86_64")]
fn held_signal_runs_as_on_main_when_the_tracer_is_killed_at(request: u32, probe: &str) {
    let refused = (request, libc::SECCOMP_RET_KILL_PROCESS);
    let (output, log, _) = test_fn_under_tracer_filter(Some(refused), || unsafe {
        install_recorder(libc::SIGUSR1);
        let set = block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        let errno = *libc::__errno_location();
        // Blocked again for `print_recorded`'s check.
        block(&[libc::SIGUSR1]);
        print_recorded(ret, errno, libc::SIGUSR1);
    });
    check_recorded(
        &output,
        probe,
        &log,
        &format!("-1 {}", libc::EINTR),
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes, SIGUSR1 interrupts getpid before it runs, and no hook runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        Vec::<i32>::new(),
        "the held signal is passed on unreported, as on main"
    );
}

/// `held_signal_keeps_its_siginfo_after_a_signal_hook_injection` with no
/// seccomp filter, but where the siginfo of the held SIGUSR1 cannot be
/// recorded at its stop: the interrupted `getpid` runs with no descriptor
/// left to open, so the read of the tracer thread's seccomp mode fails
/// (EMFILE). That read succeeds again by the time the held signal would be
/// reported. Without its record, the siginfo could not be written back after
/// the hook's injection, so the signal is passed on unreported, as on main,
/// and the handler sees the queued siginfo.
#[cfg(target_arch = "x86_64")]
#[test]
fn held_signal_is_not_reported_without_its_recorded_siginfo() {
    const NAME: &str = "held_signal_is_not_reported_without_its_recorded_siginfo";
    in_child_process(NAME, || {
        // Under a filter the held signal is passed on unreported without
        // reaching the record check.
        assert_tracer_unfiltered();
        GETPID_WITHOUT_DESCRIPTORS.store(true, Ordering::Relaxed);
        let (output, log) = test_fn::<InjectInFirstSignalHook, _>(|| unsafe {
            install_recorder(libc::SIGUSR1);
            let set = block(&[libc::SIGUSR1]);
            queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
            let ret = libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            let errno = *libc::__errno_location();
            // Blocked again for `print_recorded`'s check.
            block(&[libc::SIGUSR1]);
            print_recorded(ret, errno, libc::SIGUSR1);
        })
        .expect("run held-unrecorded guest");
        check_recorded(
            &output,
            "held-unrecorded",
            &log,
            &format!("-1 {}", libc::EINTR),
            libc::SI_QUEUE,
        );
        assert_eq!(
            *log.injected.lock().unwrap(),
            vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
            "the unblock completes, SIGUSR1 interrupts getpid before it runs, and no hook runs"
        );
        assert_eq!(
            *log.signals.lock().unwrap(),
            Vec::<i32>::new(),
            "the held signal is passed on unreported, as on main"
        );
    });
}

/// The filter must decline the report before the `PTRACE_GETSIGMASK` that
/// checks it.
#[cfg(target_arch = "x86_64")]
#[test]
fn held_signal_is_declined_before_a_ptrace_query_under_a_tracer_filter() {
    const NAME: &str = "held_signal_is_declined_before_a_ptrace_query_under_a_tracer_filter";
    in_child_process(NAME, || {
        held_signal_runs_as_on_main_when_the_tracer_is_killed_at(
            libc::PTRACE_GETSIGMASK,
            "held-getsigmask-filter",
        )
    });
}

/// The signal's siginfo is not read (`PTRACE_GETSIGINFO`) when it is held
/// under a tracer filter.
#[cfg(target_arch = "x86_64")]
#[test]
fn held_signal_siginfo_is_not_read_under_a_tracer_filter() {
    const NAME: &str = "held_signal_siginfo_is_not_read_under_a_tracer_filter";
    in_child_process(NAME, || {
        held_signal_runs_as_on_main_when_the_tracer_is_killed_at(
            libc::PTRACE_GETSIGINFO,
            "held-getsiginfo-filter",
        )
    });
}

/// `signal_is_delivered_when_its_siginfo_cannot_be_written_back` with a
/// filter that kills the tracer's process at a `PTRACE_GETSIGINFO`, which
/// main does not make at an ordinary delivery stop. The siginfo is not read
/// under a tracer filter, so the guest runs as on main: the signal is
/// delivered once, after the hook's injection, with the siginfo Linux makes
/// up.
#[cfg(target_arch = "x86_64")]
#[test]
fn signal_siginfo_is_not_read_under_a_tracer_filter() {
    const NAME: &str = "signal_siginfo_is_not_read_under_a_tracer_filter";
    in_child_process(NAME, || {
        let refused = (libc::PTRACE_GETSIGINFO, libc::SECCOMP_RET_KILL_PROCESS);
        let (output, log, tracer) = test_fn_under_tracer_filter(Some(refused), || unsafe {
            install_recorder(libc::SIGUSR1);
            block(&[libc::SIGUSR1]);
            queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
            // Main leaks the hook's getpid into the unblock's result; see
            // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
            unblock_returning(libc::SIGUSR1, libc::getpid() as libc::c_long);
            block(&[libc::SIGUSR1]);
            print_recorded(0, 0, libc::SIGUSR1);
        });
        let pid =
            check_recorded_made_up(&output, "ordinary-getsiginfo-filter", &log, "0 0", tracer);
        assert_eq!(
            *log.injected.lock().unwrap(),
            vec![Ok(pid)],
            "the hook's getpid runs"
        );
        assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
    });
}

/// `signal_siginfo_is_not_read_under_a_tracer_filter` with a handled
/// SIGTSTP, under a filter that returns `action` for a `PTRACE_GETSIGINFO`.
/// The tracer tells a job-control signal's delivery stop from a group stop
/// with that request, which main does not make at an ordinary delivery
/// stop. Under a tracer filter it is not made, so the guest runs as on
/// main: SIGTSTP is reported once and delivered once, after the hook's
/// injection, with the siginfo Linux makes up.
#[cfg(target_arch = "x86_64")]
fn job_control_signal_runs_as_on_main_under_a_tracer_filter(action: u32, probe: &str) {
    let refused = (libc::PTRACE_GETSIGINFO, action);
    let (output, log, tracer) = test_fn_under_tracer_filter(Some(refused), || unsafe {
        install_recorder(libc::SIGTSTP);
        block(&[libc::SIGTSTP]);
        queue_value_to_self(libc::SIGTSTP, libc::SI_QUEUE);
        // Main leaks the hook's getpid into the unblock's result; see
        // https://github.com/rrnewton/reverie/issues/892. A fix flips this to 0.
        unblock_returning(libc::SIGTSTP, libc::getpid() as libc::c_long);
        block(&[libc::SIGTSTP]);
        print_recorded(0, 0, libc::SIGTSTP);
    });
    let pid = check_recorded_made_up(&output, probe, &log, "0 0", tracer);
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid)],
        "the hook's getpid runs"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGTSTP]);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn job_control_signal_is_not_classified_when_the_tracer_is_killed_at_its_query() {
    const NAME: &str =
        "job_control_signal_is_not_classified_when_the_tracer_is_killed_at_its_query";
    in_child_process(NAME, || {
        job_control_signal_runs_as_on_main_under_a_tracer_filter(
            libc::SECCOMP_RET_KILL_PROCESS,
            "ordinary-tstp-kill-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn job_control_signal_is_not_classified_when_its_query_is_refused() {
    const NAME: &str = "job_control_signal_is_not_classified_when_its_query_is_refused";
    in_child_process(NAME, || {
        job_control_signal_runs_as_on_main_under_a_tracer_filter(
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            "ordinary-tstp-deny-filter",
        )
    });
}

/// Set by a test so that `TrapBeforeGetppid` sends SIGTSTP after SIGTRAP.
static TSTP_AFTER_TRAP: AtomicBool = AtomicBool::new(false);
/// Set by a test so that `TrapBeforeGetppid` injects `getppid` with the
/// tracer's soft `RLIMIT_NOFILE` at 0, so no descriptor can be opened during
/// it; the limit is restored when it returns.
static GETPPID_WITHOUT_DESCRIPTORS: AtomicBool = AtomicBool::new(false);
/// Set by a test, with `GETPPID_WITHOUT_DESCRIPTORS`, to a seccomp action
/// that `TrapBeforeGetppid` has a filter return for every `prctl` of the
/// tracer's threads, from just before that `getppid`; 0 for none.
static GETPPID_PRCTL_ACTION: AtomicU32 = AtomicU32::new(0);
/// Set by a test, with `GETPPID_WITHOUT_DESCRIPTORS`, so that the guest of
/// `trap_before_getppid_guest` leaves the tracer without descriptors from
/// before its first SIGSYS (`NO_DESCRIPTORS_FD`), not only during the
/// injected `getppid`.
static NO_DESCRIPTORS_FROM_FIRST_SIGSYS: AtomicBool = AtomicBool::new(false);
/// The tracer's `RLIMIT_NOFILE` while `tracer_without_descriptors` has
/// lowered it, restored when the injected `getppid` returns.
static SAVED_NOFILE: Mutex<Option<libc::rlimit>> = Mutex::new(None);

/// Adds a seccomp filter returning `action` for every `prctl`, and allowing
/// every other syscall, to all of the tracer's threads (they share the
/// filters they already have, which `SECCOMP_FILTER_FLAG_TSYNC` requires).
#[cfg(target_arch = "x86_64")]
fn filter_tracer_prctl(action: u32) {
    let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let filter = [
        // seccomp_data.nr is at offset 0.
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
        statement(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_prctl as u32,
            0,
            1,
        ),
        statement(libc::BPF_RET | libc::BPF_K, action, 0, 0),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: restricts only the tracer's threads, which end with the test.
    let installed = unsafe {
        // Required to add a filter without CAP_SYS_ADMIN, if not yet set.
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const libc::sock_fprog,
        )
    };
    assert_eq!(installed, 0, "filter prctl on every tracer thread");
}

/// Adds the `prctl` filter of `GETPPID_PRCTL_ACTION`, if any, then sets the
/// tracer's soft `RLIMIT_NOFILE` to 0, so no descriptor can be opened, saving
/// the limit in `SAVED_NOFILE`. The guest, forked from the tracer's thread,
/// installs its own filter with prctl, so the tracer's is added only now.
#[cfg(target_arch = "x86_64")]
fn tracer_without_descriptors() {
    let action = GETPPID_PRCTL_ACTION.load(Ordering::Relaxed);
    if action != 0 {
        filter_tracer_prctl(action);
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both calls only read or set this process's limit.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        let lowered = libc::rlimit {
            rlim_cur: 0,
            rlim_max: limit.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lowered), 0);
    }
    *SAVED_NOFILE.lock().unwrap() = Some(limit);
}

/// `ReplaceMarker`, whose hook for `GETPPID_FD` first injects `getpid`, then
/// sends SIGTRAP to the guest's thread from the tracer, then SIGTSTP when
/// `TSTP_AFTER_TRAP` is set. Linux dequeues the SIGTRAP when the injected `getppid` is stepped,
/// before its `syscall` runs.
#[derive(Clone, Copy, Debug, Default)]
struct TrapBeforeGetppid;

#[reverie::tool]
impl Tool for TrapBeforeGetppid {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if matches!(syscall, Syscall::Write(write) if write.fd() == NO_DESCRIPTORS_FD && write.len() == 0)
        {
            tracer_without_descriptors();
            return Ok(0);
        }
        if matches!(syscall, Syscall::Write(write) if write.fd() == GETPPID_FD && write.len() == 0)
        {
            // A complete injection first, unreported: an earlier injection's
            // step SIGTRAP can still be queued, and a SIGTRAP sent now would
            // coalesce with it and be discarded as that stale trap
            // (`TrapThenGetpidInSigusr1Hook`).
            guest.inject(Getpid::new()).await?;
            let mut signals = vec![libc::SIGTRAP];
            if TSTP_AFTER_TRAP.load(Ordering::Relaxed) {
                signals.push(libc::SIGTSTP);
            }
            for signal in signals {
                // SAFETY: tgkill has no memory-safety preconditions.
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        guest.pid().as_raw(),
                        guest.tid().as_raw(),
                        signal,
                    )
                };
                assert_eq!(sent, 0, "send signal {signal} to the guest");
            }
            if GETPPID_WITHOUT_DESCRIPTORS.load(Ordering::Relaxed) {
                if SAVED_NOFILE.lock().unwrap().is_none() {
                    tracer_without_descriptors();
                }
                let result = guest.inject(Getppid::new()).await;
                let limit = SAVED_NOFILE.lock().unwrap().take().unwrap();
                // SAFETY: restores the limit `tracer_without_descriptors` read.
                unsafe { assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0) };
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                return Ok(result?);
            }
        }
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        Ok(Some(signal))
    }
}

static SIGTSTP_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_sigtstp(_signal: libc::c_int) {
    SIGTSTP_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Requires the calling thread, the tracer's, to be under no seccomp filter.
#[cfg(target_arch = "x86_64")]
fn assert_tracer_unfiltered() {
    let status = std::fs::read_to_string("/proc/thread-self/status").expect("read thread status");
    assert!(
        status.lines().any(|line| line == "Seccomp:\t0"),
        "the tracer thread must be under no seccomp filter: {status}"
    );
}

/// The guest of `injected_syscall_trapped_by_guest_seccomp_reports_enosys`,
/// run with `TrapBeforeGetppid`, and with a handler counting SIGTSTP when
/// `tstp` is set. Prints the handler's count last. With
/// `NO_DESCRIPTORS_FROM_FIRST_SIGSYS` set, it submits `NO_DESCRIPTORS_FD`
/// after loading its filter.
#[cfg(target_arch = "x86_64")]
fn trap_before_getppid_guest(tstp: bool) -> impl FnOnce() + Send + 'static {
    move || unsafe {
        SIGTSTP_HANDLER_CALLS.store(0, Ordering::Relaxed);
        if tstp {
            install_counter(libc::SIGTSTP, count_sigtstp);
        }
        trap_getppid();
        if NO_DESCRIPTORS_FROM_FIRST_SIGSYS.load(Ordering::Relaxed) {
            let ret = libc::syscall(
                libc::SYS_write,
                NO_DESCRIPTORS_FD,
                std::ptr::null::<u8>(),
                0usize,
            );
            assert_eq!(ret, 0, "the tracer is left without descriptors");
        }
        print_seccomp_trap(libc::syscall(libc::SYS_getppid));
        let ret = libc::syscall(libc::SYS_write, GETPPID_FD, std::ptr::null::<u8>(), 0usize);
        print_seccomp_trap(ret);
        println!("{}", SIGTSTP_HANDLER_CALLS.load(Ordering::Relaxed));
    }
}

/// Runs the guest of `injected_syscall_trapped_by_guest_seccomp_reports_enosys`
/// with a SIGTRAP pending when the tool injects `getppid`
/// (`TrapBeforeGetppid`), on a tracer under no seccomp filter, with no
/// descriptor left to open during the injection when `without_descriptors`
/// is set, from before the guest's first SIGSYS when `from_first_sigsys` is
/// also set. The trap stops the step before the `syscall` runs.
#[cfg(target_arch = "x86_64")]
fn trap_before_getppid_on_an_unfiltered_tracer(
    without_descriptors: bool,
    from_first_sigsys: bool,
) -> (reverie::process::Output, Log) {
    assert_tracer_unfiltered();
    TSTP_AFTER_TRAP.store(false, Ordering::Relaxed);
    GETPPID_WITHOUT_DESCRIPTORS.store(without_descriptors, Ordering::Relaxed);
    GETPPID_PRCTL_ACTION.store(0, Ordering::Relaxed);
    NO_DESCRIPTORS_FROM_FIRST_SIGSYS.store(from_first_sigsys, Ordering::Relaxed);
    test_fn::<TrapBeforeGetppid, _>(trap_before_getppid_guest(false))
        .expect("run trap-before-getppid guest")
}

/// `trap_before_getppid_on_an_unfiltered_tracer` with descriptors left. The
/// trap is discarded, and the step runs the `getppid`, which the guest's
/// filter traps as without the SIGTRAP.
#[cfg(target_arch = "x86_64")]
fn sigtrap_before_an_injected_syscall_is_discarded(probe: &str) {
    let (output, log) = trap_before_getppid_on_an_unfiltered_tracer(false, false);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} status={:?} guest={:?} injected={:?} signals={:?}",
        output.status,
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Err(libc::ENOSYS)],
        "the trapped getppid did not run"
    );
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        [
            format!("4242 1 1 {} {}", libc::SYS_getppid, libc::SYS_getppid),
            format!("4242 2 1 {} {}", libc::SYS_getppid, -libc::ENOSYS),
            "0".to_string(),
        ],
        "in place and injected, the guest's SIGSYS handler emulates getppid once"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGSYS, libc::SIGSYS],
        "each SIGSYS reaches the tool, and the discarded SIGTRAP does not"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_discarded_and_the_syscall_runs() {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_discarded_and_the_syscall_runs";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_is_discarded("trap-before-getppid")
    });
}

/// As `sigtrap_before_an_injected_syscall_is_discarded_and_the_syscall_runs`,
/// but no descriptor can be opened during the injection, so procfs cannot
/// report the tracer thread's seccomp mode at the decision (EMFILE). The
/// thread is taken as filtered, and the trap for the step's report, as on
/// main: the `getppid` does not run.
///
/// Disclosed gap (coord ruling msg1001): where no fresh procfs read can
/// report the tracer thread's seccomp mode at a decision, the step goes as
/// on main before https://github.com/rrnewton/reverie/pull/831, without its
/// correction (https://github.com/rrnewton/reverie/issues/845,
/// https://github.com/rrnewton/reverie/issues/912).
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_taken_as_on_main_with_no_descriptor_left() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_taken_as_on_main_with_no_descriptor_left";
    in_child_process(NAME, || {
        let (output, log) = trap_before_getppid_on_an_unfiltered_tracer(true, false);
        check_trap_before_getppid_taken_as_on_main(
            &output,
            &log,
            false,
            "trap-before-getppid-emfile",
        )
    });
}

/// As `..._is_taken_as_on_main_with_no_descriptor_left`, but no descriptor
/// can be opened from before the guest's first SIGSYS, whose stop cannot
/// read the tracer thread's mode either.
///
/// Disclosed gap (coord ruling msg1001): where no fresh procfs read can
/// report the tracer thread's seccomp mode at a decision, the step goes as
/// on main before https://github.com/rrnewton/reverie/pull/831, without its
/// correction (https://github.com/rrnewton/reverie/issues/845,
/// https://github.com/rrnewton/reverie/issues/912).
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_taken_as_on_main_with_no_descriptor_from_the_first_sigsys()
{
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_taken_as_on_main_with_no_descriptor_from_the_first_sigsys";
    in_child_process(NAME, || {
        let (output, log) = trap_before_getppid_on_an_unfiltered_tracer(true, true);
        check_trap_before_getppid_taken_as_on_main(
            &output,
            &log,
            false,
            "trap-before-getppid-early-emfile",
        )
    });
}

/// `sigtrap_before_an_injected_syscall_is_discarded_and_the_syscall_runs`
/// under a tracer filter that returns `action` for a `ptrace` of `request`,
/// with SIGTSTP pending after the SIGTRAP when `tstp` is set. Retried, the
/// step would stop at requests main does not make for this guest: at the
/// guest filter's SIGSYS, the `PTRACE_GETSIGMASK` that checks it; at the
/// SIGTSTP, the `PTRACE_GETSIGINFO` that tells its delivery from a group
/// stop. Under a tracer filter the trap is taken for the step's report
/// instead, as on main, and the guest runs as on main: the `getppid` does
/// not run, and the injection returns the syscall number left in RAX (110),
/// a known gap (https://github.com/rrnewton/reverie/issues/845). A pending
/// SIGTSTP is then reported, and its handler runs once. With `prctl` set,
/// no descriptor can be opened during the injected `getppid`, so procfs
/// cannot report the tracer thread's mode, and every `prctl` of the tracer
/// gets that action from then on. With `from_first_sigsys` also set, that
/// starts before the guest's first SIGSYS, whose delivery stop is then the
/// first at which the tracer could open procfs to read its mode.
#[cfg(target_arch = "x86_64")]
fn sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
    request: u32,
    action: u32,
    tstp: bool,
    prctl: Option<u32>,
    from_first_sigsys: bool,
    probe: &str,
) {
    TSTP_AFTER_TRAP.store(tstp, Ordering::Relaxed);
    GETPPID_WITHOUT_DESCRIPTORS.store(prctl.is_some(), Ordering::Relaxed);
    GETPPID_PRCTL_ACTION.store(prctl.unwrap_or(0), Ordering::Relaxed);
    NO_DESCRIPTORS_FROM_FIRST_SIGSYS.store(from_first_sigsys, Ordering::Relaxed);
    let (output, log, _) = test_tool_under_tracer_filter::<TrapBeforeGetppid, _>(
        Some((request, action)),
        trap_before_getppid_guest(tstp),
    );
    check_trap_before_getppid_taken_as_on_main(&output, &log, tstp, probe);
}

/// Checks main's outcome for `trap_before_getppid_guest(tstp)`: the SIGTRAP
/// is taken for the step's report, so the injected `getppid` does not run
/// and returns the syscall number left in RAX (110), and a SIGTSTP handler
/// runs once.
#[cfg(target_arch = "x86_64")]
fn check_trap_before_getppid_taken_as_on_main(
    output: &reverie::process::Output,
    log: &Log,
    tstp: bool,
    probe: &str,
) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} status={:?} guest={:?} injected={:?} signals={:?}",
        output.status,
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(libc::SYS_getppid)],
        "the SIGTRAP is taken for the step's report, as on main"
    );
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        [
            format!("4242 1 1 {} {}", libc::SYS_getppid, libc::SYS_getppid),
            format!(
                "{} 1 1 {} {}",
                libc::SYS_getppid,
                libc::SYS_getppid,
                libc::SYS_getppid
            ),
            usize::from(tstp).to_string(),
        ],
        "the injected getppid does not run, and a SIGTSTP handler runs once"
    );
    let mut signals = vec![libc::SIGSYS];
    if tstp {
        signals.push(libc::SIGTSTP);
    }
    assert_eq!(*log.signals.lock().unwrap(), signals);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_getsigmask() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_getsigmask";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_KILL_PROCESS,
            false,
            None,
            false,
            "trap-getsigmask-kill-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_getsigmask_is_refused() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_not_retried_when_getsigmask_is_refused";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            false,
            None,
            false,
            "trap-getsigmask-deny-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_getsiginfo() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_getsiginfo";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGINFO,
            libc::SECCOMP_RET_KILL_PROCESS,
            true,
            None,
            false,
            "trap-tstp-getsiginfo-kill-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_getsiginfo_is_refused() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_not_retried_when_getsiginfo_is_refused";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGINFO,
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            true,
            None,
            false,
            "trap-tstp-getsiginfo-deny-filter",
        )
    });
}

/// A tracer thread under a filter, whose mode procfs cannot report at the
/// decision (no descriptor can be opened), is not asked for it with a
/// syscall main does not make for this guest: here a filter kills the
/// tracer at every `prctl`. The trap is taken for the step's report, as on
/// main.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_left_when_prctl_kills() {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_left_when_prctl_kills";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_KILL_PROCESS,
            false,
            Some(libc::SECCOMP_RET_KILL_PROCESS),
            false,
            "trap-emfile-prctl-kill-filter",
        )
    });
}

/// As `..._when_prctl_kills`, with a filter that traps every `prctl`
/// (SIGSYS, which the tracer does not handle).
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_left_when_prctl_traps() {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_left_when_prctl_traps";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_KILL_PROCESS,
            false,
            Some(libc::SECCOMP_RET_TRAP),
            false,
            "trap-emfile-prctl-trap-filter",
        )
    });
}

/// As `..._when_prctl_kills`, with a filter that answers every `prctl`
/// with 0 without running it, which would read as "no filter": the step is
/// still not retried, so the refused `PTRACE_GETSIGMASK` is not reached.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_left_when_prctl_answers_0()
{
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_left_when_prctl_answers_0";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            false,
            Some(libc::SECCOMP_RET_ERRNO),
            false,
            "trap-emfile-prctl-errno0-filter",
        )
    });
}

/// As `..._with_no_descriptor_left_when_prctl_kills`, but no descriptor can
/// be opened from before the guest's first SIGSYS, so procfs never reports
/// the tracer thread's mode during the guest's run. The thread is taken as
/// filtered at the decision, and no `prctl` is made.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_from_the_first_sigsys_when_prctl_kills()
 {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_from_the_first_sigsys_when_prctl_kills";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_KILL_PROCESS,
            false,
            Some(libc::SECCOMP_RET_KILL_PROCESS),
            true,
            "trap-early-emfile-prctl-kill-filter",
        )
    });
}

/// As `..._from_the_first_sigsys_when_prctl_kills`, with a filter that traps
/// every `prctl`.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_from_the_first_sigsys_when_prctl_traps()
 {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_from_the_first_sigsys_when_prctl_traps";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_KILL_PROCESS,
            false,
            Some(libc::SECCOMP_RET_TRAP),
            true,
            "trap-early-emfile-prctl-trap-filter",
        )
    });
}

/// As `..._from_the_first_sigsys_when_prctl_kills`, with a filter that
/// answers every `prctl` with 0 without running it.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_from_the_first_sigsys_when_prctl_answers_0()
 {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_with_no_descriptor_from_the_first_sigsys_when_prctl_answers_0";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_tracer_filter(
            libc::PTRACE_GETSIGMASK,
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            false,
            Some(libc::SECCOMP_RET_ERRNO),
            true,
            "trap-early-emfile-prctl-errno0-filter",
        )
    });
}

/// `TrapBeforeGetppid` on a tracer under no seccomp filter when it takes the
/// guest, which, from before the guest's first SIGSYS, gets a filter
/// returning `prctl_action` for every `prctl` and no descriptor to open
/// (`NO_DESCRIPTORS_FROM_FIRST_SIGSYS`). Procfs never reports the tracer
/// thread's mode once it is filtered, so it is taken as filtered at the
/// decision, it is not asked with `prctl`, and the trap is taken for the
/// step's report, as on main.
#[cfg(target_arch = "x86_64")]
fn sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_filter_added_after_spawn(
    prctl_action: u32,
    probe: &str,
) {
    assert_tracer_unfiltered();
    TSTP_AFTER_TRAP.store(false, Ordering::Relaxed);
    GETPPID_WITHOUT_DESCRIPTORS.store(true, Ordering::Relaxed);
    GETPPID_PRCTL_ACTION.store(prctl_action, Ordering::Relaxed);
    NO_DESCRIPTORS_FROM_FIRST_SIGSYS.store(true, Ordering::Relaxed);
    let (output, log) = test_fn::<TrapBeforeGetppid, _>(trap_before_getppid_guest(false))
        .expect("run trap-before-getppid guest");
    check_trap_before_getppid_taken_as_on_main(&output, &log, false, probe);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_under_a_filter_added_after_spawn_when_prctl_kills()
 {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_under_a_filter_added_after_spawn_when_prctl_kills";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_filter_added_after_spawn(
            libc::SECCOMP_RET_KILL_PROCESS,
            "trap-late-filter-emfile-prctl-kill",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_under_a_filter_added_after_spawn_when_prctl_traps()
 {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_under_a_filter_added_after_spawn_when_prctl_traps";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_under_a_filter_added_after_spawn(
            libc::SECCOMP_RET_TRAP,
            "trap-late-filter-emfile-prctl-trap",
        )
    });
}

/// `sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_getsigmask`
/// with a tracer filter that also returns `action` for every syscall `nr`,
/// which main does not make for this guest. Reading the tracer thread's
/// seccomp mode makes no such syscall, so the guest runs as on main.
#[cfg(target_arch = "x86_64")]
fn sigtrap_before_an_injected_syscall_runs_as_on_main_when_the_tracer_filters(
    numbers: &'static [(libc::c_long, u32)],
    probe: &str,
) {
    TSTP_AFTER_TRAP.store(false, Ordering::Relaxed);
    GETPPID_WITHOUT_DESCRIPTORS.store(false, Ordering::Relaxed);
    GETPPID_PRCTL_ACTION.store(0, Ordering::Relaxed);
    NO_DESCRIPTORS_FROM_FIRST_SIGSYS.store(false, Ordering::Relaxed);
    let (output, log, _) = test_tool_under_tracer_filters::<TrapBeforeGetppid, _>(
        Some((libc::PTRACE_GETSIGMASK, libc::SECCOMP_RET_KILL_PROCESS)),
        numbers,
        trap_before_getppid_guest(false),
    );
    check_trap_before_getppid_taken_as_on_main(&output, &log, false, probe);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_lseek() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_lseek";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_when_the_tracer_filters(
            &[(libc::SYS_lseek, libc::SECCOMP_RET_KILL_PROCESS)],
            "trap-lseek-kill-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_lseek_traps() {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_when_lseek_traps";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_when_the_tracer_filters(
            &[(libc::SYS_lseek, libc::SECCOMP_RET_TRAP)],
            "trap-lseek-trap-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_pread() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_not_retried_when_the_tracer_is_killed_at_pread";
    in_child_process(NAME, || {
        sigtrap_before_an_injected_syscall_runs_as_on_main_when_the_tracer_filters(
            &[
                (libc::SYS_pread64, libc::SECCOMP_RET_KILL_PROCESS),
                (libc::SYS_preadv, libc::SECCOMP_RET_KILL_PROCESS),
                (libc::SYS_preadv2, libc::SECCOMP_RET_KILL_PROCESS),
            ],
            "trap-pread-kill-filter",
        )
    });
}

/// What `TrapBeforeEachGetppid` does around the injection for each
/// `GETPPID_FD` marker, in order: whether it first sets the tracer's soft
/// `RLIMIT_NOFILE` to 0 (`LOWER`), first adds a filter to every tracer
/// thread that kills its process at `PTRACE_GETSIGMASK` and every `prctl`
/// (`FILTER`), or restores the limit after the injection (`RESTORE`).
static EACH_GETPPID_SCRIPT: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
const LOWER: u32 = 1;
const FILTER: u32 = 2;
const RESTORE: u32 = 4;
/// `GETPPID_FD` markers `TrapBeforeEachGetppid` has handled.
static EACH_GETPPID_MARKERS: AtomicUsize = AtomicUsize::new(0);

/// Sets the tracer's soft `RLIMIT_NOFILE` to 0, so no descriptor can be
/// opened, and returns the limit to restore.
#[cfg(target_arch = "x86_64")]
fn lower_nofile() -> libc::rlimit {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both calls only read or set this process's limit.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        let lowered = libc::rlimit {
            rlim_cur: 0,
            rlim_max: limit.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lowered), 0);
    }
    limit
}

/// Restores a limit `lower_nofile` returned.
#[cfg(target_arch = "x86_64")]
fn restore_nofile(limit: libc::rlimit) {
    // SAFETY: only sets this process's limit.
    unsafe { assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0) };
}

/// Adds a filter to every tracer thread (`SECCOMP_FILTER_FLAG_TSYNC`) that
/// kills its process at `PTRACE_GETSIGMASK` and at every `prctl`.
#[cfg(target_arch = "x86_64")]
fn filter_tracer_getsigmask_and_prctl() {
    let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let kill = libc::SECCOMP_RET_KILL_PROCESS;
    let filter = [
        // seccomp_data.nr is at offset 0, and the low half of args[0] at 16.
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
        statement(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_prctl as u32,
            0,
            1,
        ),
        statement(libc::BPF_RET | libc::BPF_K, kill, 0, 0),
        statement(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_ptrace as u32,
            0,
            3,
        ),
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 16, 0, 0),
        statement(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::PTRACE_GETSIGMASK,
            0,
            1,
        ),
        statement(libc::BPF_RET | libc::BPF_K, kill, 0, 0),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: restricts only the tracer's threads, which end with the test.
    let installed = unsafe {
        // Required to add a filter without CAP_SYS_ADMIN, if not yet set.
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const libc::sock_fprog,
        )
    };
    assert_eq!(installed, 0, "filter the tracer's threads");
}

/// `TrapBeforeGetppid` for two `GETPPID_FD` markers, each with the
/// `EACH_GETPPID_SCRIPT` entry of its turn.
#[derive(Clone, Copy, Debug, Default)]
struct TrapBeforeEachGetppid;

#[reverie::tool]
impl Tool for TrapBeforeEachGetppid {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if !matches!(syscall, Syscall::Write(write) if write.fd() == GETPPID_FD && write.len() == 0)
        {
            return replace_marker(guest, syscall).await;
        }
        let turn = EACH_GETPPID_MARKERS.fetch_add(1, Ordering::Relaxed);
        let script = EACH_GETPPID_SCRIPT[turn].load(Ordering::Relaxed);
        // As in `TrapBeforeGetppid`, a complete injection first.
        guest.inject(Getpid::new()).await?;
        // SAFETY: tgkill has no memory-safety preconditions.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                guest.pid().as_raw(),
                guest.tid().as_raw(),
                libc::SIGTRAP,
            )
        };
        assert_eq!(sent, 0, "send SIGTRAP to the guest");
        if script & LOWER != 0 {
            *SAVED_NOFILE.lock().unwrap() = Some(lower_nofile());
        }
        if script & FILTER != 0 {
            filter_tracer_getsigmask_and_prctl();
        }
        let result = guest.inject(Getppid::new()).await;
        if script & RESTORE != 0 {
            restore_nofile(SAVED_NOFILE.lock().unwrap().take().unwrap());
        }
        guest
            .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
            .await;
        Ok(result?)
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        Ok(Some(signal))
    }
}

/// Runs `TrapBeforeEachGetppid` with `script`, on a tracer thread under no
/// seccomp filter when it takes the guest, which, after its filter trapping
/// `getppid`, calls `getppid` and then submits two `GETPPID_FD` markers. For
/// each marker, checks whether the step is retried (`true`: the trap is
/// discarded, and the guest's filter traps the `getppid`, which returns
/// `ENOSYS` to the tool, and whose SIGSYS the guest handles) or the trap is
/// taken for the step's report, as on main (`false`: the injection returns
/// the syscall number left in RAX, and nothing runs in the guest).
#[cfg(target_arch = "x86_64")]
fn sigtrap_before_each_injected_syscall(script: [u32; 2], retried: [bool; 2], probe: &str) {
    assert_tracer_unfiltered();
    EACH_GETPPID_MARKERS.store(0, Ordering::Relaxed);
    for (entry, value) in EACH_GETPPID_SCRIPT.iter().zip(script) {
        entry.store(value, Ordering::Relaxed);
    }
    let (output, log) = test_fn::<TrapBeforeEachGetppid, _>(|| unsafe {
        trap_getppid();
        print_seccomp_trap(libc::syscall(libc::SYS_getppid));
        for _ in 0..2 {
            let ret = libc::syscall(libc::SYS_write, GETPPID_FD, std::ptr::null::<u8>(), 0usize);
            print_seccomp_trap(ret);
        }
    })
    .expect("run trap-before-each-getppid guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE {probe} status={:?} guest={:?} injected={:?} signals={:?}",
        output.status,
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let getppid = libc::SYS_getppid;
    let mut lines = vec![format!("4242 1 1 {getppid} {getppid}")];
    let mut injected = Vec::new();
    let mut signals = vec![libc::SIGSYS];
    let (mut traps, mut rax) = (1, getppid);
    for retried in retried {
        if retried {
            traps += 1;
            rax = -libc::ENOSYS as i64;
            lines.push(format!("4242 {traps} 1 {getppid} {rax}"));
            injected.push(Err(libc::ENOSYS));
            signals.push(libc::SIGSYS);
        } else {
            lines.push(format!("{getppid} {traps} 1 {getppid} {rax}"));
            injected.push(Ok(getppid));
        }
    }
    let got: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(got, lines);
    assert_eq!(*log.injected.lock().unwrap(), injected);
    assert_eq!(*log.signals.lock().unwrap(), signals);
}

/// No descriptor can be opened during either injection, but can between
/// them. Procfs cannot report the tracer thread's mode at either decision,
/// so both traps are taken as on main.
///
/// Disclosed gap (coord ruling msg1001): where no fresh procfs read can
/// report the tracer thread's seccomp mode at a decision, the step goes as
/// on main before https://github.com/rrnewton/reverie/pull/831, without its
/// correction (https://github.com/rrnewton/reverie/issues/845,
/// https://github.com/rrnewton/reverie/issues/912).
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_injected_syscalls_is_taken_as_on_main_with_no_descriptor_at_either_decision() {
    const NAME: &str = "sigtrap_before_injected_syscalls_is_taken_as_on_main_with_no_descriptor_at_either_decision";
    in_child_process(NAME, || {
        sigtrap_before_each_injected_syscall(
            [LOWER | RESTORE, LOWER | RESTORE],
            [false, false],
            "trap-each-emfile-each",
        )
    });
}

/// No descriptor can be opened from the first decision through the second,
/// so procfs cannot report the tracer thread's mode at either, and both
/// traps are taken as on main.
///
/// Disclosed gap (coord ruling msg1001): where no fresh procfs read can
/// report the tracer thread's seccomp mode at a decision, the step goes as
/// on main before https://github.com/rrnewton/reverie/pull/831, without its
/// correction (https://github.com/rrnewton/reverie/issues/845,
/// https://github.com/rrnewton/reverie/issues/912).
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_injected_syscalls_is_taken_as_on_main_with_no_descriptor_through_both_decisions()
{
    const NAME: &str = "sigtrap_before_injected_syscalls_is_taken_as_on_main_with_no_descriptor_through_both_decisions";
    in_child_process(NAME, || {
        sigtrap_before_each_injected_syscall(
            [LOWER, RESTORE],
            [false, false],
            "trap-each-emfile-through-both",
        )
    });
}

/// As `..._with_no_descriptor_through_both_decisions`, but a filter killing
/// the tracer's process at `PTRACE_GETSIGMASK` and every `prctl` is added to
/// the tracer's threads between the decisions. With nothing to report its
/// mode, the thread is taken as filtered at the second decision, and the
/// trap is taken as on main, without asking `prctl`; retried, the step would
/// reach that `PTRACE_GETSIGMASK` at the guest's SIGSYS. The first decision,
/// on an unfiltered thread, is the gap below.
///
/// Disclosed gap (coord ruling msg1001): where no fresh procfs read can
/// report the tracer thread's seccomp mode at a decision, the step goes as
/// on main before https://github.com/rrnewton/reverie/pull/831, without its
/// correction (https://github.com/rrnewton/reverie/issues/845,
/// https://github.com/rrnewton/reverie/issues/912).
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_not_retried_under_a_filter_added_with_no_descriptor_left()
{
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_not_retried_under_a_filter_added_with_no_descriptor_left";
    in_child_process(NAME, || {
        sigtrap_before_each_injected_syscall(
            [LOWER, FILTER | RESTORE],
            [false, false],
            "trap-each-emfile-late-filter",
        )
    });
}

/// No descriptor can be opened during the first injection, but can during
/// the second. Each decision reads procfs afresh: the first trap is taken as
/// on main (the gap above), and the second, with mode 0 read, is discarded.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_discarded_again_once_a_descriptor_can_be_opened() {
    const NAME: &str =
        "sigtrap_before_an_injected_syscall_is_discarded_again_once_a_descriptor_can_be_opened";
    in_child_process(NAME, || {
        sigtrap_before_each_injected_syscall(
            [LOWER | RESTORE, 0],
            [false, true],
            "trap-each-emfile-then-open",
        )
    });
}

/// A filter killing the tracer's process at `PTRACE_GETSIGMASK` and every
/// `prctl` is added to the tracer's threads between the decisions. Procfs
/// reports mode 0 at the first, whose trap is discarded, and the filter at
/// the second, whose trap is taken as on main; retried, the step would
/// reach that `PTRACE_GETSIGMASK` at the guest's SIGSYS.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_discarded_until_a_filter_is_added() {
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_discarded_until_a_filter_is_added";
    in_child_process(NAME, || {
        sigtrap_before_each_injected_syscall([0, FILTER], [true, false], "trap-each-late-filter")
    });
}

/// As `..._is_discarded_until_a_filter_is_added`, but no descriptor can be
/// opened during the second injection either, so procfs reports nothing
/// there: the thread is taken as filtered, and the trap as on main.
#[cfg(target_arch = "x86_64")]
#[test]
fn sigtrap_before_an_injected_syscall_is_discarded_until_a_filter_is_added_with_no_descriptor_left()
{
    const NAME: &str = "sigtrap_before_an_injected_syscall_is_discarded_until_a_filter_is_added_with_no_descriptor_left";
    in_child_process(NAME, || {
        sigtrap_before_each_injected_syscall(
            [0, LOWER | FILTER | RESTORE],
            [true, false],
            "trap-each-late-filter-emfile",
        )
    });
}

/// A guest that does not execute a program inherits no procfs status from
/// the tracer, whatever its number: here descriptors 3 to 255, which a guest
/// closes as on main, are all taken, so any status the tracer kept open
/// would get a higher number. Another tracer thread has taken a guest and is
/// still running, and this thread has run its first guest; the second guest
/// lists the procfs statuses it has open.
#[cfg(target_arch = "x86_64")]
#[test]
fn guest_inherits_no_held_seccomp_status() {
    const NAME: &str = "guest_inherits_no_held_seccomp_status";
    in_child_process(NAME, || {
        use std::os::fd::IntoRawFd;
        assert_tracer_unfiltered();
        let null = std::fs::File::open("/dev/null")
            .expect("open /dev/null")
            .into_raw_fd();
        for fd in 3..256 {
            // SAFETY: fills free descriptors only, with copies of `null`.
            unsafe {
                if libc::fcntl(fd, libc::F_GETFD) == -1 {
                    assert_eq!(libc::dup2(null, fd), fd);
                }
            }
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || {
            let (output, _) = test_fn::<ReplaceMarker, _>(|| {}).expect("run first guest");
            ready_tx.send(()).unwrap();
            done_rx.recv().unwrap();
            output
        });
        ready_rx.recv().unwrap();
        let (first, _) = test_fn::<ReplaceMarker, _>(|| {}).expect("run first guest");
        let (second, _) = test_fn::<ReplaceMarker, _>(|| {
            for entry in std::fs::read_dir("/proc/self/fd").expect("list descriptors") {
                let entry = entry.expect("descriptor");
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let target = target.to_string_lossy().into_owned();
                    if target.starts_with("/proc/") && target.ends_with("/status") {
                        println!("{} {target}", entry.file_name().to_string_lossy());
                    }
                }
            }
        })
        .expect("run second guest");
        done_tx.send(()).unwrap();
        let other = other.join().expect("other tracer thread");
        let stdout = String::from_utf8_lossy(&second.stdout);
        eprintln!(
            "PROBE held-status-inheritance status={:?} statuses={:?}",
            second.status,
            stdout.trim()
        );
        for output in [&other, &first, &second] {
            assert_eq!(
                output.status,
                ExitStatus::Exited(0),
                "stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(stdout.trim(), "", "the guest has no procfs status open");
    });
}

/// Counts SIGUSR1, then submits the `GETPPID_FD` marker, which the tool
/// replaces with an injected `getppid`.
#[cfg(target_arch = "x86_64")]
extern "C" fn count_sigusr1_then_inject_getppid(_signal: libc::c_int) {
    SIGUSR1_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: a zero-length write from no buffer.
    unsafe { libc::syscall(libc::SYS_write, GETPPID_FD, std::ptr::null::<u8>(), 0usize) };
}

/// The guest of `signal_is_delivered_after_a_signal_hook_vfork_at_its_delivery_stop`,
/// whose SIGUSR1 handler also has the tool inject `getppid`, which a filter
/// the guest loads first traps (`trap_getppid`).
#[cfg(target_arch = "x86_64")]
fn vfork_hook_guest_injecting_in_its_handler() -> impl FnOnce() + Send + 'static {
    || unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        trap_getppid();
        install_counter(libc::SIGUSR1, count_sigusr1_then_inject_getppid);
        block(&[libc::SIGCHLD]);
        let ret = syscall_exiting_a_vfork_child(
            libc::SYS_tgkill,
            libc::getpid() as i64,
            libc::syscall(libc::SYS_gettid),
            libc::SIGUSR1 as i64,
        );
        let calls = SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed);
        let mut status = 0;
        let child = libc::waitpid(-1, &mut status, 0);
        println!("{ret} {calls} {child} {status}");
    }
}

/// Checks a `vfork_hook_guest_injecting_in_its_handler` run: the guest's
/// line, `{ret} {handler runs} {reaped child} {status}`, with `ret` the
/// leaked vfork child PID (https://github.com/rrnewton/reverie/issues/892),
/// and the injections and signals the tool saw: the hook's vfork, then, if
/// the handler ran, its trapped `getppid` (`ENOSYS`) and that SIGSYS.
#[cfg(target_arch = "x86_64")]
fn check_vfork_hook_injecting_in_its_handler(
    output: &reverie::process::Output,
    log: &Log,
    probe: &str,
    handled: bool,
) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected = log.injected.lock().unwrap();
    let signals = log.signals.lock().unwrap();
    eprintln!(
        "PROBE {probe} status={:?} guest={:?} injected={:?} signals={:?}",
        output.status,
        stdout.trim(),
        *injected,
        *signals
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let Some(&Ok(child)) = injected.first() else {
        panic!("vfork failed: {:?}", *injected);
    };
    let mut expected = vec![Ok(child)];
    let mut expected_signals = vec![libc::SIGUSR1];
    if handled {
        expected.push(Err(libc::ENOSYS));
        expected_signals.push(libc::SIGSYS);
    }
    assert_eq!(*injected, expected);
    let fields: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(
        fields,
        [
            child.to_string().as_str(),
            if handled { "1" } else { "0" },
            &child.to_string(),
            "0"
        ],
        "the guest gets the leaked child PID, runs the SIGUSR1 handler once or not at all, and reaps the hook's child"
    );
    assert_eq!(*signals, expected_signals);
}

/// With no tracer filter, the vfork injection steps on past its vfork-done
/// stop, so SIGUSR1 is delivered and its handler's injected `getppid` runs.
#[cfg(target_arch = "x86_64")]
#[test]
fn signal_hook_vfork_delivers_a_signal_whose_handler_injects() {
    const NAME: &str = "signal_hook_vfork_delivers_a_signal_whose_handler_injects";
    in_child_process(NAME, || {
        assert_tracer_unfiltered();
        let (output, log) =
            test_fn::<VforkInFirstSignalHook, _>(vfork_hook_guest_injecting_in_its_handler())
                .expect("run vfork-hook guest");
        check_vfork_hook_injecting_in_its_handler(&output, &log, "vfork-handler-injects", true);
    });
}

/// `signal_hook_vfork_delivers_a_signal_whose_handler_injects` under a
/// tracer filter that returns `action` for `PTRACE_GETSIGMASK`. Stepped on,
/// the injection would deliver SIGUSR1, and the handler's `getppid` would
/// raise a guest SIGSYS, whose check makes that request, which main does not
/// make for this guest. Under a tracer filter the injection keeps the
/// vfork-done stop, as on main, and the guest runs as on main: Linux drops
/// SIGUSR1, and the handler does not run.
#[cfg(target_arch = "x86_64")]
fn signal_hook_vfork_runs_as_on_main_under_a_tracer_filter(action: u32, probe: &str) {
    let (output, log, _) = test_tool_under_tracer_filter::<VforkInFirstSignalHook, _>(
        Some((libc::PTRACE_GETSIGMASK, action)),
        vfork_hook_guest_injecting_in_its_handler(),
    );
    check_vfork_hook_injecting_in_its_handler(&output, &log, probe, false);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn signal_hook_vfork_is_not_stepped_on_when_the_tracer_is_killed_at_getsigmask() {
    const NAME: &str =
        "signal_hook_vfork_is_not_stepped_on_when_the_tracer_is_killed_at_getsigmask";
    in_child_process(NAME, || {
        signal_hook_vfork_runs_as_on_main_under_a_tracer_filter(
            libc::SECCOMP_RET_KILL_PROCESS,
            "vfork-getsigmask-kill-filter",
        )
    });
}

#[cfg(target_arch = "x86_64")]
#[test]
fn signal_hook_vfork_is_not_stepped_on_when_getsigmask_is_refused() {
    const NAME: &str = "signal_hook_vfork_is_not_stepped_on_when_getsigmask_is_refused";
    in_child_process(NAME, || {
        signal_hook_vfork_runs_as_on_main_under_a_tracer_filter(
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            "vfork-getsigmask-deny-filter",
        )
    });
}

/// What `ScriptedSignalHook`'s callbacks on a thread do, one entry per
/// callback, as `action` encodes it. The guest writes it before its first
/// signal, and the tool reads the guest's copy. Callbacks past the last
/// entry repeat it, up to `HOOK_INJECTIONS` callbacks, and later ones pass
/// their signal through.
static SCRIPT: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
/// The mask `INJECT_SET_MASK` installs.
static SCRIPT_MASK: AtomicU64 = AtomicU64::new(0);
/// The siginfo `INJECT_QUEUE` queues, which the guest fills in.
static mut SCRIPT_INFO: libc::siginfo_t = unsafe { std::mem::zeroed() };
/// The program `INJECT_EXEC` executes, which the guest fills in.
static mut SCRIPT_EXEC: ExecArgs = ExecArgs {
    path: std::ptr::null(),
    argv: std::ptr::null(),
    envp: std::ptr::null(),
};
/// Set to 1 by the tool when `INJECT_PARK` parks a callback.
static SCRIPT_PARKED: AtomicU64 = AtomicU64::new(0);
/// The old set `INJECT_BAD_SET` asks for.
static SCRIPT_OLDSET: AtomicU64 = AtomicU64::new(0);
/// The arguments `INJECT_PGETEVENTS` passes, which the guest fills in
/// (`fill_script_pgetevents`).
static mut SCRIPT_PGETEVENTS: PgeteventsArgs = unsafe { std::mem::zeroed() };

/// An AIO context and the buffers an `io_pgetevents` with a temporary
/// signal mask reads and writes.
#[repr(C)]
struct PgeteventsArgs {
    /// The context `io_setup` made.
    context: u64,
    /// The temporary mask.
    mask: u64,
    /// The `struct __aio_sigset`: the mask's address and size.
    sigset: [usize; 2],
    /// A zero timeout, so the call returns at once.
    timeout: libc::timespec,
    /// Room for one `struct io_event`.
    events: [u64; 4],
}

/// Injects nothing.
const INJECT_NONE: u64 = 0;
/// Injects `getpid`.
const INJECT_GETPID: u64 = 1;
/// Injects `rt_sigprocmask(SIG_BLOCK, NULL, NULL, 8)`, which reads the mask
/// and writes nothing.
const INJECT_QUERY: u64 = 2;
/// Injects `rt_sigprocmask(SIG_BLOCK, {SIGUSR1}, NULL, 4)`, which fails
/// with EINVAL before it writes the mask.
const INJECT_BAD_SIZE: u64 = 3;
/// Injects `rt_sigprocmask(SIG_BLOCK, {SIGUSR1}, 8, 8)`, which blocks
/// SIGUSR1 and then fails with EFAULT writing the old set.
const INJECT_BLOCK_BAD_OLDSET: u64 = 4;
/// Injects `rt_sigprocmask(SIG_SETMASK, &SCRIPT_MASK, NULL, 8)`.
const INJECT_SET_MASK: u64 = 5;
/// Injects an `execve` of `SCRIPT_EXEC`.
const INJECT_EXEC: u64 = 6;
/// Injects `getpid`, then an `rt_tgsigqueueinfo` to the thread with
/// `SCRIPT_INFO` for each signal in the action's argument, a mask.
const INJECT_QUEUE: u64 = 7;
/// Injects nothing, sets `SCRIPT_PARKED` in the guest, and never returns.
const INJECT_PARK: u64 = 8;
/// Injects `rt_sigprocmask(SIG_BLOCK, 8, &SCRIPT_OLDSET, 8)`, which fails
/// with EFAULT reading the new set, before it writes the mask or the old
/// set.
const INJECT_BAD_SET: u64 = 9;
/// Injects `io_pgetevents` with `SCRIPT_PGETEVENTS`'s context, no minimum,
/// its zero timeout and its temporary mask. It returns 0 at once, and
/// Linux restores the mask it replaced before it returns.
const INJECT_PGETEVENTS: u64 = 10;
/// Passes the signal through.
const VERDICT_PASS: u64 = 0;
/// Suppresses the signal.
const VERDICT_SUPPRESS: u64 = 1;
/// Delivers the signal in the action's argument instead.
const VERDICT_REPLACE: u64 = 2;

/// A `SCRIPT` entry: `inject` (`INJECT_*`), then `verdict` (`VERDICT_*`),
/// with `arg` for either.
const fn action(inject: u64, verdict: u64, arg: u64) -> u64 {
    inject | verdict << 8 | arg << 32
}

/// Writes `actions` to `SCRIPT`, and empty actions after them.
fn set_script(actions: &[u64]) {
    for (i, entry) in SCRIPT.iter().enumerate() {
        entry.store(actions.get(i).copied().unwrap_or(0), Ordering::Relaxed);
    }
}

/// Fills in `SCRIPT_INFO` as `queue_value_to_self` fills in its siginfo,
/// with `SI_QUEUE`.
///
/// # Safety
/// Writes `SCRIPT_INFO`.
unsafe fn fill_script_info() {
    unsafe {
        let info = &raw mut SCRIPT_INFO;
        (*info).si_code = libc::SI_QUEUE;
        let fields = info.cast::<u8>().add(16);
        fields.cast::<libc::pid_t>().write(libc::getpid());
        fields.add(4).cast::<libc::uid_t>().write(libc::getuid());
        fields.add(8).cast::<usize>().write(QUEUED_VALUE);
    }
}

/// Makes `SCRIPT_PGETEVENTS` a new AIO context with an empty temporary mask
/// and a zero timeout.
///
/// # Safety
/// Writes `SCRIPT_PGETEVENTS`.
unsafe fn fill_script_pgetevents() {
    unsafe {
        let args = &raw mut SCRIPT_PGETEVENTS;
        assert_eq!(
            libc::syscall(libc::SYS_io_setup, 1, &raw mut (*args).context),
            0
        );
        (*args).mask = 0;
        (*args).sigset = [&raw const (*args).mask as usize, 8];
        (*args).timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
    }
}

/// The calling thread's signal mask.
fn current_mask() -> u64 {
    let mut mask = 0u64;
    // SAFETY: rt_sigprocmask with no new set only writes the 8-byte old set.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            0usize,
            &mut mask as *mut u64,
            8usize,
        )
    };
    assert_eq!(ret, 0);
    mask
}

/// Makes the alternate signal stack one the guest cannot write, so Linux
/// cannot build the frame of an `SA_ONSTACK` handler and forces a SIGSEGV.
///
/// # Safety
/// Replaces the calling thread's alternate signal stack.
unsafe fn install_unwritable_altstack() {
    unsafe {
        let size = 1 << 16;
        let stack = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(stack, libc::MAP_FAILED);
        let alternate = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: size,
        };
        assert_eq!(libc::sigaltstack(&alternate, std::ptr::null_mut()), 0);
    }
}

/// Like `ReplaceMarker`, but each signal hook does what its `SCRIPT` entry
/// says, reporting each injection, and RDTSC is intercepted and reported.
#[derive(Clone, Copy, Debug, Default)]
struct ScriptedSignalHook;

#[reverie::tool]
impl Tool for ScriptedSignalHook {
    type GlobalState = Log;
    /// Signal hooks run on this thread so far.
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        #[cfg(target_arch = "x86_64")]
        subscription.rdtsc();
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: reverie::Rdtsc,
    ) -> Result<reverie::RdtscResult, Errno> {
        guest.send_rpc(Report::Rdtsc).await;
        Ok(reverie::RdtscResult::new(request))
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        let index = *guest.thread_state();
        *guest.thread_state_mut() += 1;
        if index >= HOOK_INJECTIONS {
            return Ok(Some(signal));
        }
        let entry = (index as usize).min(SCRIPT.len() - 1);
        let address =
            Addr::<u64>::from_raw(SCRIPT.as_ptr() as usize + entry * 8).ok_or(Errno::EFAULT)?;
        let action: u64 = guest.memory().read_value(address)?;
        let arg = action >> 32;
        let usr1_set = Addr::from_raw(&SIGUSR1_SET as *const u64 as usize);
        let mut results = Vec::new();
        match action & 0xff {
            INJECT_NONE => {}
            INJECT_GETPID => results.push(guest.inject(Getpid::new()).await),
            INJECT_QUERY => results.push(
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_BLOCK)
                            .with_set(None)
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await,
            ),
            INJECT_BAD_SIZE => results.push(
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_BLOCK)
                            .with_set(usr1_set)
                            .with_oldset(None)
                            .with_sigsetsize(4),
                    )
                    .await,
            ),
            INJECT_BLOCK_BAD_OLDSET => results.push(
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_BLOCK)
                            .with_set(usr1_set)
                            .with_oldset(AddrMut::from_raw(8))
                            .with_sigsetsize(8),
                    )
                    .await,
            ),
            INJECT_SET_MASK => results.push(
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_SETMASK)
                            .with_set(Addr::from_raw(SCRIPT_MASK.as_ptr() as usize))
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await,
            ),
            INJECT_EXEC => {
                let base = &raw const SCRIPT_EXEC as usize;
                let mut args = [0usize; 3];
                for (i, offset) in [
                    std::mem::offset_of!(ExecArgs, path),
                    std::mem::offset_of!(ExecArgs, argv),
                    std::mem::offset_of!(ExecArgs, envp),
                ]
                .into_iter()
                .enumerate()
                {
                    let address = Addr::<usize>::from_raw(base + offset).ok_or(Errno::EFAULT)?;
                    args[i] = guest.memory().read_value(address)?;
                }
                let execve = Syscall::from_raw(
                    Sysno::execve,
                    SyscallArgs::new(args[0], args[1], args[2], 0, 0, 0),
                );
                // Returns only if the exec fails.
                results.push(guest.inject(execve).await);
            }
            INJECT_QUEUE => {
                results.push(guest.inject(Getpid::new()).await);
                for queued in 1..32 {
                    if arg & bit(queued) != 0 {
                        results.push(
                            guest
                                .inject(
                                    RtTgsigqueueinfo::new()
                                        .with_tgid(guest.pid().as_raw())
                                        .with_tid(guest.tid().as_raw())
                                        .with_sig(queued)
                                        .with_siginfo(AddrMut::from_raw(
                                            &raw mut SCRIPT_INFO as usize,
                                        )),
                                )
                                .await,
                        );
                    }
                }
            }
            INJECT_BAD_SET => results.push(
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_BLOCK)
                            .with_set(Addr::from_raw(8))
                            .with_oldset(AddrMut::from_raw(SCRIPT_OLDSET.as_ptr() as usize))
                            .with_sigsetsize(8),
                    )
                    .await,
            ),
            INJECT_PGETEVENTS => {
                let base = &raw const SCRIPT_PGETEVENTS as usize;
                let context =
                    Addr::<u64>::from_raw(base + std::mem::offset_of!(PgeteventsArgs, context))
                        .ok_or(Errno::EFAULT)?;
                let context: u64 = guest.memory().read_value(context)?;
                let pgetevents = Syscall::from_raw(
                    Sysno::io_pgetevents,
                    SyscallArgs::new(
                        context as usize,
                        0,
                        1,
                        base + std::mem::offset_of!(PgeteventsArgs, events),
                        base + std::mem::offset_of!(PgeteventsArgs, timeout),
                        base + std::mem::offset_of!(PgeteventsArgs, sigset),
                    ),
                );
                results.push(guest.inject(pgetevents).await);
            }
            INJECT_PARK => {
                let parked = AddrMut::<u64>::from_raw(SCRIPT_PARKED.as_ptr() as usize)
                    .ok_or(Errno::EFAULT)?;
                guest.memory().write_value(parked, &1)?;
                std::future::pending::<()>().await;
            }
            other => panic!("unknown script injection {other}"),
        }
        for result in results {
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(match (action >> 8) & 0xff {
            VERDICT_PASS => Some(signal),
            VERDICT_SUPPRESS => None,
            VERDICT_REPLACE => Some(Signal::try_from(arg as i32).map_err(|_| Errno::EINVAL)?),
            other => panic!("unknown script verdict {other}"),
        })
    }
}

/// Prints the guest's status, stdout, injections and signals, and checks
/// that it exited with 0.
fn check_exited(output: &reverie::process::Output, probe: &str, log: &Log) -> String {
    check_status(output, probe, log, ExitStatus::Exited(0))
}

/// As `check_exited`, but checks that the guest ended with `status`.
fn check_status(
    output: &reverie::process::Output,
    probe: &str,
    log: &Log,
    status: ExitStatus,
) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    eprintln!(
        "PROBE {probe} status={:?} guest={:?} injected={:?} signals={:?} rdtscs={}",
        output.status,
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap(),
        log.rdtscs.load(Ordering::Relaxed)
    );
    assert_eq!(
        output.status,
        status,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// The guest ignores SIGUSR1, queues it blocked, and calls `epoll_pwait`
/// with an empty temporary mask, its `syscall` instruction followed at once
/// by RDTSC, which the Tool intercepts. `epoll_pwait` takes SIGUSR1, which
/// untraced Linux discards. The guest's RDTSC faults: a SIGSEGV that the
/// Tool's RDTSC hook emulates, and the guest goes on with the saved mask
/// restored.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the hook's `getpid` restores the saved mask, which blocks SIGUSR1, so
/// SIGUSR1 is requeued, as in `always_injecting_hook_requeues_an_ignored_signal`,
/// and stays pending, where untraced Linux has discarded it.
#[cfg(target_arch = "x86_64")]
#[test]
fn rdtsc_after_a_requeued_ignored_signal_is_emulated() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[action(INJECT_GETPID, VERDICT_PASS, 0)]);
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let epfd = libc::epoll_create1(0);
        assert!(epfd >= 0);
        let mut events: [libc::epoll_event; 1] = std::mem::zeroed();
        let mask = 0u64;
        let low: u64;
        let high: u64;
        // RDTSC overwrites the syscall's result in rax.
        std::arch::asm!(
            "syscall",
            "rdtsc",
            inout("rax") libc::SYS_epoll_pwait as u64 => low,
            in("rdi") epfd as u64,
            in("rsi") events.as_mut_ptr(),
            inout("rdx") 1u64 => high,
            in("r10") 5000u64,
            in("r8") &mask as *const u64,
            in("r9") 8u64,
            out("rcx") _,
            out("r11") _,
        );
        println!(
            "{} {} {}",
            is_blocked(libc::SIGUSR1),
            is_pending(libc::SIGUSR1),
            (high << 32 | low) != 0
        );
        println!("{}", libc::getpid());
    })
    .expect("run discarded-signal RDTSC guest");
    let stdout = check_exited(&output, "rdtsc-after-discard", &log);
    let (fields, pid) = stdout.trim().rsplit_once('\n').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        fields, "1 1 true",
        "the saved mask is restored, SIGUSR1 is still pending (known gap), and RDTSC returns a counter"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid)]);
    assert_eq!(
        log.rdtscs.load(Ordering::Relaxed),
        1,
        "the Tool emulates the RDTSC"
    );
}

/// As `always_injecting_hook_lets_a_forced_sigsegv_end_the_guest`, with
/// SIGSEGV's default action and only SIGUSR1 blocked outside `ppoll`. The
/// first hook injects `getpid`, and the second injects
/// `rt_sigprocmask(SIG_SETMASK, {SIGUSR2})` and suppresses its signal.
/// Untraced Linux, delivering SIGUSR1 on the unwritable alternate stack,
/// forces a SIGSEGV, at whose stop the second hook runs: `ppoll` returns
/// EINTR with the Tool's mask, and no handler runs.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued, as in `always_injecting_hook_requeues_at_a_delivery_stop`,
/// so no SIGSEGV is forced. `ppoll` returns the hook's `getpid` result with
/// the saved mask, and the second hook runs when the guest unblocks SIGUSR1:
/// it suppresses SIGUSR1, so no handler runs.
#[test]
fn signal_hook_mask_after_a_requeue_is_set_at_the_unblock() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_SET_MASK, VERDICT_SUPPRESS, 0),
        ]);
        SCRIPT_MASK.store(bit(libc::SIGUSR2), Ordering::Relaxed);
        install_unwritable_altstack();
        install_recorder_with(
            libc::SIGUSR1,
            record_siginfo as *const () as usize,
            libc::SA_ONSTACK,
        );
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        println!("{:#x}", current_mask());
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run forced-SIGSEGV mask-setting hook guest");
    let stdout = check_exited(&output, "forced-sigsegv-set-mask", &log);
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    let (mask, fields) = fields.split_once('\n').expect("mask line");
    let fields: Vec<&str> = fields.split(' ').collect();
    assert_eq!(
        (mask, fields[0], &fields[2..]),
        (
            format!("{:#x}", bit(libc::SIGUSR1)).as_str(),
            pid.to_string().as_str(),
            &["0", "0", "0", "0", "1", "1", "0"][..]
        ),
        "the hook's getpid with the saved mask; SIGUSR1 pending until the unblock, then suppressed (known gap)"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "SIGUSR1 is reported at its delivery stop and again after the unblock (known gap)"
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid), Ok(0)]);
}

/// As `signal_hook_mask_after_a_requeue_is_set_at_the_unblock`, with
/// SIGUSR2 blocked outside `ppoll` too and caught by `record_frame_masks`,
/// and the hook of the forced SIGSEGV replaces it with SIGUSR2, injecting
/// nothing. Linux delivers a replacement under the mask the forced SIGSEGV
/// was taken under, `ppoll`'s temporary one, which does not block SIGUSR2,
/// with the siginfo it makes up for a tracer's replacement (`SI_USER`, the
/// tracer's PID, no value). The handler runs once, under that mask plus
/// SIGUSR2, and its frame saves `ppoll`'s saved mask; `ppoll` returns EINTR.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued, so no SIGSEGV is forced and the replacing hook never
/// runs: `ppoll` returns the first hook's `getpid` result, SIGUSR1 stays
/// pending behind the saved mask, and no SIGUSR2 is sent.
#[test]
fn replacement_hook_does_not_run_for_a_requeued_signal() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_NONE, VERDICT_REPLACE, libc::SIGUSR2 as u64),
        ]);
        install_unwritable_altstack();
        install_recorder_with(
            libc::SIGUSR1,
            record_siginfo as *const () as usize,
            libc::SA_ONSTACK,
        );
        install_recorder_with(libc::SIGUSR2, record_frame_masks as *const () as usize, 0);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let tracer = status
            .lines()
            .find_map(|line| line.strip_prefix("TracerPid:"))
            .unwrap()
            .trim()
            .to_owned();
        block(&[libc::SIGUSR1, libc::SIGUSR2]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        println!("{tracer}");
        print_frame_masks();
        print_recorded(ret, errno, libc::SIGUSR2);
    })
    .expect("run forced-SIGSEGV replacing hook guest");
    let stdout = check_exited(&output, "forced-sigsegv-replace", &log);
    let mut lines = stdout.trim().lines();
    let (tracer, masks, recorded) = (
        lines.next().expect("tracer line"),
        lines.next().expect("frame masks line"),
        lines.next().expect("recorded line"),
    );
    assert!(!tracer.is_empty());
    assert_eq!(masks, "0x0 0x0 0x0", "no SIGUSR2 handler runs (known gap)");
    let fields: Vec<&str> = recorded.split(' ').collect();
    let pid: i64 = fields[9].parse().expect("guest pid");
    assert_eq!(
        (fields[0], &fields[2..9]),
        (
            pid.to_string().as_str(),
            &["0", "0", "0", "0", "1", "0", "0"][..]
        ),
        "the hook's getpid; SIGUSR2 is never sent (known gap)"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "SIGUSR1 is reported once and stays pending (known gap)"
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid)]);
}

/// As `replacement_hook_does_not_run_for_a_requeued_signal`, but
/// the hook of the forced SIGSEGV injects `getpid` before it replaces it
/// with SIGUSR2. The reference is a ptrace tracer that makes the same
/// verdicts without injecting: as there, SIGUSR2's handler should run once
/// before `ppoll` returns EINTR.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// as in `replacement_hook_does_not_run_for_a_requeued_signal`, SIGUSR1 is
/// requeued, so no SIGSEGV is forced and the leader's second hook, for that
/// SIGSEGV, never runs; the guest prints its state and exits 0.
#[test]
fn inject_then_replace_hook_does_not_run_for_a_requeued_signal() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_GETPID, VERDICT_REPLACE, libc::SIGUSR2 as u64),
        ]);
        install_unwritable_altstack();
        install_recorder_with(
            libc::SIGUSR1,
            record_siginfo as *const () as usize,
            libc::SA_ONSTACK,
        );
        install_recorder_with(libc::SIGUSR2, record_siginfo as *const () as usize, 0);
        block(&[libc::SIGUSR1, libc::SIGUSR2]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        let runs = RECORDED_CALLS.load(Ordering::Relaxed);
        println!("{runs}");
        print_recorded(ret, errno, libc::SIGUSR2);
    })
    .expect("run forced-SIGSEGV inject-then-replace hook guest");
    let stdout = check_exited(&output, "forced-sigsegv-inject-replace", &log);
    let (runs, recorded) = stdout.trim().split_once('\n').expect("two lines");
    assert_eq!(runs, "0", "no handler runs before ppoll returns");
    let fields: Vec<&str> = recorded.split(' ').collect();
    let pid: i64 = fields[9].parse().expect("guest pid");
    assert_eq!(
        (fields[0], &fields[2..9]),
        (
            pid.to_string().as_str(),
            &["0", "0", "0", "0", "1", "0", "0"][..]
        ),
        "the first hook's getpid; SIGUSR2 is never sent (known gap)"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "SIGUSR1 is reported once and stays pending (known gap)"
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid)]);
}

/// As `signal_hook_mask_after_a_requeue_is_set_at_the_unblock`, but the
/// hook of the forced SIGSEGV executes `cat /proc/self/status`. Linux
/// restores `ppoll`'s saved mask when the stop resumes to run the `execve`,
/// so the new image starts with SIGUSR1 blocked.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued, so no SIGSEGV is forced and the executing hook never
/// runs: `ppoll` returns and the guest exits with 3.
#[test]
fn exec_hook_does_not_run_for_a_requeued_signal() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_EXEC, VERDICT_PASS, 0),
        ]);
        let path = c"/bin/cat";
        let argv = [
            c"cat".as_ptr(),
            c"/proc/self/status".as_ptr(),
            std::ptr::null(),
        ];
        let envp = [std::ptr::null()];
        let exec = &raw mut SCRIPT_EXEC;
        (*exec).path = path.as_ptr();
        (*exec).argv = argv.as_ptr();
        (*exec).envp = envp.as_ptr();
        install_unwritable_altstack();
        install_recorder_with(
            libc::SIGUSR1,
            record_siginfo as *const () as usize,
            libc::SA_ONSTACK,
        );
        block(&[libc::SIGUSR1]);
        use std::io::Write;
        println!("{}", libc::getpid());
        std::io::stdout().flush().unwrap();
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        ppoll_with_empty_mask();
        // Reached only if the hook did not execute the program.
        libc::_exit(3);
    })
    .expect("run forced-SIGSEGV exec hook guest");
    let stdout = check_status(&output, "forced-sigsegv-exec", &log, ExitStatus::Exited(3));
    let pid: i64 = stdout.trim().parse().expect("guest pid");
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "SIGUSR1 is reported once and stays pending (known gap)"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(pid)],
        "only the first hook's getpid runs (known gap)"
    );
}

/// As `always_injecting_hook_requeues_at_a_delivery_stop`, but every hook
/// injects `inject`, an `rt_sigprocmask` that leaves the mask as it was.
/// Untraced Linux runs the handler once and `ppoll` returns EINTR.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued as there, so `ppoll` returns the hook's
/// `rt_sigprocmask` result (`ret`, `errno`), and the signal is reported
/// again, and handled, when the guest unblocks it. The second report's
/// injection result (`result`) is also what the unblock returns. Main leaks
/// the injected result into both (<https://github.com/rrnewton/reverie/issues/892>);
/// a fix flips these pins.
fn signal_hook_mask_call_that_sets_nothing_requeues(
    inject: u64,
    result: Result<i64, i32>,
    ret: &str,
    errno: Option<i32>,
) {
    // Main leaks the second report's injected result into the unblock's;
    // see https://github.com/rrnewton/reverie/issues/892. A fix flips this
    // to 0 where that result is not already 0 (`INJECT_QUERY`'s is).
    let unblocked: libc::c_long = match result {
        Ok(value) => value as libc::c_long,
        Err(_) => -1,
    };
    let (output, log) = test_fn::<ScriptedSignalHook, _>(move || unsafe {
        set_script(&[action(inject, VERDICT_PASS, 0); 4]);
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_recorded_unblocking_to(ret, errno, libc::SIGUSR1, unblocked);
    })
    .expect("run mask-call hook guest");
    check_requeued_known_gap(
        &output,
        &format!("mask-call-{inject}"),
        &log,
        ret,
        errno,
        libc::SI_QUEUE,
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![result, result]);
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1]
    );
}

#[test]
fn signal_hook_querying_the_mask_requeues() {
    signal_hook_mask_call_that_sets_nothing_requeues(INJECT_QUERY, Ok(0), "0", None);
}

#[test]
fn signal_hook_failing_to_set_the_mask_requeues() {
    signal_hook_mask_call_that_sets_nothing_requeues(
        INJECT_BAD_SIZE,
        Err(Errno::EINVAL.into_raw()),
        "-1",
        Some(libc::EINVAL),
    );
}

/// As `signal_hook_blocking_its_signal_at_a_delivery_stop_requeues_it`, but
/// the hook's `rt_sigprocmask` fails with EFAULT writing the old set, after
/// it blocked SIGUSR1. The mask is still the Tool's, so Linux requeues the
/// signal, and the restarted `ppoll` takes it again.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// `ppoll` returns the hook's EFAULT instead of restarting, and the handler
/// runs when the guest unblocks SIGUSR1.
#[test]
fn signal_hook_block_that_faults_after_writing_requeues() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[action(INJECT_BLOCK_BAD_OLDSET, VERDICT_PASS, 0)]);
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run faulting-block hook guest");
    check_requeued_known_gap(
        &output,
        "block-bad-oldset",
        &log,
        "-1",
        Some(libc::EFAULT),
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Err(Errno::EFAULT.into_raw())]
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported when taken, and again after the unblock (known gap)"
    );
}

/// As `signal_hook_block_that_faults_after_writing_requeues`, but every
/// hook injects an `rt_sigprocmask` that fails with EFAULT reading its new
/// set, before it writes anything (`INJECT_BAD_SET`). The injection leaves
/// the mask as it was. Untraced Linux reports SIGUSR1 once, runs its
/// handler once, and `ppoll` returns EINTR.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued as in
/// `always_injecting_hook_requeues_at_a_delivery_stop`: `ppoll` returns the
/// hook's EFAULT, and the signal is reported again, and handled, when the
/// guest unblocks it. The unblock returns -1, the second report's EFAULT.
/// Main leaks the injected result into both
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips these
/// pins.
#[test]
fn signal_hook_block_that_faults_before_writing_requeues() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[action(INJECT_BAD_SET, VERDICT_PASS, 0); 4]);
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        // Main leaks the hook's failed injection into the unblock's result;
        // see https://github.com/rrnewton/reverie/issues/892. A fix flips
        // this to 0.
        print_recorded_unblocking_to(ret, errno, libc::SIGUSR1, -1);
    })
    .expect("run bad-set hook guest");
    check_requeued_known_gap(
        &output,
        "block-bad-set",
        &log,
        "-1",
        Some(libc::EFAULT),
        libc::SI_QUEUE,
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Err(Errno::EFAULT.into_raw()), Err(Errno::EFAULT.into_raw())]
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported at its delivery stop and again after the unblock (known gap)"
    );
}

/// As `signal_hook_block_that_faults_before_writing_requeues`, but every
/// hook injects an `io_pgetevents` with a temporary mask that returns 0 at
/// once (`INJECT_PGETEVENTS`): Linux restores the mask it replaced before
/// the call returns, so the injection leaves the mask as it was, and
/// untraced Linux delivers SIGUSR1 once.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// as there, `ppoll` returns the hook's 0.
#[test]
fn signal_hook_pgetevents_that_restores_its_mask_requeues() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[action(INJECT_PGETEVENTS, VERDICT_PASS, 0); 4]);
        fill_script_pgetevents();
        install_recorder(libc::SIGUSR1);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_recorded(ret, errno, libc::SIGUSR1);
    })
    .expect("run io_pgetevents hook guest");
    check_requeued_known_gap(&output, "pgetevents", &log, "0", None, libc::SI_QUEUE);
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(0), Ok(0)]);
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR1],
        "the signal is reported at its delivery stop and again after the unblock (known gap)"
    );
}

/// The guest ignores SIGUSR1, catches SIGSEGV with a counter, blocks both,
/// queues SIGUSR1, and calls `epoll_pwait` with an empty temporary mask,
/// which returns EINTR without a restart. The instruction after its
/// `syscall` faults. The hook of SIGUSR1 injects `getpid`, whose step lets
/// Linux restore the saved mask, which blocks SIGUSR1, so passing it through
/// requeues it; the hook of SIGSEGV passes SIGSEGV through. On untraced Linux the fault comes after
/// `epoll_pwait`'s saved mask is restored, so SIGSEGV is blocked: Linux
/// resets it to its default action and unblocks it, and it ends the guest
/// after one report. Run under the temporary mask instead, the fault would
/// run the counter, return to the faulting instruction, and fault again.
#[cfg(target_arch = "x86_64")]
#[test]
fn fault_after_a_discarded_signal_runs_under_the_saved_mask() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_NONE, VERDICT_PASS, 0),
        ]);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &no_core), 0);
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        SIGSEGV_HANDLER_CALLS.store(0, Ordering::Relaxed);
        install_counter(libc::SIGSEGV, count_sigsegv);
        block(&[libc::SIGUSR1, libc::SIGSEGV]);
        use std::io::Write;
        println!("{}", libc::getpid());
        std::io::stdout().flush().unwrap();
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let epfd = libc::epoll_create1(0);
        assert!(epfd >= 0);
        let mut events: [libc::epoll_event; 1] = std::mem::zeroed();
        let mask = 0u64;
        // The load from address 8 is the first instruction after the
        // `syscall`.
        std::arch::asm!(
            "syscall",
            "mov {scratch}, qword ptr [{address}]",
            address = in(reg) 8usize,
            scratch = out(reg) _,
            inlateout("rax") libc::SYS_epoll_pwait => _,
            in("rdi") epfd,
            in("rsi") events.as_mut_ptr(),
            in("rdx") 1,
            in("r10") 5000,
            in("r8") &mask as *const u64,
            in("r9") 8,
            out("rcx") _,
            out("r11") _,
        );
        // Reached only if the fault did not end the guest.
        libc::_exit(3);
    })
    .expect("run fault-after-discard guest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE fault-after-discard status={:?} guest={} injected={:?} signals={:?}",
        output.status,
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert!(
        matches!(output.status, ExitStatus::Signaled(Signal::SIGSEGV, _)),
        "the blocked SIGSEGV ends the guest: {:?}",
        output.status
    );
    let pid: i64 = stdout.trim().parse().expect("guest pid");
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid)]);
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGSEGV],
        "SIGSEGV is reported once"
    );
}

/// Loads a seccomp filter that traps `write` to `fd` (`SECCOMP_RET_TRAP`)
/// and allows everything else.
///
/// # Safety
/// Restricts the calling thread's syscalls for the rest of its life.
#[cfg(target_arch = "x86_64")]
unsafe fn trap_write_to(fd: u32) {
    unsafe {
        let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let filter = [
            // seccomp_data.nr is at offset 0, and the low half of args[0]
            // at offset 16.
            statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            statement(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                libc::SYS_write as u32,
                0,
                3,
            ),
            statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 16, 0, 0),
            statement(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, fd, 0, 1),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_TRAP, 0, 0),
            statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog
            ),
            0
        );
    }
}

/// `struct iocb` for an `IOCB_CMD_PREAD`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Iocb {
    data: u64,
    key: u32,
    rw_flags: i32,
    opcode: u16,
    reqprio: i16,
    fd: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved: u64,
    flags: u32,
    resfd: u32,
}

/// The guest ignores SIGUSR1, catches seccomp's SIGSYS with
/// `record_frame_masks`, blocks SIGUSR1, and queues it. It completes a read
/// of `/dev/zero` on an AIO context and calls `io_pgetevents` with an
/// empty temporary mask: the call returns the completion, 1, and with
/// SIGUSR1 pending Linux still owes the restore of the saved mask. The
/// next instruction is a `syscall`, whose number is that 1, `write`, to a
/// descriptor a seccomp filter traps. The hook of SIGUSR1 injects `getpid`,
/// whose step lets Linux restore the saved mask, which blocks SIGUSR1, so
/// passing it through requeues it. On untraced
/// Linux the saved mask is restored before the `write`, and the SIGSYS
/// handler runs under it plus SIGSYS, with the saved mask in its frame.
///
/// Pinned: the hook's getpid result is left in the guest's return register,
/// so the next `syscall`'s number is the guest's pid, not 1: it fails with
/// ENOSYS, the filter never traps, and no SIGSYS handler runs. Main leaks
/// the injected result here (<https://github.com/rrnewton/reverie/issues/892>);
/// a fix flips these pins back to the untraced masks, one handler run and a
/// reported SIGSYS.
#[cfg(target_arch = "x86_64")]
#[test]
fn trapped_syscall_after_a_discarded_signal_runs_under_the_saved_mask() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_NONE, VERDICT_PASS, 0),
        ]);
        let mut context = 0u64;
        assert_eq!(libc::syscall(libc::SYS_io_setup, 1, &mut context), 0);
        let zero = libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY);
        assert!(zero >= 0);
        let mut buffer = [1u8; 8];
        let mut iocb: Iocb = std::mem::zeroed();
        iocb.fd = zero as u32;
        iocb.buf = buffer.as_mut_ptr() as u64;
        iocb.nbytes = buffer.len() as u64;
        let mut iocbs = [&mut iocb as *mut Iocb];
        assert_eq!(
            libc::syscall(libc::SYS_io_submit, context, 1, iocbs.as_mut_ptr()),
            1
        );
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        install_recorder_with(libc::SIGSYS, record_frame_masks as *const () as usize, 0);
        trap_write_to(context as u32);
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let mut events = [0u64; 4];
        let mask = 0u64;
        let sigset = [&mask as *const u64 as usize, 8];
        // The `write` is the first instruction after `io_pgetevents`'s
        // `syscall`, and its number is `io_pgetevents`'s result.
        std::arch::asm!(
            "syscall",
            "syscall",
            inlateout("rax") Sysno::io_pgetevents.id() as i64 => _,
            in("rdi") context,
            in("rsi") 1,
            in("rdx") 1,
            in("r10") events.as_mut_ptr(),
            in("r8") 0,
            in("r9") sigset.as_ptr(),
            out("rcx") _,
            out("r11") _,
        );
        print_frame_masks();
        println!(
            "{} {}",
            RECORDED_CALLS.load(Ordering::Relaxed),
            libc::getpid()
        );
    })
    .expect("run trapped-syscall-after-discard guest");
    let (masks, output) = split_frame_masks(output);
    let stdout = check_exited(&output, "trapped-syscall-after-discard", &log);
    let (calls, pid) = stdout.trim().split_once(' ').expect("calls and pid");
    let pid: i64 = pid.parse().expect("guest pid");
    // Main leaks the hook's getpid into the next syscall's number; see
    // https://github.com/rrnewton/reverie/issues/892. A fix flips these pins:
    // masks `{saved|SIGSYS} {saved} {saved}` with saved = SIGUSR1's bit, one
    // handler run, and signals [SIGUSR1, SIGSYS].
    assert_eq!(
        masks, "0x0 0x0 0x0",
        "no SIGSYS handler runs: the write's number is the leaked pid (known leak)"
    );
    assert_eq!(calls, "0", "no SIGSYS handler runs (known leak)");
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid)]);
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "only SIGUSR1 is reported; no SIGSYS is raised (known leak)"
    );
}

/// The guest ignores SIGUSR1, catches `signal` with `record_frame_masks`,
/// blocks both, queues SIGUSR1, and calls `ppoll` with an empty temporary
/// mask. The hook of SIGUSR1 injects `getpid` and queues `signal` with
/// `QUEUED_VALUE`, which the restored saved mask blocks. Linux discards
/// SIGUSR1 under `ppoll`'s temporary mask and takes `signal` under it too:
/// the handler runs once with the queued siginfo, under the temporary mask
/// plus `signal`, its frame saves `ppoll`'s saved mask, and `ppoll`
/// returns EINTR. `signal` is reported once. SIGSTKFLT is the number of
/// Reverie's timer signal; this one is the guest's.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// `ppoll` returns the hook's last injection's 0, as main does, and `signal`
/// stays pending until the guest unblocks it, so its handler runs then,
/// after the guest has printed the masks, which are therefore empty.
fn check_signal_queued_by_a_hook_after_a_discard(signal: libc::c_int) {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(move || unsafe {
        set_script(&[action(INJECT_QUEUE, VERDICT_PASS, bit(signal))]);
        fill_script_info();
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        install_recorder_with(signal, record_frame_masks as *const () as usize, 0);
        block(&[libc::SIGUSR1, signal]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let ret = ppoll_with_empty_mask();
        let errno = *libc::__errno_location();
        print_frame_masks();
        print_recorded(ret, errno, signal);
    })
    .expect("run discard-then-queued hook guest");
    let (masks, output) = split_frame_masks(output);
    let pid = check_requeued_known_gap(
        &output,
        &format!("discard-then-queued-{signal}"),
        &log,
        "0",
        None,
        libc::SI_QUEUE,
    );
    assert_eq!(
        masks, "0x0 0x0 0x0",
        "no handler has run when the guest prints the masks, before the unblock (known gap)"
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid), Ok(0)]);
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1, signal]);
}

#[test]
fn signal_queued_by_a_hook_after_a_discard_waits_for_the_unblock() {
    check_signal_queued_by_a_hook_after_a_discard(libc::SIGUSR2);
}

#[test]
fn timer_numbered_signal_queued_by_a_hook_after_a_discard_waits_for_the_unblock() {
    check_signal_queued_by_a_hook_after_a_discard(libc::SIGSTKFLT);
}

/// The program `parked_hook_does_not_run_for_a_requeued_signal`
/// executes. Its first write is a Tool injection; it then prints whether
/// SIGUSR1 and SIGUSR2 are blocked, and the PID.
const PRINT_USR_MASK_PY: &std::ffi::CStr = c"import os, signal
os.write(2, b'')
mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
print(int(signal.SIGUSR1 in mask), int(signal.SIGUSR2 in mask), os.getpid())
";

/// As in `exec_hook_does_not_run_for_a_requeued_signal`, the leader takes
/// SIGUSR1 in `ppoll` and its callback injects `getpid`; on untraced Linux
/// the delivery forces a SIGSEGV. That SIGSEGV's callback parks without
/// injecting, and a worker that blocks only SIGUSR2 executes another
/// program, which ends the leader and its callback. As on untraced Linux,
/// the new program should start with the worker's mask.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// SIGUSR1 is requeued, so no SIGSEGV is forced and the parking callback
/// never runs: `ppoll` returns, and the leader exits with 4 before the
/// worker executes anything.
#[test]
fn parked_hook_does_not_run_for_a_requeued_signal() {
    extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: plain libc calls on this thread's signal state and on
        // buffers that outlive each call.
        unsafe {
            let mut usr2: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut usr2);
            libc::sigaddset(&mut usr2, libc::SIGUSR2);
            libc::pthread_sigmask(libc::SIG_SETMASK, &usr2, std::ptr::null_mut());
            // The clock is read with the syscall: the vDSO's RDTSC would trap
            // to the Tool, and a trap racing the leader's exit can reach the
            // signal hook as a SIGSEGV of this worker.
            let monotonic_secs = || {
                let mut now: libc::timespec = std::mem::zeroed();
                libc::syscall(
                    libc::SYS_clock_gettime,
                    libc::CLOCK_MONOTONIC,
                    &mut now as *mut libc::timespec,
                );
                now.tv_sec
            };
            let start = monotonic_secs();
            while SCRIPT_PARKED.load(Ordering::Acquire) == 0 {
                if monotonic_secs() - start > 30 {
                    libc::_exit(5);
                }
                libc::sched_yield();
            }
            let path = c"/usr/bin/python3";
            let argv = [
                c"python3".as_ptr(),
                c"-c".as_ptr(),
                PRINT_USR_MASK_PY.as_ptr(),
                std::ptr::null(),
            ];
            let envp = [std::ptr::null()];
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(3);
        }
    }
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(INJECT_GETPID, VERDICT_PASS, 0),
            action(INJECT_PARK, VERDICT_PASS, 0),
        ]);
        SCRIPT_PARKED.store(0, Ordering::Relaxed);
        install_unwritable_altstack();
        install_recorder_with(
            libc::SIGUSR1,
            record_siginfo as *const () as usize,
            libc::SA_ONSTACK,
        );
        let mut thread: libc::pthread_t = 0;
        assert_eq!(
            libc::pthread_create(&mut thread, std::ptr::null(), worker, std::ptr::null_mut()),
            0
        );
        block(&[libc::SIGUSR1]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        ppoll_with_empty_mask();
        // Reached only if the worker did not execute the program.
        libc::_exit(4);
    })
    .expect("run parked-callback sibling-exec guest");
    let stdout = check_status(&output, "parked-sibling-exec", &log, ExitStatus::Exited(4));
    assert_eq!(stdout, "", "no program runs (known gap)");
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "SIGUSR1 is reported once and stays pending (known gap)"
    );
    let injected = log.injected.lock().unwrap();
    assert!(
        matches!(injected[..], [Ok(pid)] if pid > 0),
        "only the first hook's getpid runs (known gap): {injected:?}"
    );
    assert_eq!(
        log.rdtscs.load(Ordering::Relaxed),
        0,
        "the worker reads no TSC, so it takes no RDTSC trap"
    );
}

/// As `check_signal_queued_by_a_hook_after_a_discard` with SIGSTKFLT, but the hook also queues SIGWINCH, caught by
/// `record_siginfo`, the guest waits in `epoll_pwait`, which returns EINTR
/// without a restart, and the hook of SIGSTKFLT suppresses it. On untraced
/// Linux's equivalent, Linux goes on under `epoll_pwait`'s temporary mask
/// and takes SIGWINCH: its handler runs once before `epoll_pwait` returns.
///
/// Known gap pinned here (https://github.com/rrnewton/reverie/issues/845):
/// the first hook's injections restore the saved mask, which blocks
/// SIGUSR1, so SIGUSR1 is requeued, and SIGSTKFLT and SIGWINCH stay
/// pending behind the saved mask. SIGWINCH is reported when the guest
/// unblocks it, and the second hook suppresses it, so its handler never
/// runs. SIGSTKFLT is never reported.
///
/// Also pinned: `epoll_pwait` returns 0, the first hook's last injection's
/// result, instead of EINTR. Main leaks the injected result here
/// (<https://github.com/rrnewton/reverie/issues/892>); a fix flips this pin
/// to `-1 EINTR`.
#[cfg(target_arch = "x86_64")]
#[test]
fn signal_pending_behind_a_requeued_signal_waits_for_the_unblock() {
    let (output, log) = test_fn::<ScriptedSignalHook, _>(|| unsafe {
        set_script(&[
            action(
                INJECT_QUEUE,
                VERDICT_PASS,
                bit(libc::SIGSTKFLT) | bit(libc::SIGWINCH),
            ),
            action(INJECT_NONE, VERDICT_SUPPRESS, 0),
        ]);
        fill_script_info();
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        install_recorder(libc::SIGWINCH);
        block(&[libc::SIGUSR1, libc::SIGSTKFLT, libc::SIGWINCH]);
        queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
        let epfd = libc::epoll_create1(0);
        assert!(epfd >= 0);
        let mut events: [libc::epoll_event; 1] = std::mem::zeroed();
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        // A successful return leaves errno alone, so clear any earlier value.
        *libc::__errno_location() = 0;
        let ret = libc::epoll_pwait(epfd, events.as_mut_ptr(), 1, 5000, &mask);
        let errno = *libc::__errno_location();
        print_recorded(ret as libc::c_long, errno, libc::SIGWINCH);
    })
    .expect("run suppressed-signal guest");
    let stdout = check_exited(&output, "suppressed-signal", &log);
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    // Main leaks the hook's last injected result into epoll_pwait's; see
    // https://github.com/rrnewton/reverie/issues/892. A fix flips this pin
    // to format!("-1 {} 0 0 0 0 1 1 0", libc::EINTR).
    assert_eq!(
        fields, "0 0 0 0 0 0 1 1 0",
        "epoll_pwait returns the leaked 0 (known leak); SIGWINCH blocked and pending, then suppressed at the unblock (known gap)"
    );
    assert_eq!(*log.injected.lock().unwrap(), vec![Ok(pid), Ok(0), Ok(0)]);
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGWINCH],
        "SIGSTKFLT is never reported; SIGWINCH is reported at the unblock (known gap)"
    );
}

/// Runs `f` under `T` like `test_fn`, on its own thread, and fails if the
/// guest has not finished within 60 seconds instead of waiting forever.
fn test_fn_bounded<T, F>(f: F, what: &str) -> (reverie::process::Output, Log)
where
    T: Tool<GlobalState = Log> + 'static,
    F: FnOnce() + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // A closed receiver means the test already timed out and failed.
        let _ = tx.send(test_fn::<T, _>(f).map_err(|error| error.to_string()));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => panic!("{what}: {error}"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what}: the guest did not finish within 60 seconds")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{what}: the tracer thread panicked")
        }
    }
}

/// Like `ReplaceMarker`, but the signal hook of SIGUSR1 ends with
/// `tail_inject(getpid)`; other signals pass through.
#[derive(Clone, Copy, Debug, Default)]
struct TailInjectInSigusr1Hook;

#[reverie::tool]
impl Tool for TailInjectInSigusr1Hook {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        match signal {
            Signal::SIGUSR1 => guest.tail_inject(Getpid::new()).await,
            _ => Ok(Some(signal)),
        }
    }
}

/// The guest of `signal_pending_before_injected_syscall_interrupts_it`,
/// whose held SIGUSR1 is reported to a hook that ends with `tail_inject`.
/// The tail injection ends the callback, as it does a syscall hook, and the
/// held signal is delivered as the hook did not decide otherwise: the guest
/// sees what it sees on main, where the hook is not called, EINTR and one
/// handler run. (The same hook on an ordinarily delivered signal still
/// parks the guest:
/// https://github.com/rrnewton/reverie/issues/862.)
#[test]
fn held_signal_hook_ending_with_a_tail_injection_delivers_the_signal() {
    let (output, log) = test_fn_bounded::<TailInjectInSigusr1Hook, _>(
        || unsafe {
            SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGUSR1, count_sigusr1);
            let set = block(&[libc::SIGUSR1]);
            assert_eq!(
                libc::syscall(
                    libc::SYS_tgkill,
                    libc::getpid(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGUSR1
                ),
                0
            );
            let ret = libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            let errno = *libc::__errno_location();
            println!(
                "{ret} {errno} {}",
                SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed)
            );
        },
        "held signal, tail-injecting hook",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE held-tail guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; the signal interrupts getpid before it runs"
    );
    assert_eq!(
        stdout.trim(),
        format!("-1 {} 1", libc::EINTR),
        "guest sees EINTR and one handler run"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
}

static SECOND_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_second(_signal: libc::c_int) {
    SECOND_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Like `ReplaceMarker`, but the signal hook of SIGUSR1 injects a `getpid`,
/// reported, before passing it through.
#[derive(Clone, Copy, Debug, Default)]
struct InjectInSigusr1Hook;

#[reverie::tool]
impl Tool for InjectInSigusr1Hook {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal == Signal::SIGUSR1 {
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// SIGUSR1 and `second` are both pending when the injected unblock lets
/// them through; SIGUSR1, the lower number, stops the following `getpid`
/// and is held. A hook of the held SIGUSR1 that injects would have its own
/// step take `second` into the held slot, which nothing flushes before this
/// guest exits without another subscribed syscall. So a held signal is
/// passed unreported while another is pending, as on main: both handlers
/// run before the marker returns, and the Tool sees only `second`, at its
/// own delivery stop.
///
/// Known gap: the Tool never sees the held SIGUSR1, the
/// https://github.com/rrnewton/hermit/issues/3468 defect on this input
/// (https://github.com/rrnewton/reverie/issues/845).
fn check_held_signal_with_another_pending(second: libc::c_int) {
    let (output, log) = test_fn_bounded::<InjectInSigusr1Hook, _>(
        move || unsafe {
            SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
            SECOND_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGUSR1, count_sigusr1);
            install_counter(second, count_second);
            let set = block(&[libc::SIGUSR1, second]);
            for signal in [libc::SIGUSR1, second] {
                assert_eq!(
                    libc::syscall(
                        libc::SYS_tgkill,
                        libc::getpid(),
                        libc::syscall(libc::SYS_gettid),
                        signal
                    ),
                    0
                );
            }
            libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            let calls = SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed) * 10
                + SECOND_HANDLER_CALLS.load(Ordering::Relaxed);
            // No later subscribed syscall: a signal left in the held slot
            // would never be delivered.
            libc::_exit(calls as libc::c_int);
        },
        "two pending signals",
    );
    eprintln!(
        "PROBE held-two-pending second={second} status={:?} injected={:?} signals={:?}",
        output.status,
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(11),
        "each handler runs once; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes; SIGUSR1 interrupts getpid before it runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![second],
        "the held SIGUSR1 passes unreported, as on main; the other signal is reported at its delivery stop"
    );
}

#[test]
fn held_signal_is_not_reported_while_another_signal_is_pending() {
    check_held_signal_with_another_pending(libc::SIGUSR2);
}

/// The other pending signal is the guest's own SIGSTKFLT, the number of
/// Reverie's timer signal, which no timer sent.
#[test]
fn held_signal_is_not_reported_while_a_guest_timer_number_signal_is_pending() {
    check_held_signal_with_another_pending(libc::SIGSTKFLT);
}

/// The first hook of an unblocked SI_QUEUE SIGUSR1 blocks it with an
/// injected `rt_sigprocmask` and passes it through, so Linux requeues it
/// (`signal_hook_blocking_its_signal_keeps_it_pending`). The guest's marker
/// then unblocks it with an injection, and the same queued instance stops
/// the following `getpid` and is held. Its Tool has already seen it, so it
/// is delivered without a second report. The counts are as on main: the
/// Tool sees SIGUSR1 once and the handler runs once. The siginfo is not: the
/// handler now sees the queued `SI_QUEUE`, the guest's PID and the value 77,
/// where main gave it `SI_USER`, the tracer's PID and the value 0.
#[test]
fn requeued_signal_recaptured_by_an_injection_is_not_reported_again() {
    let (output, log) = test_fn_bounded::<BlockInFirstSignalHook, _>(
        || unsafe {
            install_recorder(libc::SIGUSR1);
            queue_value_to_self(libc::SIGUSR1, libc::SI_QUEUE);
            let ret = libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &SIGUSR1_SET as *const u64,
                0usize,
            );
            let errno = *libc::__errno_location();
            print_recorded(ret, errno, libc::SIGUSR1);
        },
        "requeued then held signal",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE requeued-then-held guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (fields, pid) = stdout.trim().rsplit_once(' ').expect("guest pid");
    let pid: i64 = pid.parse().expect("guest pid");
    assert_eq!(
        fields,
        format!(
            "-1 {} 1 {} {pid} {QUEUED_VALUE} 0 0 1",
            libc::EINTR,
            libc::SI_QUEUE
        ),
        "EINTR and one handler run with the queued siginfo; not blocked or pending after it"
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the hook's block, the marker's unblock, and the getpid the signal interrupts"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "the one queued instance is reported once"
    );
}

/// Like `InjectInSigusr1Hook`, but the signal hook of SIGUSR1 first queues
/// SIGUSR2 to the guest's thread from the tracer, with `SI_QUEUE`, the
/// guest's PID and `QUEUED_VALUE`, as a signal that arrives while the hook
/// runs.
#[derive(Clone, Copy, Debug, Default)]
struct QueueSigusr2InSigusr1Hook;

#[reverie::tool]
impl Tool for QueueSigusr2InSigusr1Hook {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal == Signal::SIGUSR1 {
            // SAFETY: a zeroed siginfo is valid; the fields written open its
            // union after the three ints, as in `queue_value_to_self`.
            let queued = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                info.si_signo = libc::SIGUSR2;
                info.si_code = libc::SI_QUEUE;
                let fields = (&mut info as *mut libc::siginfo_t).cast::<u8>().add(16);
                fields.cast::<libc::pid_t>().write(guest.pid().as_raw());
                fields.add(8).cast::<usize>().write(QUEUED_VALUE);
                libc::syscall(
                    libc::SYS_rt_tgsigqueueinfo,
                    guest.pid().as_raw(),
                    guest.tid().as_raw(),
                    libc::SIGUSR2,
                    &mut info as *mut libc::siginfo_t,
                )
            };
            assert_eq!(queued, 0, "queue SIGUSR2 to the guest");
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// A held SIGUSR1, as in `held_signal_hook_ending_with_a_tail_injection_delivers_the_signal`,
/// is reported to a hook during which SIGUSR2 arrives: it stops the hook's
/// `getpid` before the `syscall`. Held there, it would wait in the single
/// held slot, which the SIGUSR1 resume does not empty, for a subscribed
/// syscall this guest never makes. It is put back in the kernel's queue
/// with its siginfo instead: the `getpid` runs, both handlers run, the
/// SIGUSR2 handler sees the queued siginfo, and the Tool sees SIGUSR2 at its
/// own delivery stop. (On main the hook is not called, so no SIGUSR2 is
/// sent.)
#[test]
fn signal_arriving_during_a_held_signal_hook_is_delivered() {
    let (output, log) = test_fn_bounded::<QueueSigusr2InSigusr1Hook, _>(
        || unsafe {
            SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGUSR1, count_sigusr1);
            install_recorder(libc::SIGUSR2);
            let set = block(&[libc::SIGUSR1]);
            assert_eq!(
                libc::syscall(
                    libc::SYS_tgkill,
                    libc::getpid(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGUSR1
                ),
                0
            );
            libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            let queued = RECORDED_CODE.load(Ordering::Relaxed) == libc::SI_QUEUE
                && RECORDED_PID.load(Ordering::Relaxed) == libc::getpid()
                && RECORDED_VALUE.load(Ordering::Relaxed) == QUEUED_VALUE;
            let status = SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed) * 100
                + RECORDED_CALLS.load(Ordering::Relaxed) * 10
                + queued as usize;
            // No later subscribed syscall: a signal left in the held slot
            // would never be delivered.
            libc::_exit(status as libc::c_int);
        },
        "signal arriving during a held signal's hook",
    );
    let injected = log.injected.lock().unwrap();
    eprintln!(
        "PROBE held-hook-arrival status={:?} injected={:?} signals={:?}",
        output.status,
        *injected,
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(111),
        "each handler runs once, SIGUSR2's with the queued siginfo; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        matches!(
            injected[..],
            [Ok(0), Err(e), Ok(pid)] if e == Errno::ERESTARTSYS.into_raw() && pid > 0
        ),
        "the unblock completes, SIGUSR1 interrupts the marker's getpid, and the hook's getpid runs: {injected:?}"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1, libc::SIGUSR2],
        "the held SIGUSR1 is reported, then SIGUSR2 at its own delivery stop"
    );
}

/// Like `InjectInSigusr1Hook`, but the marker hook of `UNBLOCK_THEN_GETPID_FD`
/// then sends SIGTRAP to the guest's thread from the tracer, a guest trap
/// pending when the held signal would be reported.
#[derive(Clone, Copy, Debug, Default)]
struct TrapAfterUnblockThenGetpid;

#[reverie::tool]
impl Tool for TrapAfterUnblockThenGetpid {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let trap = matches!(
            syscall,
            Syscall::Write(write) if write.fd() == UNBLOCK_THEN_GETPID_FD && write.len() == 0
        );
        let result = replace_marker(guest, syscall).await;
        if trap {
            // SAFETY: tgkill has no memory-safety preconditions.
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    guest.pid().as_raw(),
                    guest.tid().as_raw(),
                    libc::SIGTRAP,
                )
            };
            assert_eq!(sent, 0, "send SIGTRAP to the guest");
        }
        result
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal == Signal::SIGUSR1 {
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// A held SIGUSR1 with a guest SIGTRAP pending, not the step SIGTRAP of the
/// injection that held it (`stale_private_step_trap`). Reported, its hook's
/// `getpid` would stop at that SIGTRAP before the `syscall`, which the
/// injection discards before it steps the `syscall` again
/// (`untraced_syscall_with`), consuming the guest's trap. So the held signal is passed
/// on unreported, as while any other signal is pending
/// (`check_held_signal_with_another_pending`), and as on main: the hook's
/// `getpid` never runs, and the SIGUSR1 handler runs once. Without the trap
/// configuration nothing claims the SIGTRAP, so the main loop suppresses it
/// (`handle_sigtrap`), as on main, and the Tool sees no signal. Known gap:
/// the held SIGUSR1 is not reported
/// (https://github.com/rrnewton/reverie/issues/845).
#[test]
fn held_signal_is_not_reported_while_a_guest_sigtrap_is_pending() {
    let (output, log) = test_fn_bounded::<TrapAfterUnblockThenGetpid, _>(
        || unsafe {
            SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGUSR1, count_sigusr1);
            let set = block(&[libc::SIGUSR1]);
            assert_eq!(
                libc::syscall(
                    libc::SYS_tgkill,
                    libc::getpid(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGUSR1
                ),
                0
            );
            libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            libc::_exit(SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed) as libc::c_int);
        },
        "held signal with a guest SIGTRAP pending",
    );
    eprintln!(
        "PROBE held-pending-trap status={:?} injected={:?} signals={:?}",
        output.status,
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(1),
        "the SIGUSR1 handler runs once; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes, SIGUSR1 interrupts getpid, and no hook injection runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        Vec::<i32>::new(),
        "the held SIGUSR1 passes unreported, and the unclaimed SIGTRAP is suppressed"
    );
}

/// Nonzero when `RestartBlockInFirstSignalHook` suppresses the signal. Its
/// hook reads it from the guest's memory, at the same address there.
static RESTART_BLOCK_SUPPRESS: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` ends its hook with a
/// successful `RESTART_BLOCK_FINAL_SLEEP`. Read like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_FINAL: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` injects `restart_syscall`
/// in place of its 5-second sleep. Read like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_RESUME: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` writes zero to the guest's
/// return register with `Guest::set_regs` after its last injection. Read
/// like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_ZERO_RAX: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` writes the guest's
/// registers back unchanged with `Guest::set_regs` before its final sleep.
/// Read like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_REWRITE: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` writes the guest's
/// registers back unchanged with `Guest::set_regs` after its final sleep.
/// Read like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_REWRITE_LAST: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` writes
/// `RESTART_BLOCK_EARLY_RET` to the guest's return register with
/// `Guest::set_regs` before its first injection. Read like
/// `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_EARLY_RAX: AtomicU64 = AtomicU64::new(0);
/// What `RESTART_BLOCK_EARLY_RAX` writes.
const RESTART_BLOCK_EARLY_RET: u64 = 123;
/// Nonzero when `RestartBlockInFirstSignalHook` saves the guest's
/// registers after its timer injection, before its sleep, and writes them
/// back with `Guest::set_regs` after its final sleep. Read like
/// `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_CACHED: AtomicU64 = AtomicU64::new(0);
/// The signal number `RestartBlockInFirstSignalHook` resumes with in place
/// of SIGALRM, when nonzero; it then neither suppresses nor passes SIGALRM.
/// Read like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_VERDICT: AtomicU64 = AtomicU64::new(0);
/// Nonzero when `RestartBlockInFirstSignalHook` overwrites the guest's
/// `nanosleep` request, at the address in its first argument register, with
/// `RESTART_BLOCK_INVALID_SLEEP` after its last injection: a restart of the
/// guest's sleep with its original arguments then fails with EINVAL. Read
/// like `RESTART_BLOCK_SUPPRESS`.
static RESTART_BLOCK_POISON: AtomicU64 = AtomicU64::new(0);
/// What `RESTART_BLOCK_POISON` writes: a nanosecond count `nanosleep`
/// rejects.
const RESTART_BLOCK_INVALID_SLEEP: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 1_000_000_000,
};
/// The sleep `RestartBlockInFirstSignalHook` injects last when
/// `RESTART_BLOCK_FINAL` is set: 350 ms, which no signal interrupts.
static RESTART_BLOCK_FINAL_SLEEP: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 350_000_000,
};
/// The one-shot `ITIMER_REAL` timer `RestartBlockInFirstSignalHook` arms.
static RESTART_BLOCK_TIMER: libc::itimerval = libc::itimerval {
    it_interval: libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
    it_value: libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    },
};
/// The sleep `RestartBlockInFirstSignalHook` injects.
static RESTART_BLOCK_SLEEP: libc::timespec = libc::timespec {
    tv_sec: 5,
    tv_nsec: 0,
};
/// How many times `RestartBlockInFirstSignalHook` tries its `getpid`.
const RESTART_BLOCK_GETPID_TRIES: usize = 3;

/// Like `ReplaceMarker`, but the first signal hook of SIGALRM on each
/// thread writes `RESTART_BLOCK_EARLY_RET` to the guest's return register
/// when `RESTART_BLOCK_EARLY_RAX` is set, arms a 200 ms `ITIMER_REAL`
/// timer, injects a 5-second `nanosleep` the timer's SIGALRM interrupts,
/// which replaces the thread's restart block, or instead `restart_syscall`
/// when `RESTART_BLOCK_RESUME` is set in the guest, which resumes the
/// guest's sleep through that block until the SIGALRM interrupts it, then
/// injects `getpid` until it succeeds, and then `RESTART_BLOCK_FINAL_SLEEP`
/// when `RESTART_BLOCK_FINAL` is set in the guest, first writing the
/// guest's registers back unchanged when `RESTART_BLOCK_REWRITE` is set,
/// and after it when `RESTART_BLOCK_REWRITE_LAST` is set, or the registers
/// it saved after its timer injection when `RESTART_BLOCK_CACHED` is set;
/// each injection is reported. It then writes zero to the guest's return register when
/// `RESTART_BLOCK_ZERO_RAX` is set, and overwrites the guest's sleep
/// request when `RESTART_BLOCK_POISON` is set. It resumes with the signal
/// `RESTART_BLOCK_VERDICT` names when that is set, else suppresses the
/// signal when `RESTART_BLOCK_SUPPRESS` is set in the guest and passes it
/// through otherwise.
#[derive(Clone, Copy, Debug, Default)]
struct RestartBlockInFirstSignalHook;

#[reverie::tool]
impl Tool for RestartBlockInFirstSignalHook {
    type GlobalState = Log;
    /// Whether the hook of SIGALRM has run on this thread.
    type ThreadState = bool;

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal != Signal::SIGALRM || std::mem::replace(guest.thread_state_mut(), true) {
            return Ok(Some(signal));
        }
        let flag = |flag: &AtomicU64| {
            Addr::<u64>::from_raw(flag as *const AtomicU64 as usize).ok_or(Errno::EFAULT)
        };
        if guest.memory().read_value(flag(&RESTART_BLOCK_EARLY_RAX)?)? != 0 {
            let mut regs = guest.regs().await;
            regs.rax = RESTART_BLOCK_EARLY_RET;
            guest
                .set_regs(regs)
                .await
                .expect("write the guest's registers");
        }
        let timer = Syscall::from_raw(
            Sysno::setitimer,
            SyscallArgs::new(
                libc::ITIMER_REAL as usize,
                &RESTART_BLOCK_TIMER as *const libc::itimerval as usize,
                0,
                0,
                0,
                0,
            ),
        );
        let sleep = if guest.memory().read_value(flag(&RESTART_BLOCK_RESUME)?)? != 0 {
            Syscall::from_raw(Sysno::restart_syscall, SyscallArgs::new(0, 0, 0, 0, 0, 0))
        } else {
            Syscall::from_raw(
                Sysno::nanosleep,
                SyscallArgs::new(
                    &RESTART_BLOCK_SLEEP as *const libc::timespec as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                ),
            )
        };
        let cache = guest.memory().read_value(flag(&RESTART_BLOCK_CACHED)?)? != 0;
        let mut cached = None;
        for syscall in [timer, sleep] {
            let result = guest.inject(syscall).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            if cache && cached.is_none() {
                cached = Some(guest.regs().await);
            }
        }
        // The timer's SIGALRM, pending after the sleep's step, stops the
        // first `getpid` before it runs.
        for _ in 0..RESTART_BLOCK_GETPID_TRIES {
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            if result.is_ok() {
                break;
            }
        }
        if guest.memory().read_value(flag(&RESTART_BLOCK_REWRITE)?)? != 0 {
            let regs = guest.regs().await;
            guest
                .set_regs(regs)
                .await
                .expect("write the guest's registers");
        }
        if guest.memory().read_value(flag(&RESTART_BLOCK_FINAL)?)? != 0 {
            let sleep = Syscall::from_raw(
                Sysno::nanosleep,
                SyscallArgs::new(
                    &RESTART_BLOCK_FINAL_SLEEP as *const libc::timespec as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                ),
            );
            let result = guest.inject(sleep).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        if let Some(regs) = cached {
            guest
                .set_regs(regs)
                .await
                .expect("write the guest's registers");
        }
        if guest
            .memory()
            .read_value(flag(&RESTART_BLOCK_REWRITE_LAST)?)?
            != 0
        {
            let regs = guest.regs().await;
            guest
                .set_regs(regs)
                .await
                .expect("write the guest's registers");
        }
        if guest.memory().read_value(flag(&RESTART_BLOCK_ZERO_RAX)?)? != 0 {
            let mut regs = guest.regs().await;
            regs.rax = 0;
            guest
                .set_regs(regs)
                .await
                .expect("write the guest's registers");
        }
        if guest.memory().read_value(flag(&RESTART_BLOCK_POISON)?)? != 0 {
            let request = AddrMut::<libc::timespec>::from_raw(guest.regs().await.rdi as usize)
                .ok_or(Errno::EFAULT)?;
            guest
                .memory()
                .write_value(request, &RESTART_BLOCK_INVALID_SLEEP)?;
        }
        let verdict = guest.memory().read_value(flag(&RESTART_BLOCK_VERDICT)?)?;
        if verdict != 0 {
            Ok(Some(
                Signal::try_from(verdict as i32).map_err(|_| Errno::EINVAL)?,
            ))
        } else if guest.memory().read_value(flag(&RESTART_BLOCK_SUPPRESS)?)? != 0 {
            Ok(None)
        } else {
            Ok(Some(signal))
        }
    }
}

/// How `RestartBlockInFirstSignalHook` ends its hook in
/// `check_restart_block_replaced_by_a_hook_injection`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum RestartBlockEnd {
    /// The hook passes SIGALRM through.
    Deliver,
    /// The hook suppresses SIGALRM after its `getpid`.
    Suppress,
    /// The hook injects `RESTART_BLOCK_FINAL_SLEEP` after its `getpid` and
    /// suppresses SIGALRM; the guest sleeps 300 ms instead of 3 seconds.
    SuppressAfterSleep,
    /// The hook injects `restart_syscall` in place of its 5-second sleep,
    /// which resumes the guest's 600 ms sleep until the hook's SIGALRM
    /// interrupts it, and suppresses SIGALRM; the guest gets the `getpid`'s
    /// PID (https://github.com/rrnewton/reverie/issues/892).
    SuppressAfterResume,
    /// The hook writes zero to the guest's return register after its
    /// `getpid` and suppresses SIGALRM.
    SuppressAfterZeroingRax,
    /// As `SuppressAfterSleep`, but the hook first writes the guest's
    /// registers back unchanged with `Guest::set_regs`.
    SuppressAfterRewriteAndSleep,
    /// As `SuppressAfterSleep`, but the hook writes the guest's registers
    /// back unchanged with `Guest::set_regs` after its final sleep.
    SuppressAfterSleepAndRewrite,
    /// As `SuppressAfterSleep`, but the hook writes
    /// `RESTART_BLOCK_EARLY_RET` to the guest's return register with
    /// `Guest::set_regs` before its first injection.
    SuppressAfterEarlyWriteAndSleep,
    /// As `SuppressAfterSleep`, but the hook saves the guest's registers
    /// after its timer injection and writes them back with
    /// `Guest::set_regs` after its final sleep.
    SuppressAfterSleepAndCachedWrite,
    /// As `SuppressAfterSleep`, but the hook resumes with SIGURG, which the
    /// guest ignores by default, in place of suppressing SIGALRM.
    IgnoredAfterSleep,
    /// As `SuppressAfterSleep`, but the hook resumes with SIGUSR2, which the
    /// guest catches and blocks, in place of suppressing SIGALRM.
    BlockedAfterSleep,
}

/// SIGALRM interrupts the guest's `nanosleep` (3 seconds, or 300 ms when
/// the hook ends with its final sleep), which leaves `-ERESTART_RESTARTBLOCK` for the
/// kernel to restart through `restart_syscall` and the thread's restart
/// block. Its hook injects a 5-second `nanosleep` that a second SIGALRM
/// interrupts, which replaces that restart block with the injected sleep's,
/// and then a successful `getpid`. The hook runs at SIGALRM's own delivery
/// stop, so each injection leaves its own return register, as on main: the
/// guest sees the latest injection's result, or the Tool's latest write.
///
/// When the hook passes SIGALRM through, the handler runs, well before
/// either deadline, and the guest sees the `getpid`'s PID, as on main.
/// Untraced Linux returns EINTR there, a known gap
/// (https://github.com/rrnewton/reverie/issues/845).
///
/// When it suppresses SIGALRM, untraced Linux would restart the guest's
/// sleep, which the replaced restart block rules out. The guest sees the
/// latest injection's result, as on main: the `getpid`'s PID, which main
/// leaks (<https://github.com/rrnewton/reverie/issues/892>; a fix flips that
/// pin), or, after the hook's
/// final 350 ms sleep outlasts the guest's 300 ms deadline, zero, what
/// untraced Linux returns there.
///
/// The same zero is returned when the hook resumes after that final sleep
/// with a signal that enters no handler, one the guest ignores
/// (`IgnoredAfterSleep`) or blocks (`BlockedAfterSleep`), and the Tool's own
/// zero when it writes one to the return register (`SuppressAfterZeroingRax`),
/// as on main. A register write before the final sleep
/// (`SuppressAfterRewriteAndSleep`), or before the hook's first injection
/// (`SuppressAfterEarlyWriteAndSleep`), does not change that: the sleep's
/// zero is the latest value, as on main. Nor does writing the registers back
/// unchanged after the final sleep (`SuppressAfterSleepAndRewrite`): the
/// hook reads the sleep's zero, as on main. Writing back after the final
/// sleep the registers saved after the timer injection
/// (`SuppressAfterSleepAndCachedWrite`) returns the timer's zero they hold,
/// as on main.
///
/// With `SuppressAfterResume` the hook's interrupted `restart_syscall`
/// leaves the guest's restart block in place, and untraced Linux would
/// restart the guest's sleep to its own deadline and return zero. The guest
/// sees the `getpid`'s PID, which main leaks
/// (<https://github.com/rrnewton/reverie/issues/892>; a fix flips that pin).
///
/// In every case the second SIGALRM, held by the hook's `getpid`, is
/// delivered at the guest's next subscribed syscall, its `println`.
fn check_restart_block_replaced_by_a_hook_injection(end: RestartBlockEnd) {
    let suppress = end != RestartBlockEnd::Deliver;
    let final_sleep = matches!(
        end,
        RestartBlockEnd::SuppressAfterSleep
            | RestartBlockEnd::SuppressAfterRewriteAndSleep
            | RestartBlockEnd::SuppressAfterSleepAndRewrite
            | RestartBlockEnd::SuppressAfterEarlyWriteAndSleep
            | RestartBlockEnd::SuppressAfterSleepAndCachedWrite
            | RestartBlockEnd::IgnoredAfterSleep
            | RestartBlockEnd::BlockedAfterSleep
    );
    let rewrite = end == RestartBlockEnd::SuppressAfterRewriteAndSleep;
    let rewrite_last = end == RestartBlockEnd::SuppressAfterSleepAndRewrite;
    let early_rax = end == RestartBlockEnd::SuppressAfterEarlyWriteAndSleep;
    let cached = end == RestartBlockEnd::SuppressAfterSleepAndCachedWrite;
    let resume = end == RestartBlockEnd::SuppressAfterResume;
    let zero_rax = end == RestartBlockEnd::SuppressAfterZeroingRax;
    let verdict = match end {
        RestartBlockEnd::IgnoredAfterSleep => libc::SIGURG,
        RestartBlockEnd::BlockedAfterSleep => libc::SIGUSR2,
        _ => 0,
    };
    let (output, log) = test_fn_bounded::<RestartBlockInFirstSignalHook, _>(
        move || unsafe {
            RESTART_BLOCK_SUPPRESS.store(suppress as u64, Ordering::Relaxed);
            RESTART_BLOCK_FINAL.store(final_sleep as u64, Ordering::Relaxed);
            RESTART_BLOCK_RESUME.store(resume as u64, Ordering::Relaxed);
            RESTART_BLOCK_ZERO_RAX.store(zero_rax as u64, Ordering::Relaxed);
            RESTART_BLOCK_REWRITE.store(rewrite as u64, Ordering::Relaxed);
            RESTART_BLOCK_REWRITE_LAST.store(rewrite_last as u64, Ordering::Relaxed);
            RESTART_BLOCK_EARLY_RAX.store(early_rax as u64, Ordering::Relaxed);
            RESTART_BLOCK_CACHED.store(cached as u64, Ordering::Relaxed);
            RESTART_BLOCK_VERDICT.store(verdict as u64, Ordering::Relaxed);
            RESTART_BLOCK_POISON.store(0, Ordering::Relaxed);
            SIGALRM_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGALRM, count_sigalrm);
            if verdict == libc::SIGUSR2 {
                install_counter(libc::SIGUSR2, count_second);
                block(&[libc::SIGUSR2]);
            }
            let timer = libc::itimerval {
                it_interval: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                it_value: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 100_000,
                },
            };
            assert_eq!(
                libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()),
                0
            );
            let sleep = if final_sleep || resume {
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: if resume { 600_000_000 } else { 300_000_000 },
                }
            } else {
                libc::timespec {
                    tv_sec: 3,
                    tv_nsec: 0,
                }
            };
            let start = std::time::Instant::now();
            let ret = libc::syscall(libc::SYS_nanosleep, &sleep as *const libc::timespec, 0usize);
            let errno = *libc::__errno_location();
            let elapsed = start.elapsed().as_millis();
            let calls = SIGALRM_HANDLER_CALLS.load(Ordering::Relaxed);
            println!("{ret} {errno} {calls} {elapsed} {}", libc::getpid());
            println!("{}", SIGALRM_HANDLER_CALLS.load(Ordering::Relaxed));
        },
        "restart block replaced by a hook injection",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE restart-block end={end:?} guest={:?} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let injected = log.injected.lock().unwrap();
    assert_eq!(
        injected[..2],
        [Ok(0), Err(Errno::ERESTART_RESTARTBLOCK.into_raw())],
        "the hook's timer is armed, and its SIGALRM interrupts the injected sleep or restart_syscall"
    );
    let pid = match (final_sleep, &injected[2..]) {
        (false, [Err(512), Ok(pid)]) | (true, [Err(512), Ok(pid), Ok(0)]) if *pid > 0 => *pid,
        _ => panic!(
            "the second SIGALRM interrupts the first getpid, the second succeeds, and so does a final sleep: {injected:?}"
        ),
    };
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "guest output: {stdout:?}");
    let fields: Vec<&str> = lines[0].split(' ').collect();
    assert_eq!(fields.len(), 5, "guest output: {stdout:?}");
    assert_eq!(
        fields[4],
        pid.to_string(),
        "the injected getpid's result is the guest's own PID"
    );
    match end {
        RestartBlockEnd::Deliver => assert_eq!(
            [fields[0], fields[2]],
            [pid.to_string().as_str(), "1"],
            "the injected getpid's PID, as on main, with a handler run"
        ),
        RestartBlockEnd::Suppress => assert_eq!(
            [fields[0], fields[2]],
            [pid.to_string().as_str(), "0"],
            "the injected getpid's PID, as on main, and no handler run"
        ),
        RestartBlockEnd::SuppressAfterSleep
        | RestartBlockEnd::SuppressAfterRewriteAndSleep
        | RestartBlockEnd::SuppressAfterSleepAndRewrite
        | RestartBlockEnd::SuppressAfterEarlyWriteAndSleep => {
            assert_eq!(
                [fields[0], fields[2]],
                ["0", "0"],
                "the final injected sleep's zero, as on main and untraced Linux, and no handler run"
            )
        }
        RestartBlockEnd::SuppressAfterSleepAndCachedWrite => assert_eq!(
            [fields[0], fields[2]],
            ["0", "0"],
            "the timer injection's zero that the hook saved, as on main, and no handler run"
        ),
        RestartBlockEnd::SuppressAfterResume => assert_eq!(
            [fields[0], fields[2]],
            [pid.to_string().as_str(), "0"],
            "the injected getpid's PID, which main leaks (https://github.com/rrnewton/reverie/issues/892; a fix flips this pin), and no handler run"
        ),
        RestartBlockEnd::SuppressAfterZeroingRax => assert_eq!(
            [fields[0], fields[2]],
            ["0", "0"],
            "the Tool's own zero, as on main, and no handler run"
        ),
        RestartBlockEnd::IgnoredAfterSleep | RestartBlockEnd::BlockedAfterSleep => assert_eq!(
            [fields[0], fields[2]],
            ["0", "0"],
            "the final injected sleep's zero, as on main, and no SIGALRM handler run"
        ),
    }
    let elapsed: u128 = fields[3].parse().expect("elapsed milliseconds");
    assert!(
        elapsed < 2000,
        "the guest's sleep ends well before the injected sleep's deadline: {elapsed} ms"
    );
    if final_sleep {
        assert!(
            elapsed >= 300,
            "the guest's sleep ends after its own 300 ms deadline: {elapsed} ms"
        );
    }
    assert_eq!(
        lines[1],
        if suppress { "1" } else { "2" },
        "the held second SIGALRM is delivered at the guest's next subscribed syscall"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGALRM, libc::SIGALRM],
        "each SIGALRM is reported once"
    );
}

static SIGALRM_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_sigalrm(_signal: libc::c_int) {
    SIGALRM_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn suppressed_signal_after_a_restart_block_replacing_injection_returns_the_injection_result() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::Suppress);
}

#[test]
fn suppressed_signal_after_a_restart_block_replacing_injection_keeps_a_final_zero() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::SuppressAfterSleep);
}

#[test]
fn suppressed_signal_after_a_register_write_and_a_final_sleep_keeps_the_final_zero() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::SuppressAfterRewriteAndSleep);
}

#[test]
fn suppressed_signal_after_a_final_sleep_and_a_register_write_keeps_the_final_zero() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::SuppressAfterSleepAndRewrite);
}

#[test]
fn suppressed_signal_after_an_early_register_write_and_a_final_sleep_keeps_the_final_zero() {
    check_restart_block_replaced_by_a_hook_injection(
        RestartBlockEnd::SuppressAfterEarlyWriteAndSleep,
    );
}

#[test]
fn suppressed_signal_after_a_final_sleep_and_a_cached_register_write_keeps_the_cached_zero() {
    check_restart_block_replaced_by_a_hook_injection(
        RestartBlockEnd::SuppressAfterSleepAndCachedWrite,
    );
}

#[test]
fn suppressed_signal_after_an_injected_restart_syscall_returns_the_injection_result() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::SuppressAfterResume);
}

#[test]
fn suppressed_signal_after_a_restart_block_replacing_injection_keeps_the_tool_return_register() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::SuppressAfterZeroingRax);
}

#[test]
fn ignored_signal_after_a_restart_block_replacing_injection_keeps_a_final_zero() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::IgnoredAfterSleep);
}

#[test]
fn blocked_signal_after_a_restart_block_replacing_injection_keeps_a_final_zero() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::BlockedAfterSleep);
}

#[test]
fn delivered_signal_after_a_restart_block_replacing_injection_returns_the_injection_result() {
    check_restart_block_replaced_by_a_hook_injection(RestartBlockEnd::Deliver);
}

/// The guest ignores SIGALRM, and its marker arms a 200 ms `ITIMER_REAL`
/// timer and injects an 800 ms `nanosleep`, which the timer's SIGALRM
/// interrupts with `-ERESTART_RESTARTBLOCK`, and then a `getpid`, which the
/// pending SIGALRM interrupts before it runs and so holds. The tool returns
/// the sleep's `-ERESTART_RESTARTBLOCK`, for the kernel to restart through
/// the thread's restart block, the sleep's.
///
/// The held SIGALRM is passed on unreported, as on main, which reports no
/// held signal: the hook's injected sleep would replace that restart block,
/// and the guest would get the hook's last result in place of the restarted
/// sleep's. The ignored SIGALRM enters no handler, so the kernel restarts
/// the sleep to its 800 ms deadline, and the guest gets its zero, as on
/// main and untraced Linux.
#[test]
fn held_signal_is_not_reported_while_the_guest_restarts_through_its_restart_block() {
    let (output, log) = test_fn_bounded::<RestartBlockInFirstSignalHook, _>(
        || unsafe {
            for flag in [
                &RESTART_BLOCK_FINAL,
                &RESTART_BLOCK_RESUME,
                &RESTART_BLOCK_ZERO_RAX,
                &RESTART_BLOCK_REWRITE,
                &RESTART_BLOCK_REWRITE_LAST,
                &RESTART_BLOCK_EARLY_RAX,
                &RESTART_BLOCK_CACHED,
                &RESTART_BLOCK_VERDICT,
                &RESTART_BLOCK_POISON,
            ] {
                flag.store(0, Ordering::Relaxed);
            }
            RESTART_BLOCK_SUPPRESS.store(1, Ordering::Relaxed);
            assert_ne!(libc::signal(libc::SIGALRM, libc::SIG_IGN), libc::SIG_ERR);
            let mut args: TimedSleepArgs = std::mem::zeroed();
            args.timer.it_value.tv_usec = 200_000;
            args.sleep.tv_nsec = 800_000_000;
            let start = std::time::Instant::now();
            let ret = libc::syscall(
                libc::SYS_write,
                TIMED_SLEEP_THEN_GETPID_FD,
                &args as *const TimedSleepArgs,
                0usize,
            );
            println!("{ret} {}", start.elapsed().as_millis());
        },
        "held signal while the guest restarts through its restart block",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE held-restart-block guest={:?} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![
            Ok(0),
            Err(Errno::ERESTART_RESTARTBLOCK.into_raw()),
            Err(Errno::ERESTARTSYS.into_raw())
        ],
        "the timer is armed, its SIGALRM interrupts the sleep, and the pending SIGALRM interrupts getpid before it runs"
    );
    let fields: Vec<&str> = stdout.trim().split(' ').collect();
    assert_eq!(fields.len(), 2, "guest output: {stdout:?}");
    assert_eq!(fields[0], "0", "the restarted sleep's zero, as on main");
    let elapsed: u128 = fields[1].parse().expect("elapsed milliseconds");
    assert!(
        elapsed >= 800,
        "the restarted sleep ends at its own 800 ms deadline: {elapsed} ms"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        Vec::<i32>::new(),
        "the held SIGALRM is not reported, as on main"
    );
}

/// A Tool whose signal hook of SIGUSR1 saves the guest's registers, reports
/// its original syscall number and return register, injects `getpid`,
/// reported, writes the saved registers back with `Guest::set_regs`, and
/// resumes with SIGUSR2 in place of SIGUSR1. Other signals pass through.
#[derive(Clone, Copy, Debug, Default)]
struct RestoreRegsAfterGetpidHook;

#[reverie::tool]
impl Tool for RestoreRegsAfterGetpidHook {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::none()
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal != Signal::SIGUSR1 {
            return Ok(Some(signal));
        }
        let regs = guest.regs().await;
        guest
            .send_rpc(Report::Regs(regs.orig_rax as i64, regs.rax as i64))
            .await;
        let result = guest.inject(Getpid::new()).await;
        guest
            .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
            .await;
        guest
            .set_regs(regs)
            .await
            .expect("write the guest's registers");
        Ok(Some(Signal::SIGUSR2))
    }
}

/// A helper thread interrupts the guest's `read` of an empty pipe with
/// SIGUSR1 after 100 ms, and writes one byte to the pipe 200 ms later. The
/// hook of SIGUSR1 injects `getpid`, writes back the registers it saved
/// before the injection, so the return register holds the `read`'s
/// `-ERESTARTSYS` again, and resumes with SIGUSR2, which the guest blocks.
/// Linux requeues SIGUSR2, enters no handler, and restarts the `read`, which
/// returns the byte: 1, as on main. The Tool's own write decides the return
/// register.
#[test]
fn blocked_verdict_after_the_tool_restores_its_registers_restarts_the_read() {
    let (output, log) = test_fn_bounded::<RestoreRegsAfterGetpidHook, _>(
        || unsafe {
            SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
            SECOND_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGUSR1, count_sigusr1);
            install_counter(libc::SIGUSR2, count_second);
            // The helper thread inherits the mask, so SIGUSR2 can reach
            // neither thread's handler.
            block(&[libc::SIGUSR2]);
            let mut fds = [0; 2];
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            let (pid, tid) = (libc::getpid(), libc::gettid());
            let writer = fds[1];
            let helper = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                assert_eq!(libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1), 0);
                std::thread::sleep(std::time::Duration::from_millis(200));
                assert_eq!(libc::write(writer, b"Z".as_ptr().cast(), 1), 1);
            });
            let mut byte = b'?';
            let ret = libc::read(fds[0], (&mut byte as *mut u8).cast(), 1);
            let errno = if ret < 0 {
                *libc::__errno_location()
            } else {
                0
            };
            helper.join().expect("join the helper thread");
            let mut unread: libc::c_int = 0;
            assert_eq!(libc::ioctl(fds[0], libc::FIONREAD, &mut unread), 0);
            println!(
                "{ret} {errno} {} {unread} {} {} {}",
                byte as char,
                SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed),
                SECOND_HANDLER_CALLS.load(Ordering::Relaxed),
                is_pending(libc::SIGUSR2)
            );
        },
        "blocked verdict after the Tool restores its registers",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE tool-restores-regs guest={:?} regs={:?} injected={:?} signals={:?}",
        stdout.trim(),
        *log.regs.lock().unwrap(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.regs.lock().unwrap(),
        vec![(libc::SYS_read, -(Errno::ERESTARTSYS.into_raw() as i64))],
        "SIGUSR1 stops the guest in its read, which leaves -ERESTARTSYS"
    );
    let injected = log.injected.lock().unwrap();
    assert!(
        matches!(injected[..], [Ok(pid)] if pid > 0),
        "the hook's getpid succeeds: {injected:?}"
    );
    assert_eq!(
        stdout.trim(),
        "1 0 Z 0 0 0 1",
        "the restarted read returns the byte, as on main; no handler runs, and SIGUSR2 stays pending"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGUSR1],
        "SIGUSR1 is reported once; the blocked SIGUSR2 is never delivered"
    );
}

/// Like `InjectInSigusr1Hook`, but the signal hook of SIGUSR1 injects
/// `getpid`, then sends SIGTRAP to the guest's thread from the tracer, so the
/// trap is pending when the hook's second `getpid` is stepped.
#[derive(Clone, Copy, Debug, Default)]
struct TrapThenGetpidInSigusr1Hook;

#[reverie::tool]
impl Tool for TrapThenGetpidInSigusr1Hook {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal == Signal::SIGUSR1 {
            // A precaution: if an earlier injection had left its step
            // SIGTRAP queued, a SIGTRAP sent now would coalesce with it and
            // be discarded as that stale trap. One complete injection first
            // leaves no step SIGTRAP behind, so the SIGTRAP sent next is
            // the only one pending.
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
            // SAFETY: tgkill has no memory-safety preconditions.
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    guest.pid().as_raw(),
                    guest.tid().as_raw(),
                    libc::SIGTRAP,
                )
            };
            assert_eq!(sent, 0, "send SIGTRAP to the guest");
            let result = guest.inject(Getpid::new()).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// The hook of a held SIGUSR1 injects `getpid`, a complete injection that
/// leaves no step SIGTRAP queued for the next to coalesce with, sends the guest's thread
/// a SIGTRAP, and injects `getpid` again. Linux dequeues that SIGTRAP when
/// the second injection is stepped, before its `syscall` runs, and stops
/// there. That is not the
/// step's own trap: taken for it, the injection would return the syscall
/// number left in RAX (39) in place of the PID. The trap is discarded, as
/// the main loop discards a SIGTRAP no gdb, breakpoint or trap
/// configuration claims (`handle_sigtrap`), and the step runs the `getpid`,
/// which returns the guest's PID. The held SIGUSR1 is then delivered, so
/// the guest sees EINTR and one handler run, and SIGTRAP kills nothing
/// (https://github.com/rrnewton/reverie/issues/845).
#[test]
fn sigtrap_sent_before_a_held_signal_hook_injection_is_discarded_and_the_injection_runs() {
    let (output, log) = test_fn_bounded::<TrapThenGetpidInSigusr1Hook, _>(
        || unsafe {
            SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
            install_counter(libc::SIGUSR1, count_sigusr1);
            let set = block(&[libc::SIGUSR1]);
            assert_eq!(
                libc::syscall(
                    libc::SYS_tgkill,
                    libc::getpid(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGUSR1
                ),
                0
            );
            let ret = libc::syscall(
                libc::SYS_write,
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t,
                0usize,
            );
            let errno = *libc::__errno_location();
            println!(
                "{ret} {errno} {} {}",
                SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed),
                libc::getpid()
            );
        },
        "SIGTRAP sent by a held signal hook",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE held-hook-trap guest={:?} injected={:?} signals={:?}",
        stdout.trim(),
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fields: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(fields.len(), 4, "guest output: {stdout:?}");
    let pid: i64 = fields[3].parse().expect("the guest's PID");
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(pid), Ok(pid)],
        "the unblock completes, SIGUSR1 interrupts getpid before it runs, and both of the hook's getpid calls return the PID"
    );
    assert_eq!(
        fields[..3].join(" "),
        format!("-1 {} 1", libc::EINTR),
        "the guest sees EINTR and one SIGUSR1 handler run"
    );
    assert_eq!(*log.signals.lock().unwrap(), vec![libc::SIGUSR1]);
}

/// Like `ReplaceMarker`, but the signal hook of SIGUSR1 injects a 20-second
/// `poll` of no descriptors, reported, before passing it through. It reads
/// no guest memory: the guest is re-executed, so a pointer into this test
/// process's statics need not be mapped in it.
#[derive(Clone, Copy, Debug, Default)]
struct SleepInSigusr1Hook;

#[reverie::tool]
impl Tool for SleepInSigusr1Hook {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        replace_marker(guest, syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(Report::Signal(signal as i32)).await;
        if signal == Signal::SIGUSR1 {
            let sleep = Syscall::from_raw(Sysno::poll, SyscallArgs::new(0, 0, 20000, 0, 0, 0));
            let result = guest.inject(sleep).await;
            guest
                .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                .await;
        }
        Ok(Some(signal))
    }
}

/// Set by the guest's SIGTRAP handler (1) or by its helper thread when no
/// SIGTRAP reached the handler in time (2).
static HELD_TRAP_FLAG: AtomicU64 = AtomicU64::new(0);
/// Set by the guest once it waits for `HELD_TRAP_FLAG` with RAX and RDI zero.
static HELD_TRAP_READY: AtomicU64 = AtomicU64::new(0);
static HELD_TRAP_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_held_trap(_signal: libc::c_int) {
    HELD_TRAP_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
    let _ = HELD_TRAP_FLAG.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
}

/// The guest of `held_signal_is_not_reported_under_the_injected_syscall_trap`:
/// its held SIGUSR1 is followed by a SIGTRAP its helper thread sends while it
/// waits with RAX holding the trap configuration's marker, zero, and RDI a
/// frame address Reverie cannot read. Exits with ten times the SIGUSR1
/// handler's runs plus the SIGTRAP handler's.
fn held_trap_guest() -> ! {
    unsafe {
        SIGUSR1_HANDLER_CALLS.store(0, Ordering::Relaxed);
        let (pid, tid) = (libc::getpid(), libc::gettid());
        let helper = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while HELD_TRAP_READY.load(Ordering::SeqCst) == 0
                && start.elapsed() < std::time::Duration::from_secs(1)
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert_eq!(libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGTRAP), 0);
            let start = std::time::Instant::now();
            while HELD_TRAP_FLAG.load(Ordering::SeqCst) == 0
                && start.elapsed() < std::time::Duration::from_secs(3)
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = HELD_TRAP_FLAG.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
        });
        // Only now: creating the helper thread under Reverie resets a
        // SIGTRAP handler installed before it to SIG_DFL
        // (https://github.com/rrnewton/reverie/issues/879).
        install_counter(libc::SIGTRAP, count_held_trap);
        install_counter(libc::SIGUSR1, count_sigusr1);
        let set = block(&[libc::SIGUSR1]);
        assert_eq!(libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1), 0);
        libc::syscall(
            libc::SYS_write,
            UNBLOCK_THEN_GETPID_FD,
            &set as *const libc::sigset_t,
            0usize,
        );
        std::arch::asm!(
            "mov qword ptr [{ready}], 1",
            "2:",
            "cmp qword ptr [{flag}], 0",
            "je 2b",
            ready = in(reg) HELD_TRAP_READY.as_ptr(),
            flag = in(reg) HELD_TRAP_FLAG.as_ptr(),
            in("rax") 0u64,
            in("rdi") 0u64,
            options(nostack),
        );
        helper.join().expect("join the helper thread");
        libc::_exit(
            (SIGUSR1_HANDLER_CALLS.load(Ordering::Relaxed) * 10
                + HELD_TRAP_HANDLER_CALLS.load(Ordering::Relaxed)) as libc::c_int,
        );
    }
}

/// Under the trap configuration (`TracerBuilder::injected_syscall_trap`) the
/// main loop delivers a SIGTRAP that stops the guest with the marker in RAX
/// and no readable frame at RDI to the guest (`handle_sigtrap`). A Tool hook
/// of a held signal can see none of that: a SIGTRAP that arrives while its
/// injection is stepped is taken for the step's own and consumed. So under
/// this configuration a held signal is passed on unreported, as on main
/// (`sigtrap_may_be_claimed`). Here the held SIGUSR1 would be reported to a
/// hook that injects a 20-second `poll`, which the helper's SIGTRAP would
/// interrupt and consume (exit 10). Instead the SIGUSR1 handler runs, the guest waits
/// with the marker in RAX, and the helper's SIGTRAP reaches the guest's
/// handler: exit 11. The Tool sees only the delivered SIGTRAP. Known gap:
/// the held SIGUSR1 is not reported under this configuration, nor under
/// gdb, a breakpoint, or a LiteInst runtime that is not Ready
/// (https://github.com/rrnewton/reverie/issues/845).
#[test]
fn held_signal_is_not_reported_under_the_injected_syscall_trap() {
    const NAME: &str = "held_signal_is_not_reported_under_the_injected_syscall_trap";
    const ROLE: &str = "REVERIE_HELD_TRAP_GUEST";
    if std::env::var(ROLE).as_deref() == Ok(NAME) {
        held_trap_guest();
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut command =
            reverie::process::Command::new(std::env::current_exe().expect("test binary"));
        command
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(ROLE, NAME)
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
        let result = reverie_ptrace::testing::run_tokio_test(async move {
            let tracer = reverie_ptrace::TracerBuilder::<SleepInSigusr1Hook>::new(command)
                .injected_syscall_trap(0, 0)
                .spawn()
                .await?;
            tracer.wait_with_output().await
        });
        // A closed receiver means the test already timed out and failed.
        let _ = tx.send(result.map_err(|error| error.to_string()));
    });
    let (output, log) = match rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => panic!("held signal under the trap configuration: {error}"),
        Err(error) => panic!("held signal under the trap configuration: {error}"),
    };
    eprintln!(
        "PROBE held-trap-config status={:?} injected={:?} signals={:?}",
        output.status,
        *log.injected.lock().unwrap(),
        *log.signals.lock().unwrap()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(11),
        "each handler runs once; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())],
        "the unblock completes, SIGUSR1 interrupts getpid, and no hook injection runs"
    );
    assert_eq!(
        *log.signals.lock().unwrap(),
        vec![libc::SIGTRAP],
        "the held SIGUSR1 passes unreported; the SIGTRAP is reported as it is delivered"
    );
}

/// Set to stop the disposition flipper of
/// `restart_block_verdict_raced_by_a_disposition_change_never_leaves_a_bare_eintr`.
static DISPOSITION_FLIPPER_STOP: AtomicBool = AtomicBool::new(false);

/// How many workers that test runs. Each ends its sleep about 1 second in.
const DISPOSITION_RACE_WORKERS: usize = 16;

/// As `BlockedAfterSleep` in `check_restart_block_replaced_by_a_hook_injection`,
/// but the guest does not block SIGUSR2, and a sibling thread keeps switching
/// its process-wide disposition between a handler and `SIG_IGN`. The hook
/// resumes the guest's interrupted `nanosleep` with SIGUSR2 after its final
/// injected sleep, and the disposition in force when the kernel delivers the
/// signal can differ from the one at the hook's verdict. Untraced Linux, for
/// a signal arriving while the sleep is interrupted, either runs the handler
/// and returns EINTR, or ignores the signal and restarts the sleep to its
/// own deadline. Reverie does not read the disposition: the guest resumes
/// with the final injected sleep's zero, as on main, and the handler runs
/// or not as the kernel finds it at delivery. So each worker sees zero,
/// with or without a handler run; zero with a handler run, where untraced
/// Linux returns EINTR, is a known gap here
/// (https://github.com/rrnewton/reverie/issues/845). EINTR with no handler
/// run, which no untraced run returns, is never seen, nor a restart of the
/// guest's sleep with its original arguments, which would sleep 300 ms
/// past the deadline: the hook overwrites the guest's request with one
/// `nanosleep` rejects (`RESTART_BLOCK_POISON`), so a restart returns
/// EINVAL.
#[test]
fn restart_block_verdict_raced_by_a_disposition_change_never_leaves_a_bare_eintr() {
    let (output, log) = test_fn_bounded::<RestartBlockInFirstSignalHook, _>(
        || unsafe {
            RESTART_BLOCK_SUPPRESS.store(0, Ordering::Relaxed);
            RESTART_BLOCK_FINAL.store(1, Ordering::Relaxed);
            RESTART_BLOCK_RESUME.store(0, Ordering::Relaxed);
            RESTART_BLOCK_ZERO_RAX.store(0, Ordering::Relaxed);
            RESTART_BLOCK_REWRITE.store(0, Ordering::Relaxed);
            RESTART_BLOCK_REWRITE_LAST.store(0, Ordering::Relaxed);
            RESTART_BLOCK_EARLY_RAX.store(0, Ordering::Relaxed);
            RESTART_BLOCK_CACHED.store(0, Ordering::Relaxed);
            RESTART_BLOCK_VERDICT.store(libc::SIGUSR2 as u64, Ordering::Relaxed);
            RESTART_BLOCK_POISON.store(1, Ordering::Relaxed);
            install_counter(libc::SIGALRM, count_sigalrm);
            install_counter(libc::SIGUSR2, count_second);
            // Only the workers take the process-wide SIGALRM of ITIMER_REAL.
            block(&[libc::SIGALRM]);
            let flipper = std::thread::spawn(|| {
                let mut ignore: libc::sigaction = std::mem::zeroed();
                ignore.sa_sigaction = libc::SIG_IGN;
                libc::sigemptyset(&mut ignore.sa_mask);
                while !DISPOSITION_FLIPPER_STOP.load(Ordering::Relaxed) {
                    install_counter(libc::SIGUSR2, count_second);
                    assert_eq!(
                        libc::sigaction(libc::SIGUSR2, &ignore, std::ptr::null_mut()),
                        0
                    );
                }
            });
            for _ in 0..DISPOSITION_RACE_WORKERS {
                std::thread::spawn(|| {
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, libc::SIGALRM);
                    assert_eq!(
                        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
                        0
                    );
                    let timer = libc::itimerval {
                        it_interval: libc::timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        it_value: libc::timeval {
                            tv_sec: 0,
                            tv_usec: 100_000,
                        },
                    };
                    assert_eq!(
                        libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()),
                        0
                    );
                    let sleep = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 300_000_000,
                    };
                    let before = SECOND_HANDLER_CALLS.load(Ordering::SeqCst);
                    let ret =
                        libc::syscall(libc::SYS_nanosleep, &sleep as *const libc::timespec, 0usize);
                    let errno = if ret == -1 {
                        *libc::__errno_location()
                    } else {
                        0
                    };
                    let usr2 = SECOND_HANDLER_CALLS.load(Ordering::SeqCst) - before;
                    println!("{ret} {errno} {usr2}");
                })
                .join()
                .expect("join a worker");
            }
            DISPOSITION_FLIPPER_STOP.store(true, Ordering::Relaxed);
            flipper.join().expect("join the flipper");
        },
        "restart block verdict raced by a disposition change",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "PROBE disposition-race guest={:?} injected={} signals={}",
        stdout.lines().collect::<Vec<_>>(),
        log.injected.lock().unwrap().len(),
        log.signals.lock().unwrap().len()
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        DISPOSITION_RACE_WORKERS,
        "one line per worker: {stdout:?}"
    );
    for line in &lines {
        assert!(
            ["0 0 0", "0 0 1"].contains(line),
            "zero, with or without a handler run; never EINTR alone or a restart's EINVAL: \
             {line:?} in {stdout:?}"
        );
    }
}
