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
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Signal;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::Getpid;
use reverie::syscalls::Getppid;
use reverie::syscalls::Ppoll;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::RtTgsigqueueinfo;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
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
/// A zero-length write to this descriptor is replaced with
/// `ppoll(NULL, 0, &buf.timeout, &buf.mask, 8)` for a `PpollArgs` at `buf`.
const PPOLL_FD: i32 = 904;
/// Like `PPOLL_FD`, followed by an injected `getpid` whose result the tool
/// returns to the guest.
const PPOLL_THEN_GETPID_FD: i32 = 905;
/// A zero-length write to this descriptor is replaced with `getppid`.
const GETPPID_FD: i32 = 906;

/// Guest memory for the injected `ppoll`.
#[repr(C)]
struct PpollArgs {
    mask: libc::sigset_t,
    timeout: libc::timespec,
}
const MARKERS: usize = 1500;

#[derive(Debug, Deserialize, Serialize)]
enum Report {
    Injected(Result<i64, i32>),
    Signal(i32),
}

#[derive(Default)]
struct Log {
    injected: Mutex<Vec<Result<i64, i32>>>,
    signals: Mutex<Vec<i32>>,
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
                let result = guest.inject(Getpid::new()).await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            Syscall::Write(write)
                if (write.fd() == PPOLL_FD || write.fd() == PPOLL_THEN_GETPID_FD)
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
                let result = guest.inject(Getpid::new()).await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            Syscall::Write(write) if write.fd() == GETPPID_FD && write.len() == 0 => {
                let result = guest.inject(Getppid::new()).await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            other => Ok(guest.inject(other).await?),
        }
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
    eprintln!(
        "PROBE interrupted guest={} injected={:?} signals={:?}",
        stdout.trim(),
        *injected,
        *log.signals.lock().unwrap()
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
/// pid. The tool list is pinned as it stands: the signal that stops
/// `getpid` before its `syscall` is delivered through the single
/// `pending_signal` slot, which bypasses `Tool::handle_signal_event`, so only
/// SIGSEGV is observed. A fix for that bypass must update this assertion.
///
/// Known gaps pinned here, tracked in TaskGraph: the interrupted `getpid`
/// and the signal parked in the single slot are `reverie_pending_signal_single_slot`;
/// the tool never seeing SIGSYS is
/// `reverie_held_signal_skips_tool_handle_signal_event`.
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
/// Known gap pinned here: the held SIGSYS reaches the guest through the
/// `pending_signal` slot and so bypasses `Tool::handle_signal_event`; only
/// SIGSEGV, delivered from the kernel queue, is reported to the tool
/// (TaskGraph `reverie_held_signal_skips_tool_handle_signal_event`).
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
