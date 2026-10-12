/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Realtime signals, numbered 32 to 64, under the ptrace backend
//! (<https://github.com/rrnewton/reverie/issues/207>). nix's `Signal` names
//! only 1 to 31, so a realtime signal-delivery stop is reported to
//! `Tool::handle_raw_signal_event` with its raw number and resumed with it.
//! Before, decoding such a stop failed with EINVAL and ended the run.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Getpid;
use reverie::syscalls::Ppoll;
use reverie::syscalls::Read;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::RtTgsigqueueinfo;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_fn;
use serde::Deserialize;
use serde::Serialize;

/// A zero-length write to this descriptor is replaced with an injected
/// `ppoll(NULL, 0, NULL, buf, 8)`: it sleeps under the mask at `buf` until a
/// signal that mask admits arrives. The tool returns its result.
const PPOLL_FD: i32 = 900;
/// A zero-length write to this descriptor is replaced with an injected
/// `rt_sigprocmask(SIG_UNBLOCK, buf, NULL)`, then an injected `getpid`. The
/// tool returns the `getpid` result.
const UNBLOCK_THEN_GETPID_FD: i32 = 901;
/// The Tool suppresses this signal: `handle_raw_signal_event` returns `None`.
const SUPPRESSED: i32 = 50;

#[derive(Debug, Deserialize, Serialize)]
enum Report {
    /// A signal shown to `Tool::handle_raw_signal_event`.
    Raw(i32),
    /// The injected `ppoll`'s result.
    Injected(Result<i64, i32>),
}

#[derive(Default)]
struct Log {
    raw: Mutex<Vec<i32>>,
    injected: Mutex<Vec<Result<i64, i32>>>,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Report;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        match report {
            Report::Raw(signal) => self.raw.lock().unwrap().push(signal),
            Report::Injected(result) => self.injected.lock().unwrap().push(result),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RawSignalTool;

#[reverie::tool]
impl Tool for RawSignalTool {
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
            Syscall::Write(write) if write.fd() == PPOLL_FD && write.len() == 0 => {
                let mask = write.buf().map_or(0, |buf| buf.as_raw());
                let result = guest
                    .inject(
                        Ppoll::new()
                            .with_fds(None)
                            .with_nfds(0)
                            .with_timeout(None)
                            .with_sigmask(Addr::from_raw(mask))
                            .with_sigsetsize(8),
                    )
                    .await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            Syscall::Write(write) if write.fd() == UNBLOCK_THEN_GETPID_FD && write.len() == 0 => {
                let set = write.buf().and_then(|buf| Addr::from_raw(buf.as_raw()));
                let unblocked = guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_UNBLOCK)
                            .with_set(set)
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await;
                guest
                    .send_rpc(Report::Injected(unblocked.map_err(Errno::into_raw)))
                    .await;
                let result = guest.inject(Getpid::new()).await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_raw_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: i32,
    ) -> Result<Option<i32>, Errno> {
        guest.send_rpc(Report::Raw(signal)).await;
        Ok((signal != SUPPRESSED).then_some(signal))
    }
}

/// Handler calls, each recorded as `signal << 32 | si_value`.
static DELIVERED: [AtomicI64; 4] = [const { AtomicI64::new(0) }; 4];
static DELIVERIES: AtomicUsize = AtomicUsize::new(0);
/// The si_code (high half) and si_pid (low half) of the last SIGUSR1 handled.
static LAST_SIGUSR1_ORIGIN: AtomicI64 = AtomicI64::new(0);

extern "C" fn record_delivery(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: an SA_SIGINFO handler gets the kernel's siginfo.
    let value = unsafe { (*info).si_value().sival_ptr } as i64;
    if signal == libc::SIGUSR1 {
        // SAFETY: as above.
        let (code, pid) = unsafe { ((*info).si_code, (*info).si_pid()) };
        LAST_SIGUSR1_ORIGIN.store((i64::from(code) << 32) | i64::from(pid), Ordering::SeqCst);
    }
    let slot = DELIVERIES.fetch_add(1, Ordering::SeqCst);
    if let Some(slot) = DELIVERED.get(slot) {
        slot.store((signal as i64) << 32 | value, Ordering::SeqCst);
    }
}

fn delivered() -> Vec<(i32, i64)> {
    let count = DELIVERIES.load(Ordering::SeqCst).min(DELIVERED.len());
    DELIVERED[..count]
        .iter()
        .map(|slot| {
            let record = slot.load(Ordering::SeqCst);
            ((record >> 32) as i32, record & 0xffff_ffff)
        })
        .collect()
}

fn handle_with_siginfo(signal: i32) {
    // SAFETY: the action is fully initialized; glibc accepts 34 to 64.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_delivery as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
    }
}

/// Ignores `signal` with a raw `rt_sigaction`: glibc's `sigaction` refuses
/// 32 and 33, which it reserves for itself.
fn ignore_raw(signal: i32) {
    #[repr(C)]
    struct KernelSigaction {
        handler: usize,
        flags: u64,
        restorer: usize,
        mask: u64,
    }
    let action = KernelSigaction {
        handler: libc::SIG_IGN,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    // SAFETY: `action` is a complete kernel sigaction; no old action is read.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            signal,
            &action as *const KernelSigaction,
            std::ptr::null_mut::<KernelSigaction>(),
            8,
        )
    };
    assert_eq!(ret, 0);
}

fn send_to_self(signal: i32) {
    // SAFETY: plain syscalls with integer arguments.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_tgkill,
            libc::getpid(),
            libc::syscall(libc::SYS_gettid),
            signal,
        )
    };
    assert_eq!(ret, 0);
}

fn queue_to_self(signal: i32, value: i64) {
    let value = libc::sigval {
        sival_ptr: value as usize as *mut libc::c_void,
    };
    // SAFETY: sigqueue takes plain values.
    assert_eq!(unsafe { libc::sigqueue(libc::getpid(), signal, value) }, 0);
}

fn set_blocked(signal: i32, blocked: bool) {
    // SAFETY: the set is initialized before use and the output pointer is null.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        let how = if blocked {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        assert_eq!(libc::pthread_sigmask(how, &set, std::ptr::null_mut()), 0);
    }
}

/// Every realtime number stops the guest and reaches the Tool, the glibc
/// reserved 32 and 33 included, and is delivered as the Tool returned it: to
/// the guest's handler with its `sigqueue` value, or to its ignored
/// disposition, or not at all when the Tool suppresses it (50). Linux reports
/// an ignored signal to a ptracer before applying the disposition
/// (`sig_ignored`).
#[test]
fn realtime_signal_stops_reach_the_tool_and_are_delivered() {
    let (output, log) = test_fn::<RawSignalTool, _>(|| {
        DELIVERIES.store(0, Ordering::SeqCst);
        ignore_raw(32);
        ignore_raw(33);
        handle_with_siginfo(34);
        handle_with_siginfo(SUPPRESSED);
        handle_with_siginfo(64);
        send_to_self(32);
        send_to_self(33);
        queue_to_self(34, 340);
        queue_to_self(SUPPRESSED, 500);
        queue_to_self(64, 640);
        assert_eq!(delivered(), vec![(34, 340), (64, 640)]);
    })
    .expect("run realtime-signal ptrace guest");

    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(*log.raw.lock().unwrap(), vec![32, 33, 34, SUPPRESSED, 64]);
}

/// Two queued instances of a realtime signal wake an injected `ppoll` whose
/// mask admits them, as they would wake the guest's own `ppoll`. The
/// injection returns ERESTARTNOHAND. The kernel reports the step's SIGTRAP
/// before the signal (a realtime signal is never synchronous-class), so the
/// first instance is not held: it stops the guest after the injection, at an
/// ordinary signal-delivery stop, and reaches the handler; the second stays
/// queued behind the guest's restored mask until the guest unblocks it. Both
/// keep their `sigqueue` values and order. The held path is
/// `a_realtime_signal_pending_before_an_injected_syscall_interrupts_it`.
#[test]
fn a_realtime_signal_that_wakes_an_injected_syscall_is_delivered_after_it() {
    let (output, log) = test_fn::<RawSignalTool, _>(|| {
        DELIVERIES.store(0, Ordering::SeqCst);
        let signal = libc::SIGRTMIN() + 2;
        handle_with_siginfo(signal);
        set_blocked(signal, true);
        queue_to_self(signal, 1);
        queue_to_self(signal, 2);
        // SAFETY: an empty set the tool's `ppoll` reads as its mask.
        let mut admit_all: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut admit_all) };
        // SAFETY: the tool replaces this zero-length write.
        let ret = unsafe {
            libc::write(
                PPOLL_FD,
                &admit_all as *const libc::sigset_t as *const libc::c_void,
                0,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((ret, errno), (-1, Some(libc::EINTR)));
        assert_eq!(delivered(), vec![(signal, 1)]);
        set_blocked(signal, false);
        assert_eq!(delivered(), vec![(signal, 1), (signal, 2)]);
    })
    .expect("run realtime-wake ptrace guest");

    assert_eq!(output.status, ExitStatus::Exited(0));
    let signal = libc::SIGRTMIN() + 2;
    assert_eq!(*log.raw.lock().unwrap(), vec![signal, signal]);
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Err(Errno::ERESTARTNOHAND.into_raw())]
    );
}

/// A realtime signal that the Tool's injected `rt_sigprocmask` unblocks stops
/// the Tool's next injection, a `getpid`, before its `syscall`, as a standard
/// signal does (`signal_pending_before_injected_syscall_interrupts_it` in
/// `injected_syscall_group_stop.rs`): the unblock's own step SIGTRAP is
/// dequeued first, as a realtime signal is never synchronous-class. The
/// injection reports ERESTARTSYS, the signal is held, reported to the Tool
/// once and delivered with its siginfo when the guest resumes, and the
/// guest's call returns EINTR.
#[test]
fn a_realtime_signal_pending_before_an_injected_syscall_interrupts_it() {
    let (output, log) = test_fn::<RawSignalTool, _>(|| {
        DELIVERIES.store(0, Ordering::SeqCst);
        let signal = libc::SIGRTMIN() + 4;
        handle_with_siginfo(signal);
        set_blocked(signal, true);
        queue_to_self(signal, 77);
        // SAFETY: the set is initialized before use.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, signal);
        }
        // SAFETY: the tool replaces this zero-length write.
        let ret = unsafe {
            libc::write(
                UNBLOCK_THEN_GETPID_FD,
                &set as *const libc::sigset_t as *const libc::c_void,
                0,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((ret, errno), (-1, Some(libc::EINTR)));
        assert_eq!(delivered(), vec![(signal, 77)]);
    })
    .expect("run realtime interrupted-injection guest");

    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signal = libc::SIGRTMIN() + 4;
    assert_eq!(*log.raw.lock().unwrap(), vec![signal]);
    assert_eq!(
        *log.injected.lock().unwrap(),
        vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())]
    );
}

/// A zero-length write to this descriptor is replaced, for a `HeldCallbackPlan`
/// at `buf`, with an injected `rt_sigprocmask(SIG_UNBLOCK, &buf.unblock_a,
/// NULL)`, then an injected `getpid`. The tool returns the `getpid` result.
const HELD_CALLBACK_FD: i32 = 902;

/// Guest memory for `HELD_CALLBACK_FD`.
#[repr(C)]
struct HeldCallbackPlan {
    unblock_a: u64,
    block_b: u64,
    info2: libc::siginfo_t,
    info3: libc::siginfo_t,
}

static PLAN_ADDR: AtomicUsize = AtomicUsize::new(0);
static PLAN_DONE: AtomicBool = AtomicBool::new(false);

fn held_a() -> i32 {
    libc::SIGRTMIN() + 4
}

fn queued_b() -> i32 {
    libc::SIGRTMIN() + 6
}

/// Like `RawSignalTool` for `HELD_CALLBACK_FD`; its raw-signal hook, at the
/// first report of `held_a()`, injects: block `queued_b()`, queue it twice
/// with `rt_tgsigqueueinfo` (values 2 and 3), unblock it, and `getpid`.
#[derive(Clone, Copy, Debug, Default)]
struct HeldCallbackTool;

#[reverie::tool]
impl Tool for HeldCallbackTool {
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
            Syscall::Write(write) if write.fd() == HELD_CALLBACK_FD && write.len() == 0 => {
                let base = write.buf().map_or(0, |buf| buf.as_raw());
                PLAN_ADDR.store(base, Ordering::SeqCst);
                let unblocked = guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_UNBLOCK)
                            .with_set(Addr::from_raw(base))
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await;
                guest
                    .send_rpc(Report::Injected(unblocked.map_err(Errno::into_raw)))
                    .await;
                let result = guest.inject(Getpid::new()).await;
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_raw_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: i32,
    ) -> Result<Option<i32>, Errno> {
        guest.send_rpc(Report::Raw(signal)).await;
        if signal == held_a() && !PLAN_DONE.swap(true, Ordering::SeqCst) {
            let base = PLAN_ADDR.load(Ordering::SeqCst);
            let block_b = Addr::from_raw(base + std::mem::offset_of!(HeldCallbackPlan, block_b));
            let pid = guest.pid().as_raw();
            let tid = guest.tid().as_raw();
            let mut results = vec![
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_BLOCK)
                            .with_set(block_b)
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await,
            ];
            for offset in [
                std::mem::offset_of!(HeldCallbackPlan, info2),
                std::mem::offset_of!(HeldCallbackPlan, info3),
            ] {
                results.push(
                    guest
                        .inject(
                            RtTgsigqueueinfo::new()
                                .with_tgid(pid)
                                .with_tid(tid)
                                .with_sig(queued_b())
                                .with_siginfo(AddrMut::from_raw(base + offset)),
                        )
                        .await,
                );
            }
            results.push(
                guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_UNBLOCK)
                            .with_set(block_b)
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await,
            );
            results.push(guest.inject(Getpid::new()).await);
            for result in results {
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
            }
        }
        Ok(Some(signal))
    }
}

/// A queued siginfo for `rt_tgsigqueueinfo`: SI_QUEUE from this process,
/// with `value`. x86_64 layout: si_signo, si_errno, si_code, padding, then
/// si_pid, si_uid and si_value.
fn queued_siginfo(signal: i32, value: i64) -> libc::siginfo_t {
    let mut raw = [0u8; 128];
    raw[0..4].copy_from_slice(&signal.to_ne_bytes());
    raw[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    // SAFETY: getpid and getuid have no preconditions.
    raw[16..20].copy_from_slice(&unsafe { libc::getpid() }.to_ne_bytes());
    raw[20..24].copy_from_slice(&unsafe { libc::getuid() }.to_ne_bytes());
    raw[24..32].copy_from_slice(&value.to_ne_bytes());
    // SAFETY: siginfo_t is 128 plain bytes on Linux.
    unsafe { std::mem::transmute(raw) }
}

/// Instances of one realtime signal that a held signal's callback queues
/// keep their order, and the held signal keeps its siginfo, through the
/// callback's injections (from the review of
/// https://github.com/rrnewton/reverie/pull/995). A, held when it stops the
/// marker's injected `getpid`, is reported to the raw hook, whose injections
/// queue B twice (values 2, then 3) and unblock it. An injection there that
/// took B from the kernel's queue would put it back behind the later
/// instance, and the handlers would see B 3 before B 2. Linux runs them as:
/// B 2 (its frame nested above A's), B 3 once B 2's handler returns, then A
/// with value 77.
#[test]
fn queued_realtime_instances_keep_their_order_through_a_held_signals_callback() {
    let (output, log) = test_fn::<HeldCallbackTool, _>(|| {
        DELIVERIES.store(0, Ordering::SeqCst);
        let (a, b) = (held_a(), queued_b());
        handle_with_siginfo(a);
        handle_with_siginfo(b);
        set_blocked(a, true);
        queue_to_self(a, 77);
        let plan = HeldCallbackPlan {
            unblock_a: 1u64 << (a - 1),
            block_b: 1u64 << (b - 1),
            info2: queued_siginfo(b, 2),
            info3: queued_siginfo(b, 3),
        };
        // SAFETY: the tool replaces this zero-length write.
        let ret = unsafe {
            libc::write(
                HELD_CALLBACK_FD,
                &plan as *const HeldCallbackPlan as *const libc::c_void,
                0,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((ret, errno), (-1, Some(libc::EINTR)));
        assert_eq!(delivered(), vec![(b, 2), (b, 3), (a, 77)]);
    })
    .expect("run held-callback realtime-order guest");

    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (a, b) = (held_a(), queued_b());
    assert_eq!(*log.raw.lock().unwrap(), vec![a, b, b]);
    // The marker's unblock and its getpid (stopped by A), then the
    // callback's block, two queues, unblock and getpid (a pid).
    let injected = log.injected.lock().unwrap();
    assert_eq!(
        injected[..6],
        [
            Ok(0),
            Err(Errno::ERESTARTSYS.into_raw()),
            Ok(0),
            Ok(0),
            Ok(0),
            Ok(0)
        ]
    );
    assert!(
        matches!(injected[6..], [Ok(pid)] if pid > 0),
        "{injected:?}"
    );
}

/// A zero-length write to this descriptor is replaced with an injected
/// `rt_sigprocmask(SIG_UNBLOCK, buf, NULL)`, then `Guest::inject_with_retry`
/// of `getpid`. The tool returns the `getpid` result.
const RETRY_FD: i32 = 903;
/// Like `RETRY_FD`, but the retried syscall is `read(READ_TIMER_FD, buf, 8)`,
/// which blocks until the guest's timer at `READ_TIMER_FD` expires.
const RETRY_READ_FD: i32 = 904;
/// The descriptor the guest moves its timerfd to for `RETRY_READ_FD`.
const READ_TIMER_FD: i32 = 905;

/// Like `RawSignalTool`, for `RETRY_FD`.
#[derive(Clone, Copy, Debug, Default)]
struct RetryTool;

#[reverie::tool]
impl Tool for RetryTool {
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
            Syscall::Write(write)
                if (write.fd() == RETRY_FD || write.fd() == RETRY_READ_FD) && write.len() == 0 =>
            {
                let set = write.buf().and_then(|buf| Addr::from_raw(buf.as_raw()));
                let unblocked = guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_UNBLOCK)
                            .with_set(set)
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await;
                guest
                    .send_rpc(Report::Injected(unblocked.map_err(Errno::into_raw)))
                    .await;
                let result = if write.fd() == RETRY_READ_FD {
                    guest
                        .inject_with_retry(
                            Read::new()
                                .with_fd(READ_TIMER_FD)
                                .with_buf(
                                    write.buf().and_then(|buf| AddrMut::from_raw(buf.as_raw())),
                                )
                                .with_len(8),
                        )
                        .await
                } else {
                    guest.inject_with_retry(Getpid::new()).await
                };
                guest
                    .send_rpc(Report::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(result?)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_raw_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: i32,
    ) -> Result<Option<i32>, Errno> {
        guest.send_rpc(Report::Raw(signal)).await;
        Ok(Some(signal))
    }
}

/// An ordinary syscall callback's `inject_with_retry` keeps every queued
/// instance of a realtime signal (from the Codex review of
/// https://github.com/rrnewton/reverie/pull/995). The callback unblocks the
/// signal, so its first instance stops the retried `getpid` before its
/// `syscall` and is held. A retry that took the next instance would hold it
/// in the same single slot and lose the first. The retry keeps the realtime
/// signals queued instead, so `getpid` completes and the handlers see every
/// value in order: the held instance keeps its siginfo when it is passed on
/// after the callback's injections. `queued` is 0 and 1 for the controls.
fn realtime_instances_survive_an_ordinary_retry(queued: usize) {
    let (output, log) = test_fn::<RetryTool, _>(move || {
        DELIVERIES.store(0, Ordering::SeqCst);
        let signal = libc::SIGRTMIN() + 4;
        handle_with_siginfo(signal);
        set_blocked(signal, true);
        for value in [111, 222].into_iter().take(queued) {
            queue_to_self(signal, value);
        }
        // SAFETY: the set is initialized before use.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, signal);
        }
        // SAFETY: the tool replaces this zero-length write.
        let ret = unsafe {
            libc::write(
                RETRY_FD,
                &set as *const libc::sigset_t as *const libc::c_void,
                0,
            )
        };
        // SAFETY: getpid has no preconditions.
        assert_eq!(ret, unsafe { libc::getpid() } as isize);
        let expected: Vec<(i32, i64)> = [111, 222]
            .into_iter()
            .take(queued)
            .map(|value| (signal, value))
            .collect();
        assert_eq!(delivered(), expected);
    })
    .expect("run ordinary-retry realtime guest");

    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // With a second instance pending, the held first one is passed on
    // unreported, as any held signal is while another signal is pending
    // (`report_held_signal`), and keeps its siginfo (value 111 above); the
    // second is reported at its own stop.
    assert_eq!(log.raw.lock().unwrap().len(), queued.min(1));
    let injected = log.injected.lock().unwrap();
    assert!(
        matches!(injected[..], [Ok(0), Ok(pid)] if pid > 0),
        "{injected:?}"
    );
}

#[test]
fn two_realtime_instances_survive_an_ordinary_retry() {
    realtime_instances_survive_an_ordinary_retry(2);
}

#[test]
fn one_realtime_instance_survives_an_ordinary_retry() {
    realtime_instances_survive_an_ordinary_retry(1);
}

#[test]
fn an_ordinary_retry_without_a_realtime_signal_completes() {
    realtime_instances_survive_an_ordinary_retry(0);
}

/// An ordinary callback's `inject_with_retry` of a blocking syscall, with one
/// signal held and a realtime signal queued, returns the syscall's restart
/// code at once (https://github.com/rrnewton/reverie/issues/998). SIGUSR1
/// stops the first `read` before its `syscall` and is held. The retry keeps
/// SIGRTMIN+4 queued until the `read`'s entry, where it is pending, so the
/// `read` returns ERESTARTSYS without blocking. A further retry would return
/// the same until the timer expired; instead the guest's syscall returns it,
/// the signals run their handlers as when the guest unblocked them natively,
/// and the guest's `write`, whose handlers lack SA_RESTART, fails with EINTR.
/// The guest calls again and the `read` blocks until the timer expires.
#[test]
fn a_retried_blocking_syscall_returns_its_restart_code_while_a_signal_is_held() {
    let (output, log) = test_fn::<RetryTool, _>(move || {
        DELIVERIES.store(0, Ordering::SeqCst);
        let realtime = libc::SIGRTMIN() + 4;
        handle_with_siginfo(libc::SIGUSR1);
        handle_with_siginfo(realtime);
        set_blocked(libc::SIGUSR1, true);
        set_blocked(realtime, true);
        queue_to_self(libc::SIGUSR1, 7);
        queue_to_self(realtime, 111);
        // SAFETY: plain syscalls; the timer spec is fully initialized.
        unsafe {
            let timer = libc::timerfd_create(libc::CLOCK_MONOTONIC, 0);
            assert!(timer >= 0);
            let spec = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 500_000_000,
                },
            };
            assert_eq!(
                libc::timerfd_settime(timer, 0, &spec, std::ptr::null_mut()),
                0
            );
            assert_eq!(libc::dup2(timer, READ_TIMER_FD), READ_TIMER_FD);
        }
        let call = || {
            // SAFETY: the set is initialized before use.
            let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGUSR1);
                libc::sigaddset(&mut set, realtime);
            }
            // SAFETY: the tool replaces this zero-length write; the `read`
            // it injects writes 8 bytes into `set`.
            let ret = unsafe {
                libc::write(
                    RETRY_READ_FD,
                    &mut set as *mut libc::sigset_t as *const libc::c_void,
                    0,
                )
            };
            (ret, std::io::Error::last_os_error().raw_os_error())
        };
        assert_eq!(call(), (-1, Some(libc::EINTR)));
        assert_eq!(delivered(), vec![(realtime, 111), (libc::SIGUSR1, 7)]);
        assert_eq!(call().0, 8);
    })
    .expect("run retried-blocking-syscall guest");

    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let injected = log.injected.lock().unwrap();
    assert_eq!(
        injected[..],
        [Ok(0), Err(Errno::ERESTARTSYS.into_raw()), Ok(0), Ok(8),],
        "the first retry returns the restart code instead of retrying until the timer expires"
    );
}

/// A guest that a realtime signal kills ends with
/// `ExitStatus::SignaledRaw`, and its exit status is the signal; the tracer
/// panicked decoding it (<https://github.com/rrnewton/reverie/issues/997>).
#[test]
fn a_guest_killed_by_a_realtime_signal_exits_with_it() {
    let signal = libc::SIGRTMIN() + 1;
    let (output, log) = test_fn::<RawSignalTool, _>(move || {
        // SAFETY: raise has no preconditions; the default action ends the
        // process.
        unsafe { libc::raise(signal) };
    })
    .expect("run realtime-termination guest");

    assert_eq!(output.status, ExitStatus::SignaledRaw(signal, false));
    assert_eq!(output.status.signal(), Some(signal));
    assert_eq!(*log.raw.lock().unwrap(), vec![signal]);
}

/// A guest's child that a realtime signal kills is reaped by the guest
/// with that signal, and the guest runs on to its own exit.
#[test]
fn a_child_killed_by_a_realtime_signal_is_reaped_with_it() {
    let signal = libc::SIGRTMIN() + 1;
    let (output, log) = test_fn::<RawSignalTool, _>(move || {
        // SAFETY: the child only raises and exits; the parent waits for it.
        unsafe {
            let child = libc::fork();
            if child == 0 {
                libc::raise(signal);
                libc::_exit(3);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert!(libc::WIFSIGNALED(status), "status {status:#x}");
            assert_eq!(libc::WTERMSIG(status), signal);
        }
    })
    .expect("run realtime-killed-child guest");

    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(*log.raw.lock().unwrap(), vec![signal]);
}

/// A held named signal passed on unreported keeps its siginfo too
/// (https://github.com/rrnewton/reverie/issues/999). SIGUSR1 queued with
/// value 7 stops the retried `getpid` and is held; with SIGRTMIN+4 (value
/// 111) pending, it is passed on unreported, resumed from the injection's
/// stop. Linux would make up an SI_USER siginfo with no value for it there.
/// The handlers run as natively: SIGRTMIN+4's frame nests above SIGUSR1's.
#[test]
fn a_held_named_signal_passed_on_keeps_its_value() {
    let (output, _log) = test_fn::<RetryTool, _>(move || {
        DELIVERIES.store(0, Ordering::SeqCst);
        let realtime = libc::SIGRTMIN() + 4;
        handle_with_siginfo(libc::SIGUSR1);
        handle_with_siginfo(realtime);
        set_blocked(libc::SIGUSR1, true);
        set_blocked(realtime, true);
        queue_to_self(libc::SIGUSR1, 7);
        queue_to_self(realtime, 111);
        // SAFETY: the set is initialized before use.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::sigaddset(&mut set, realtime);
        }
        // SAFETY: the tool replaces this zero-length write.
        let ret = unsafe {
            libc::write(
                RETRY_FD,
                &set as *const libc::sigset_t as *const libc::c_void,
                0,
            )
        };
        // SAFETY: getpid has no preconditions.
        assert_eq!(ret, unsafe { libc::getpid() } as isize);
        assert_eq!(delivered(), vec![(realtime, 111), (libc::SIGUSR1, 7)]);
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        assert_eq!(
            LAST_SIGUSR1_ORIGIN.load(Ordering::SeqCst),
            (i64::from(libc::SI_QUEUE) << 32) | i64::from(me),
            "SIGUSR1's si_code and si_pid are the ones sigqueue gave it"
        );
    })
    .expect("run held-named-signal guest");

    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
