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
use reverie::syscalls::Getpid;
use reverie::syscalls::Ppoll;
use reverie::syscalls::RtSigprocmask;
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

extern "C" fn record_delivery(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: an SA_SIGINFO handler gets the kernel's siginfo.
    let value = unsafe { (*info).si_value().sival_ptr } as i64;
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
/// mask admits them, as they would wake the guest's own `ppoll`: the first
/// stops the injection, is held, and reaches the handler when the guest
/// resumes; the second stays queued behind the guest's restored mask until
/// the guest unblocks it. Both keep their `sigqueue` values and order.
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
