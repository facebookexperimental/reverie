/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::deliver_signal` on ptrace, end to end (A5 step 3.1,
//! <https://github.com/rrnewton/hermit/issues/4485>):
//! - a tool that approves a caught signal with the right masks gets
//!   `Accepted`, and the guest's handler then runs under exactly the approved
//!   handler mask;
//! - a wrong frame mask is a `Mismatch` naming it, which approves nothing, and
//!   the signal is still delivered by the old path;
//! - after an injection inside the signal callback (with the guest's
//!   registers put back), it is accepted, and the kernel delivers the
//!   reported instance with its own siginfo;
//! - at a held signal's report, after the syscall callback whose injection
//!   it stopped, it is accepted against the guest's syscall registers;
//! - at a delivery stop inside the kernel's own `rt_sigsuspend`, where the
//!   frame's mask (the saved one) differs from the current (temporary) one,
//!   it is accepted;
//! - after an injection there, which lets the kernel restore the saved mask,
//!   the signal is blocked at resume and it is unavailable; the kernel then
//!   requeues the signal and delivers it again, approved;
//! - a caught realtime signal, queued with a value, is accepted through the
//!   raw-signal hook, and its handler gets that exact instance's value;
//! - outside a signal callback (a syscall stop) it is unavailable;
//! - an injection, a register write, a tail injection or an exec after an
//!   approval breaks it, and the run then ends with the named failure
//!   rather than deliver what the checks did not cover.

#![cfg(target_arch = "x86_64")]

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Interruption;
use reverie::Pid;
use reverie::Signal;
use reverie::SignalAction;
use reverie::SignalDelivery;
use reverie::Subscription;
use reverie::Tool;
use reverie::signal_set_bit;
use reverie::syscalls::Addr;
use reverie::syscalls::CArrayPtr;
use reverie::syscalls::CStrPtr;
use reverie::syscalls::Execve;
use reverie::syscalls::FromToRaw;
use reverie::syscalls::Getpid;
use reverie::syscalls::PathPtr;
use reverie::syscalls::Pause;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_fn;

/// A zero-length write to this descriptor asks the tool to call
/// `deliver_signal` from the syscall callback.
const PROBE_FD: i32 = 905;

/// A zero-length write to this descriptor, whose buffer is a signal set,
/// asks the tool to unblock that set with an injected `rt_sigprocmask` and
/// then inject `getpid`, which the now-admitted pending signal interrupts
/// before it runs. The signal is held, and reported after the write's
/// callback returns that `ERESTARTSYS`.
const HELD_FD: i32 = 906;

/// The guest's own mask while it signals itself.
const GUEST_MASK: u64 = signal_set_bit(libc::SIGINT);

/// Every handler's `sa_mask`.
const SA_MASK: u64 = signal_set_bit(libc::SIGUSR2);

/// The guest's mask before its `rt_sigsuspend`, which the frame saves.
const SUSPEND_SAVED: u64 =
    signal_set_bit(libc::SIGINT) | signal_set_bit(libc::SIGALRM) | signal_set_bit(libc::SIGXCPU);

/// The temporary mask of the guest's `rt_sigsuspend`.
const SUSPEND_TEMPORARY: u64 = signal_set_bit(libc::SIGINT);

/// The realtime signal of the raw-signal case.
const REALTIME: i32 = 40;

/// Whether the tool has seen the first SIGXCPU, whose delivery it breaks
/// with an injection.
static FIRST_XCPU_SEEN: AtomicBool = AtomicBool::new(false);

/// The program the exec case runs, and its argv. The guest is a fork of the
/// test process, so these have the same addresses in the guest.
static TRUE_PATH: &[u8] = b"/bin/true\0";
static TRUE_ARGV: [usize; 2] = [0, 0];

/// The delivery Linux makes of `signal` at a delivery stop inside the
/// guest's kernel-run `rt_sigsuspend`.
fn suspended_delivery_of(signal: i32) -> SignalDelivery {
    let action = SignalAction {
        mask: SA_MASK,
        ..SignalAction::default()
    };
    SignalDelivery {
        signal,
        action,
        frame_mask: SUSPEND_SAVED,
        current_mask: SUSPEND_TEMPORARY,
        handler_mask: action.handler_mask(SUSPEND_TEMPORARY, signal),
        unchecked_mask: 0,
        interruption: Interruption::KernelRun {
            syscall: libc::SYS_rt_sigsuspend,
        },
    }
}

#[derive(Default)]
struct Log {
    outcomes: Mutex<Vec<String>>,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = String;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, outcome: String) {
        self.outcomes.lock().unwrap().push(outcome);
    }
}

/// The delivery Linux makes of `signal` to the guest of these tests, which
/// signals itself with `tgkill` (result 0) under `GUEST_MASK`, with a handler
/// whose `sa_mask` is `SA_MASK`.
fn delivery_of(signal: i32) -> SignalDelivery {
    let action = SignalAction {
        mask: SA_MASK,
        ..SignalAction::default()
    };
    SignalDelivery {
        signal,
        action,
        frame_mask: GUEST_MASK,
        current_mask: GUEST_MASK,
        handler_mask: action.handler_mask(GUEST_MASK, signal),
        unchecked_mask: 0,
        interruption: Interruption::Return {
            syscall: libc::SYS_tgkill,
            result: 0,
        },
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DeliverTool;

#[reverie::tool]
impl Tool for DeliverTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        let raw = signal as i32;
        let outcome = match signal {
            // The positive control.
            Signal::SIGUSR1 => guest.deliver_signal(delivery_of(raw)).await,
            // A held report: the guest's write was interrupted with
            // ERESTARTSYS, and its mask is `GUEST_MASK` again.
            Signal::SIGPROF => {
                guest
                    .deliver_signal(SignalDelivery {
                        interruption: Interruption::Return {
                            syscall: libc::SYS_write,
                            result: -(Errno::ERESTARTSYS.into_raw() as i64),
                        },
                        ..delivery_of(raw)
                    })
                    .await
            }
            // The negative control: the frame mask misses SIGINT.
            Signal::SIGWINCH => {
                guest
                    .deliver_signal(SignalDelivery {
                        frame_mask: 0,
                        ..delivery_of(raw)
                    })
                    .await
            }
            // An approval, then an injection that voids it.
            Signal::SIGHUP => {
                let outcome = guest.deliver_signal(delivery_of(raw)).await;
                guest.send_rpc(format!("{signal:?} {outcome:?}")).await;
                let _ = guest.inject(Getpid::new()).await;
                return Ok(Some(signal));
            }
            // An injection inside the callback, then the guest's registers
            // put back, then an approval: the kernel delivers the reported
            // instance from the injection's stop, with its own siginfo.
            Signal::SIGURG => {
                let regs = guest.regs().await;
                let _ = guest.inject(Getpid::new()).await;
                guest.set_regs(regs).await.map_err(|_| Errno::EIO)?;
                guest.deliver_signal(delivery_of(raw)).await
            }
            // An approval, then a register write that voids it.
            Signal::SIGPIPE => {
                let outcome = guest.deliver_signal(delivery_of(raw)).await;
                guest.send_rpc(format!("{signal:?} {outcome:?}")).await;
                let regs = guest.regs().await;
                guest.set_regs(regs).await.map_err(|_| Errno::EIO)?;
                return Ok(Some(signal));
            }
            // An approval, then a tail injection, which never returns to the
            // callback.
            Signal::SIGTTOU => {
                let outcome = guest.deliver_signal(delivery_of(raw)).await;
                guest.send_rpc(format!("{signal:?} {outcome:?}")).await;
                guest.tail_inject(Getpid::new()).await
            }
            // An approval, then an exec, which never returns to the callback.
            Signal::SIGPWR => {
                let outcome = guest.deliver_signal(delivery_of(raw)).await;
                guest.send_rpc(format!("{signal:?} {outcome:?}")).await;
                let exec = Execve::new()
                    .with_path(PathPtr::from_ptr(TRUE_PATH.as_ptr().cast()))
                    .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(
                        TRUE_ARGV.as_ptr() as usize
                    ))
                    .with_envp(None);
                let failed = guest.inject(exec).await;
                guest.send_rpc(format!("exec returned {failed:?}")).await;
                return Ok(Some(signal));
            }
            // An approval, then a blocking injection, during which another
            // thread of the guest execs: Linux kills this thread and loses
            // its signal, and this callback is cancelled with it.
            Signal::SIGVTALRM => {
                let outcome = guest.deliver_signal(delivery_of(raw)).await;
                guest.send_rpc(format!("{signal:?} {outcome:?}")).await;
                let _ = guest.inject(Pause::new()).await;
                return Ok(Some(signal));
            }
            // Inside the guest's kernel-run `rt_sigsuspend`: frame and
            // current masks differ.
            Signal::SIGALRM => guest.deliver_signal(suspended_delivery_of(raw)).await,
            // The same, but the first instance after an injection, which
            // lets the kernel restore the saved mask: the signal is then
            // blocked at resume, and the kernel requeues it. At a signal's
            // own delivery stop an injection leaves its own return value in
            // the guest's `rax`, so the tool puts the guest's registers back
            // (before it asks for approval) to keep `rt_sigsuspend`'s
            // ERESTARTNOHAND.
            Signal::SIGXCPU => {
                if !FIRST_XCPU_SEEN.swap(true, Ordering::SeqCst) {
                    let regs = guest.regs().await;
                    let _ = guest.inject(Getpid::new()).await;
                    guest.set_regs(regs).await.map_err(|_| Errno::EIO)?;
                }
                guest.deliver_signal(suspended_delivery_of(raw)).await
            }
            _ => return Ok(Some(signal)),
        };
        guest.send_rpc(format!("{signal:?} {outcome:?}")).await;
        Ok(Some(signal))
    }

    async fn handle_raw_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: i32,
    ) -> Result<Option<i32>, Errno> {
        if signal == REALTIME {
            // The guest queues it with `rt_tgsigqueueinfo`.
            let outcome = guest
                .deliver_signal(SignalDelivery {
                    interruption: Interruption::Return {
                        syscall: libc::SYS_rt_tgsigqueueinfo,
                        result: 0,
                    },
                    ..delivery_of(signal)
                })
                .await;
            guest.send_rpc(format!("{signal} {outcome:?}")).await;
        }
        Ok(Some(signal))
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::Write(write) = syscall
            && write.fd() == PROBE_FD
            && write.len() == 0
        {
            let outcome = guest.deliver_signal(delivery_of(libc::SIGUSR1)).await;
            guest.send_rpc(format!("syscall {outcome:?}")).await;
            return Ok(0);
        }
        if let Syscall::Write(write) = syscall
            && write.fd() == HELD_FD
            && write.len() == 0
        {
            let set = write.buf().and_then(|buf| Addr::from_raw(buf.as_raw()));
            guest
                .inject(
                    RtSigprocmask::new()
                        .with_how(libc::SIG_UNBLOCK)
                        .with_set(set)
                        .with_oldset(None)
                        .with_sigsetsize(8),
                )
                .await?;
            let interrupted = guest.inject(Getpid::new()).await;
            guest.send_rpc(format!("getpid {interrupted:?}")).await;
            return Ok(interrupted?);
        }
        guest.tail_inject(syscall).await
    }
}

static HANDLED: AtomicUsize = AtomicUsize::new(0);
static HANDLER_MASK: AtomicU64 = AtomicU64::new(0);
static HANDLER_VALUE: AtomicU64 = AtomicU64::new(0);

extern "C" fn record_siginfo_code(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    let code = unsafe { (*info).si_code };
    HANDLER_VALUE.store(code as u32 as u64, Ordering::SeqCst);
    record_handler_mask(0);
}

/// The value the realtime case queues its signal with.
const QUEUED_VALUE: usize = 0x5157_4a11;

extern "C" fn record_siginfo_value(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    let value = unsafe { (*info).si_value().sival_ptr as usize };
    HANDLER_VALUE.store(value as u64, Ordering::SeqCst);
    record_handler_mask(0);
}

extern "C" fn record_handler_mask(_signal: libc::c_int) {
    // SAFETY: a NULL set only reads the mask into `old`; sigprocmask is
    // async-signal-safe.
    let mask = unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut old);
        *(&old as *const libc::sigset_t as *const u64)
    };
    HANDLER_MASK.store(mask, Ordering::SeqCst);
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// Installs the recording handler for `signal` with `SA_MASK`, blocks
/// exactly `GUEST_MASK`, signals itself with `tgkill`, and returns the mask
/// the handler ran under.
fn signal_self_under_handler(signal: i32) -> u64 {
    HANDLED.store(0, Ordering::SeqCst);
    // SAFETY: the action and sets are fully initialized before use; the
    // handler touches only atomics and sigprocmask.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_handler_mask as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()),
            0
        );
        let ret = libc::syscall(
            libc::SYS_tgkill,
            libc::getpid(),
            libc::syscall(libc::SYS_gettid),
            signal,
        );
        assert_eq!(ret, 0);
    }
    assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
    HANDLER_MASK.load(Ordering::SeqCst)
}

/// Pins the tracer's log level to warnings, as the other signal tests do.
fn quiet_logs() {
    let collector = tracing_subscriber::fmt().with_env_filter("warn").finish();
    let _ = tracing::subscriber::set_global_default(collector);
}

fn run(name: &str, guest: fn()) -> (ExitStatus, Vec<String>) {
    quiet_logs();
    let (output, log) = test_fn::<DeliverTool, _>(guest).expect(name);
    let outcomes = log.outcomes.lock().unwrap().clone();
    if output.status != ExitStatus::Exited(0) {
        eprintln!(
            "{name}: guest exited {:?}; tool saw {outcomes:?}; guest stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    (output.status, outcomes)
}

#[test]
fn an_approved_delivery_runs_its_handler_under_the_approved_mask() {
    let (status, outcomes) = run("approved", || {
        let mask = signal_self_under_handler(libc::SIGUSR1);
        assert_eq!(
            mask,
            GUEST_MASK | SA_MASK | signal_set_bit(libc::SIGUSR1),
            "the handler's mask is the approved one"
        );
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(outcomes, ["SIGUSR1 Accepted"]);
}

#[test]
fn a_held_signal_is_approved_at_its_report() {
    let (status, outcomes) = run("held", || {
        HANDLED.store(0, Ordering::SeqCst);
        // SAFETY: the action and sets are fully initialized before use; the
        // handler touches only atomics and sigprocmask.
        let (ret, errno) = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_handler_mask as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2);
            assert_eq!(
                libc::sigaction(libc::SIGPROF, &action, std::ptr::null_mut()),
                0
            );
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::sigaddset(&mut set, libc::SIGPROF);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()),
                0
            );
            let ret = libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGPROF,
            );
            assert_eq!(ret, 0);
            let mut unblock: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut unblock);
            libc::sigaddset(&mut unblock, libc::SIGPROF);
            let ret = libc::syscall(
                libc::SYS_write,
                HELD_FD,
                &unblock as *const libc::sigset_t,
                0usize,
            );
            (ret, *libc::__errno_location())
        };
        assert_eq!((ret, errno), (-1, libc::EINTR));
        assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
        assert_eq!(
            HANDLER_MASK.load(Ordering::SeqCst),
            GUEST_MASK | SA_MASK | signal_set_bit(libc::SIGPROF)
        );
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(
        outcomes,
        ["getpid Err(ERESTARTSYS)", "SIGPROF Accepted"],
        "the held signal is approved at its report"
    );
}

/// The `sigset_t` of the kernel signal set `set`.
fn signal_set(set: u64) -> libc::sigset_t {
    // SAFETY: the set is initialized by sigemptyset before any use.
    unsafe {
        let mut sigset: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sigset);
        for signal in 1..=64 {
            if set & signal_set_bit(signal) != 0 {
                libc::sigaddset(&mut sigset, signal);
            }
        }
        sigset
    }
}

/// Arms a one-shot 20 ms `signal` timer and waits in `rt_sigsuspend` with
/// `SUSPEND_TEMPORARY`, from `SUSPEND_SAVED`. Returns the handler's mask,
/// after checking that the wait ended with EINTR, the handler ran once and
/// the saved mask is back.
fn suspend_until(signal: i32) -> u64 {
    HANDLED.store(0, Ordering::SeqCst);
    // SAFETY: every struct is fully initialized before use; the handler
    // touches only atomics and sigprocmask.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_handler_mask as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        let saved = signal_set(SUSPEND_SAVED);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut()),
            0
        );
        let mut event: libc::sigevent = std::mem::zeroed();
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = signal;
        let mut timer: libc::timer_t = std::mem::zeroed();
        assert_eq!(
            libc::timer_create(libc::CLOCK_MONOTONIC, &mut event, &mut timer),
            0
        );
        let mut when: libc::itimerspec = std::mem::zeroed();
        when.it_value.tv_nsec = 20_000_000;
        assert_eq!(
            libc::timer_settime(timer, 0, &when, std::ptr::null_mut()),
            0
        );
        let temporary = SUSPEND_TEMPORARY;
        let ret = libc::syscall(libc::SYS_rt_sigsuspend, &temporary as *const u64, 8usize);
        assert_eq!((ret, *libc::__errno_location()), (-1, libc::EINTR));
        assert_eq!(libc::timer_delete(timer), 0);
    }
    assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
    // SAFETY: a NULL set only reads the mask.
    let restored = unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut old);
        *(&old as *const libc::sigset_t as *const u64)
    };
    assert_eq!(
        restored, SUSPEND_SAVED,
        "rt_sigsuspend restored the saved mask"
    );
    HANDLER_MASK.load(Ordering::SeqCst)
}

#[test]
fn an_approval_after_a_callback_injection_delivers_the_reported_instance() {
    let (status, outcomes) = run("after an injection", || {
        HANDLED.store(0, Ordering::SeqCst);
        // SAFETY: the action and sets are fully initialized before use; the
        // handler touches only atomics and sigprocmask.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_siginfo_code as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2);
            assert_eq!(
                libc::sigaction(libc::SIGURG, &action, std::ptr::null_mut()),
                0
            );
            let mask = signal_set(GUEST_MASK);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()),
                0
            );
            let ret = libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGURG,
            );
            assert_eq!(ret, 0, "tgkill's own result survives the injection");
        }
        assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
        assert_eq!(
            HANDLER_MASK.load(Ordering::SeqCst),
            GUEST_MASK | SA_MASK | signal_set_bit(libc::SIGURG)
        );
        assert_eq!(
            HANDLER_VALUE.load(Ordering::SeqCst),
            libc::SI_TKILL as u32 as u64,
            "the handler got tgkill's siginfo, not the injection stop's"
        );
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(outcomes, ["SIGURG Accepted"]);
}

#[test]
fn a_temporary_mask_delivery_is_approved_with_distinct_frame_and_current_masks() {
    let (status, outcomes) = run("temporary mask", || {
        assert_eq!(
            suspend_until(libc::SIGALRM),
            SUSPEND_TEMPORARY | SA_MASK | signal_set_bit(libc::SIGALRM)
        );
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(outcomes, ["SIGALRM Accepted"]);
}

#[test]
fn a_signal_blocked_at_resume_is_not_approved_and_is_delivered_later() {
    let (status, outcomes) = run("blocked at resume", || {
        assert_eq!(
            suspend_until(libc::SIGXCPU),
            SUSPEND_TEMPORARY | SA_MASK | signal_set_bit(libc::SIGXCPU)
        );
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(
        outcomes,
        ["SIGXCPU Unavailable(BlockedAtResume)", "SIGXCPU Accepted"],
        "the requeued instance is delivered again, and approved"
    );
}

#[test]
fn a_realtime_signal_is_approved_through_the_raw_hook() {
    let (status, outcomes) = run("realtime", || {
        HANDLED.store(0, Ordering::SeqCst);
        // SAFETY: the action, sets and siginfo are fully initialized before
        // use; the handler touches only atomics and sigprocmask.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_siginfo_value as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2);
            assert_eq!(libc::sigaction(REALTIME, &action, std::ptr::null_mut()), 0);
            let mask = signal_set(GUEST_MASK);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()),
                0
            );
            let mut info: libc::siginfo_t = std::mem::zeroed();
            // si_signo, si_errno, si_code, then the queued fields: pid, uid
            // and the value.
            let words = &mut info as *mut libc::siginfo_t as *mut i32;
            *words = REALTIME;
            *words.add(2) = libc::SI_QUEUE;
            *words.add(4) = libc::getpid();
            *words.add(5) = libc::getuid() as i32;
            *(words.add(6) as *mut usize) = QUEUED_VALUE;
            let ret = libc::syscall(
                libc::SYS_rt_tgsigqueueinfo,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                REALTIME,
                &info as *const libc::siginfo_t,
            );
            assert_eq!(ret, 0);
        }
        assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
        assert_eq!(
            HANDLER_MASK.load(Ordering::SeqCst),
            GUEST_MASK | SA_MASK | signal_set_bit(REALTIME)
        );
        assert_eq!(
            HANDLER_VALUE.load(Ordering::SeqCst),
            QUEUED_VALUE as u64,
            "the handler got the queued instance's value"
        );
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(outcomes, ["40 Accepted"]);
}

#[test]
fn a_wrong_frame_mask_is_a_mismatch_and_the_old_path_delivers() {
    let (status, outcomes) = run("mismatch", || {
        let mask = signal_self_under_handler(libc::SIGWINCH);
        assert_eq!(mask, GUEST_MASK | SA_MASK | signal_set_bit(libc::SIGWINCH));
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(outcomes.len(), 1);
    assert!(
        outcomes[0].starts_with("SIGWINCH Mismatch(SignalDeliveryMismatch { field: FrameMask"),
        "{outcomes:?}"
    );
}

#[test]
fn a_syscall_stop_is_not_a_delivery_point() {
    let (status, outcomes) = run("syscall stop", || {
        // SAFETY: the tool replaces this zero-length write.
        let ret = unsafe { libc::write(PROBE_FD, std::ptr::null(), 0) };
        assert_eq!(ret, 0);
    });
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(outcomes, ["syscall Unavailable(NotInSignalCallback)"]);
}

/// `BrokenSignalApproval`'s reason for an approval voided by an injection or
/// a register write.
const VOIDED: &str =
    "an injection or a register write after the approval changed the stop it was checked at";

/// Runs a guest that signals itself with `signal`, whose callback approves
/// and then breaks the approval, and checks that the run ends with the named
/// failure (`reverie_ptrace::BrokenSignalApproval`) naming the signal and
/// `reason`, instead of resuming the guest.
fn assert_broken_approval_fails_the_run(guest: fn(), signal: i32, reason: &str) {
    quiet_logs();
    let error = match test_fn::<DeliverTool, _>(guest) {
        Ok((output, log)) => panic!(
            "expected the named failure; the guest exited {:?} and the tool saw {:?}",
            output.status,
            log.outcomes.lock().unwrap()
        ),
        Err(error) => error,
    };
    let failure = match &error {
        Error::Tool(inner) => inner.downcast_ref::<reverie_ptrace::BrokenSignalApproval>(),
        _ => None,
    };
    let failure = failure.unwrap_or_else(|| panic!("expected BrokenSignalApproval, got {error:?}"));
    assert_eq!(failure.signal, signal, "{failure}");
    assert_eq!(failure.reason, reason, "{failure}");
}

#[test]
fn an_injection_after_an_approval_fails_the_run() {
    assert_broken_approval_fails_the_run(
        || {
            signal_self_under_handler(libc::SIGHUP);
        },
        libc::SIGHUP,
        VOIDED,
    );
}

#[test]
fn a_register_write_after_an_approval_fails_the_run() {
    assert_broken_approval_fails_the_run(
        || {
            signal_self_under_handler(libc::SIGPIPE);
        },
        libc::SIGPIPE,
        VOIDED,
    );
}

#[test]
fn a_tail_injection_after_an_approval_fails_the_run() {
    assert_broken_approval_fails_the_run(
        || {
            signal_self_under_handler(libc::SIGTTOU);
        },
        libc::SIGTTOU,
        "then made a tail injection",
    );
}

#[test]
fn an_exec_after_an_approval_fails_the_run() {
    assert_broken_approval_fails_the_run(
        || {
            signal_self_under_handler(libc::SIGPWR);
        },
        libc::SIGPWR,
        "then executed a program",
    );
}

/// The approving thread is not the main thread: the main thread's loop
/// handles the exec, instead of the approving thread's own.
#[test]
fn an_exec_after_an_approval_on_a_spawned_thread_fails_the_run() {
    assert_broken_approval_fails_the_run(
        || {
            let _ = std::thread::spawn(|| signal_self_under_handler(libc::SIGPWR)).join();
        },
        libc::SIGPWR,
        "then executed a program",
    );
}

/// A callback that approved a delivery, cancelled because another thread
/// execs while it waits in an injection, broke nothing: Linux kills the
/// approving thread and loses its signal, and the new program runs.
#[test]
fn an_approving_callback_cancelled_by_another_threads_exec_breaks_nothing() {
    let (status, outcomes) = run("cancelled by exec", || {
        // SAFETY: the action is fully initialized before use; the handler
        // touches only atomics and sigprocmask. The spawned thread only
        // sleeps and execs, or exits the group if the exec fails.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_handler_mask as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGVTALRM, &action, std::ptr::null_mut()),
                0
            );
            let mask = signal_set(GUEST_MASK);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()),
                0
            );
        }
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(200));
            // SAFETY: TRUE_PATH is NUL-terminated and TRUE_ARGV is a
            // NULL-terminated array; exit_group ends the run if exec fails.
            unsafe {
                libc::syscall(
                    libc::SYS_execve,
                    TRUE_PATH.as_ptr(),
                    TRUE_ARGV.as_ptr(),
                    std::ptr::null::<usize>(),
                );
                libc::syscall(libc::SYS_exit_group, 4);
            }
        });
        // SAFETY: tgkill takes plain values.
        unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGVTALRM,
            );
            // Not reached: the other thread's exec ends this program.
            libc::syscall(libc::SYS_exit_group, 3);
        }
    });
    assert_eq!(status, ExitStatus::Exited(0), "the new program ran");
    assert_eq!(outcomes, ["SIGVTALRM Accepted"]);
}
