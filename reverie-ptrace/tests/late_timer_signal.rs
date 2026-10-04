/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer's overflow interrupt can arrive after the guest has already
//! reached its next syscall. That syscall cancels the timer, but the tracer's
//! own overflow signal is still in flight. It belongs to Reverie, not to the
//! guest: it must not interrupt a syscall the tool injects at that stop, and it
//! must never be delivered to the guest.
//!
//! Each iteration arms a precise timer whose target is beyond the syscall, so
//! no timer event is due, and places the counter overflow a few branches before
//! the syscall. Ordinary overflow-interrupt latency then lands the interrupt
//! after the syscall has been entered.
//!
//! A guest's own signal of the same number pending at such an injection is not
//! the timer's and must still reach the guest, including a file notification
//! whose siginfo is identical to the timer's.

#![cfg(target_arch = "x86_64")]

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
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
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::Getpid;
use reverie::syscalls::RtTgsigqueueinfo;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::do_branches;
use reverie_ptrace::testing::late_timer_signals_discarded;
use reverie_ptrace::testing::print_tracee_output;
use reverie_ptrace::testing::test_fn_with_config;
use reverie_ptrace::testing::timer_overflow_records_expired;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum Report {
    TimerEvent,
    InjectedSyscall,
    InjectError(i32),
}

#[derive(Debug, Default)]
struct Log {
    timer_events: AtomicU64,
    injected_syscalls: AtomicU64,
    inject_errors: Mutex<Vec<i32>>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Config {
    timeout_rcbs: u64,
    retry: bool,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Report;
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        match report {
            Report::TimerEvent => {
                self.timer_events.fetch_add(1, Ordering::SeqCst);
            }
            Report::InjectedSyscall => {
                self.injected_syscalls.fetch_add(1, Ordering::SeqCst);
            }
            Report::InjectError(errno) => self
                .inject_errors
                .lock()
                .expect("inject error log lock poisoned")
                .push(errno),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct LateTimerTool;

#[reverie::tool]
impl Tool for LateTimerTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_cfg: &Config) -> Subscription {
        Subscription::all()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let timeout = TimerSchedule::Rcbs(guest.config().timeout_rcbs);
                guest.set_timer_precise(timeout)?;
                Ok(0)
            }
            Sysno::getppid => {
                // The syscall event has cancelled the timer; an injected syscall
                // at this stop must complete without a Reverie-owned signal.
                let result = if guest.config().retry {
                    guest.inject_with_retry(Getpid::new()).await
                } else {
                    guest.inject(Getpid::new()).await
                };
                match result {
                    Ok(_) => guest.send_rpc(Report::InjectedSyscall).await,
                    Err(errno) => guest.send_rpc(Report::InjectError(errno.into_raw())).await,
                }
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(Report::TimerEvent).await;
    }
}

const ITERS: u64 = 400;
/// Upper bound on the number of distances, in RCBs, by which the counter
/// overflow precedes the syscall.
const MAX_OVERFLOW_LEADS: u64 = 80;
/// RCBs from arming the timer to the counter overflow.
const ARM_RCBS: u64 = 10_000;

fn arm_precise_timer() {
    // SAFETY: the tool intercepts clock_getres and never runs it, so the
    // null result pointer is not dereferenced.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") libc::SYS_clock_getres => _,
            in("rdi") libc::CLOCK_MONOTONIC,
            in("rsi") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

fn syscall_with_injection() {
    // SAFETY: getppid has no arguments and no memory effects.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") libc::SYS_getppid => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

/// The tests in this file run one at a time, so that the process-wide discard
/// count of each belongs to it alone.
fn serialize() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs the late-overflow loop. The guest first queues `queued_rt` blocked
/// real-time signals, which stay pending ahead of every timer notification.
fn run(retry: bool, queued_rt: usize) {
    let _serial = serialize();
    // Precise timers need a PMU; GitHub-hosted runners have none. The
    // self-hosted hardware job runs this test.
    if !reverie_ptrace::is_perf_supported() {
        return;
    }
    let discarded_before = late_timer_signals_discarded();
    let margin = reverie_ptrace::PmuConfig::new().skid_margin();
    // Keep the syscall well inside the margin, leaving room for the loop's own
    // branches, so the target is never reached. Supported margins range from
    // 100 to 10,000 RCBs.
    let overflow_leads = MAX_OVERFLOW_LEADS.min(margin / 4);
    assert!(overflow_leads > 0, "skid margin {margin} leaves no lead");
    // The counter overflows `margin` RCBs before the target, i.e. `ARM_RCBS`
    // after arming. Execute slightly more than that before the syscall.
    let timeout_rcbs = ARM_RCBS + margin;
    let (output, log) = test_fn_with_config::<LateTimerTool, _>(
        move || {
            if queued_rt > 0 {
                let rt = libc::SIGRTMIN();
                // SAFETY: valid signal set arguments.
                unsafe {
                    let mut set: libc::sigset_t = core::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, rt);
                    assert_eq!(
                        libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()),
                        0
                    );
                    for _ in 0..queued_rt {
                        assert_eq!(
                            libc::syscall(libc::SYS_tgkill, libc::getpid(), libc::gettid(), rt),
                            0
                        );
                    }
                }
            }
            for i in 0..ITERS {
                arm_precise_timer();
                do_branches(ARM_RCBS + i % overflow_leads);
                syscall_with_injection();
            }
        },
        Config {
            timeout_rcbs,
            retry,
        },
        true,
    )
    .expect("run late-timer-signal guest");

    let errors = log
        .inject_errors
        .lock()
        .expect("inject error log lock poisoned")
        .clone();
    if output.status != ExitStatus::Exited(0) || !errors.is_empty() {
        print_tracee_output(&output);
    }
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(
        errors,
        Vec::<i32>::new(),
        "injected syscalls were interrupted"
    );
    assert_eq!(log.injected_syscalls.load(Ordering::SeqCst), ITERS);
    assert_eq!(log.timer_events.load(Ordering::SeqCst), 0);
    let discarded = late_timer_signals_discarded() - discarded_before;
    println!("{discarded} late timer signals discarded in {ITERS} injections");
    assert!(
        discarded > 0,
        "no late timer signal reached an injected syscall, so nothing was tested"
    );
}

#[test]
fn late_overflow_signal_does_not_interrupt_injected_syscall() {
    run(false, 0);
}

#[test]
fn late_overflow_signal_is_not_delivered_to_guest_after_retry() {
    run(true, 0);
}

/// Real-time signals queue one entry each, so the notification can sit beyond
/// any fixed-size read of the pending queue.
#[test]
fn late_overflow_signal_behind_queued_realtime_signals_is_discarded() {
    run(false, 100);
}

#[derive(Debug, Default)]
struct ForeignLog {
    injected_syscalls: AtomicU64,
    inject_errors: Mutex<Vec<i32>>,
}

#[reverie::global_tool]
impl GlobalTool for ForeignLog {
    type Request = Report;
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        match report {
            Report::InjectedSyscall => {
                self.injected_syscalls.fetch_add(1, Ordering::SeqCst);
            }
            Report::InjectError(errno) => self
                .inject_errors
                .lock()
                .expect("inject error log lock poisoned")
                .push(errno),
            Report::TimerEvent => panic!("no timer was requested"),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct ForeignSignalTool;

#[reverie::tool]
impl Tool for ForeignSignalTool {
    type GlobalState = ForeignLog;
    type ThreadState = ();

    fn subscriptions(_cfg: &Config) -> Subscription {
        Subscription::all()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::getppid => {
                // Make the timer's signal number pending for the stopped guest, so its
                // delivery stop precedes the injected syscall instruction exactly as a
                // late overflow notification's does. Its siginfo is not an overflow
                // notification's.
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        guest.pid().as_raw(),
                        guest.tid().as_raw(),
                        libc::SIGSTKFLT,
                    )
                };
                assert_eq!(
                    sent,
                    0,
                    "tgkill failed: {}",
                    std::io::Error::last_os_error()
                );
                let result = if guest.config().retry {
                    guest.inject_with_retry(Getpid::new()).await
                } else {
                    guest.inject(Getpid::new()).await
                };
                match result {
                    Ok(_) => guest.send_rpc(Report::InjectedSyscall).await,
                    Err(errno) => guest.send_rpc(Report::InjectError(errno.into_raw())).await,
                }
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

const FOREIGN_ITERS: u64 = 20;

static FOREIGN_SIGNALS_HANDLED: AtomicU64 = AtomicU64::new(0);
static FOREIGN_SIGNAL_OUTSIDE_HANDLER: AtomicBool = AtomicBool::new(false);

extern "C" fn count_foreign_signal(signo: libc::c_int) {
    if signo != libc::SIGSTKFLT {
        FOREIGN_SIGNAL_OUTSIDE_HANDLER.store(true, Ordering::SeqCst);
    }
    FOREIGN_SIGNALS_HANDLED.fetch_add(1, Ordering::SeqCst);
}

fn run_foreign(retry: bool) {
    let _serial = serialize();
    let (output, log) = test_fn_with_config::<ForeignSignalTool, _>(
        || {
            // SAFETY: the handler only touches atomics.
            unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = count_foreign_signal as extern "C" fn(libc::c_int) as usize;
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGSTKFLT, &action, core::ptr::null_mut()),
                    0
                );
            }
            for i in 0..FOREIGN_ITERS {
                syscall_with_injection();
                assert_eq!(
                    FOREIGN_SIGNALS_HANDLED.load(Ordering::SeqCst),
                    i + 1,
                    "the guest's signal was not delivered after injection {i}"
                );
            }
            assert!(!FOREIGN_SIGNAL_OUTSIDE_HANDLER.load(Ordering::SeqCst));
        },
        Config {
            timeout_rcbs: 0,
            retry,
        },
        true,
    )
    .expect("run foreign-signal guest");

    if output.status != ExitStatus::Exited(0) {
        print_tracee_output(&output);
    }
    assert_eq!(output.status, ExitStatus::Exited(0));
    let errors = log
        .inject_errors
        .lock()
        .expect("inject error log lock poisoned")
        .clone();
    if retry {
        assert_eq!(errors, Vec::<i32>::new());
        assert_eq!(log.injected_syscalls.load(Ordering::SeqCst), FOREIGN_ITERS);
    } else {
        // The pending signal interrupts the injection instead of being
        // discarded.
        assert_eq!(
            errors,
            vec![reverie::Errno::ERESTARTSYS.into_raw(); FOREIGN_ITERS as usize]
        );
        assert_eq!(log.injected_syscalls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn guest_signal_interrupts_injected_syscall() {
    run_foreign(false);
}

#[test]
fn guest_signal_is_delivered_after_retry() {
    run_foreign(true);
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum CollisionReport {
    TimerEvent,
    Probe { fd: i32, result: i64 },
}

#[derive(Debug, Default)]
struct CollisionLog {
    timer_events: AtomicU64,
    probes: Mutex<Vec<(i32, i64)>>,
}

#[reverie::global_tool]
impl GlobalTool for CollisionLog {
    type Request = CollisionReport;
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, _from: Pid, report: CollisionReport) {
        match report {
            CollisionReport::TimerEvent => {
                self.timer_events.fetch_add(1, Ordering::SeqCst);
            }
            CollisionReport::Probe { fd, result } => self
                .probes
                .lock()
                .expect("probe log lock poisoned")
                .push((fd, result)),
        }
    }
}

/// Guest descriptors of a nonblocking pipe whose read end notifies the guest
/// thread with the timer's signal number.
const NOTIFY_READ_FD: usize = 900;
const NOTIFY_WRITE_FD: usize = 901;

// `fcntl(2)` definitions missing from `libc`.
const F_SETOWN_EX: libc::c_int = 15;
const F_SETSIG: libc::c_int = 10;
const F_OWNER_TID: libc::c_int = 0;

#[repr(C)]
struct FOwnerEx {
    kind: libc::c_int,
    pid: libc::pid_t,
}

static NOTIFY_BYTE: u8 = b'x';
static mut NOTIFY_SINK: [u8; 8] = [0; 8];

/// Descriptor numbers of the tracer's perf events, among them every timer
/// counter.
fn tracer_perf_fds() -> Vec<usize> {
    std::fs::read_dir("/proc/self/fd")
        .expect("read tracer descriptors")
        .flatten()
        .filter(|entry| {
            std::fs::read_link(entry.path())
                .is_ok_and(|target| target.to_string_lossy().contains("perf_event"))
        })
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect()
}

fn raw_syscall(nr: Sysno, args: [usize; 3]) -> Syscall {
    Syscall::from_raw(nr, SyscallArgs::new(args[0], args[1], args[2], 0, 0, 0))
}

#[derive(Debug, Default, Clone)]
struct CollidingDescriptorTool;

#[reverie::tool]
impl Tool for CollidingDescriptorTool {
    type GlobalState = CollisionLog;
    type ThreadState = ();

    fn subscriptions(_cfg: &Config) -> Subscription {
        Subscription::all()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let timeout = TimerSchedule::Rcbs(guest.config().timeout_rcbs);
                guest.set_timer_precise(timeout)?;
                Ok(0)
            }
            Sysno::getppid => {
                // Give the guest's notifying pipe each descriptor number of a
                // tracer perf event in turn. A guest notification then has the
                // timer's signal number, code, and descriptor number, and is
                // pending at the stop that precedes the injected syscall.
                // Duplicates share one open file description, whose fasync
                // entry keeps the descriptor number it was registered with
                // until `O_ASYNC` is cleared and set again.
                for fd in tracer_perf_fds() {
                    for (nr, args) in [
                        (Sysno::dup2, [NOTIFY_READ_FD, fd, 0]),
                        (
                            Sysno::fcntl,
                            [fd, libc::F_SETFL as usize, libc::O_NONBLOCK as usize],
                        ),
                        (
                            Sysno::fcntl,
                            [
                                fd,
                                libc::F_SETFL as usize,
                                (libc::O_NONBLOCK | libc::O_ASYNC) as usize,
                            ],
                        ),
                        (
                            Sysno::write,
                            [NOTIFY_WRITE_FD, &raw const NOTIFY_BYTE as usize, 1],
                        ),
                    ] {
                        guest
                            .inject(raw_syscall(nr, args))
                            .await
                            .unwrap_or_else(|errno| panic!("{nr} failed: {errno}"));
                    }
                    let result = match guest.inject(Getpid::new()).await {
                        Ok(pid) => pid,
                        Err(errno) => -i64::from(errno.into_raw()),
                    };
                    guest
                        .send_rpc(CollisionReport::Probe {
                            fd: fd as i32,
                            result,
                        })
                        .await;
                    for (nr, args) in [
                        (
                            Sysno::read,
                            [NOTIFY_READ_FD, &raw mut NOTIFY_SINK as usize, 8],
                        ),
                        (Sysno::close, [fd, 0, 0]),
                    ] {
                        guest
                            .inject(raw_syscall(nr, args))
                            .await
                            .unwrap_or_else(|errno| panic!("{nr} failed: {errno}"));
                    }
                }
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(CollisionReport::TimerEvent).await;
    }
}

static COLLIDING_SIGNALS_HANDLED: AtomicU64 = AtomicU64::new(0);

extern "C" fn count_colliding_signal(_signo: libc::c_int) {
    COLLIDING_SIGNALS_HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// How far the guest runs its precise timer before the probing syscall.
#[derive(Clone, Copy)]
enum TimerProgress {
    NotRequested,
    NotOverflowed,
    Fired,
    /// The timer overflows while the guest blocks its signal, and the guest
    /// then flushes the pending notification by ignoring the signal. No stop
    /// consumes the notification.
    FlushedByGuest,
}

fn run_colliding_descriptor(progress: TimerProgress) {
    let _serial = serialize();
    // The notification collides with a perf event descriptor; without a PMU
    // there is none.
    if !reverie_ptrace::is_perf_supported() {
        return;
    }
    let timeout_rcbs = match progress {
        TimerProgress::NotRequested => 0,
        TimerProgress::NotOverflowed => 1_000_000,
        TimerProgress::Fired | TimerProgress::FlushedByGuest => 50_000,
    };
    let expired_before = timer_overflow_records_expired();
    let (output, log) = test_fn_with_config::<CollidingDescriptorTool, _>(
        move || {
            // SAFETY: the handler only touches an atomic, and the descriptor
            // operations use valid arguments.
            unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = count_colliding_signal as extern "C" fn(libc::c_int) as usize;
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGSTKFLT, &action, core::ptr::null_mut()),
                    0
                );
                let mut pipe = [0; 2];
                assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK), 0);
                assert_eq!(
                    libc::dup2(pipe[0], NOTIFY_READ_FD as i32),
                    NOTIFY_READ_FD as i32
                );
                assert_eq!(
                    libc::dup2(pipe[1], NOTIFY_WRITE_FD as i32),
                    NOTIFY_WRITE_FD as i32
                );
                let owner = FOwnerEx {
                    kind: F_OWNER_TID,
                    pid: libc::syscall(libc::SYS_gettid) as libc::pid_t,
                };
                assert_eq!(libc::fcntl(NOTIFY_READ_FD as i32, F_SETOWN_EX, &owner), 0);
                assert_eq!(
                    libc::fcntl(NOTIFY_READ_FD as i32, F_SETSIG, libc::SIGSTKFLT),
                    0
                );
            }
            match progress {
                TimerProgress::NotRequested => {}
                TimerProgress::NotOverflowed => arm_precise_timer(),
                TimerProgress::Fired => {
                    arm_precise_timer();
                    do_branches(timeout_rcbs * 3);
                }
                // SAFETY: valid signal set and handler arguments.
                TimerProgress::FlushedByGuest => unsafe {
                    let mut set: libc::sigset_t = core::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, libc::SIGSTKFLT);
                    assert_eq!(
                        libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()),
                        0
                    );
                    arm_precise_timer();
                    do_branches(timeout_rcbs * 3);
                    assert_ne!(libc::signal(libc::SIGSTKFLT, libc::SIG_IGN), libc::SIG_ERR);
                    let mut action: libc::sigaction = core::mem::zeroed();
                    action.sa_sigaction =
                        count_colliding_signal as extern "C" fn(libc::c_int) as usize;
                    libc::sigemptyset(&mut action.sa_mask);
                    assert_eq!(
                        libc::sigaction(libc::SIGSTKFLT, &action, core::ptr::null_mut()),
                        0
                    );
                    assert_eq!(
                        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut()),
                        0
                    );
                },
            }
            syscall_with_injection();
            assert!(COLLIDING_SIGNALS_HANDLED.load(Ordering::SeqCst) > 0);
        },
        Config {
            timeout_rcbs,
            retry: false,
        },
        true,
    )
    .expect("run colliding-descriptor guest");

    if output.status != ExitStatus::Exited(0) {
        print_tracee_output(&output);
    }
    assert_eq!(output.status, ExitStatus::Exited(0));
    let expected_timer_events = match progress {
        TimerProgress::Fired => 1,
        TimerProgress::NotRequested
        | TimerProgress::NotOverflowed
        | TimerProgress::FlushedByGuest => 0,
    };
    if let TimerProgress::FlushedByGuest = progress {
        // Otherwise no overflow was recorded and nothing was tested.
        assert!(
            timer_overflow_records_expired() > expired_before,
            "the flushed notification's overflow records did not expire"
        );
    }
    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        expected_timer_events
    );
    let probes = log.probes.lock().expect("probe log lock poisoned").clone();
    assert!(
        !probes.is_empty(),
        "the tracer has no perf event descriptor"
    );
    // Each notification interrupts the injection instead of being discarded.
    for (fd, result) in probes {
        assert_eq!(
            result,
            -i64::from(reverie::Errno::ERESTARTSYS.into_raw()),
            "the guest notification on descriptor {fd} was discarded"
        );
    }
}

#[test]
fn colliding_guest_notification_without_timer_request_is_delivered() {
    run_colliding_descriptor(TimerProgress::NotRequested);
}

#[test]
fn colliding_guest_notification_before_overflow_is_delivered() {
    run_colliding_descriptor(TimerProgress::NotOverflowed);
}

#[test]
fn colliding_guest_notification_after_timer_event_is_delivered() {
    run_colliding_descriptor(TimerProgress::Fired);
}

#[test]
fn colliding_guest_notification_after_flushed_notification_is_delivered() {
    run_colliding_descriptor(TimerProgress::FlushedByGuest);
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct StopWindowConfig {
    timeout_rcbs: u64,
    /// Index into the tracer's perf event descriptors of the one the guest's
    /// notification collides with.
    candidate: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum StopWindowReport {
    PerfDescriptors(usize),
    Probe(i64),
}

#[derive(Debug, Default)]
struct StopWindowLog {
    perf_descriptors: Mutex<Option<usize>>,
    probes: Mutex<Vec<i64>>,
}

#[reverie::global_tool]
impl GlobalTool for StopWindowLog {
    type Request = StopWindowReport;
    type Response = ();
    type Config = StopWindowConfig;

    async fn receive_rpc(&self, _from: Pid, report: StopWindowReport) {
        match report {
            StopWindowReport::PerfDescriptors(count) => {
                *self.perf_descriptors.lock().expect("log lock poisoned") = Some(count)
            }
            StopWindowReport::Probe(result) => {
                self.probes.lock().expect("log lock poisoned").push(result)
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
struct StopWindowTool;

#[reverie::tool]
impl Tool for StopWindowTool {
    type GlobalState = StopWindowLog;
    type ThreadState = ();

    fn subscriptions(_cfg: &StopWindowConfig) -> Subscription {
        Subscription::all()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let timeout = TimerSchedule::Rcbs(guest.config().timeout_rcbs);
                guest.set_timer_precise(timeout)?;
                Ok(0)
            }
            Sysno::getuid => {
                // Register the guest's notifying pipe under one tracer perf
                // descriptor number, before the timer is armed again.
                let fds = tracer_perf_fds();
                guest
                    .send_rpc(StopWindowReport::PerfDescriptors(fds.len()))
                    .await;
                if let Some(&fd) = fds.get(guest.config().candidate) {
                    for (nr, args) in [
                        (Sysno::dup2, [NOTIFY_READ_FD, fd, 0]),
                        (
                            Sysno::fcntl,
                            [
                                fd,
                                libc::F_SETFL as usize,
                                (libc::O_NONBLOCK | libc::O_ASYNC) as usize,
                            ],
                        ),
                    ] {
                        guest
                            .inject(raw_syscall(nr, args))
                            .await
                            .unwrap_or_else(|errno| panic!("{nr} failed: {errno}"));
                    }
                }
                Ok(0)
            }
            Sysno::getppid => {
                // Make the guest's notification pending before any injection
                // starts at this stop.
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(format!("/proc/{}/fd/{NOTIFY_WRITE_FD}", guest.pid()))
                    .and_then(|mut pipe| pipe.write_all(&[NOTIFY_BYTE]))
                    .expect("write the guest's notifying pipe");
                let result = match guest.inject(Getpid::new()).await {
                    Ok(pid) => pid,
                    Err(errno) => -i64::from(errno.into_raw()),
                };
                guest.send_rpc(StopWindowReport::Probe(result)).await;
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

static STOP_WINDOW_SIGNALS_HANDLED: AtomicU64 = AtomicU64::new(0);

extern "C" fn count_stop_window_signal(_signo: libc::c_int) {
    STOP_WINDOW_SIGNALS_HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// Runs one guest whose notification collides with the tracer perf descriptor
/// at index `candidate`, and returns how many perf descriptors the tracer had.
fn run_stop_window(candidate: usize) -> usize {
    const TIMEOUT_RCBS: u64 = 50_000;
    let expired_before = timer_overflow_records_expired();
    let (output, log) = test_fn_with_config::<StopWindowTool, _>(
        || {
            // SAFETY: the handler only touches an atomic, and the descriptor
            // and signal operations use valid arguments.
            unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction =
                    count_stop_window_signal as extern "C" fn(libc::c_int) as usize;
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGSTKFLT, &action, core::ptr::null_mut()),
                    0
                );
                let mut pipe = [0; 2];
                assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK), 0);
                assert_eq!(
                    libc::dup2(pipe[0], NOTIFY_READ_FD as i32),
                    NOTIFY_READ_FD as i32
                );
                assert_eq!(
                    libc::dup2(pipe[1], NOTIFY_WRITE_FD as i32),
                    NOTIFY_WRITE_FD as i32
                );
                let owner = FOwnerEx {
                    kind: F_OWNER_TID,
                    pid: libc::syscall(libc::SYS_gettid) as libc::pid_t,
                };
                assert_eq!(libc::fcntl(NOTIFY_READ_FD as i32, F_SETOWN_EX, &owner), 0);
                assert_eq!(
                    libc::fcntl(NOTIFY_READ_FD as i32, F_SETSIG, libc::SIGSTKFLT),
                    0
                );
                // The timer's descriptors exist once it has been armed.
                arm_precise_timer();
                libc::getuid();

                // The timer overflows while its signal is blocked, and the
                // guest flushes the notification. None of these syscalls is
                // injected, so no injection sees the queue until the probe.
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGSTKFLT);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()),
                    0
                );
                arm_precise_timer();
                do_branches(TIMEOUT_RCBS * 3);
                assert_ne!(libc::signal(libc::SIGSTKFLT, libc::SIG_IGN), libc::SIG_ERR);
                assert_eq!(
                    libc::sigaction(libc::SIGSTKFLT, &action, core::ptr::null_mut()),
                    0
                );
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut()),
                    0
                );
            }
            syscall_with_injection();
            assert_eq!(STOP_WINDOW_SIGNALS_HANDLED.load(Ordering::SeqCst), 1);
        },
        StopWindowConfig {
            timeout_rcbs: TIMEOUT_RCBS,
            candidate,
        },
        true,
    )
    .expect("run stop-window guest");

    if output.status != ExitStatus::Exited(0) {
        print_tracee_output(&output);
    }
    let perf_descriptors = log
        .perf_descriptors
        .lock()
        .expect("log lock poisoned")
        .expect("the guest reached its setup syscall");
    let probes = log.probes.lock().expect("log lock poisoned").clone();
    // Each notification interrupts the injection instead of being discarded.
    assert_eq!(
        probes,
        vec![-i64::from(reverie::Errno::ERESTARTSYS.into_raw())],
        "the guest notification on perf descriptor {candidate} of {perf_descriptors} \
         was discarded"
    );
    assert_eq!(output.status, ExitStatus::Exited(0));
    // Otherwise no overflow was recorded and nothing was tested.
    assert!(
        timer_overflow_records_expired() > expired_before,
        "the flushed notification's overflow records did not expire"
    );
    perf_descriptors
}

/// A notification the guest flushes between two stops leaves the queue without
/// an injection seeing it. A guest notification with the timer's siginfo that
/// is pending when the next injection starts must still be delivered, so the
/// stop itself expires the overflow records.
#[test]
fn colliding_guest_notification_after_flush_between_stops_is_delivered() {
    let _serial = serialize();
    if !reverie_ptrace::is_perf_supported() {
        return;
    }
    let mut candidate = 0;
    loop {
        let perf_descriptors = run_stop_window(candidate);
        assert!(
            perf_descriptors > 0,
            "the tracer has no perf event descriptor"
        );
        candidate += 1;
        if candidate >= perf_descriptors {
            break;
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum RequeueReport {
    TimerEvent,
    Injected(Result<i64, i32>),
    Signal(i32),
}

#[derive(Debug, Default)]
struct RequeueLog {
    timer_events: AtomicU64,
    injected: Mutex<Vec<Result<i64, i32>>>,
    signals: Mutex<Vec<i32>>,
}

#[reverie::global_tool]
impl GlobalTool for RequeueLog {
    type Request = RequeueReport;
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, _from: Pid, report: RequeueReport) {
        match report {
            RequeueReport::TimerEvent => {
                self.timer_events.fetch_add(1, Ordering::SeqCst);
            }
            RequeueReport::Injected(result) => self
                .injected
                .lock()
                .expect("injected log lock poisoned")
                .push(result),
            RequeueReport::Signal(signal) => self
                .signals
                .lock()
                .expect("signal log lock poisoned")
                .push(signal),
        }
    }
}

/// At the `getppid` stop, injects `rt_tgsigqueueinfo(self, self, SIGSYS,
/// rdi)`, where the guest's `rdi` points at a siginfo it prepared.
#[derive(Debug, Default, Clone)]
struct LateTimerSigqueueTool;

#[reverie::tool]
impl Tool for LateTimerSigqueueTool {
    type GlobalState = RequeueLog;
    type ThreadState = ();

    fn subscriptions(_cfg: &Config) -> Subscription {
        Subscription::all()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let timeout = TimerSchedule::Rcbs(guest.config().timeout_rcbs);
                guest.set_timer_precise(timeout)?;
                Ok(0)
            }
            Sysno::getppid => {
                let (_, args) = syscall.into_parts();
                let result = guest
                    .inject(
                        RtTgsigqueueinfo::new()
                            .with_tgid(guest.pid().as_raw())
                            .with_tid(guest.tid().as_raw())
                            .with_sig(libc::SIGSYS)
                            .with_siginfo(AddrMut::from_raw(args.arg0)),
                    )
                    .await;
                guest
                    .send_rpc(RequeueReport::Injected(result.map_err(Errno::into_raw)))
                    .await;
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(RequeueReport::Signal(signal as i32)).await;
        Ok(Some(signal))
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(RequeueReport::TimerEvent).await;
    }
}

static REQUEUED_SIGSYS_HANDLED: AtomicU64 = AtomicU64::new(0);

extern "C" fn count_requeued_sigsys(_signo: libc::c_int) {
    REQUEUED_SIGSYS_HANDLED.fetch_add(1, Ordering::SeqCst);
}

fn getppid_with_siginfo(info: *mut libc::siginfo_t) {
    // SAFETY: the tool intercepts this getppid; the kernel ignores rdi for
    // getppid, and the tool reads the siginfo `info` points at.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") libc::SYS_getppid => _,
            in("rdi") info,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

/// After a late overflow notification is discarded before the private
/// `syscall`, the injection steps again. That step must get the same handling
/// as the first one. Here the injected syscall queues a synchronous-class
/// SIGSYS to its own thread, which Linux dequeues ahead of the step SIGTRAP,
/// so the step stops with the syscall already complete. The signal must be
/// returned to the kernel queue and reach the Tool through an ordinary
/// signal-delivery stop, once per injection, exactly as in the injections
/// with no late notification. A step that bypassed that handling would hold
/// the signal in the pending-signal slot instead: the guest's handler would
/// still run, but the Tool would never see the signal, and the step SIGTRAP
/// would stay queued without being marked stale.
#[test]
fn late_overflow_discard_steps_again_with_completed_signal_handling() {
    let _serial = serialize();
    if !reverie_ptrace::is_perf_supported() {
        return;
    }
    let discarded_before = late_timer_signals_discarded();
    let margin = reverie_ptrace::PmuConfig::new().skid_margin();
    let overflow_leads = MAX_OVERFLOW_LEADS.min(margin / 4);
    assert!(overflow_leads > 0, "skid margin {margin} leaves no lead");
    let timeout_rcbs = ARM_RCBS + margin;
    let (output, log) = test_fn_with_config::<LateTimerSigqueueTool, _>(
        move || {
            // SAFETY: the handler only touches an atomic; the siginfo is
            // plain data.
            let mut info: libc::siginfo_t = unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = count_requeued_sigsys as extern "C" fn(libc::c_int) as usize;
                // No SA_RESTART, so an interrupted syscall would be visible.
                action.sa_flags = 0;
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGSYS, &action, core::ptr::null_mut()),
                    0
                );
                core::mem::zeroed()
            };
            info.si_signo = libc::SIGSYS;
            // A positive si_code makes the signal synchronous-class. Its
            // si_call_addr is 0, so it is not taken for a seccomp trap.
            info.si_code = 1;
            for i in 0..ITERS {
                arm_precise_timer();
                do_branches(ARM_RCBS + i % overflow_leads);
                getppid_with_siginfo(&mut info);
            }
            println!("{}", REQUEUED_SIGSYS_HANDLED.load(Ordering::SeqCst));
        },
        Config {
            timeout_rcbs,
            retry: false,
        },
        true,
    )
    .expect("run late-timer sigqueue guest");

    if output.status != ExitStatus::Exited(0) {
        print_tracee_output(&output);
    }
    assert_eq!(output.status, ExitStatus::Exited(0));
    let injected = log.injected.lock().expect("injected log lock poisoned");
    assert_eq!(
        *injected,
        vec![Ok(0); ITERS as usize],
        "each injected rt_tgsigqueueinfo runs once and succeeds"
    );
    let signals = log.signals.lock().expect("signal log lock poisoned");
    assert_eq!(
        *signals,
        vec![libc::SIGSYS; ITERS as usize],
        "each queued SIGSYS reaches the Tool as a signal delivery"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        ITERS.to_string(),
        "the guest's handler runs once per injection"
    );
    assert_eq!(log.timer_events.load(Ordering::SeqCst), 0);
    let discarded = late_timer_signals_discarded() - discarded_before;
    println!("{discarded} late timer signals discarded in {ITERS} injections");
    assert!(
        discarded > 0,
        "no late timer signal reached an injected syscall, so nothing was tested"
    );
}
