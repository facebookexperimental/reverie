/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer event is decided by the first Tool-observable stop after it
//! is requested. When the overflow interrupt is late, that stop can be the
//! guest's next syscall even though the guest has already executed the target
//! branch. The syscall cancels the event, so the Tool sees the syscall where
//! the timer event was due. The event cannot be recovered at that point, but it
//! must be recorded as a skid overshoot so a supervisor can refuse the run.
//!
//! Interrupt latency cannot be forced in a test, so the guest blocks the timer
//! signal instead: no notification is ever handled, which is the limiting case
//! of a late interrupt. Blocking it at a boundary one branch either side of the
//! target shows exactly where the event becomes due.

#![cfg(target_arch = "x86_64")]

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::check_fn_with_config;
use reverie_ptrace::testing::do_branches;
use serde::Deserialize;
use serde::Serialize;
use test_case::test_case;

/// Far above any skid margin, so the request programs a real PMU notification.
const TIMEOUT_RCBS: u64 = 100_000;

/// Far more instructions than separate the target branch from `getpid` when
/// the guest takes a single further branch.
const OFFSET_INSTRS: u64 = 100;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
enum Report {
    TimerEvent,
    OvertakingSyscall,
}

#[derive(Debug, Default)]
struct Log {
    timer_events: AtomicU64,
    overtaking_syscalls: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Report;
    type Response = ();
    /// The precise request's instruction offset past the target branch.
    type Config = u64;

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        let counter = match report {
            Report::TimerEvent => &self.timer_events,
            Report::OvertakingSyscall => &self.overtaking_syscalls,
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_cfg: &u64) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([
            Sysno::clock_getres,
            Sysno::getpid,
            Sysno::rt_sigprocmask,
            Sysno::exit,
        ]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let schedule = match *guest.config() {
                    0 => TimerSchedule::Rcbs(TIMEOUT_RCBS),
                    offset => TimerSchedule::RcbsAndInstructions(TIMEOUT_RCBS, offset),
                };
                guest.set_timer_precise(schedule).unwrap();
                Ok(0)
            }
            Sysno::getpid => {
                guest.send_rpc(Report::OvertakingSyscall).await;
                guest.tail_inject(syscall).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(Report::TimerEvent).await;
    }
}

/// A syscall with no conditional branch between its caller and the kernel
/// entry, so the guest's branch count at the stop is exact.
#[inline(always)]
unsafe fn syscall_no_branches(no: Sysno) {
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") no as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

fn block_timer_signal() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGSTKFLT);
        assert_eq!(
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
            0
        );
    }
}

/// The skid witness counter is process global; each case owns it while it
/// runs. No other test in this binary uses it.
static WITNESS: Mutex<()> = Mutex::new(());

// `do_branches(n)` executes `n + 1` conditional branches, so `TIMEOUT_RCBS - 1`
// lands exactly on the target when the guest reaches `getpid`, and one fewer
// stops a single branch short. Blocking the signal also blocks the artificial
// kick, so no case can deliver the event.
//
// With an instruction offset, the event is due `OFFSET_INSTRS` instructions
// after the target branch. A stop at or past the target branch is witnessed
// whether or not the guest has covered the offset: the counter cannot show
// how many of the offset's instructions the guest ran past that branch, so the
// delivery point may already have passed. Reaching the target with the offset
// outstanding, or one branch past it, is witnessed exactly as covering it is.
#[test_case(TIMEOUT_RCBS / 2, 0, 0; "well before the target")]
#[test_case(TIMEOUT_RCBS - 2, 0, 0; "one branch before the target")]
#[test_case(TIMEOUT_RCBS - 1, 0, 1; "exactly at the target")]
#[test_case(TIMEOUT_RCBS * 2, 0, 1; "well past the target")]
#[test_case(TIMEOUT_RCBS - 2, OFFSET_INSTRS, 0; "one branch before the target with an offset")]
#[test_case(TIMEOUT_RCBS - 1, OFFSET_INSTRS, 1; "at the target with the offset outstanding")]
#[test_case(TIMEOUT_RCBS, OFFSET_INSTRS, 1; "one branch past the target with the offset outstanding")]
#[test_case(TIMEOUT_RCBS - 1 + OFFSET_INSTRS, OFFSET_INSTRS, 1; "branches past the target cover the offset")]
#[test_case(TIMEOUT_RCBS * 2, OFFSET_INSTRS, 1; "well past the target and the offset")]
fn overtaken_precise_event_is_witnessed(branches: u64, offset: u64, witnesses: u64) {
    ret_without_perf!();
    let _owner = WITNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = reverie::take_skid_overshoot_count();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            block_timer_signal();
            unsafe { syscall_no_branches(Sysno::clock_getres) };
            do_branches(branches);
            unsafe { syscall_no_branches(Sysno::getpid) };
        },
        offset,
        true,
    );

    assert_eq!(
        log.overtaking_syscalls.load(Ordering::SeqCst),
        1,
        "the guest must reach the syscall stop exactly once"
    );
    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        0,
        "the syscall cancels the undelivered event"
    );
    assert_eq!(
        reverie::take_skid_overshoot_count(),
        witnesses,
        "a precise event overtaken after its target must be witnessed exactly once"
    );
}

/// Where the guest goes after a trap that Reverie consumes without a Tool
/// callback.
#[derive(Debug, Clone, Copy)]
enum AfterTrap {
    /// A syscall the Tool observes, which decides the event.
    Syscall,
    /// Straight to `exit_group`, which the Tool does not observe: the thread
    /// exits with the event undecided.
    Exit,
    /// To `exit`, which the Tool observes and passes on: the syscall decides
    /// the event, and ends the thread before its stop's handling returns.
    ObservedExit,
}

// A trap that the Tool does not observe does not decide the event: the event
// is left as it was, so it is witnessed only by what does end it, once. That
// is the stop that cancels it, or, if the guest exits first, the exit.
// The trap is a guest `icebp`, which Reverie consumes without delivering it
// (a guest's own `int3` is delivered, as on Linux).
#[test_case(AfterTrap::Syscall, 1; "the syscall after the trap is the one witness")]
#[test_case(AfterTrap::Exit, 1; "an exit after the trap is the one witness")]
#[test_case(AfterTrap::ObservedExit, 1; "an observed exit after the trap is the one witness")]
fn a_disregarded_trap_past_the_target_is_witnessed_once(after: AfterTrap, witnesses: u64) {
    ret_without_perf!();
    let _owner = WITNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = reverie::take_skid_overshoot_count();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            block_timer_signal();
            unsafe { syscall_no_branches(Sysno::clock_getres) };
            do_branches(TIMEOUT_RCBS * 2);
            unsafe { core::arch::asm!(".byte 0xf1") };
            match after {
                AfterTrap::Syscall => unsafe { syscall_no_branches(Sysno::getpid) },
                AfterTrap::Exit => unsafe { syscall_no_branches(Sysno::exit_group) },
                AfterTrap::ObservedExit => unsafe { syscall_no_branches(Sysno::exit) },
            }
        },
        0,
        true,
    );

    assert_eq!(
        log.overtaking_syscalls.load(Ordering::SeqCst),
        match after {
            AfterTrap::Syscall => 1,
            AfterTrap::Exit | AfterTrap::ObservedExit => 0,
        },
        "the guest must reach the syscall stop exactly once, if it makes the syscall"
    );
    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        0,
        "the blocked notification never delivers the event"
    );
    assert_eq!(
        reverie::take_skid_overshoot_count(),
        witnesses,
        "only a stop that retires the event past its target may witness it"
    );
}

/// [`PreciseTimerTool`] without `rt_sigprocmask` among its syscalls, so a
/// guest can unblock the timer signal without a stop: the pending
/// notification is then the first stop after the target, and it finds the
/// guest wherever the guest has run to.
#[derive(Debug, Default, Clone)]
struct UnobservedUnblockTool;

#[reverie::tool]
impl Tool for UnobservedUnblockTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_cfg: &u64) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres, Sysno::getpid, Sysno::exit]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let schedule = match *guest.config() {
                    0 => TimerSchedule::Rcbs(TIMEOUT_RCBS),
                    offset => TimerSchedule::RcbsAndInstructions(TIMEOUT_RCBS, offset),
                };
                guest.set_timer_precise(schedule).unwrap();
                Ok(0)
            }
            Sysno::getpid => {
                guest.send_rpc(Report::OvertakingSyscall).await;
                guest.tail_inject(syscall).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(Report::TimerEvent).await;
    }
}

/// Unblocks the timer signal with `rt_sigprocmask` and no conditional branch
/// before the kernel entry, so the guest's branch count when the pending
/// notification is handled, on the syscall's return, is exact. The result is
/// checked only after that return.
#[inline(always)]
unsafe fn unblock_timer_signal_no_branches(set: *const libc::sigset_t) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") Sysno::rt_sigprocmask as usize => ret,
            in("rdi") libc::SIG_UNBLOCK as usize,
            in("rsi") set as usize,
            in("rdx") 0usize,
            in("r10") std::mem::size_of::<u64>(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn timer_signal_set() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGSTKFLT);
        set
    }
}

// The guest blocks the timer signal, runs `branches` conditional branches
// past the request and unblocks it with no stop in between, so the overflow
// notification, held pending while the signal was blocked, is handled only
// where the guest then is: the limiting case of a late notification. As in
// `overtaken_precise_event_is_witnessed`, `TIMEOUT_RCBS - 1` branches leave the
// guest exactly at the target when it unblocks the signal. Short of the target
// no overflow is pending and the guest's syscall cancels the event. At or past
// the target the notification delivers the event at the observed counter.
// With an instruction offset it cannot count the offset from there, since the
// guest may have run any number of instructions past the target branch, so it
// is witnessed as a skid overshoot even exactly at the target. Without an
// offset, an event found exactly at its target is delivered there unwitnessed
// and one found past it is witnessed, as before.
#[test_case(TIMEOUT_RCBS / 2, OFFSET_INSTRS, 0, 0; "short of the target with an offset")]
#[test_case(TIMEOUT_RCBS - 1, 0, 1, 0; "exactly at the target without an offset")]
#[test_case(TIMEOUT_RCBS - 1, OFFSET_INSTRS, 1, 1; "exactly at the target with an offset")]
#[test_case(TIMEOUT_RCBS * 2, OFFSET_INSTRS, 1, 1; "past the target with an offset")]
#[test_case(TIMEOUT_RCBS * 2, 0, 1, 1; "past the target without an offset")]
fn a_late_notification_of_an_offset_event_is_witnessed(
    branches: u64,
    offset: u64,
    timer_events: u64,
    witnesses: u64,
) {
    ret_without_perf!();
    let _owner = WITNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = reverie::take_skid_overshoot_count();

    let log = check_fn_with_config::<UnobservedUnblockTool, _>(
        move || {
            let set = timer_signal_set();
            block_timer_signal();
            unsafe { syscall_no_branches(Sysno::clock_getres) };
            do_branches(branches);
            let unblocked = unsafe { unblock_timer_signal_no_branches(&set) };
            unsafe { syscall_no_branches(Sysno::getpid) };
            assert_eq!(unblocked, 0, "rt_sigprocmask(SIG_UNBLOCK) failed");
        },
        offset,
        true,
    );

    assert_eq!(
        log.overtaking_syscalls.load(Ordering::SeqCst),
        1,
        "the guest must reach the syscall stop exactly once"
    );
    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        timer_events,
        "only a notification at or past the target delivers the event"
    );
    assert_eq!(
        reverie::take_skid_overshoot_count(),
        witnesses,
        "a notification that cannot place the event is witnessed exactly once"
    );
}
