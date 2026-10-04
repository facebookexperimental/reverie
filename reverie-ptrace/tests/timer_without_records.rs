/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer's overflow records tell a stop whether the kernel has lost
//! the notification of a counter past its period. Without them, on a kernel
//! that is or may be `PREEMPT_RT` or where they cannot be mapped, a stop that
//! Reverie consumes without a Tool callback cannot tell a lost notification
//! from a pending one, nor a pending one that will arrive before the target
//! from one that will arrive after it. Such a stop within the keep margin
//! (`PmuConfig::keep_margin`) of the target therefore cancels the event, as a
//! stop the Tool observes does, and so does one during the single steps
//! toward the event. The keep margin is at least the largest skid margin in
//! Reverie's PMU table, so every such stop that could be past the period on
//! some processor cancels, and the event never fires at a clock, and never
//! has a fate, that depends on when the host handled the interrupt or on the
//! processor. A stop further from the target leaves the event as it was.
//!
//! This binary maps no overflow records for any timer.

#![cfg(target_arch = "x86_64")]

use std::sync::Mutex;

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
use reverie_ptrace::PmuConfig;
use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::KeptTimerProgrammingChecks;
use reverie_ptrace::testing::assert_at_target_unless_witnessed;
use reverie_ptrace::testing::check_fn_with_config;
use reverie_ptrace::testing::disable_timer_overflow_records;
use reverie_ptrace::testing::do_branches;
use reverie_ptrace::testing::rerun_at_skid_margin;
use reverie_ptrace::testing::rerun_skid_margin;

/// Above the largest skid margin in Reverie's PMU table, so the request
/// programs a real PMU notification on every host in the table.
const PERF_RCBS: u64 = 30_000;

/// The clock from the request to each timer event.
#[derive(Debug, Default)]
struct TimerEvents(Mutex<Vec<u64>>);

#[reverie::global_tool]
impl GlobalTool for TimerEvents {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, clock: u64) {
        self.0.lock().unwrap().push(clock);
    }
}

#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = TimerEvents;
    /// The clock at the request.
    type ThreadState = u64;

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                *guest.thread_state_mut() = guest.read_clock().unwrap();
                guest
                    .set_timer_precise(TimerSchedule::Rcbs(PERF_RCBS))
                    .unwrap();
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let clock = guest.read_clock().unwrap() - *guest.thread_state();
        guest.send_rpc(clock).await;
    }
}

/// The skid witness counter and the kept programming checks are process
/// global; each case that reads them owns them while it runs.
static WITNESS: Mutex<()> = Mutex::new(());

/// Runs `guest` under the Tool, with no overflow records, and returns the
/// clock from the request to each timer event, the skid witnesses, and the
/// traps that kept the event, each of which must have left its programming
/// as the request made it, at the trap and at the thread's next stop (see
/// `KeptTimerProgrammingChecks`).
fn run(guest: impl FnOnce() + Send + 'static) -> (Vec<u64>, u64, u64) {
    // Checks that a re-run's skid margin override is in effect.
    let _ = rerun_skid_margin();
    disable_timer_overflow_records();
    let _owner = WITNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = reverie::take_skid_overshoot_count();
    let checks = KeptTimerProgrammingChecks::start();
    let events = check_fn_with_config::<PreciseTimerTool, _>(guest, (), true);
    let keeps = checks.keeps();
    (
        events.0.into_inner().unwrap(),
        reverie::take_skid_overshoot_count(),
        keeps,
    )
}

/// The `clock_getres` at which the Tool requests the timer, with no
/// conditional branch between it and the caller.
fn request() {
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

/// Blocks or unblocks the timer's signal with a raw `rt_sigprocmask`, which
/// the Tool does not observe.
fn mask_timer_signal(how: libc::c_int) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGSTKFLT);
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                how,
                &set as *const libc::sigset_t,
                std::ptr::null_mut::<libc::sigset_t>(),
                std::mem::size_of::<libc::c_ulong>(),
            ),
            0
        );
    }
}

/// Makes the request, then runs `rounds` rounds of a loop with an `int3` and
/// one conditional branch each.
fn int3_loop(rounds: u64) {
    unsafe {
        core::arch::asm!(
            "syscall",
            "2:",
            "int3",
            "dec {rounds}",
            "jnz 2b",
            rounds = inout(reg) rounds => _,
            inlateout("rax") Sysno::clock_getres as usize => _,
            inlateout("rdi") 0usize => _,
            inlateout("rsi") 0usize => _,
            out("rcx") _,
            out("r11") _,
        )
    }
}

// A guest `int3` that Reverie consumes one branch after the request, far
// before the period, leaves the event as it was, and it fires once at its
// target, or past it only with a witnessed skid overshoot, should the
// processor raise the notification more than the skid margin late.
#[test]
fn a_trap_before_the_period_does_not_cancel_the_timer() {
    ret_without_perf!();
    let (events, witnesses, keeps) = run(|| {
        request();
        unsafe { core::arch::asm!("int3") };
        do_branches(2 * PERF_RCBS);
    });
    assert_eq!(
        keeps, 1,
        "the trap must keep the event, with its programming unchanged"
    );
    assert_eq!(events.len(), 1, "the timer must fire once: {events:?}");
    assert_at_target_unless_witnessed(&events, PERF_RCBS, witnesses);
}

// The guest holds the notification back until after a trap past the target,
// the limiting case of an interrupt so late that the trap comes first and the
// notification only after the target. With records the notification is known
// to be pending and fires the event late, with a skid witness. Without them
// the trap cancels the event, which is witnessed as overtaken, and the
// notification finds it cancelled.
#[test]
fn a_trap_past_the_target_cancels_the_timer() {
    ret_without_perf!();
    let (events, witnesses, keeps) = run(|| {
        mask_timer_signal(libc::SIG_BLOCK);
        request();
        do_branches(2 * PERF_RCBS);
        unsafe { core::arch::asm!("int3") };
        mask_timer_signal(libc::SIG_UNBLOCK);
        do_branches(PERF_RCBS);
    });
    assert_eq!(keeps, 0, "the trap must not keep the event");
    assert_eq!(
        events,
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(witnesses, 1, "the trap overtook the due event");
}

// The same with the trap past the period but before the target. The
// notification would still be in time, but without records the trap cannot
// tell, and the trap is within the keep margin of the target, so it cancels
// the event, which was not yet due.
#[test]
fn a_trap_past_the_period_cancels_the_timer() {
    ret_without_perf!();
    let (events, witnesses, keeps) = run(|| {
        mask_timer_signal(libc::SIG_BLOCK);
        request();
        do_branches(PERF_RCBS - 2);
        unsafe { core::arch::asm!("int3") };
        mask_timer_signal(libc::SIG_UNBLOCK);
        do_branches(PERF_RCBS);
    });
    assert_eq!(keeps, 0, "the trap must not keep the event");
    assert_eq!(
        events,
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(witnesses, 0, "the event was not due at the trap");
}

// The same trap with the notification free to arrive. It arrives within a
// skid margin of the period, and its single steps toward the target are
// under way at the trap, which cancels the event among them rather than
// stepping on: without records the trap cannot tell steps begun from a
// notification still pending, and the event's fate must not depend on which.
// The trap is within the keep margin of the target either way.
// Should the notification come only after the trap, the trap cancels the
// event before it, the same outcome.
#[test]
fn a_trap_among_the_single_steps_cancels_the_timer() {
    ret_without_perf!();
    let (events, witnesses, keeps) = run(|| {
        request();
        do_branches(PERF_RCBS - 2);
        unsafe { core::arch::asm!("int3") };
        do_branches(PERF_RCBS);
    });
    assert_eq!(keeps, 0, "the trap must not keep the event");
    assert_eq!(
        events,
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(witnesses, 0, "the event was not due at the trap");
}

// The guest traps in every round of a loop that runs across the target, where
// Linux can lose the notification (see `TimerImpl::notification_lost`). The
// first trap within the keep margin of the target cancels the event, before
// the period on every processor in Reverie's PMU table. Either way the event is cancelled short of its target, so it
// neither fires nor is witnessed, whenever the host delivers the
// notification.
#[test]
fn the_first_trap_near_the_target_cancels_the_timer_in_a_loop_that_traps_in_every_round() {
    ret_without_perf!();
    let (events, witnesses, keeps) = run(|| int3_loop(2 * PERF_RCBS));
    // Each trap short of the keep point keeps the event, one per branch from
    // the request's clock on, on every processor in the table.
    assert_eq!(
        keeps,
        keep_point(),
        "each trap short of the keep point must keep the event, with its programming unchanged"
    );
    assert_eq!(
        events,
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(witnesses, 0, "the event was cancelled before it was due");
}

/// The clock from the request at and after which a trap without records
/// cancels the event: the keep margin short of the target. The same on every
/// processor in Reverie's PMU table.
fn keep_point() -> u64 {
    PERF_RCBS - PmuConfig::new().keep_margin()
}

/// The conditional branches between the request and a trap placed by
/// `do_branches` that the test does not count, at most: the closure's own.
/// The traps below lie farther than this from the keep point.
const TRAP_SLACK: u64 = 200;

// A trap without records, with the notification free to arrive, just past the
// keep point cancels the event, though on a processor whose skid margin is
// below the table's largest the counter has not yet reached its period
// there, so no notification can have arrived. The trap's outcome is the one
// it would have past the period, so it does not depend on the processor's
// skid margin.
#[test]
fn a_trap_just_past_the_keep_point_cancels_the_timer() {
    ret_without_perf!();
    let branches = keep_point() + TRAP_SLACK;
    let (events, witnesses, keeps) = run(move || {
        request();
        do_branches(branches);
        unsafe { core::arch::asm!("int3") };
        do_branches(PERF_RCBS);
    });
    assert_eq!(keeps, 0, "the trap must not keep the event");
    assert_eq!(
        events,
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(witnesses, 0, "the event was not due at the trap");
}

// A trap without records just short of the keep point leaves the event as it
// was, on every processor in the table, and it fires once at its target, or
// past it only with a witnessed skid overshoot.
#[test]
fn a_trap_just_short_of_the_keep_point_keeps_the_timer() {
    ret_without_perf!();
    let branches = keep_point() - 2 * TRAP_SLACK;
    let (events, witnesses, keeps) = run(move || {
        request();
        do_branches(branches);
        unsafe { core::arch::asm!("int3") };
        do_branches(2 * PERF_RCBS);
    });
    assert_eq!(
        keeps, 1,
        "the trap must keep the event, with its programming unchanged"
    );
    assert_eq!(events.len(), 1, "the timer must fire once: {events:?}");
    assert_at_target_unless_witnessed(&events, PERF_RCBS, witnesses);
}

/// This test's name, which its re-runs skip.
const MARGIN_TEST: &str = "the_keep_point_does_not_depend_on_the_skid_margin";

/// The cases of this binary other than `MARGIN_TEST`.
const OTHER_CASES: usize = 7;

// Every other case passes unchanged at a skid margin of 100, as on Intel
// processors, and of 10000, the largest in the table, so a trap's outcome does not depend on the processor's margin. Each
// margin needs a process of its own, since a process fixes its margin with its
// first timer.
#[test]
fn the_keep_point_does_not_depend_on_the_skid_margin() {
    ret_without_perf!();
    if rerun_skid_margin().is_some() {
        return;
    }
    for margin in [100, 10_000] {
        rerun_at_skid_margin(
            &["--skip", MARGIN_TEST],
            margin,
            OTHER_CASES,
            std::time::Duration::from_secs(300),
        );
    }
}
