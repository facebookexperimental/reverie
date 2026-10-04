/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer event single-steps the guest to its target, and each step
//! ends in a SIGTRAP stop. An instruction that raises a SIGTRAP of its own,
//! such as `int3`, ends in a SIGTRAP stop too. The stepping passes that stop
//! on to the code that handles SIGTRAPs rather than take it for its step's,
//! so that a trap that Reverie handles, such as a LiteInst hook's, reaches it;
//! reverie-liteinst/tests/hybrid.rs tests that.
//!
//! A trap that Reverie neither handles nor delivers makes no Tool callback, so
//! it must leave the timer event as it was, and the steps toward it that it
//! interrupted must continue. The event then fires at its target, whether the
//! trap comes before the PMU signal, among the steps, or in every round of a
//! loop that runs across the target. A Tool rearms its timer only in its
//! callbacks, so a trap that cancelled the event would leave a guest that
//! traps, and then spins, with no preemption at all. These tests check that
//! the event fires once, at its target. An event that an artificial signal
//! delivers must fire exactly there. One that a PMU notification delivers
//! fires past it if the processor raised the notification more than the skid
//! margin late, which Reverie witnesses as a skid overshoot (see
//! `reverie_ptrace::testing::assert_at_target_unless_witnessed`), so it may
//! fire late only with a witness. They pass whether the stepping takes a
//! guest's trap for its step's or passes it on, as long as it counts the
//! trap's instruction once.
//!
//! Each guest makes the syscall at which the Tool requests the timer, then
//! runs two loops with one conditional branch per round and the instructions
//! under test between them.

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
use serde::Deserialize;
use serde::Serialize;
use test_case::test_case;

/// Above the largest skid margin in Reverie's PMU table, 10,000 RCBs, so the
/// request programs a real PMU notification on every host in the table. The
/// steps then start wherever the processor raises its signal, up to the skid
/// margin before the target.
const PERF_RCBS: u64 = 30_000;

/// Low enough that the timer is delivered with an artificial signal. The
/// stepping then starts at the syscall that requested the timer, so every
/// instruction from there to the target is stepped.
const LESS_RCBS: u64 = 15;

/// The clock from the request to each timer event, and where each timer
/// event found the guest.
#[derive(Debug, Default)]
struct TimerEvents(Mutex<Vec<u64>>, Mutex<Vec<Place>>);

/// The guest's instruction pointer at a timer event, and the address of the
/// branch at which the guests that `between_loops!` runs expect it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Place {
    rip: u64,
    second_loop_branch: u64,
}

#[reverie::global_tool]
impl GlobalTool for TimerEvents {
    type Request = (u64, Place);
    type Response = ();
    type Config = Schedule;

    async fn receive_rpc(&self, _from: Pid, (clock, place): (u64, Place)) {
        self.0.lock().unwrap().push(clock);
        self.1.lock().unwrap().push(place);
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
struct Schedule {
    /// The timer's RCBs from the request to the target.
    rcbs: u64,
    /// Instructions past the target branch, if any.
    instructions: Option<u64>,
}

impl Schedule {
    fn rcbs(rcbs: u64) -> Self {
        Schedule {
            rcbs,
            instructions: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = TimerEvents;
    /// The clock at the request, and the request's second argument, which a
    /// guest that `between_loops!` runs sets to the address of its second
    /// loop's branch.
    type ThreadState = (u64, u64);

    /// The Tool also observes `getppid`, which the guests that test
    /// cancellation make.
    fn subscriptions(_cfg: &Schedule) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres, Sysno::getppid]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let (_, args) = syscall.into_parts();
                *guest.thread_state_mut() = (guest.read_clock().unwrap(), args.arg1 as u64);
                let schedule = match guest.config().instructions {
                    None => TimerSchedule::Rcbs(guest.config().rcbs),
                    Some(instructions) => {
                        TimerSchedule::RcbsAndInstructions(guest.config().rcbs, instructions)
                    }
                };
                guest.set_timer_precise(schedule).unwrap();
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let (request_clock, second_loop_branch) = *guest.thread_state();
        let clock = guest.read_clock().unwrap() - request_clock;
        let rip = guest.regs().await.rip;
        guest
            .send_rpc((
                clock,
                Place {
                    rip,
                    second_loop_branch,
                },
            ))
            .await;
    }
}

/// The instruction between the guest's two loops.
#[derive(Debug, Clone, Copy)]
enum Between {
    /// A `nop`, which does not trap.
    Nop,
    /// `int3`, which Linux reports as a SIGTRAP with SI_KERNEL.
    Int3,
    /// `icebp`, which Linux reports as a SIGTRAP with TRAP_BRKPT when the
    /// processor sets no DR6 status bit for it. An AMD EPYC 9D85 sets none
    /// even when it single-steps the instruction.
    Icebp,
    /// A `tgkill` of SIGTRAP to the guest's own thread, which Linux reports
    /// with SI_TKILL. A step of its `syscall` would report TRAP_BRKPT as the
    /// syscall returns, but the guest's SIGTRAP is already pending then, and
    /// Linux does not queue a second.
    Tgkill,
    /// A `getpid` just after two loads of SS. Of consecutive loads of SS,
    /// Intel documents only the first as sure to hold the debug trap back,
    /// but an AMD EPYC 9D85 runs both and the `syscall` in one step, which
    /// Linux then reports with TRAP_BRKPT as the syscall returns. That is the
    /// step's report, and no trap of the guest's.
    SyscallAfterLoadsOfSs,
    /// An `int3` just after two loads of SS.
    Int3AfterLoadsOfSs,
    /// An `icebp` just after two loads of SS, which raises TRAP_BRKPT like
    /// the step of a `syscall` there.
    IcebpAfterLoadsOfSs,
}

/// Makes the `clock_getres` at which the Tool requests the timer, then runs
/// `$before` rounds of a loop with one conditional branch each, then the
/// given instructions, then `$after` more rounds. There is no conditional
/// branch between the syscall and the loop, so the loop's branches are the
/// first after the request. The syscall's second argument is the address of
/// the second loop's branch, which the Tool emulating it does not read.
macro_rules! between_loops {
    ($before:expr, $after:expr, [$($instruction:literal),+] $(, $($operand:tt)+)?) => {
        unsafe {
            core::arch::asm!(
                "lea rsi, [rip + 5f]",
                "syscall",
                "2:",
                "dec {before}",
                "jnz 2b",
                $($instruction,)+
                "3:",
                "dec {after}",
                "5:",
                "jnz 3b",
                before = inout(reg) $before => _,
                after = inout(reg) $after => _,
                $($($operand)+,)?
                inlateout("rax") Sysno::clock_getres as usize => _,
                inlateout("rdi") 0usize => _,
                out("rsi") _,
                out("rdx") _,
                out("rcx") _,
                out("r11") _,
            )
        }
    };
}

impl Between {
    /// Runs the guest with `before` rounds before the instruction and `after`
    /// rounds after it.
    fn run(self, before: u64, after: u64) {
        match self {
            Between::Nop => between_loops!(before, after, ["nop"]),
            Between::Int3 => between_loops!(before, after, ["int3"]),
            // `icebp`, also known as `int1`.
            Between::Icebp => between_loops!(before, after, [".byte 0xf1"]),
            Between::Tgkill => {
                let pid = unsafe { libc::getpid() } as usize;
                let tid = unsafe { libc::gettid() } as usize;
                between_loops!(
                    before,
                    after,
                    [
                        "mov eax, {tgkill}",
                        "mov rdi, {pid}",
                        "mov rsi, {tid}",
                        "mov edx, {sigtrap}",
                        "syscall"
                    ],
                    pid = in(reg) pid,
                    tid = in(reg) tid,
                    tgkill = const libc::SYS_tgkill,
                    sigtrap = const libc::SIGTRAP
                )
            }
            Between::SyscallAfterLoadsOfSs => between_loops!(
                before,
                after,
                [
                    "mov {ss:e}, ss",
                    "mov eax, {getpid}",
                    "mov ss, {ss:e}",
                    "mov ss, {ss:e}",
                    "syscall"
                ],
                ss = out(reg) _,
                getpid = const libc::SYS_getpid
            ),
            Between::Int3AfterLoadsOfSs => between_loops!(
                before,
                after,
                ["mov {ss:e}, ss", "mov ss, {ss:e}", "mov ss, {ss:e}", "int3"],
                ss = out(reg) _
            ),
            Between::IcebpAfterLoadsOfSs => between_loops!(
                before,
                after,
                [
                    "mov {ss:e}, ss",
                    "mov ss, {ss:e}",
                    "mov ss, {ss:e}",
                    ".byte 0xf1"
                ],
                ss = out(reg) _
            ),
        }
    }
}

/// The skid witness counter and the kept programming checks are process
/// global; each case owns them while it runs.
static WITNESS: Mutex<()> = Mutex::new(());

/// The clock from the request to each timer event, where each timer event
/// found the guest, and the skid overshoots Reverie witnessed.
struct Run {
    clocks: Vec<u64>,
    places: Vec<Place>,
    witnesses: u64,
    /// The traps that kept the event while it waited for its PMU
    /// notification, each of which must have left its programming as the
    /// request made it, at the trap and, unless it handed the event on, at
    /// the thread's next stop (see `KeptTimerProgrammingChecks`). A trap
    /// among the steps is not one.
    keeps: u64,
    /// The traps of `keeps` that handed the event on, having found its
    /// notification lost, to single steps.
    handed_on: u64,
}

impl Run {
    /// Asserts that `keeps` traps kept the event, and that none handed it on.
    fn assert_kept(&self, keeps: u64) {
        assert_eq!(
            (self.keeps, self.handed_on),
            (keeps, 0),
            "traps that kept the event, and of them handed it on"
        );
    }

    /// Checks that the timer fired once, at its target `rcbs` RCBs past the
    /// request: exactly there if an artificial signal delivered it, and past
    /// it only with a witnessed skid overshoot if a PMU notification did.
    fn assert_fired_once_at(&self, rcbs: u64, what: &str) {
        assert_eq!(
            self.clocks.len(),
            1,
            "the timer must fire once, {what}: {:?}",
            self.clocks
        );
        if rcbs == LESS_RCBS {
            assert_eq!(self.clocks, [rcbs], "the timer must fire {what}");
            assert_eq!(
                self.witnesses, 0,
                "steps from the request cannot pass the target"
            );
        } else {
            assert_at_target_unless_witnessed(&self.clocks, rcbs, self.witnesses);
        }
    }
}

/// Runs `guest` under the Tool with `schedule`.
fn run(guest: impl FnOnce() + Send + 'static, schedule: Schedule) -> Run {
    let _owner = WITNESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = reverie::take_skid_overshoot_count();
    let checks = KeptTimerProgrammingChecks::start();
    let events = check_fn_with_config::<PreciseTimerTool, _>(guest, schedule, true);
    let (keeps, handed_on) = checks.keeps_and_handed_on();
    Run {
        clocks: events.0.into_inner().unwrap(),
        places: events.1.into_inner().unwrap(),
        witnesses: reverie::take_skid_overshoot_count(),
        keeps,
        handed_on,
    }
}

/// Runs the guest with the instructions under test `before` conditional
/// branches after the request, and a timer `schedule.rcbs` branches after it,
/// with twice as many branches in all.
fn timer_events(between: Between, schedule: Schedule, before: u64) -> Run {
    run(
        move || between.run(before, 2 * schedule.rcbs - before),
        schedule,
    )
}

// Each guest traps one conditional branch before the target. With an
// artificial signal the steps start at the request, so they run the trap.
// With a PMU signal they run it as long as the processor's skid stays below
// the margin; a later signal comes after the trap's stop.
#[test_case(Between::Int3, LESS_RCBS; "int3, artificial signal")]
#[test_case(Between::Int3, PERF_RCBS; "int3, perf signal")]
#[test_case(Between::Icebp, LESS_RCBS; "icebp, artificial signal")]
#[test_case(Between::Icebp, PERF_RCBS; "icebp, perf signal")]
#[test_case(Between::Tgkill, LESS_RCBS; "tgkill, artificial signal")]
#[test_case(Between::Tgkill, PERF_RCBS; "tgkill, perf signal")]
#[test_case(Between::Int3AfterLoadsOfSs, LESS_RCBS; "int3 after loads of SS")]
#[test_case(Between::IcebpAfterLoadsOfSs, LESS_RCBS; "icebp after loads of SS")]
fn a_trap_before_the_target_does_not_cancel_the_timer(between: Between, rcbs: u64) {
    ret_without_perf!();
    let run = timer_events(between, Schedule::rcbs(rcbs), rcbs - 1);
    run.assert_fired_once_at(rcbs, "at its target after the trap");
    if rcbs == LESS_RCBS {
        // The steps start at the request, so the trap is among them.
        run.assert_kept(0);
    } else {
        // The trap is past the period, and among the steps unless the host
        // delivered the notification only after it, when the trap keeps the
        // event, or finds the notification lost and hands the event on.
        assert!(run.keeps <= 1, "{} traps kept the event", run.keeps);
    }
}

// Each guest traps one conditional branch after the request, 29,999 before
// the target, which is further than any skid margin reaches. The trap's stop
// therefore comes before the PMU signal on every host, and whether the event
// fires must not depend on which side of the trap the signal came.
#[test_case(Between::Int3; "int3")]
#[test_case(Between::Icebp; "icebp")]
#[test_case(Between::Tgkill; "tgkill")]
fn a_trap_before_the_perf_signal_does_not_cancel_the_timer(between: Between) {
    ret_without_perf!();
    let run = timer_events(between, Schedule::rcbs(PERF_RCBS), 1);
    run.assert_fired_once_at(PERF_RCBS, "at its target after the trap");
    run.assert_kept(1);
}

// The same guests without a trap, where the timer fires one branch after the
// `nop`, and a `syscall` after two loads of SS, whose step reports the
// syscall's return.
#[test_case(Between::Nop, LESS_RCBS; "artificial signal")]
#[test_case(Between::Nop, PERF_RCBS; "perf signal")]
#[test_case(Between::SyscallAfterLoadsOfSs, LESS_RCBS; "syscall after loads of SS")]
fn the_timer_fires_without_a_trap(between: Between, rcbs: u64) {
    ret_without_perf!();
    let run = timer_events(between, Schedule::rcbs(rcbs), rcbs - 1);
    run.assert_fired_once_at(rcbs, "at its target");
    run.assert_kept(0);
}

// The trap is the instruction just past the target, so the timer fires before
// the guest runs it. Only the artificial signal starts the steps at a known
// point: a PMU signal more than the skid margin late would come after the
// trap's stop.
#[test_case(Between::Int3; "int3")]
#[test_case(Between::Icebp; "icebp")]
#[test_case(Between::Tgkill; "tgkill")]
fn a_trap_past_the_target_does_not_cancel_the_timer(between: Between) {
    ret_without_perf!();
    let run = timer_events(between, Schedule::rcbs(LESS_RCBS), LESS_RCBS);
    run.assert_fired_once_at(LESS_RCBS, "before the trap");
    run.assert_kept(0);
}

// The timer's target is `instructions` steps past the last branch of the
// first loop, which runs the instructions under test and then the `dec` of
// the second loop, and stops at its `jnz`. A step that the trap's stop
// interrupted must count once: had it not been counted, the steps would run
// the `jnz` too, and the clock would be one branch further. Had it been
// counted twice, the steps would stop an instruction short, at the `dec`,
// with the clock unchanged, so the event's instruction pointer is checked
// too.
#[test_case(Between::Nop, 2; "nop")]
#[test_case(Between::Int3, 2; "int3")]
#[test_case(Between::Icebp, 2; "icebp")]
#[test_case(Between::Tgkill, 6; "tgkill")]
fn a_trap_among_the_instructions_past_the_target_counts_once(between: Between, instructions: u64) {
    ret_without_perf!();
    let schedule = Schedule {
        rcbs: LESS_RCBS,
        instructions: Some(instructions),
    };
    let run = timer_events(between, schedule, LESS_RCBS);
    run.assert_fired_once_at(LESS_RCBS, "before the second loop's first branch");
    run.assert_kept(0);
    let places = run.places;
    assert_eq!(places.len(), 1, "the timer must fire once: {places:?}");
    assert_ne!(places[0].second_loop_branch, 0);
    assert_eq!(
        places[0].rip, places[0].second_loop_branch,
        "the timer must fire at the second loop's first branch"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, then runs
/// `rounds` rounds of a loop with an `int3` and one conditional branch each.
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

// The guest traps in every round of a loop that runs across the target, so
// every step toward the target but the first comes after a trap, and so does
// the PMU signal. The loop runs twice as many rounds as the timer's RCBs, and
// the timer must fire once, at its target, before the loop ends.
#[test_case(LESS_RCBS; "artificial signal")]
#[test_case(PERF_RCBS; "perf signal")]
fn the_timer_fires_in_a_loop_that_traps_in_every_round(rcbs: u64) {
    ret_without_perf!();
    let run = run(move || int3_loop(2 * rcbs), Schedule::rcbs(rcbs));
    run.assert_fired_once_at(rcbs, "at its target inside the loop");
    if rcbs == LESS_RCBS {
        run.assert_kept(0);
    } else {
        // Every trap from the request's clock up to the period, the skid
        // margin short of the target, keeps the event. The trap at the
        // period keeps it too unless the notification stopped the guest
        // first, and, if it finds the notification not yet queued, hands the
        // event on as lost; the steps then begin there.
        let period = rcbs - PmuConfig::new().skid_margin();
        assert!(
            (period..=period + 1).contains(&run.keeps) && run.handed_on <= 1,
            "{} traps kept the event, and {} handed it on, with the period at {period}",
            run.keeps,
            run.handed_on
        );
    }
}

/// Makes the `clock_getres` at which the Tool requests the timer, then
/// `getppids` calls of `getppid`, then runs `rounds` rounds of a loop with an
/// `int3` and one conditional branch each.
fn int3_loop_after_getppids(getppids: u64, rounds: u64) {
    unsafe {
        core::arch::asm!(
            "syscall",
            "2:",
            "mov eax, {getppid}",
            "syscall",
            "dec {getppids}",
            "jnz 2b",
            "3:",
            "int3",
            "dec {rounds}",
            "jnz 3b",
            getppids = inout(reg) getppids => _,
            rounds = inout(reg) rounds => _,
            getppid = const libc::SYS_getppid,
            inlateout("rax") Sysno::clock_getres as usize => _,
            inlateout("rdi") 0usize => _,
            inlateout("rsi") 0usize => _,
            out("rcx") _,
            out("r11") _,
        )
    }
}

// A stop that the Tool observes between the request and the same loop cancels
// the timer event, and so do two. The event must not fire, whether its PMU
// notification comes or the kernel loses it among the traps.
#[test_case(1; "one observed stop")]
#[test_case(2; "two observed stops")]
fn an_observed_stop_cancels_the_timer_in_a_loop_that_traps_in_every_round(getppids: u64) {
    ret_without_perf!();
    let run = run(
        move || int3_loop_after_getppids(getppids, 2 * PERF_RCBS),
        Schedule::rcbs(PERF_RCBS),
    );
    assert_eq!(
        run.clocks,
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(
        run.witnesses, 0,
        "the event was cancelled before it was due"
    );
    run.assert_kept(0);
}
