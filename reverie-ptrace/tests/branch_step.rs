/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The timer reaches a precise event's target with branch runs (hardware
//! breakpoints at the next stop point) while the counter stays short of it,
//! and single steps the rest. The delivery point must be exactly the one
//! that single steps alone reach: the same clock and the same pc, including
//! targets that land on each kind of branch of the loop below.
//!
//! This file holds one test, because branch runs are switched off for the
//! whole process for its second half.

#![cfg(target_arch = "aarch64")]

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
use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::PreciseTimerSteps;
use reverie_ptrace::testing::check_fn_with_config;
use reverie_ptrace::testing::precise_timer_steps;
use reverie_ptrace::testing::set_block_steps;

/// The precise timer targets the guest requests, one at a time. An
/// iteration of `mixed_branches` retires between four and eight branches
/// (`cbz`, `tbz`, `tbnz` and `b.ne` always; `bl` and `ret` on odd counts;
/// `blr` and `ret` when bit 1 of the count is clear), so consecutive targets
/// land on each kind.
const TARGETS: [u64; 8] = [
    20_000, 20_001, 20_002, 20_003, 20_004, 20_005, 20_006, 20_007,
];

/// (clock from the request, pc) at each timer event.
#[derive(Debug, Default)]
struct TimerEvents(Mutex<Vec<(u64, u64)>>);

#[reverie::global_tool]
impl GlobalTool for TimerEvents {
    type Request = (u64, u64);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, event: (u64, u64)) {
        self.0.lock().unwrap().push(event);
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
                let target = syscall.into_parts().1.arg0 as u64;
                guest
                    .set_timer_precise(TimerSchedule::Rcbs(target))
                    .unwrap();
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let clock = guest.read_clock().unwrap() - *guest.thread_state();
        let pc = guest.regs().await.pc;
        guest.send_rpc((clock, pc)).await;
    }
}

/// The `clock_getres` at which the Tool requests a timer `target` RCBs
/// ahead, with no branch between it and the caller.
fn request(target: u64) {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") Sysno::clock_getres as usize,
            inlateout("x0") target as usize => _,
            in("x1") 0usize,
            options(nostack),
        );
    }
}

/// One loop iteration: `cbz` (never taken while counting), `tbz` (taken on
/// even counts), on odd counts a `bl` to a `ret`, a `tbnz` that skips a
/// `blr` to a `ret` when bit 1 of the count is set, then `subs` and `b.ne`.
#[inline(never)]
fn mixed_branches(iterations: u64) {
    unsafe {
        core::arch::asm!(
            "2:",
            "cbz {0}, 3f",
            "tbz {0}, #0, 4f",
            "nop",
            "bl 5f",
            "4:",
            "tbnz {0}, #1, 7f",
            "adr {2}, 6f",
            "blr {2}",
            "7:",
            "subs {0}, {0}, #1",
            "b.ne 2b",
            "b 3f",
            "5:",
            "add {1}, {1}, #1",
            "ret",
            "6:",
            "add {1}, {1}, #2",
            "ret",
            "3:",
            inout(reg) iterations => _,
            inout(reg) 0u64 => _,
            out(reg) _,
            out("x30") _,
            options(nostack),
        );
    }
}

fn run() -> (Vec<(u64, u64)>, PreciseTimerSteps, u64) {
    let _ = reverie::take_skid_overshoot_count();
    let before = precise_timer_steps();
    let events = check_fn_with_config::<PreciseTimerTool, _>(
        || {
            for target in TARGETS {
                request(target);
                mixed_branches(target);
            }
        },
        (),
        true,
    );
    let steps = precise_timer_steps() - before;
    let witnesses = reverie::take_skid_overshoot_count();
    (events.0.into_inner().unwrap(), steps, witnesses)
}

#[test]
fn branch_runs_deliver_where_single_steps_do() {
    ret_without_perf!();
    set_block_steps(true);
    let (ran, run_steps, run_witnesses) = run();
    set_block_steps(false);
    let (single, single_steps, single_witnesses) = run();
    set_block_steps(true);
    eprintln!("with branch runs: {run_steps:?}, events {ran:?}");
    eprintln!("single steps only: {single_steps:?}, events {single:?}");
    assert_eq!(ran.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(single.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(
        single_steps.branch, 0,
        "switched off, no step is a branch run"
    );
    assert_eq!(
        run_steps.branch_mismatches, 0,
        "every branch run retires exactly the branches decoded: {run_steps:?}"
    );
    assert!(
        run_steps.branch > 0,
        "the approach to each target takes branch runs: {run_steps:?}"
    );
    assert!(
        run_steps.instruction * 2 < single_steps.instruction,
        "branch runs replace most single steps: {run_steps:?} against {single_steps:?}"
    );
    if run_witnesses + single_witnesses > 0 {
        // A late PMU notification is delivered at the observed counter, so
        // that event's point is the host's, not the stepping's.
        eprintln!(
            "skipping the comparison: {run_witnesses} and {single_witnesses} witnessed skid overshoots"
        );
        return;
    }
    for (event, target) in ran.iter().zip(TARGETS) {
        assert_eq!(event.0, target, "each event fires at its target: {ran:?}");
    }
    assert_eq!(
        ran, single,
        "branch runs must deliver at the clock and pc that single steps reach"
    );
    let pcs: std::collections::BTreeSet<u64> = ran.iter().map(|event| event.1).collect();
    assert!(
        pcs.len() >= 4,
        "the targets land on different branches of the loop: {ran:?}"
    );
}
