/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The timer runs a load-exclusive sequence as one unit on its way to a
//! precise target, so a guest's load-exclusive/store-exclusive retry loop
//! takes one attempt per iteration, as it does without stops. Single
//! stepped, every stop between the load and the store clears the exclusive
//! monitor, so the store fails on every attempt and the loop spins until
//! the target.
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
/// iteration of `exclusive_increments` retires two branches when its store
/// succeeds (`cbnz`, not taken, and `b.ne`), so consecutive targets land on
/// both.
const TARGETS: [u64; 4] = [20_000, 20_001, 20_002, 20_003];

/// What the guest tells the Tool.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum Report {
    /// The clock from the request, and the pc, at a timer event.
    Event(u64, u64),
    /// How many times a store-exclusive failed, over all the loops.
    Retries(u64),
}

#[derive(Debug, Default)]
struct Reports(Mutex<Vec<Report>>);

#[reverie::global_tool]
impl GlobalTool for Reports {
    type Request = Report;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        self.0.lock().unwrap().push(report);
    }
}

#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = Reports;
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
                let args = syscall.into_parts().1;
                if args.arg1 == 1 {
                    guest.send_rpc(Report::Retries(args.arg0 as u64)).await;
                    return Ok(0);
                }
                *guest.thread_state_mut() = guest.read_clock().unwrap();
                guest
                    .set_timer_precise(TimerSchedule::Rcbs(args.arg0 as u64))
                    .unwrap();
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let clock = guest.read_clock().unwrap() - *guest.thread_state();
        let pc = guest.regs().await.pc;
        guest.send_rpc(Report::Event(clock, pc)).await;
    }
}

/// A `clock_getres` the Tool reads: a timer request `value` RCBs ahead
/// (`report` 0), with no branch between it and the caller, or a report of
/// `value` retries (`report` 1).
fn call(value: u64, report: u64) {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") Sysno::clock_getres as usize,
            inlateout("x0") value as usize => _,
            in("x1") report as usize,
            options(nostack),
        );
    }
}

/// `iterations` atomic increments of `*word` by a load-exclusive /
/// store-exclusive loop, the shape of libgcc's outline-atomic fallback,
/// counting each failed store out of line. Returns the failures.
#[inline(never)]
fn exclusive_increments(word: &mut u32, iterations: u64) -> u64 {
    let mut retries = 0u64;
    unsafe {
        core::arch::asm!(
            "2:",
            "ldxr {v:w}, [{p}]",
            "add {v:w}, {v:w}, #1",
            "stxr {s:w}, {v:w}, [{p}]",
            "cbnz {s:w}, 3f",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "b 4f",
            "3:",
            "add {r}, {r}, #1",
            "b 2b",
            "4:",
            p = in(reg) word as *mut u32,
            v = out(reg) _,
            s = out(reg) _,
            n = inout(reg) iterations => _,
            r = inout(reg) retries,
            options(nostack),
        );
    }
    retries
}

fn run() -> (Vec<(u64, u64)>, u64, PreciseTimerSteps, u64) {
    let _ = reverie::take_skid_overshoot_count();
    let before = precise_timer_steps();
    let reports = check_fn_with_config::<PreciseTimerTool, _>(
        || {
            let mut word = 0u32;
            let mut retries = 0;
            for target in TARGETS {
                call(target, 0);
                retries += exclusive_increments(&mut word, target);
            }
            call(retries, 1);
        },
        (),
        true,
    );
    let steps = precise_timer_steps() - before;
    let witnesses = reverie::take_skid_overshoot_count();
    let mut events = Vec::new();
    let mut retries = None;
    for report in reports.0.into_inner().unwrap() {
        match report {
            Report::Event(clock, pc) => events.push((clock, pc)),
            Report::Retries(count) => retries = Some(count),
        }
    }
    (
        events,
        retries.expect("the guest reports its retries"),
        steps,
        witnesses,
    )
}

#[test]
fn exclusive_sequences_take_one_attempt_on_the_way_to_a_target() {
    ret_without_perf!();
    set_block_steps(true);
    let (ran, ran_retries, run_steps, run_witnesses) = run();
    set_block_steps(false);
    let (single, single_retries, single_steps, _) = run();
    set_block_steps(true);
    eprintln!("with branch runs: {run_steps:?}, {ran_retries} retries, events {ran:?}");
    eprintln!("single steps only: {single_steps:?}, {single_retries} retries, events {single:?}");
    assert_eq!(ran.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(single.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(
        run_steps.branch_mismatches, 0,
        "every run retires the branches decoded: {run_steps:?}"
    );
    assert!(
        run_steps.exclusive > 0,
        "the approach runs exclusive sequences as units: {run_steps:?}"
    );
    assert_eq!(single_steps.exclusive, 0, "switched off, no unit runs");
    // Single stepped, the first sequence of each approach fails until the
    // target: hundreds of retries, a margin's worth per target.
    assert!(
        single_retries >= 100 * TARGETS.len() as u64,
        "single steps make the store fail on every attempt: {single_retries}"
    );
    // Run as units, a store fails only when something clears the exclusive
    // monitor between its load and its store from outside the guest: the
    // host, and on a virtual CPU the hypervisor, or the PMU notification that
    // starts each approach, which lands wherever the guest is. No stepping
    // strategy prevents those. Single steps clear it at every attempt, so the
    // bar is relative to them, measured in this test: at least 50 times
    // fewer failed stores. On the Android 14 emulator, 6 or 7 against about
    // 1,450 over these four targets (over 200 times fewer).
    assert!(
        ran_retries * 50 <= single_retries,
        "units take one attempt per iteration but for interrupted ones: {ran_retries} retries, \
         against {single_retries} single stepped"
    );
    if run_witnesses > 0 {
        eprintln!("skipping the clock check: {run_witnesses} witnessed skid overshoots");
        return;
    }
    for (event, target) in ran.iter().zip(TARGETS) {
        assert_eq!(event.0, target, "each event fires at its target: {ran:?}");
    }
}
