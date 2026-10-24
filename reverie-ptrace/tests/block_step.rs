/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The timer reaches a precise event's target with block steps
//! (`PTRACE_SINGLEBLOCK`) while the decoded bound shows that the block cannot
//! reach it, and single steps the rest. The delivery point must be exactly
//! the one that single steps alone reach: the same clock and the same rip,
//! including targets that land on a conditional branch that is not taken in
//! the middle of a block.
//!
//! This file holds one test, because block steps are switched off for the
//! whole process for its second half.

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
use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::PreciseTimerSteps;
use reverie_ptrace::testing::check_fn_with_config;
use reverie_ptrace::testing::precise_timer_steps;
use reverie_ptrace::testing::set_block_steps;
use reverie_ptrace::testing::verify_block_bound_cache;

/// The precise timer targets the guest requests, one at a time. Each loop
/// iteration of `mixed_branches` retires three conditional branches, so
/// consecutive targets land on each of them: the `je` that is never taken,
/// the `jz` taken every other iteration, and the loop's `jnz`.
const TARGETS: [u64; 6] = [20_000, 20_001, 20_002, 20_003, 20_004, 20_005];

/// (clock from the request, rip) at each timer event.
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
        let rip = guest.regs().await.rip;
        guest.send_rpc((clock, rip)).await;
    }
}

/// The `clock_getres` at which the Tool requests a timer `target` RCBs
/// ahead, with no conditional branch between it and the caller.
fn request(target: u64) {
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") target as usize,
            in("rsi") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

/// Retires three conditional branches per iteration: a `je` never taken, a
/// `jz` taken on even counts, and the loop's `jnz`. A block from the loop
/// head runs to the taken `jz` (two branches) or to the `jnz` (three).
#[inline(never)]
fn mixed_branches(iterations: u64) {
    unsafe {
        core::arch::asm!(
            "2:",
            "cmp {0}, 0",
            "je 3f",
            "test {0}, 1",
            "jz 4f",
            "nop",
            "4:",
            "sub {0}, 1",
            "jnz 2b",
            "3:",
            inout(reg) iterations => _,
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
fn block_steps_deliver_where_single_steps_do() {
    ret_without_perf!();
    verify_block_bound_cache();
    set_block_steps(true);
    let (blocked, block_steps, block_witnesses) = run();
    set_block_steps(false);
    let (single, single_steps, single_witnesses) = run();
    set_block_steps(true);
    eprintln!("with block steps: {block_steps:?}, events {blocked:?}");
    eprintln!("single steps only: {single_steps:?}, events {single:?}");
    assert_eq!(blocked.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(single.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(
        single_steps.block, 0,
        "switched off, no step is a block step"
    );
    assert!(
        block_steps.block > 0,
        "the approach to each target takes block steps: {block_steps:?}"
    );
    assert!(
        block_steps.instruction < single_steps.instruction,
        "block steps replace single steps: {block_steps:?} against {single_steps:?}"
    );
    if block_witnesses + single_witnesses > 0 {
        // A late PMU notification is delivered at the observed counter, so
        // that event's point is the host's, not the stepping's.
        eprintln!(
            "skipping the comparison: {block_witnesses} and {single_witnesses} witnessed skid overshoots"
        );
        return;
    }
    for (event, target) in blocked.iter().zip(TARGETS) {
        assert_eq!(
            event.0, target,
            "each event fires at its target: {blocked:?}"
        );
    }
    assert_eq!(
        blocked, single,
        "block steps must deliver at the clock and rip that single steps reach"
    );
    let rips: std::collections::BTreeSet<u64> = blocked.iter().map(|event| event.1).collect();
    assert!(
        rips.len() >= 3,
        "the targets land on each of the loop's three branches: {blocked:?}"
    );
}
