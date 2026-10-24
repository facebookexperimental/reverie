/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer event far enough ahead is staged (`PmuConfig::stages`):
//! its first PMU notification comes the first stage margin short of the
//! target, and the guest's branch rate up to it sizes the margin of a
//! second notification, from which Reverie single steps to the target.
//! The first notification's stop resumes the guest with no Tool callback,
//! so the event fires once, at its target, as an unstaged event does.

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
use reverie_ptrace::testing::assert_at_target_unless_witnessed;
use reverie_ptrace::testing::check_fn_with_config;
use reverie_ptrace::testing::do_branches;
use reverie_ptrace::testing::precise_timer_second_stages_armed;

/// Far beyond the largest skid margin in Reverie's PMU table, so the event is
/// staged wherever staging applies.
const PERF_RCBS: u64 = 2_000_000;

/// The timer events the guest requests, one at a time.
const ROUNDS: u64 = 10;

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

// Each staged event is re-armed at its second stage and fires once, at its
// target, or past it only with a witnessed skid overshoot. An event that is
// not staged is never re-armed.
#[test]
fn a_staged_event_fires_once_at_its_target() {
    ret_without_perf!();
    let staged = PmuConfig::new()
        .expect("this host has a PMU profile")
        .stages(PERF_RCBS);
    let _ = reverie::take_skid_overshoot_count();
    let second_stages = precise_timer_second_stages_armed();
    let events = check_fn_with_config::<PreciseTimerTool, _>(
        || {
            for _ in 0..ROUNDS {
                request();
                do_branches(2 * PERF_RCBS);
            }
        },
        (),
        true,
    );
    let second_stages = precise_timer_second_stages_armed() - second_stages;
    let witnesses = reverie::take_skid_overshoot_count();
    let events = events.0.into_inner().unwrap();
    assert_eq!(
        events.len() as u64,
        ROUNDS,
        "each timer must fire once: {events:?}"
    );
    assert_at_target_unless_witnessed(&events, PERF_RCBS, witnesses);
    if staged {
        // A first stage notification later than about the first stage
        // margin less the second's is stepped from, so not every event need
        // have a second stage.
        assert!(
            second_stages >= ROUNDS / 2,
            "{second_stages} of {ROUNDS} staged events had a second stage"
        );
    } else {
        assert_eq!(second_stages, 0, "no event is staged here");
    }
    eprintln!("staged={staged} second_stages={second_stages} witnesses={witnesses}");
}
