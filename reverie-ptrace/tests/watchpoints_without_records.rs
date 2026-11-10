/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Without the precise timer's overflow records (as on a `PREEMPT_RT`
//! kernel), a watch hit's stop within the keep margin of a precise event's
//! target cancels the event, as Reverie's other traps without a Tool
//! callback do (`Timer::disregard_stop`), and the thread says so:
//! `Guest::watch_hits_keep_timer_events` is false. `watchpoints.rs` runs
//! the same guest with the records, where the event is kept.
//!
//! This binary maps no overflow records for any timer.

#![cfg(target_arch = "x86_64")]

mod watch_harness;

use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::disable_timer_overflow_records;
use watch_harness::*;

#[test]
fn without_records_a_hit_near_a_precise_target_cancels_the_event_and_the_thread_says_so() {
    ret_without_perf!();
    disable_timer_overflow_records();
    // The same guest with nothing armed: the event is delivered, at its
    // target, so it is the hit that cancels it below.
    let quiet = run(
        timer_config(PERF_RCBS, 1, false),
        store_near_the_target(half_the_keep_margin()),
    );
    assert_eq!(quiet.hits().len(), 0);
    let events = quiet.timer_events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, PERF_RCBS, "{events:?}");

    let watched = run(
        timer_config(PERF_RCBS, 1, true),
        store_near_the_target(half_the_keep_margin()),
    );
    assert_eq!(watched.hits().len(), 1);
    let armings = watched.armings();
    assert_eq!(armings.len(), 1, "{armings:?}");
    assert_eq!(armings[0].2, Ok(()));
    assert!(!armings[0].3, "the thread's hits cannot keep its events");
    assert_eq!(
        watched.timer_events(),
        Vec::<(u64, u64)>::new(),
        "the hit cancelled the event"
    );
}
