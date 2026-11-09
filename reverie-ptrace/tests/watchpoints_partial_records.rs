/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Whether a hit can move a timer event is a fact of each thread
//! (`Guest::watch_hits_keep_timer_events`): a thread whose precise timer maps
//! no overflow records says so while another thread of the same guest, whose
//! timer maps them, says otherwise. A host whose perf locked-memory budget
//! runs out partway through a run gives such a guest; this binary stops
//! mapping records partway through its one test.

#![cfg(target_arch = "x86_64")]

mod watch_harness;

use reverie::WatchKind;
use reverie_ptrace::ret_without_perf;
use watch_harness::*;

#[test]
fn a_thread_whose_timer_maps_no_records_says_its_hits_may_move_its_events() {
    ret_without_perf!();
    let watched = run(
        Config {
            sets: vec![
                vec![watch(0, WatchKind::Write)],
                vec![watch(1, WatchKind::Write)],
            ],
            timer: Some(PERF_RCBS),
            timer_events: 1,
            ..Config::default()
        },
        || {
            arm(0);
            disable_records_for_new_threads();
            std::thread::spawn(|| {
                arm(1);
                store(1, 1);
            })
            .join()
            .unwrap();
            store(0, 1);
        },
    );
    let armings = watched.armings();
    assert_eq!(armings.len(), 2, "{armings:?}");
    let main = armings.iter().find(|arming| arming.1 == 0).unwrap();
    let thread = armings.iter().find(|arming| arming.1 == 1).unwrap();
    assert_ne!(main.0, thread.0);
    assert_eq!(main.2, Ok(()));
    assert_eq!(thread.2, Ok(()));
    assert!(main.3, "the first thread's timer maps its records");
    assert!(!thread.3, "the new thread's timer maps none");
    assert_eq!(watched.hits().len(), 2);
}
