/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `launch_late_open_descriptor`'s case with a handled, restarting `SIGUSR1`
//! sent to the launcher while a supervisor holds its first `pipe2`. The
//! handler sleeps in a real system call. A signal that cancelled the held
//! call would restart it, and the restarted call would look like a retry; the
//! handler checks from the registers the signal saved that the first `pipe2`
//! returned EMFILE instead. A separate binary, so that the fixture's statics
//! and the handler are this test's own.

// The filters match x86_64 system call numbers only.
#![cfg(target_arch = "x86_64")]

#[path = "support/late_open_fixture.rs"]
mod late_open_fixture;

#[test]
fn a_launch_retries_a_pipe_after_a_late_open_with_a_signal_during_the_held_pipe() {
    late_open_fixture::launch_retries_a_pipe_after_a_late_open_releases_its_descriptor(true);
}
