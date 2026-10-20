/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A launch whose `pipe2` fails with EMFILE because another thread's
//! transient open, which began during the launch after
//! `launch_window::OPEN_WAIT_LIMIT`, still holds the last free descriptor,
//! retries the `pipe2` once and completes once the open has closed
//! (<https://github.com/rrnewton/reverie/issues/930>, round-7 R7-1 of
//! <https://github.com/rrnewton/reverie/issues/912>). See
//! `support/late_open_fixture.rs` for how.

// The filters match x86_64 system call numbers only.
#![cfg(target_arch = "x86_64")]

#[path = "support/late_open_fixture.rs"]
mod late_open_fixture;

#[test]
fn a_launch_retries_a_pipe_after_a_late_open_releases_its_descriptor() {
    late_open_fixture::launch_retries_a_pipe_after_a_late_open_releases_its_descriptor(false);
}
