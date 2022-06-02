/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use nix::sys::signal::Signal;

/// Options for scheduling a timer event.
pub enum TimerSchedule {
    /// Request that a timer event occur after approximataly this duration.
    /// Conversion to real time is best-effort only.
    Time(core::time::Duration),
    /// Request that a timer event occur after exactly this many retired
    /// conditional branches (RCBs).
    Rcbs(u64),
}

/// signal used by reverie perf counter timer.
pub const PERF_EVENT_SIGNAL: Signal = Signal::SIGSTKFLT;
