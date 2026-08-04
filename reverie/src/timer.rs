/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
    /// Request that a timer event occur after exactly this many retired
    /// conditional branches (RCBs) and this many instructions
    RcbsAndInstructions(u64, u64),
}

/// signal used by reverie perf counter timer.
pub const PERF_EVENT_SIGNAL: Signal = Signal::SIGSTKFLT;

/// The single, greppable marker emitted to stderr whenever an RCB-fallback
/// preemption path overshoots its programmed target by more than the configured
/// skid margin. This is the *one* canonical shape of the overshoot signal, and
/// it lives in the backend-agnostic `reverie` crate so every layer that can
/// detect an overshoot — the `reverie-ptrace` precise single-step guard and
/// hermit's detcore `report_rcb_overshoot` log-and-continue path alike — emits
/// exactly this token. A downstream harness then has a single string to grep
/// for.
///
/// Safety property for any retry harness built on this: a `--strict --verify`
/// divergence may be retried *iff* the same run emitted this marker. A
/// divergence with no marker is a real determinism bug and must never be
/// retried. Skid on the affected class of CPU is heavy-tailed (p99 well under
/// 1000 RCB, but rare outliers reach tens of thousands at every load level), so
/// no fixed margin can cover the tail — detect-and-retry is the correct
/// mitigation, not a larger constant.
pub const SKID_OVERSHOOT_MARKER: &str = "HERMIT_SKID_OVERSHOOT";
