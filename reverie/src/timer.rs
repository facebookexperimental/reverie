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

/// Process-global count of skid-overshoot events recorded since the last
/// [`take_skid_overshoot_count`].
///
/// This is a structural, in-process side-channel that complements the greppable
/// [`SKID_OVERSHOOT_MARKER`] stderr line. The line is human/log oriented and, on
/// a `--strict --verify` run, is written to the supervisor's own stderr rather
/// than into either guest run's captured output — so an in-process classifier
/// (hermit's `verify`) cannot see it there. This counter closes that gap: every
/// overshoot-detection site increments it via [`record_skid_overshoot`], and the
/// supervisor reads and resets it between the two verify runs with
/// [`take_skid_overshoot_count`] to attribute an overshoot to a specific run.
///
/// Crucially, a *guest* cannot forge this counter: it can only print text to its
/// own stderr, never mutate the supervisor's process-global state. That makes a
/// "divergence caused by skid" classification built on this counter *causally*
/// bound — it can be true only when an overshoot actually occurred in one of the
/// compared runs — rather than merely authenticating who printed a marker.
static SKID_OVERSHOOT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record that a skid overshoot was detected. Called at every overshoot-detection
/// site (the `reverie-ptrace` precise single-step guard and hermit's detcore
/// `report_rcb_overshoot` log-and-continue path) alongside the
/// [`SKID_OVERSHOOT_MARKER`] emission. Cheap and lock-free; the overshoot path is
/// rare.
pub fn record_skid_overshoot() {
    SKID_OVERSHOOT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Atomically read and reset the recorded skid-overshoot count. The in-process
/// supervisor calls this after each verify run to attribute overshoots per run;
/// resetting to zero keeps the two runs' counts disjoint.
pub fn take_skid_overshoot_count() -> u64 {
    SKID_OVERSHOOT_COUNT.swap(0, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_then_take_counts_and_resets() {
        // Drain any residue first so this test is order-independent.
        let _ = take_skid_overshoot_count();
        record_skid_overshoot();
        record_skid_overshoot();
        assert_eq!(take_skid_overshoot_count(), 2);
        // A second take with no intervening record must be zero (reset semantics).
        assert_eq!(take_skid_overshoot_count(), 0);
    }
}
