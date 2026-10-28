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

/// Read the recorded skid-overshoot count without resetting it, as a report
/// written before the run's final [`take_skid_overshoot_count`] does.
pub fn skid_overshoot_count() -> u64 {
    SKID_OVERSHOOT_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// How a precise timer event came to be past its target (see
/// [`SkidOvershootDetail`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkidOvershootKind {
    /// The event's overflow notification found the thread already past the
    /// target, or the kernel lost the notification and a later stop found it
    /// there, and the event was delivered at the observed counter.
    DeliveredLate,
    /// The thread reached the event's delivery point, but something other
    /// than the event's notification ended the event first, undelivered.
    Missed {
        /// What ended the event: another stop, or the thread's exit.
        by: String,
        /// Whether the event's own notification was queued for the thread at
        /// that stop: the kernel had handled the overflow and queued its
        /// signal, which the stop came before.
        notification_queued: bool,
    },
}

/// What a backend knew about one skid overshoot when it detected it, beyond
/// the [`SKID_OVERSHOOT_MARKER`] line: where the counter overflowed and how
/// late the overflow was handled. A precise event is programmed to overflow
/// the counter short of its target and is single stepped from the overflow
/// to the target, so an overshoot means the overflow was handled after the
/// thread had run the whole margin.
///
/// [`take_skid_overshoot_details`] returns the details recorded since the
/// last take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkidOvershootDetail {
    /// The thread of the event.
    pub tid: crate::Tid,
    /// How the event ended up past its target.
    pub kind: SkidOvershootKind,
    /// The counter value at which the backend found the thread.
    pub rcb_actual: u64,
    /// The counter value at which the event was due.
    pub rcb_target: u64,
    /// The counter value at which the event's last programming overflows the
    /// counter, or `None` if it programmed no overflow (an event due within a
    /// few branches is notified by a signal instead).
    pub overflow_point: Option<u64>,
    /// Whether the kernel handled an overflow of that programming, or `None`
    /// where the backend has no overflow records or the programming has no
    /// overflow point. `Some(false)` past the overflow point means the kernel
    /// did not handle the overflow: it lost it, or the counter stopped first.
    pub overflow_recorded: Option<bool>,
    /// How long before the detection the kernel handled the newest overflow
    /// of that programming, in nanoseconds, by the time in its sample
    /// record, or `None` without a handled overflow or a sample time. A
    /// programming whose counter ran on past several periods has overflowed
    /// more than once; this is the newest.
    pub sample_age_ns: Option<u64>,
}

impl SkidOvershootDetail {
    /// How many counted events the thread ran past the target.
    pub fn past_target(&self) -> u64 {
        self.rcb_actual.saturating_sub(self.rcb_target)
    }

    /// How many counted events the thread ran past the overflow point.
    pub fn past_overflow(&self) -> Option<u64> {
        self.overflow_point
            .map(|point| self.rcb_actual.saturating_sub(point))
    }
}

/// One line of `key=value` fields; a field the backend does not know is
/// left out.
impl std::fmt::Display for SkidOvershootDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tid={}", self.tid)?;
        match &self.kind {
            SkidOvershootKind::DeliveredLate => write!(f, " kind=delivered_late")?,
            SkidOvershootKind::Missed {
                by,
                notification_queued,
            } => write!(
                f,
                " kind=missed by={by:?} notification_queued={notification_queued}"
            )?,
        }
        write!(
            f,
            " rcb_actual={} rcb_target={} past_target={}",
            self.rcb_actual,
            self.rcb_target,
            self.past_target()
        )?;
        if let Some(point) = self.overflow_point {
            write!(
                f,
                " overflow_point={point} past_overflow={}",
                self.rcb_actual.saturating_sub(point)
            )?;
        }
        if let Some(recorded) = self.overflow_recorded {
            write!(f, " overflow_recorded={recorded}")?;
        }
        if let Some(age) = self.sample_age_ns {
            write!(f, " sample_age_ns={age}")?;
        }
        Ok(())
    }
}

/// How many details [`record_skid_overshoot_detail`] keeps between takes.
/// Later ones are counted by [`record_skid_overshoot`] but not kept.
/// The count can exceed the details even below this: a site may count an
/// overshoot without recording a detail.
pub const SKID_OVERSHOOT_DETAILS_KEPT: usize = 16;

/// The first [`SKID_OVERSHOOT_DETAILS_KEPT`] details recorded since the last
/// [`take_skid_overshoot_details`].
static SKID_OVERSHOOT_DETAILS: std::sync::Mutex<Vec<SkidOvershootDetail>> =
    std::sync::Mutex::new(Vec::new());

/// Record what a detection site knew about a skid overshoot it counted with
/// [`record_skid_overshoot`]. Only the first [`SKID_OVERSHOOT_DETAILS_KEPT`]
/// since the last take are kept, so a run with many overshoots keeps its
/// earliest ones in bounded memory.
pub fn record_skid_overshoot_detail(detail: SkidOvershootDetail) {
    let mut details = SKID_OVERSHOOT_DETAILS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if details.len() < SKID_OVERSHOOT_DETAILS_KEPT {
        details.push(detail);
    }
}

/// Take the recorded skid-overshoot details, in detection order, and start
/// keeping anew. They need not match [`take_skid_overshoot_count`] one to
/// one: a site may count an overshoot without a detail, and only the first
/// [`SKID_OVERSHOOT_DETAILS_KEPT`] are kept.
pub fn take_skid_overshoot_details() -> Vec<SkidOvershootDetail> {
    std::mem::take(
        &mut *SKID_OVERSHOOT_DETAILS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    )
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
        assert_eq!(skid_overshoot_count(), 2, "a read does not reset");
        assert_eq!(take_skid_overshoot_count(), 2);
        // A second take with no intervening record must be zero (reset semantics).
        assert_eq!(take_skid_overshoot_count(), 0);
        assert_eq!(skid_overshoot_count(), 0);
    }

    fn detail(rcb_actual: u64) -> SkidOvershootDetail {
        SkidOvershootDetail {
            tid: crate::Tid::from_raw(7),
            kind: SkidOvershootKind::DeliveredLate,
            rcb_target: 33_000,
            rcb_actual,
            overflow_point: Some(31_000),
            overflow_recorded: Some(true),
            sample_age_ns: Some(1_500),
        }
    }

    // This test is the only writer of the details in this binary.
    #[test]
    fn the_first_details_since_a_take_are_kept_in_order() {
        let _ = take_skid_overshoot_details();
        for past in 0..SKID_OVERSHOOT_DETAILS_KEPT as u64 + 3 {
            record_skid_overshoot_detail(detail(33_001 + past));
        }
        let details = take_skid_overshoot_details();
        assert_eq!(details.len(), SKID_OVERSHOOT_DETAILS_KEPT);
        for (past, kept) in details.iter().enumerate() {
            assert_eq!(kept.rcb_actual, 33_001 + past as u64);
        }
        assert!(take_skid_overshoot_details().is_empty());
        // A take makes room again.
        record_skid_overshoot_detail(detail(90_000));
        assert_eq!(take_skid_overshoot_details(), vec![detail(90_000)]);
    }

    #[test]
    fn a_detail_prints_the_fields_it_knows() {
        let late = detail(41_000);
        assert_eq!(late.past_target(), 8_000);
        assert_eq!(late.past_overflow(), Some(10_000));
        assert_eq!(
            late.to_string(),
            "tid=7 kind=delivered_late rcb_actual=41000 rcb_target=33000 past_target=8000 \
             overflow_point=31000 past_overflow=10000 overflow_recorded=true sample_age_ns=1500"
        );
        let missed = SkidOvershootDetail {
            kind: SkidOvershootKind::Missed {
                by: "Seccomp stop".to_owned(),
                notification_queued: false,
            },
            rcb_actual: 33_000,
            overflow_point: None,
            overflow_recorded: None,
            sample_age_ns: None,
            ..late
        };
        assert_eq!(missed.past_target(), 0);
        assert_eq!(missed.past_overflow(), None);
        assert_eq!(
            missed.to_string(),
            "tid=7 kind=missed by=\"Seccomp stop\" notification_queued=false rcb_actual=33000 \
             rcb_target=33000 past_target=0"
        );
    }
}
