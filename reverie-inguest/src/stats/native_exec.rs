//! Inactive native continuity for the shared actual statistics collector.
//! Fields remain private. This cohort is data bookkeeping, never exec authority.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Refusal before any restoration store, or a changed final live cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    /// The actual scalar collector is absent.
    MissingCollector,
    /// The actual frontend runtime is absent.
    MissingRuntime,
    /// Address-indexed or hook state is outside the bounded domain.
    UnsupportedSites,
    /// A fixed bound was exceeded.
    Bounds,
    /// The exact state representation is invalid.
    Encoding,
    /// Actual counters or their sum overflowed.
    Overflow,
    /// Actual counter relationships are inconsistent.
    InconsistentCounters,
    /// The final live cut changed.
    Changed,
    /// The replacement collector already observed activity.
    NotFresh,
    /// Restoration was already attempted.
    DuplicateRestore,
}

/// The one process-local scalar/fallback counter continuity cohort.
#[doc(hidden)]
pub struct CounterContinuity {
    activity: AtomicBool,
    checked: AtomicBool,
    overflow: AtomicBool,
    path_total: AtomicU64,
    restored: AtomicU8,
}

/// Shared collector and frontend counters use this same actual cohort.
#[doc(hidden)]
pub static CONTINUITY: CounterContinuity = CounterContinuity {
    activity: AtomicBool::new(false),
    checked: AtomicBool::new(false),
    overflow: AtomicBool::new(false),
    path_total: AtomicU64::new(0),
    restored: AtomicU8::new(0),
};

impl CounterContinuity {
    /// Note actual producer/reset activity, even when counters later become zero.
    pub fn note_activity(&self) {
        self.activity.store(true, Ordering::Release);
    }
    /// Whether any actual producer/reset activity occurred.
    pub fn has_activity(&self) -> bool {
        self.activity.load(Ordering::Acquire)
    }
    /// Whether native continuity has actually been armed.
    pub fn is_checked(&self) -> bool {
        self.checked.load(Ordering::Acquire)
    }
    /// Whether actual increments overflowed, including before native arming.
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::Acquire)
    }
    /// Current exact sum retained at the native cut.
    pub fn path_total(&self) -> u64 {
        self.path_total.load(Ordering::Acquire)
    }
    /// Whether restoration has already been attempted.
    pub fn restore_started(&self) -> bool {
        self.restored.load(Ordering::Acquire) != 0
    }
    /// Arm after an actual exclusive, validated collector capture.
    ///
    /// # Safety
    /// The caller owns the genuine quiescent cut, validates all actual counters
    /// and the exact sum, and retains that ownership. This does not admit exec.
    pub unsafe fn arm(&self, total: u64) {
        self.path_total.store(total, Ordering::Release);
        self.checked.store(true, Ordering::Release);
    }
    /// Claim the one restore attempt after complete fresh-image validation.
    ///
    /// # Safety
    /// The caller owns actual fresh collector/runtime storage and excludes all
    /// producers while validating and restoring the authenticated full state.
    pub unsafe fn begin_restore(&self) -> Result<(), StateError> {
        self.restored
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| StateError::DuplicateRestore)
    }
    /// Complete stores after restoring the exact actual scalar and fallback set.
    ///
    /// # Safety
    /// The same owner has claimed restoration and completed every validated
    /// collector store, retaining all fresh-image and composite authority.
    pub unsafe fn finish_restore(&self, total: u64) {
        unsafe {
            self.arm(total);
        }
        self.restored.store(2, Ordering::Release);
    }
    /// Preserve ordinary increments; after arming, overflow takes the existing
    /// shared terminal gate rather than wrapping or saturating the report.
    pub fn increment(&self, counter: &AtomicU64, report_path: bool) {
        self.note_activity();
        if !self.is_checked() {
            if counter.fetch_add(1, Ordering::Relaxed) == u64::MAX {
                self.overflow.store(true, Ordering::Release);
            }
            return;
        }
        let add = |value: u64| value.checked_add(1);
        if (report_path
            && self
                .path_total
                .try_update(Ordering::AcqRel, Ordering::Acquire, add)
                .is_err())
            || counter
                .try_update(Ordering::AcqRel, Ordering::Acquire, add)
                .is_err()
        {
            self.overflow.store(true, Ordering::Release);
            unsafe { crate::guest::support::exit_now(122) };
        }
    }
}
