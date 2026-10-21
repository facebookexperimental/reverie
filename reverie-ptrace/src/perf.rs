//! Ptrace validation owner and compatibility imports for shared perf mechanics.
use std::sync::LazyLock;

pub use reverie::perf::do_branches;
pub use reverie::perf::is_perf_supported;
pub(crate) use reverie::perf::*;
use tracing::error;

use crate::validation::PmuValidationError;
use crate::validation::check_for_pmu_bugs as run_pmu_validation;

static PMU_BUG: LazyLock<Result<(), PmuValidationError>> = LazyLock::new(run_pmu_validation);

/// Whether this host's performance counters passed Reverie's validation: the
/// counters work, and no known counting bug (such as AMD Zen SpecLockMap) is
/// present. Reverie computes this once per process, on the first call here or
/// the first timer, and only logs a failure. A tool that needs exact
/// retired-branch counts, such as a deterministic one, can refuse to run on a
/// host where this returns an error.
///
/// The validation reads the PMU configuration, which fixes it for the
/// process: call [`set_pmu_config`](crate::set_pmu_config) first, or it will
/// fail.
pub fn pmu_validation() -> Result<(), &'static PmuValidationError> {
    PMU_BUG.as_ref().copied()
}

/// Keep validation at the original precise-timer constructor callpoint.
pub(crate) fn check_for_pmu_bugs() {
    static LOGGED: std::sync::Once = std::sync::Once::new();
    if let Err(pmu_error) = &*PMU_BUG {
        // Once per process, not once per timer: the result never changes.
        LOGGED.call_once(|| {
            error!(
                error = ?pmu_error,
                "PMU validation failed; RCB timers may be unreliable"
            )
        });
    }
}

/// Concisely return when hardware perf counters are unavailable.
#[macro_export]
macro_rules! ret_without_perf {
    () => {
        if !$crate::is_perf_supported() {
            return;
        }
    };
    (expr:expr) => {
        if !$crate::is_perf_supported() {
            return ($expr);
        }
    };
}
