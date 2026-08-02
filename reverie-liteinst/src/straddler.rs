//! Policy for concurrently publishing patch words across a cache line.

use std::ffi::OsStr;
use std::io;
use std::sync::OnceLock;

use liteinst2::cache_line::CacheLineSize;
use liteinst2::patcher::PatchStrategy;
use liteinst2::patcher::StalenessBudget;
use liteinst2::patcher::classify_word_patch;

/// Opt-in calibrated WordPatch++ delay, in timestamp-counter ticks.
///
/// The value must exceed the current machine's measured instruction-fetch
/// staleness bound (`Tmax`). When unset, concurrent cross-cache-line sites are
/// rejected so the in-process runtime retains its trap fallback. The stopped
/// ptrace helper instead uses caller-verified quiescent publication and does
/// not consult this policy. An uncalibrated value is unsafe and violates the
/// WordPatch++ publication contract.
pub const STRADDLER_STALENESS_TICKS_ENV: &str = "REVERIE_LITEINST_STRADDLER_STALENESS_TICKS";

static CALIBRATED_STALENESS: OnceLock<Option<StalenessBudget>> = OnceLock::new();

/// Parses the calibrated straddler delay selected for this machine.
///
/// `None` disables guarded cross-line publication. A configured value must be
/// a nonzero decimal count of timestamp-counter ticks.
pub fn straddler_staleness_from_env_value(
    value: Option<&OsStr>,
) -> io::Result<Option<StalenessBudget>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{STRADDLER_STALENESS_TICKS_ENV} must be valid UTF-8"),
        )
    })?;
    let cycles = text.trim().parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{STRADDLER_STALENESS_TICKS_ENV} must be a nonzero decimal TSC-tick count"),
        )
    })?;
    StalenessBudget::new(cycles).map(Some).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{STRADDLER_STALENESS_TICKS_ENV} must be a nonzero decimal TSC-tick count"),
        )
    })
}

pub(crate) fn initialize_from_environment() -> io::Result<()> {
    let staleness = straddler_staleness_from_env_value(
        std::env::var_os(STRADDLER_STALENESS_TICKS_ENV).as_deref(),
    )?;
    CALIBRATED_STALENESS
        .set(staleness)
        .map_err(|_| io::Error::other("LiteInst straddler policy initialized twice"))
}

pub(crate) fn budget_for_patch(
    address: usize,
    cache_line: CacheLineSize,
) -> io::Result<StalenessBudget> {
    let calibrated = CALIBRATED_STALENESS
        .get()
        .copied()
        .ok_or_else(|| io::Error::other("LiteInst straddler policy was not initialized"))?;
    budget_for_patch_with(address, cache_line, calibrated)
}

fn budget_for_patch_with(
    address: usize,
    cache_line: CacheLineSize,
    calibrated: Option<StalenessBudget>,
) -> io::Result<StalenessBudget> {
    match classify_word_patch(address, cache_line) {
        PatchStrategy::AtomicWord => Ok(StalenessBudget::new(1).expect("one is nonzero")),
        PatchStrategy::GuardedSplit { .. } => calibrated.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "cross-cache-line LiteInst publication is disabled; set \
                     {STRADDLER_STALENESS_TICKS_ENV} to a delay measured above this machine's Tmax"
                ),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use liteinst2::cache_line::CacheLineSize;
    use liteinst2::patcher::StalenessBudget;

    use super::STRADDLER_STALENESS_TICKS_ENV;
    use super::budget_for_patch_with;
    use super::straddler_staleness_from_env_value;

    const LINE: CacheLineSize = CacheLineSize::new(64).unwrap();

    #[test]
    fn unset_staleness_disables_guarded_publication() {
        assert_eq!(straddler_staleness_from_env_value(None).unwrap(), None);
        for offset in 57..64 {
            assert!(
                budget_for_patch_with(offset, LINE, None).is_err(),
                "offset {offset} must require calibrated opt-in"
            );
        }
    }

    #[test]
    fn calibrated_staleness_enables_every_split_offset() {
        let calibrated = StalenessBudget::new(17_000).unwrap();
        for offset in 57..64 {
            assert_eq!(
                budget_for_patch_with(offset, LINE, Some(calibrated)).unwrap(),
                calibrated
            );
        }
    }

    #[test]
    fn single_line_publication_does_not_need_a_staleness_delay() {
        assert_eq!(budget_for_patch_with(56, LINE, None).unwrap().cycles(), 1);
    }

    #[test]
    fn staleness_parser_accepts_only_nonzero_decimal_ticks() {
        assert_eq!(
            straddler_staleness_from_env_value(Some(OsStr::new(" 17000 ")))
                .unwrap()
                .unwrap()
                .cycles(),
            17_000
        );
        for invalid in ["", "0", "-1", "3.5", "Tmax"] {
            assert!(
                straddler_staleness_from_env_value(Some(OsStr::new(invalid))).is_err(),
                "{STRADDLER_STALENESS_TICKS_ENV}={invalid:?} must be rejected"
            );
        }
    }
}
