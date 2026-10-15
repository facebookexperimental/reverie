//! Inactive fixed native state for the actual LiteInst statistics collectors.
//!
//! This is bounded state data, not a successor redemption control. The consumer
//! must bind these bytes, Hermit's actual dispatch sequence and DETLOG empty cut
//! under the authenticated composite digest before any fresh image publication.

use std::sync::atomic::AtomicU64;

/// All existing per-number fallback buckets are carried, including zeroes.
pub const FALLBACK_BUCKETS: usize = 512;
/// Exact byte length: fixed header, eleven tagged scalars and two full tables.
pub const STATE_BYTES: usize = 16 + 11 * 10 + 2 * (10 + FALLBACK_BUCKETS * 8);
const HEADER: [u8; 16] = [
    b'H', b'L', b'X', b'S', b'T', b'0', b'0', b'1', 1, 0, 11, 0, 0, 2, 2, 0,
];

pub use reverie_inguest::stats::native_exec::StateError;

/// Fixed identities of the eleven actual GUEST_STATS scalar atomics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Scalar {
    InGuestSigsys,
    InGuestNestedSigsys,
    InGuestNestedHook,
    InGuestPhysicalSigsys,
    FallbackCompletionSigsys,
    CachelineStraddlerFallback,
    UnpatchableOrOtherFallback,
    FallbackRefusal,
    InheritedSigsys,
    InheritedHooks,
    PatchingDisabledFallback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FallbackState {
    pub(crate) total: u64,
    pub(crate) by_number: [u64; FALLBACK_BUCKETS],
}

/// Captured actual collector values. Fields cannot be constructed by callers.
/// Safe decode only establishes exact bounded representation, not authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeExecStatsV1 {
    scalars: [u64; 11],
    fallbacks: [FallbackState; 2],
}

use reverie_inguest::stats::native_exec::CONTINUITY;

pub(crate) fn note_activity() {
    CONTINUITY.note_activity();
}
pub(crate) fn increment(counter: &AtomicU64, report_path: bool) {
    CONTINUITY.increment(counter, report_path);
}

impl NativeExecStatsV1 {
    /// Read one genuine scalar captured from GUEST_STATS.
    pub fn scalar(&self, scalar: Scalar) -> u64 {
        self.scalars[scalar as usize]
    }

    /// Existing public fallback total, dispatch or refusal respectively.
    pub fn fallback_total(&self, refusal: bool) -> u64 {
        self.fallbacks[usize::from(refusal)].total
    }

    /// Existing public fallback per-number count; out-of-table numbers return
    /// zero, while their real contribution remains in fallback_total.
    pub fn fallback_number(&self, refusal: bool, number: i64) -> u64 {
        usize::try_from(number)
            .ok()
            .and_then(|index| {
                self.fallbacks[usize::from(refusal)]
                    .by_number
                    .get(index)
                    .copied()
            })
            .unwrap_or(0)
    }

    fn path_total(&self) -> Result<u64, StateError> {
        [0, 1, 2, 3, 4, 5, 6, 7, 10]
            .into_iter()
            .try_fold(0u64, |total, index| {
                total
                    .checked_add(self.scalars[index])
                    .ok_or(StateError::Overflow)
            })
    }

    fn validate(&self) -> Result<(), StateError> {
        if self.scalars.into_iter().any(|value| value == u64::MAX) || self.path_total()? == u64::MAX
        {
            return Err(StateError::Overflow);
        }
        // Empty real site/hook state cannot carry a nested or inherited hook
        // count. Refuse rather than let the terminal direct-hook projection
        // silently saturate away an inherited count.
        if self.scalars[Scalar::InGuestNestedHook as usize] != 0
            || self.scalars[Scalar::InheritedHooks as usize] != 0
        {
            return Err(StateError::UnsupportedSites);
        }
        for table in &self.fallbacks {
            if table.total == u64::MAX || table.by_number.contains(&u64::MAX) {
                return Err(StateError::Overflow);
            }
            let tracked = table.by_number.iter().try_fold(0u64, |sum, value| {
                sum.checked_add(*value).ok_or(StateError::Overflow)
            })?;
            if tracked > table.total {
                return Err(StateError::InconsistentCounters);
            }
        }
        if self.fallbacks[1].total > self.fallbacks[0].total
            || self.fallbacks[1]
                .by_number
                .iter()
                .zip(&self.fallbacks[0].by_number)
                .any(|(refused, dispatched)| refused > dispatched)
        {
            return Err(StateError::InconsistentCounters);
        }
        Ok(())
    }

    fn read_actual() -> Result<Self, StateError> {
        if CONTINUITY.overflowed() {
            return Err(StateError::Overflow);
        }
        crate::runtime::native_exec_site_cut()?;
        let state = Self {
            scalars: crate::stats::native_exec_stats()?,
            fallbacks: crate::runtime::native_exec_fallbacks(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Capture the actual eleven scalars and both complete fallback tables.
    /// It does not reset counters, submit a report or replace the endpoint.
    ///
    /// # Safety
    /// The trusted native owner must exclusively hold a single-threaded,
    /// quiescent live image with handlers/producers excluded throughout this
    /// read. Site patching must genuinely be disabled by installed runtime.
    pub unsafe fn capture() -> Result<Self, StateError> {
        let state = Self::read_actual()?;
        let total = state.path_total()?;
        if CONTINUITY.is_checked() {
            if CONTINUITY.path_total() != total {
                return Err(StateError::Changed);
            }
        } else {
            unsafe { CONTINUITY.arm(total) };
        }
        Ok(state)
    }

    /// Final exact read-only equality check. The source performs no allocation,
    /// formatting, locks or syscall on either success or refusal. The consuming
    /// native leaf still needs independent compiled fixed-gate qualification.
    ///
    /// # Safety
    /// The same actual owner must retain exclusive quiescence and the frozen
    /// runtime cut. This does not establish Hermit's DETLOG empty cut or Tool
    /// snapshot equality; the actual consumer must check those separately.
    pub unsafe fn check_frozen(&self) -> Result<(), StateError> {
        if CONTINUITY.overflowed() {
            return Err(StateError::Overflow);
        }
        crate::runtime::native_exec_site_cut()?;
        crate::stats::check_native_exec_stats(&self.scalars)?;
        crate::runtime::check_native_exec_fallbacks(&self.fallbacks)?;
        if CONTINUITY.path_total() != self.path_total()? {
            return Err(StateError::Changed);
        }
        Ok(())
    }

    /// Encode into preallocated bounded state storage. The fixed order and
    /// tags admit neither unknown nor duplicate scalar/table identities.
    pub fn encode_into(&self, bytes: &mut [u8; STATE_BYTES]) {
        bytes[..16].copy_from_slice(&HEADER);
        let mut offset = 16;
        for (index, value) in self.scalars.iter().enumerate() {
            bytes[offset..offset + 2].copy_from_slice(&((index + 1) as u16).to_le_bytes());
            bytes[offset + 2..offset + 10].copy_from_slice(&value.to_le_bytes());
            offset += 10;
        }
        for (index, table) in self.fallbacks.iter().enumerate() {
            bytes[offset..offset + 2].copy_from_slice(&((index + 1) as u16).to_le_bytes());
            bytes[offset + 2..offset + 10].copy_from_slice(&table.total.to_le_bytes());
            offset += 10;
            for value in &table.by_number {
                bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                offset += 8;
            }
        }
    }

    /// Exact fixed-version decode; wrong size, unknown/duplicate/out-of-order
    /// identities, trailing bytes, unsupported hooks and overflow refuse.
    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() != STATE_BYTES {
            return Err(StateError::Bounds);
        }
        if bytes[..16] != HEADER {
            return Err(StateError::Encoding);
        }
        let mut scalars = [0; 11];
        let mut fallbacks = std::array::from_fn(|_| FallbackState {
            total: 0,
            by_number: [0; FALLBACK_BUCKETS],
        });
        let mut offset = 16;
        for (index, value) in scalars.iter_mut().enumerate() {
            if bytes[offset..offset + 2] != ((index + 1) as u16).to_le_bytes() {
                return Err(StateError::Encoding);
            }
            *value = u64::from_le_bytes(bytes[offset + 2..offset + 10].try_into().unwrap());
            offset += 10;
        }
        for (index, table) in fallbacks.iter_mut().enumerate() {
            if bytes[offset..offset + 2] != ((index + 1) as u16).to_le_bytes() {
                return Err(StateError::Encoding);
            }
            table.total = u64::from_le_bytes(bytes[offset + 2..offset + 10].try_into().unwrap());
            offset += 10;
            for value in &mut table.by_number {
                *value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
            }
        }
        let state = Self { scalars, fallbacks };
        state.validate()?;
        Ok(state)
    }

    /// Restore exactly once into real fresh collector storage before any work.
    /// Preflight refuses activity even if a fork reset made its counts zero.
    /// No failure path zeroes live counters to fit the snapshot.
    ///
    /// # Safety
    /// The caller must have verified authenticated composite bytes against
    /// both independently expected digests and exact watched owner/new image.
    /// It exclusively owns a genuine fresh single-threaded image, with no
    /// guest/handler/observer work before restoration or publication. The
    /// fresh statistics endpoint and installation must be genuine. It must
    /// also restore Hermit's authenticated sequence before observer publication
    /// and prove the actual DETLOG empty boundary. This API is not authority
    /// for any of those facts and has no existing production caller.
    pub unsafe fn restore_fresh(&self) -> Result<(), StateError> {
        self.validate()?;
        let total = self.path_total()?;
        if CONTINUITY.restore_started() {
            return Err(StateError::DuplicateRestore);
        }
        let current = Self::read_actual()?;
        if CONTINUITY.has_activity()
            || CONTINUITY.is_checked()
            || current.scalars != [0; 11]
            || current
                .fallbacks
                .iter()
                .any(|table| table.total != 0 || table.by_number != [0; FALLBACK_BUCKETS])
        {
            return Err(StateError::NotFresh);
        }
        unsafe { CONTINUITY.begin_restore()? };
        unsafe { crate::stats::restore_native_exec_stats(&self.scalars) };
        crate::runtime::restore_native_exec_fallbacks(&self.fallbacks);
        unsafe { CONTINUITY.finish_restore(total) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;

    use super::*;
    use crate::stats::GuestStatsHooks;
    use crate::stats::InheritedEntry;
    use crate::stats::LiteinstDispatchPath;

    const ROLE: &str = "HERMIT_NATIVE_STATS_TEST_ROLE";

    // Each case gets new actual process-global collector/site storage. These
    // tests model only installation selection, never a Linux dispatch or exec.
    fn setup() -> GuestStatsHooks {
        crate::runtime::prepare_native_exec_state_test();
        crate::stats::initialize_guest_stats(std::path::Path::new("/unused-native-stats-test"))
            .unwrap()
    }

    fn child(name: &str, role: &str, bytes: Option<&[u8]>) -> std::process::Output {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("native_exec_state::tests::{name}"),
                "--nocapture",
            ])
            .env(ROLE, role)
            .stdin(if bytes.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(bytes) = bytes {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    }

    fn passed(output: std::process::Output) {
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("running 1 test"), "{stdout}");
        assert!(stdout.contains("1 passed"), "{stdout}");
    }

    fn isolated(name: &str) -> bool {
        if std::env::var(ROLE).ok().as_deref() == Some(name) {
            return false;
        }
        passed(child(name, name, None));
        true
    }

    fn populate(hooks: GuestStatsHooks) {
        let paths = [
            LiteinstDispatchPath::InGuestSigsys,
            LiteinstDispatchPath::InGuestNestedSigsys,
            LiteinstDispatchPath::InGuestPhysicalSigsys,
            LiteinstDispatchPath::FallbackCompletionSigsys,
            LiteinstDispatchPath::CachelineStraddlerFallback,
            LiteinstDispatchPath::UnpatchableOrOtherFallback,
            LiteinstDispatchPath::FallbackRefusal,
            LiteinstDispatchPath::PatchingDisabledFallback,
        ];
        for (index, path) in paths.into_iter().enumerate() {
            for _ in 0..index + 1 {
                hooks.record_path(path);
            }
        }
        hooks.record_inherited_entry(InheritedEntry::Sigsys);
        for number in [39, 39, -1, 512] {
            crate::runtime::record_fallback_dispatch(number);
        }
        crate::runtime::record_native_exec_refusal_test(39);
    }

    fn report_matches(state: &NativeExecStatsV1) {
        let report = crate::stats::native_exec_report_test();
        let fields = [
            (LiteinstDispatchPath::InGuestSigsys, Scalar::InGuestSigsys),
            (
                LiteinstDispatchPath::InGuestNestedSigsys,
                Scalar::InGuestNestedSigsys,
            ),
            (
                LiteinstDispatchPath::InGuestNestedHook,
                Scalar::InGuestNestedHook,
            ),
            (
                LiteinstDispatchPath::InGuestPhysicalSigsys,
                Scalar::InGuestPhysicalSigsys,
            ),
            (
                LiteinstDispatchPath::FallbackCompletionSigsys,
                Scalar::FallbackCompletionSigsys,
            ),
            (
                LiteinstDispatchPath::CachelineStraddlerFallback,
                Scalar::CachelineStraddlerFallback,
            ),
            (
                LiteinstDispatchPath::UnpatchableOrOtherFallback,
                Scalar::UnpatchableOrOtherFallback,
            ),
            (
                LiteinstDispatchPath::FallbackRefusal,
                Scalar::FallbackRefusal,
            ),
            (
                LiteinstDispatchPath::PatchingDisabledFallback,
                Scalar::PatchingDisabledFallback,
            ),
        ];
        for (path, scalar) in fields {
            assert_eq!(report.paths().count(&path), state.scalar(scalar));
        }
        assert_eq!(report.paths().count(&LiteinstDispatchPath::DirectHook), 0);
        assert_eq!(
            report.inherited().sigsys,
            state.scalar(Scalar::InheritedSigsys)
        );
        assert_eq!(
            report.inherited().hooks,
            state.scalar(Scalar::InheritedHooks)
        );
        assert!(report.sites().is_empty());
        assert_eq!(
            crate::runtime::fallback_dispatch_count(),
            state.fallback_total(false)
        );
        assert_eq!(
            crate::runtime::fallback_refusal_count(),
            state.fallback_total(true)
        );
        for number in -1..=512 {
            assert_eq!(
                crate::runtime::fallback_syscall_count(number),
                state.fallback_number(false, number)
            );
            assert_eq!(
                crate::runtime::fallback_syscall_refusal_count(number),
                state.fallback_number(true, number)
            );
        }
    }

    #[test]
    fn collector_roundtrip_into_fresh_image_and_next_counts() {
        let name = "collector_roundtrip_into_fresh_image_and_next_counts";
        match std::env::var(ROLE).ok().as_deref() {
            Some("restore-child") => {
                let mut bytes = [0; STATE_BYTES];
                std::io::stdin().read_exact(&mut bytes).unwrap();
                let old = NativeExecStatsV1::decode(&bytes).unwrap();
                let hooks = setup();
                // SAFETY: collector protocol fixture only. The outer child
                // supplied bytes from its actual state, not authenticated exec.
                unsafe {
                    old.restore_fresh().unwrap();
                }
                assert_eq!(unsafe { NativeExecStatsV1::capture().unwrap() }, old);
                assert_eq!(unsafe { old.check_frozen() }, Ok(()));
                report_matches(&old);
                assert_eq!(
                    unsafe { old.restore_fresh() },
                    Err(StateError::DuplicateRestore)
                );
                assert_eq!(NativeExecStatsV1::read_actual().unwrap(), old);
                hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
                crate::runtime::record_fallback_dispatch(39);
                let next = unsafe { NativeExecStatsV1::capture().unwrap() };
                let mut expected = old.clone();
                expected.scalars[Scalar::InGuestSigsys as usize] += 1;
                expected.fallbacks[0].total += 1;
                expected.fallbacks[0].by_number[39] += 1;
                assert_eq!(next, expected);
                assert_eq!(unsafe { old.check_frozen() }, Err(StateError::Changed));
                report_matches(&next);
            }
            Some(role) if role == name => {
                let hooks = setup();
                populate(hooks);
                let state = unsafe { NativeExecStatsV1::capture().unwrap() };
                assert_eq!(state.scalars, [1, 2, 0, 3, 4, 5, 6, 7, 1, 0, 8]);
                assert_eq!(state.fallback_total(false), 4);
                assert_eq!(state.fallback_number(false, 39), 2);
                assert_eq!(state.fallback_total(true), 1);
                report_matches(&state);
                let mut bytes = [0; STATE_BYTES];
                state.encode_into(&mut bytes);
                assert_eq!(STATE_BYTES, 8338);
                const { assert!(STATE_BYTES < 1024 * 1024) };
                assert_eq!(NativeExecStatsV1::decode(&bytes).unwrap(), state);
                passed(child(name, "restore-child", Some(&bytes)));
                assert_eq!(unsafe { state.check_frozen() }, Ok(()));
                assert_eq!(NativeExecStatsV1::read_actual().unwrap(), state);
            }
            _ => passed(child(name, name, None)),
        }
    }

    #[test]
    fn failed_exec_recheck_keeps_old_collectors() {
        if isolated("failed_exec_recheck_keeps_old_collectors") {
            return;
        }
        let hooks = setup();
        populate(hooks);
        let sealed = unsafe { NativeExecStatsV1::capture().unwrap() };
        assert_eq!(unsafe { sealed.check_frozen() }, Ok(()));
        assert_eq!(NativeExecStatsV1::read_actual().unwrap(), sealed);
        hooks.record_path(LiteinstDispatchPath::PatchingDisabledFallback);
        let changed = NativeExecStatsV1::read_actual().unwrap();
        assert_eq!(unsafe { sealed.check_frozen() }, Err(StateError::Changed));
        assert_eq!(unsafe { sealed.restore_fresh() }, Err(StateError::NotFresh));
        assert_eq!(NativeExecStatsV1::read_actual().unwrap(), changed);
        report_matches(&changed);
    }

    #[test]
    fn restore_refuses_activity_even_after_existing_fork_reset() {
        if isolated("restore_refuses_activity_even_after_existing_fork_reset") {
            return;
        }
        let hooks = setup();
        let empty = NativeExecStatsV1::read_actual().unwrap();
        hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
        crate::runtime::record_fallback_dispatch(39);
        hooks.reset_after_fork();
        crate::runtime::reset_fallback_observability();
        assert_eq!(NativeExecStatsV1::read_actual().unwrap(), empty);
        assert_eq!(unsafe { empty.restore_fresh() }, Err(StateError::NotFresh));
        assert_eq!(NativeExecStatsV1::read_actual().unwrap(), empty);
    }

    #[test]
    fn restore_refuses_nonzero_fallback_activity_and_preserves_it() {
        if isolated("restore_refuses_nonzero_fallback_activity_and_preserves_it") {
            return;
        }
        setup();
        let empty = NativeExecStatsV1::read_actual().unwrap();
        crate::runtime::record_fallback_dispatch(511);
        crate::runtime::record_native_exec_refusal_test(511);
        let live = NativeExecStatsV1::read_actual().unwrap();
        assert_eq!(unsafe { empty.restore_fresh() }, Err(StateError::NotFresh));
        assert_eq!(NativeExecStatsV1::read_actual().unwrap(), live);
        report_matches(&live);
    }

    #[test]
    fn actual_site_state_and_disabled_patching_required() {
        if isolated("actual_site_state_and_disabled_patching_required") {
            return;
        }
        assert_eq!(
            unsafe { NativeExecStatsV1::capture() },
            Err(StateError::UnsupportedSites)
        );
        setup();
        let sealed = unsafe { NativeExecStatsV1::capture().unwrap() };
        crate::runtime::contaminate_native_exec_state_test();
        assert_eq!(
            unsafe { sealed.check_frozen() },
            Err(StateError::UnsupportedSites)
        );
        assert_eq!(
            unsafe { sealed.restore_fresh() },
            Err(StateError::UnsupportedSites)
        );
        assert_eq!(crate::stats::native_exec_stats().unwrap(), sealed.scalars);
        assert_eq!(crate::runtime::native_exec_fallbacks(), sealed.fallbacks);
    }

    #[test]
    fn actual_hook_history_refuses_empty_site_slice() {
        if isolated("actual_hook_history_refuses_empty_site_slice") {
            return;
        }
        let hooks = setup();
        hooks.record_inherited_entry(InheritedEntry::Hook);
        assert_eq!(
            unsafe { NativeExecStatsV1::capture() },
            Err(StateError::UnsupportedSites)
        );
        assert_eq!(crate::stats::native_exec_stats().unwrap()[9], 1);
    }

    #[test]
    fn missing_actual_collector_refuses() {
        if isolated("missing_actual_collector_refuses") {
            return;
        }
        crate::runtime::prepare_native_exec_state_test();
        assert_eq!(
            unsafe { NativeExecStatsV1::capture() },
            Err(StateError::MissingCollector)
        );
    }

    #[test]
    fn codec_refuses_unknown_duplicate_trailing_and_overflow() {
        if isolated("codec_refuses_unknown_duplicate_trailing_and_overflow") {
            return;
        }
        let hooks = setup();
        populate(hooks);
        let state = unsafe { NativeExecStatsV1::capture().unwrap() };
        let mut good = [0; STATE_BYTES];
        state.encode_into(&mut good);
        for size in [0, 15, STATE_BYTES - 1] {
            assert_eq!(
                NativeExecStatsV1::decode(&good[..size]),
                Err(StateError::Bounds)
            );
        }
        let mut trailing = good.to_vec();
        trailing.push(0);
        assert_eq!(
            NativeExecStatsV1::decode(&trailing),
            Err(StateError::Bounds)
        );
        for offset in [0, 8, 10, 12, 14, 16, 26, 126, 4232] {
            let mut bad = good;
            bad[offset] ^= 0xff;
            assert_eq!(NativeExecStatsV1::decode(&bad), Err(StateError::Encoding));
        }
        let mut duplicate = good;
        duplicate[26..28].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            NativeExecStatsV1::decode(&duplicate),
            Err(StateError::Encoding)
        );
        let mut overflow = good;
        overflow[18..26].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            NativeExecStatsV1::decode(&overflow),
            Err(StateError::Overflow)
        );
        let mut sum_overflow = good;
        sum_overflow[18..26].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        assert_eq!(
            NativeExecStatsV1::decode(&sum_overflow),
            Err(StateError::Overflow)
        );
        let mut inconsistent = good;
        inconsistent[128..136].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            NativeExecStatsV1::decode(&inconsistent),
            Err(StateError::InconsistentCounters)
        );
        let mut hook = good;
        hook[38..46].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            NativeExecStatsV1::decode(&hook),
            Err(StateError::UnsupportedSites)
        );
        assert_eq!(unsafe { state.check_frozen() }, Ok(()));
    }

    #[test]
    fn native_counter_overflow_is_terminal() {
        let name = "native_counter_overflow_is_terminal";
        if std::env::var(ROLE).ok().as_deref() != Some(name) {
            let output = child(name, name, None);
            assert_eq!(output.status.code(), Some(122), "{output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("running 1 test")
            );
            return;
        }
        let hooks = setup();
        crate::stats::seed_native_exec_counter_test(u64::MAX - 2);
        let old = unsafe { NativeExecStatsV1::capture().unwrap() };
        assert_eq!(old.scalar(Scalar::InGuestSigsys), u64::MAX - 2);
        hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
        assert_eq!(crate::stats::native_exec_stats().unwrap()[0], u64::MAX - 1);
        hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
        assert_eq!(crate::stats::native_exec_stats().unwrap()[0], u64::MAX);
        hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
        panic!("overflow must terminate through the real refusal gate");
    }

    #[test]
    fn prior_unarmed_counter_wrap_is_not_a_fresh_zero() {
        if isolated("prior_unarmed_counter_wrap_is_not_a_fresh_zero") {
            return;
        }
        let hooks = setup();
        crate::stats::seed_native_exec_counter_test(u64::MAX);
        hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
        assert_eq!(crate::stats::native_exec_stats().unwrap()[0], 0);
        assert_eq!(
            unsafe { NativeExecStatsV1::capture() },
            Err(StateError::Overflow)
        );
    }

    #[test]
    fn native_fallback_overflow_is_terminal() {
        let name = "native_fallback_overflow_is_terminal";
        if std::env::var(ROLE).ok().as_deref() != Some(name) {
            let output = child(name, name, None);
            assert_eq!(output.status.code(), Some(122), "{output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("running 1 test")
            );
            return;
        }
        setup();
        crate::runtime::seed_native_exec_fallback_test(u64::MAX - 2);
        let old = unsafe { NativeExecStatsV1::capture().unwrap() };
        assert_eq!(old.fallback_total(false), u64::MAX - 2);
        assert_eq!(old.fallback_number(false, 511), u64::MAX - 2);
        for value in [u64::MAX - 1, u64::MAX] {
            crate::runtime::record_fallback_dispatch(511);
            assert_eq!(crate::runtime::fallback_dispatch_count(), value);
            assert_eq!(crate::runtime::fallback_syscall_count(511), value);
        }
        crate::runtime::record_fallback_dispatch(511);
        panic!("fallback overflow must terminate through the real refusal gate");
    }

    #[test]
    fn actual_report_path_sum_overflow_refuses() {
        if isolated("actual_report_path_sum_overflow_refuses") {
            return;
        }
        let hooks = setup();
        populate(hooks);
        crate::stats::seed_native_exec_counter_test(u64::MAX - 1);
        let before = crate::stats::native_exec_stats().unwrap();
        assert_eq!(
            unsafe { NativeExecStatsV1::capture() },
            Err(StateError::Overflow)
        );
        assert_eq!(crate::stats::native_exec_stats().unwrap(), before);
        assert!(!CONTINUITY.is_checked());
    }

    #[test]
    fn every_actual_scalar_mutation_after_seal_refuses() {
        let name = "every_actual_scalar_mutation_after_seal_refuses";
        let role = std::env::var(ROLE).ok();
        let index = role
            .as_deref()
            .and_then(|role| role.strip_prefix("scalar-mutation-"))
            .and_then(|index| index.parse::<usize>().ok());
        let Some(index) = index else {
            for index in 0..11 {
                passed(child(name, &format!("scalar-mutation-{index}"), None));
            }
            return;
        };
        let hooks = setup();
        let sealed = unsafe { NativeExecStatsV1::capture().unwrap() };
        match index {
            0 => hooks.record_path(LiteinstDispatchPath::InGuestSigsys),
            1 => hooks.record_path(LiteinstDispatchPath::InGuestNestedSigsys),
            2 => hooks.record_path(LiteinstDispatchPath::InGuestNestedHook),
            3 => hooks.record_path(LiteinstDispatchPath::InGuestPhysicalSigsys),
            4 => hooks.record_path(LiteinstDispatchPath::FallbackCompletionSigsys),
            5 => hooks.record_path(LiteinstDispatchPath::CachelineStraddlerFallback),
            6 => hooks.record_path(LiteinstDispatchPath::UnpatchableOrOtherFallback),
            7 => hooks.record_path(LiteinstDispatchPath::FallbackRefusal),
            8 => hooks.record_inherited_entry(InheritedEntry::Sigsys),
            9 => hooks.record_inherited_entry(InheritedEntry::Hook),
            10 => hooks.record_path(LiteinstDispatchPath::PatchingDisabledFallback),
            _ => panic!("unknown mutation control"),
        }
        let mut expected = [0; 11];
        expected[index] = 1;
        assert_eq!(crate::stats::native_exec_stats().unwrap(), expected);
        assert_eq!(unsafe { sealed.check_frozen() }, Err(StateError::Changed));
        assert_eq!(crate::stats::native_exec_stats().unwrap(), expected);
    }

    #[test]
    fn actual_fallback_mutation_after_seal_refuses() {
        if isolated("actual_fallback_mutation_after_seal_refuses") {
            return;
        }
        setup();
        let empty = unsafe { NativeExecStatsV1::capture().unwrap() };
        crate::runtime::record_fallback_dispatch(511);
        let dispatched = unsafe { NativeExecStatsV1::capture().unwrap() };
        assert_eq!(unsafe { empty.check_frozen() }, Err(StateError::Changed));
        crate::runtime::record_native_exec_refusal_test(511);
        let refused = unsafe { NativeExecStatsV1::capture().unwrap() };
        assert_eq!(
            unsafe { dispatched.check_frozen() },
            Err(StateError::Changed)
        );
        assert_eq!(unsafe { refused.check_frozen() }, Ok(()));
        assert_eq!(crate::runtime::fallback_dispatch_count(), 1);
        assert_eq!(crate::runtime::fallback_syscall_count(511), 1);
        assert_eq!(crate::runtime::fallback_refusal_count(), 1);
        assert_eq!(crate::runtime::fallback_syscall_refusal_count(511), 1);
    }
}
