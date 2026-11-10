//! Compatibility exports for the shared in-guest statistics implementation.

pub(crate) use reverie_inguest::stats::GuestStatsHooks;
pub use reverie_inguest::stats::InheritedEntries;
pub(crate) use reverie_inguest::stats::InheritedEntry;
pub use reverie_inguest::stats::LiteinstBackendStatsSnapshot;
pub use reverie_inguest::stats::LiteinstBackendStatsSource;
pub use reverie_inguest::stats::LiteinstDispatchPath;
pub use reverie_inguest::stats::LiteinstPatchDecision;
pub(crate) use reverie_inguest::stats::LiteinstProcessSiteStats;
#[cfg(feature = "native-exec-state")]
pub(crate) use reverie_inguest::stats::check_native_exec_stats;
pub use reverie_inguest::stats::guest_stats_enabled;
#[cfg(feature = "exec-private-init")]
pub(crate) use reverie_inguest::stats::initialize_guest_stats;
#[cfg(all(test, feature = "native-exec-state"))]
pub(crate) use reverie_inguest::stats::native_exec_report_test;
#[cfg(feature = "native-exec-state")]
pub(crate) use reverie_inguest::stats::native_exec_stats;
#[cfg(feature = "native-exec-state")]
pub(crate) use reverie_inguest::stats::restore_native_exec_stats;

#[cfg(all(test, feature = "native-exec-state"))]
pub(crate) fn seed_native_exec_counter_test(value: u64) {
    // SAFETY: callers are the existing isolated native statistics test children,
    // before admitting any runtime work; no collector operation overlaps.
    unsafe { reverie_inguest::stats::seed_native_exec_counter_test(value) }
}
