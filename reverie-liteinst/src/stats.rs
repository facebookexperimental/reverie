//! Compatibility exports for the shared in-guest statistics implementation.

pub(crate) use reverie_inguest::stats::GuestStatsHooks;
pub use reverie_inguest::stats::InheritedEntries;
pub(crate) use reverie_inguest::stats::InheritedEntry;
pub use reverie_inguest::stats::LiteinstBackendStatsSnapshot;
pub use reverie_inguest::stats::LiteinstBackendStatsSource;
pub use reverie_inguest::stats::LiteinstDispatchPath;
pub use reverie_inguest::stats::LiteinstPatchDecision;
pub(crate) use reverie_inguest::stats::LiteinstProcessSiteStats;
pub use reverie_inguest::stats::guest_stats_enabled;
pub(crate) use reverie_inguest::stats::initialize_guest_stats;
