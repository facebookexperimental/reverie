/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed preparation statistics for the e9patch backend.

use std::fmt;

use reverie::BackendStatsSnapshot;
use reverie::BackendStatsSource;

use crate::rewrite::RewriteReport;

/// Whether rewrite coverage was measured for the root executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E9patchRewriteSupport {
    /// The root executable was an ELF image and e9tool measured its sites.
    Measured,
    /// The root command was not an ELF image, so e9patch did not analyze it.
    UnsupportedNonElf,
}

/// Where intercepted root-executable events originate after preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E9patchEventSource {
    /// No sites were rewritten, so ptrace supplies the events.
    Ptrace,
    /// At least one rewritten site supplies events through an injected trap.
    InjectedTrap,
}

impl fmt::Display for E9patchEventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ptrace => "ptrace",
            Self::InjectedTrap => "injected-trap",
        })
    }
}

/// Stable e9patch statistics captured while preparing one backend run.
///
/// Site counts are optional because a non-ELF root executable is unsupported
/// by the rewriter. `Some(0)` is reserved for an ELF image that e9tool really
/// analyzed and found to contain zero sites.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E9patchBackendStatsSnapshot {
    rewrite_support: E9patchRewriteSupport,
    recovered_sites: Option<usize>,
    patched_sites: Option<usize>,
    b0_sites: Option<usize>,
    event_source: E9patchEventSource,
}

impl E9patchBackendStatsSnapshot {
    /// Whether the root executable's rewrite coverage was measured.
    pub const fn rewrite_support(&self) -> E9patchRewriteSupport {
        self.rewrite_support
    }

    /// Number of recovered syscall sites, or `None` when rewriting was unsupported.
    pub const fn recovered_sites(&self) -> Option<usize> {
        self.recovered_sites
    }

    /// Number of patched syscall sites, or `None` when rewriting was unsupported.
    pub const fn patched_sites(&self) -> Option<usize> {
        self.patched_sites
    }

    /// Number of signal-based B0 sites, or `None` when rewriting was unsupported.
    pub const fn b0_sites(&self) -> Option<usize> {
        self.b0_sites
    }

    /// Event source selected for the root executable.
    pub const fn event_source(&self) -> E9patchEventSource {
        self.event_source
    }
}

impl fmt::Display for E9patchBackendStatsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rewrite_support {
            E9patchRewriteSupport::Measured => write!(
                formatter,
                "e9patch rewrite stats: rewrite=measured recovered_sites={} patched_sites={} b0_sites={} event_source={}",
                self.recovered_sites
                    .expect("measured coverage has recovered count"),
                self.patched_sites
                    .expect("measured coverage has patched count"),
                self.b0_sites.expect("measured coverage has B0 count"),
                self.event_source,
            ),
            E9patchRewriteSupport::UnsupportedNonElf => write!(
                formatter,
                "e9patch rewrite stats: rewrite=unsupported(non-ELF) recovered_sites=n/a patched_sites=n/a b0_sites=n/a event_source={}",
                self.event_source,
            ),
        }
    }
}

impl BackendStatsSnapshot for E9patchBackendStatsSnapshot {
    const BACKEND_NAME: &'static str = "e9patch";
}

/// Backend-owned source for one e9patch preparation snapshot.
#[derive(Clone, Debug)]
pub struct E9patchBackendStatsSource {
    snapshot: E9patchBackendStatsSnapshot,
}

impl E9patchBackendStatsSource {
    pub(crate) fn unsupported_non_elf() -> Self {
        Self {
            snapshot: E9patchBackendStatsSnapshot {
                rewrite_support: E9patchRewriteSupport::UnsupportedNonElf,
                recovered_sites: None,
                patched_sites: None,
                b0_sites: None,
                event_source: E9patchEventSource::Ptrace,
            },
        }
    }

    pub(crate) fn from_report(report: &RewriteReport) -> Self {
        Self::measured(
            report.recovered_sites(),
            report.patched_sites(),
            report.b0_sites(),
        )
    }

    fn measured(recovered_sites: usize, patched_sites: usize, b0_sites: usize) -> Self {
        Self {
            snapshot: E9patchBackendStatsSnapshot {
                rewrite_support: E9patchRewriteSupport::Measured,
                recovered_sites: Some(recovered_sites),
                patched_sites: Some(patched_sites),
                b0_sites: Some(b0_sites),
                event_source: if patched_sites == 0 {
                    E9patchEventSource::Ptrace
                } else {
                    E9patchEventSource::InjectedTrap
                },
            },
        }
    }

    /// Returns the captured snapshot.
    pub const fn snapshot(&self) -> &E9patchBackendStatsSnapshot {
        &self.snapshot
    }
}

impl BackendStatsSource for E9patchBackendStatsSource {
    type Snapshot = E9patchBackendStatsSnapshot;

    fn backend_stats(&self) -> Self::Snapshot {
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_rewrite_does_not_print_zero_counts() {
        let snapshot = E9patchBackendStatsSource::unsupported_non_elf().backend_stats();
        assert_eq!(
            snapshot.rewrite_support(),
            E9patchRewriteSupport::UnsupportedNonElf
        );
        assert_eq!(snapshot.recovered_sites(), None);
        assert_eq!(snapshot.patched_sites(), None);
        let rendered = snapshot.to_string();
        assert!(rendered.contains("rewrite=unsupported(non-ELF)"));
        assert!(rendered.contains("recovered_sites=n/a"));
        assert!(!rendered.contains("recovered_sites=0"));
    }

    #[test]
    fn measured_zero_remains_distinct_from_unsupported() {
        let snapshot = E9patchBackendStatsSource::measured(0, 0, 0).backend_stats();
        assert_eq!(snapshot.rewrite_support(), E9patchRewriteSupport::Measured);
        assert_eq!(snapshot.recovered_sites(), Some(0));
        assert_eq!(snapshot.patched_sites(), Some(0));
        assert!(snapshot.to_string().contains("recovered_sites=0"));
    }
}
