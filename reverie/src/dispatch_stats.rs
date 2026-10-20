/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One backend-neutral record of how intercepted guest events were delivered.
//!
//! Every backend keeps its own detailed statistics snapshot. This record is the
//! common projection of those snapshots, so runs on different backends (or with
//! different patching strategies) can be compared counter by counter. Backends
//! build it from the counters they already maintain; it is never a second place
//! where an event is counted.
//!
//! A counter is `None` when the backend does not measure it. `Some(0)` means
//! the backend measured it, or the route is structurally impossible for that
//! backend (for example, plain ptrace never takes a patched direct call).

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Version of the serialized [`DispatchStats`] layout.
///
/// Bump this whenever a field is renamed, removed, or changes meaning. Adding
/// an optional field that older readers can ignore does not require a bump.
pub const DISPATCH_STATS_SCHEMA_VERSION: u32 = 1;

/// Counts of intercepted guest events by the route that delivered them.
///
/// The first five fields are dispatch routes, and they count physical
/// deliveries (a signal, a patched-call entry, a ptrace stop), which is what a
/// patching strategy pays for. They are not a count of syscalls or of tool
/// callbacks:
///
/// - one syscall can be delivered more than once: a lazily patched site's
///   first call takes a signal that installs the patch and then enters through
///   it, and a restarted syscall traps again;
/// - a delivery the backend completes without a tool callback still counts,
///   such as an unsubscribed syscall that the filter traps or a syscall the
///   tool itself makes.
///
/// The ptrace syscall-entry and syscall-exit stops are tracer overhead, not
/// routes, and refusals are attempts that never reached ordinary tool dispatch.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DispatchCounters {
    /// Events delivered to an in-guest handler by a seccomp `SIGSYS` signal.
    pub signal_traps: Option<u64>,
    /// Events delivered through a patched direct jump or call, with neither a
    /// signal nor a ptrace stop.
    pub patched_direct_calls: Option<u64>,
    /// Events delivered to a ptrace tracer by a seccomp trace stop.
    pub ptrace_seccomp_stops: Option<u64>,
    /// Events at patched sites delivered to a ptrace tracer by a `SIGTRAP` stop.
    pub ptrace_sigtrap_stops: Option<u64>,
    /// Events delivered to an in-guest handler by a `SIGILL` marker written
    /// over the original instruction.
    pub sigill_marker_hits: Option<u64>,
    /// `PTRACE_SYSCALL` syscall-entry stops observed by the tracer.
    pub ptrace_syscall_entry_stops: Option<u64>,
    /// `PTRACE_SYSCALL` syscall-exit stops observed by the tracer.
    pub ptrace_syscall_exit_stops: Option<u64>,
    /// Intercepted events the backend refused instead of dispatching.
    pub refusals: Option<u64>,
}

impl DispatchCounters {
    /// Every counter set to `Some(0)`.
    pub const ZERO: Self = Self {
        signal_traps: Some(0),
        patched_direct_calls: Some(0),
        ptrace_seccomp_stops: Some(0),
        ptrace_sigtrap_stops: Some(0),
        sigill_marker_hits: Some(0),
        ptrace_syscall_entry_stops: Some(0),
        ptrace_syscall_exit_stops: Some(0),
        refusals: Some(0),
    };

    /// Total deliveries by any route (see [`DispatchCounters`] for why this is
    /// not the number of syscalls).
    ///
    /// `None` when any route is unmeasured: a partial sum would read as a
    /// total.
    pub fn dispatches(&self) -> Option<u64> {
        sum_all([self.patched_direct_calls, self.trapped_dispatches()])
    }

    /// Deliveries through a signal or a ptrace stop rather than a patched
    /// direct call; `None` when any of those routes is unmeasured.
    pub fn trapped_dispatches(&self) -> Option<u64> {
        sum_all([
            self.signal_traps,
            self.ptrace_seccomp_stops,
            self.ptrace_sigtrap_stops,
            self.sigill_marker_hits,
        ])
    }

    fn fields(&self) -> [(&'static str, Option<u64>); 8] {
        [
            ("signal_traps", self.signal_traps),
            ("patched_direct_calls", self.patched_direct_calls),
            ("ptrace_seccomp_stops", self.ptrace_seccomp_stops),
            ("ptrace_sigtrap_stops", self.ptrace_sigtrap_stops),
            ("sigill_marker_hits", self.sigill_marker_hits),
            (
                "ptrace_syscall_entry_stops",
                self.ptrace_syscall_entry_stops,
            ),
            ("ptrace_syscall_exit_stops", self.ptrace_syscall_exit_stops),
            ("refusals", self.refusals),
        ]
    }
}

fn sum_all<const N: usize>(values: [Option<u64>; N]) -> Option<u64> {
    values
        .into_iter()
        .try_fold(0_u64, |total, value| value.map(|value| total + value))
}

/// Counts of distinct instrumentation sites.
///
/// What a candidate is depends on the backend's strategy, so compare site
/// counts across backends with care: e9patch counts the sites it found in the
/// root executable before the run, SaBRe the sites it decoded in each image
/// as it was loaded, and LiteInst only the sites the guest actually executed,
/// because it patches lazily on a site's first trap.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SiteCounters {
    /// Distinct sites the backend considered for patching.
    pub candidates: Option<u64>,
    /// Candidates that were patched.
    pub patched: Option<u64>,
    /// Candidates left unpatched and serviced by a fallback route instead.
    pub fell_back: Option<u64>,
}

impl SiteCounters {
    /// Sites for a backend that never patches: every count is zero.
    pub const NONE_PATCHED: Self = Self {
        candidates: Some(0),
        patched: Some(0),
        fell_back: Some(0),
    };

    /// Sites of a rewrite that measured `candidates` sites and patched
    /// `patched` of them, where every candidate it did not patch fell back.
    pub fn from_rewrite(candidates: u64, patched: u64) -> Self {
        Self {
            candidates: Some(candidates),
            patched: Some(patched),
            fell_back: Some(candidates.saturating_sub(patched)),
        }
    }
}

/// The counters attributed to one guest process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessDispatchStats {
    /// Backend-assigned process index in first-observed order; 0 is the root.
    ///
    /// Host process ids are deliberately not recorded: they differ between
    /// otherwise identical runs, and this record is meant to be compared.
    pub process: u32,
    /// Counters attributed to this process.
    pub counters: DispatchCounters,
}

/// The shared end-of-run dispatch record for one backend run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DispatchStats {
    /// Always [`DISPATCH_STATS_SCHEMA_VERSION`] for records built by this crate.
    pub schema_version: u32,
    /// Canonical backend name, as in `BackendStatsSnapshot::BACKEND_NAME`.
    pub backend: String,
    /// Aggregate counters for the whole run.
    pub counters: DispatchCounters,
    /// Aggregate instrumentation-site counts.
    pub sites: SiteCounters,
    /// Per-process counters, when the backend attributes events to processes.
    ///
    /// Sorted by `process`. Only the counters a backend attributes per process are
    /// `Some` here; each such counter sums to the matching aggregate.
    pub per_process: Option<Vec<ProcessDispatchStats>>,
}

impl DispatchStats {
    /// Creates an aggregate-only record.
    pub fn new(backend: &str, counters: DispatchCounters, sites: SiteCounters) -> Self {
        Self {
            schema_version: DISPATCH_STATS_SCHEMA_VERSION,
            backend: backend.to_owned(),
            counters,
            sites,
            per_process: None,
        }
    }

    /// Attaches per-process counters, sorted by process index.
    pub fn with_per_process(
        mut self,
        processes: impl IntoIterator<Item = ProcessDispatchStats>,
    ) -> Self {
        let mut processes: Vec<_> = processes.into_iter().collect();
        processes.sort_by_key(|process| process.process);
        self.per_process = Some(processes);
        self
    }

    /// Returns every internal inconsistency in this record.
    ///
    /// An empty result means: the schema version is current, patched and
    /// fallback sites do not exceed candidates, process indices are
    /// unique, and every counter reported per process sums to its aggregate.
    pub fn inconsistencies(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.schema_version != DISPATCH_STATS_SCHEMA_VERSION {
            problems.push(format!(
                "schema_version {} is not {DISPATCH_STATS_SCHEMA_VERSION}",
                self.schema_version
            ));
        }
        if let Some(candidates) = self.sites.candidates {
            let patched = self.sites.patched.unwrap_or(0);
            let fell_back = self.sites.fell_back.unwrap_or(0);
            if patched + fell_back > candidates {
                problems.push(format!(
                    "sites: patched {patched} + fell_back {fell_back} exceeds candidates {candidates}"
                ));
            }
        }
        if let Some(processes) = &self.per_process {
            if processes
                .windows(2)
                .any(|pair| pair[0].process >= pair[1].process)
            {
                problems.push("per_process indices are not unique and sorted".to_owned());
            }
            for (index, (name, aggregate)) in self.counters.fields().into_iter().enumerate() {
                let attributed: Vec<_> = processes
                    .iter()
                    .map(|process| process.counters.fields()[index].1)
                    .collect();
                if attributed.iter().all(Option::is_none) {
                    continue;
                }
                let Some(sum) = attributed
                    .iter()
                    .try_fold(0_u64, |total, value| value.map(|value| total + value))
                else {
                    problems.push(format!("{name} is attributed to only some processes"));
                    continue;
                };
                if aggregate != Some(sum) {
                    problems.push(format!(
                        "{name}: per-process sum {sum} does not match aggregate {}",
                        Measured(aggregate)
                    ));
                }
            }
        }
        problems
    }
}

/// Displays an optional counter as its value or `n/a`.
struct Measured(Option<u64>);

impl fmt::Display for Measured {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(formatter, "{value}"),
            None => formatter.write_str("n/a"),
        }
    }
}

impl fmt::Display for DispatchCounters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (name, value)) in self.fields().into_iter().enumerate() {
            if index != 0 {
                formatter.write_str(" ")?;
            }
            write!(formatter, "{name}={}", Measured(value))?;
        }
        Ok(())
    }
}

impl fmt::Display for DispatchStats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "dispatch stats v{} backend={} dispatches={} trapped={} direct={} [{}] sites[candidates={} patched={} fell_back={}]",
            self.schema_version,
            self.backend,
            Measured(self.counters.dispatches()),
            Measured(self.counters.trapped_dispatches()),
            Measured(self.counters.patched_direct_calls),
            self.counters,
            Measured(self.sites.candidates),
            Measured(self.sites.patched),
            Measured(self.sites.fell_back),
        )?;
        match &self.per_process {
            Some(processes) => write!(formatter, " processes={}", processes.len()),
            None => formatter.write_str(" processes=n/a"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(process: u32, seccomp: u64) -> ProcessDispatchStats {
        ProcessDispatchStats {
            process,
            counters: DispatchCounters {
                ptrace_seccomp_stops: Some(seccomp),
                ..DispatchCounters::default()
            },
        }
    }

    fn ptrace_like(seccomp: u64) -> DispatchStats {
        DispatchStats::new(
            "ptrace",
            DispatchCounters {
                ptrace_seccomp_stops: Some(seccomp),
                ..DispatchCounters::ZERO
            },
            SiteCounters::NONE_PATCHED,
        )
    }

    #[test]
    fn dispatch_totals_separate_trapped_from_direct_routes() {
        let counters = DispatchCounters {
            signal_traps: Some(3),
            patched_direct_calls: Some(40),
            ptrace_seccomp_stops: Some(2),
            ptrace_sigtrap_stops: Some(0),
            sigill_marker_hits: Some(1),
            ptrace_syscall_entry_stops: Some(100),
            ptrace_syscall_exit_stops: Some(100),
            refusals: Some(5),
        };
        assert_eq!(counters.trapped_dispatches(), Some(6));
        assert_eq!(counters.dispatches(), Some(46));
        assert_eq!(DispatchCounters::default().dispatches(), None);
        let partial = DispatchCounters {
            ptrace_sigtrap_stops: None,
            ..counters
        };
        assert_eq!(partial.trapped_dispatches(), None);
        assert_eq!(partial.dispatches(), None);
        assert_eq!(partial.patched_direct_calls, Some(40));
    }

    #[test]
    fn unmeasured_counters_render_distinctly_from_zero() {
        let record = DispatchStats::new(
            "e9patch",
            DispatchCounters::default(),
            SiteCounters {
                candidates: Some(0),
                patched: Some(0),
                fell_back: Some(0),
            },
        );
        let rendered = record.to_string();
        assert!(rendered.contains("signal_traps=n/a"), "{rendered}");
        assert!(rendered.contains("dispatches=n/a"), "{rendered}");
        assert!(rendered.contains("candidates=0"), "{rendered}");
        assert!(rendered.ends_with("processes=n/a"), "{rendered}");
    }

    #[test]
    fn json_round_trip_keeps_unmeasured_counters_as_null() {
        let record = ptrace_like(7).with_per_process([process(20, 4), process(10, 3)]);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["schema_version"], DISPATCH_STATS_SCHEMA_VERSION);
        assert_eq!(json["counters"]["ptrace_seccomp_stops"], 7);
        assert_eq!(json["per_process"][0]["process"], 10);
        assert!(json["per_process"][0]["counters"]["signal_traps"].is_null());
        let decoded: DispatchStats = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn consistent_record_reports_no_problems() {
        let record = ptrace_like(7).with_per_process([process(10, 3), process(20, 4)]);
        assert_eq!(record.inconsistencies(), Vec::<String>::new());
    }

    #[test]
    fn per_process_sum_mismatch_is_reported() {
        let record = ptrace_like(8).with_per_process([process(10, 3), process(20, 4)]);
        assert_eq!(
            record.inconsistencies(),
            ["ptrace_seccomp_stops: per-process sum 7 does not match aggregate 8"]
        );
    }

    #[test]
    fn partially_attributed_counter_is_reported() {
        let mut unattributed = process(20, 4);
        unattributed.counters.ptrace_seccomp_stops = None;
        let record = ptrace_like(7).with_per_process([process(10, 3), unattributed]);
        assert_eq!(
            record.inconsistencies(),
            ["ptrace_seccomp_stops is attributed to only some processes"]
        );
    }

    #[test]
    fn duplicate_process_and_excess_sites_are_reported() {
        let mut record = ptrace_like(7).with_per_process([process(10, 3), process(10, 4)]);
        record.sites = SiteCounters {
            candidates: Some(2),
            patched: Some(2),
            fell_back: Some(1),
        };
        assert_eq!(
            record.inconsistencies(),
            [
                "sites: patched 2 + fell_back 1 exceeds candidates 2",
                "per_process indices are not unique and sorted",
            ]
        );
    }
}
