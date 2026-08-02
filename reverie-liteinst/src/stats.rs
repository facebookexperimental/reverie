/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed end-of-run statistics owned by the LiteInst backend.

use std::fmt;

use reverie::BackendStatsSnapshot;
use reverie::BackendStatsSource;
use reverie::CounterSnapshot;
use reverie::PatchShapeStats;

/// A distinct outcome for one candidate LiteInst patch site.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LiteinstPatchDecision {
    /// A direct pun patch was installed.
    DirectPun,
    /// A replace-first relocation patch was installed.
    Relocated,
    /// Ptrace retained the original syscall because its patch crossed a cache line.
    PtraceStraddlerFallback,
    /// Ptrace retained the original syscall for another unpatchable-site reason.
    PtraceOtherFallback,
}

/// A dispatch or installation path taken by the ptrace-host LiteInst hybrid.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LiteinstDispatchPath {
    /// The first subscribed syscall observed at a previously unseen site.
    FirstSiteSigsys,
    /// A successful stopped-tracee patch installation performed through ptrace.
    PtraceInstallation,
    /// A cache-line-straddling site that retained the ptrace fallback.
    CachelineStraddlerFallback,
    /// An unpatchable or otherwise rejected site that retained the ptrace fallback.
    UnpatchableOrOtherFallback,
    /// A patched-site callback that returned to the ptrace-host Tool through SIGTRAP.
    DirectHook,
}

/// Stable LiteInst statistics captured after one backend run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteinstBackendStatsSnapshot {
    patch_shapes: PatchShapeStats,
    patch_decisions: CounterSnapshot<LiteinstPatchDecision>,
    dispatch_paths: CounterSnapshot<LiteinstDispatchPath>,
}

impl LiteinstBackendStatsSnapshot {
    /// Aggregate shape distribution over distinct patch-site identities.
    ///
    /// Collection deduplicates by process, exec generation, and virtual RIP.
    /// Those raw identities are discarded before this aggregate is constructed.
    pub const fn patch_shapes(&self) -> &PatchShapeStats {
        &self.patch_shapes
    }

    /// Patch decisions in deterministic enum order.
    pub const fn patch_decisions(&self) -> &CounterSnapshot<LiteinstPatchDecision> {
        &self.patch_decisions
    }

    /// Dispatch-path counts in deterministic enum order.
    pub const fn dispatch_paths(&self) -> &CounterSnapshot<LiteinstDispatchPath> {
        &self.dispatch_paths
    }

    fn decision_count(&self, decision: LiteinstPatchDecision) -> u64 {
        count(&self.patch_decisions, decision)
    }

    fn path_count(&self, path: LiteinstDispatchPath) -> u64 {
        count(&self.dispatch_paths, path)
    }
}

impl fmt::Display for LiteinstBackendStatsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LiteInst instrumentation stats: distinct_rips_patched={} patch_candidates={} decisions[direct_pun={},relocated={},ptrace_straddler={},ptrace_other={}] paths[first_site_sigsys={},ptrace_installation={},cacheline_straddler={},unpatchable_or_other={},direct_hook={}] classified_candidates={} cacheline_straddlers={} non_straddling={} instruction_lengths[",
            self.patch_shapes.patched_rips(),
            self.patch_shapes.candidate_rips(),
            self.decision_count(LiteinstPatchDecision::DirectPun),
            self.decision_count(LiteinstPatchDecision::Relocated),
            self.decision_count(LiteinstPatchDecision::PtraceStraddlerFallback),
            self.decision_count(LiteinstPatchDecision::PtraceOtherFallback),
            self.path_count(LiteinstDispatchPath::FirstSiteSigsys),
            self.path_count(LiteinstDispatchPath::PtraceInstallation),
            self.path_count(LiteinstDispatchPath::CachelineStraddlerFallback),
            self.path_count(LiteinstDispatchPath::UnpatchableOrOtherFallback),
            self.path_count(LiteinstDispatchPath::DirectHook),
            self.patch_shapes.classified_candidates(),
            self.patch_shapes.cacheline_straddlers(),
            self.patch_shapes.non_straddling(),
        )?;
        write_buckets(formatter, self.patch_shapes.instruction_lengths())?;
        formatter.write_str("] straddle_prefix[")?;
        write_buckets(formatter, self.patch_shapes.straddle_after())?;
        formatter.write_str("]")
    }
}

impl BackendStatsSnapshot for LiteinstBackendStatsSnapshot {
    const BACKEND_NAME: &'static str = "liteinst";
}

/// Backend-owned source for a typed LiteInst end-of-run snapshot.
#[derive(Clone, Debug)]
pub struct LiteinstBackendStatsSource {
    snapshot: LiteinstBackendStatsSnapshot,
}

impl LiteinstBackendStatsSource {
    pub(crate) fn from_ptrace_host_hybrid(
        stats: reverie_ptrace::LiteinstInstrumentationStats,
    ) -> Self {
        let decisions = stats.decision_counts();
        let paths = stats.dispatch_path_counts();
        Self {
            snapshot: LiteinstBackendStatsSnapshot {
                patch_shapes: stats.patch_shape_stats(),
                patch_decisions: CounterSnapshot::new([
                    (LiteinstPatchDecision::DirectPun, decisions[0]),
                    (LiteinstPatchDecision::Relocated, decisions[1]),
                    (LiteinstPatchDecision::PtraceStraddlerFallback, decisions[2]),
                    (LiteinstPatchDecision::PtraceOtherFallback, decisions[3]),
                ]),
                dispatch_paths: CounterSnapshot::new([
                    (LiteinstDispatchPath::FirstSiteSigsys, paths[0]),
                    (LiteinstDispatchPath::PtraceInstallation, paths[1]),
                    (LiteinstDispatchPath::CachelineStraddlerFallback, paths[2]),
                    (LiteinstDispatchPath::UnpatchableOrOtherFallback, paths[3]),
                    (LiteinstDispatchPath::DirectHook, paths[4]),
                ]),
            },
        }
    }

    /// Returns the captured snapshot without performing another collection pass.
    pub const fn snapshot(&self) -> &LiteinstBackendStatsSnapshot {
        &self.snapshot
    }

    /// Returns the number of distinct instruction pointers successfully patched.
    pub fn distinct_rips(&self) -> usize {
        self.snapshot.patch_shapes.patched_rips() as usize
    }

    /// Returns distinct patch candidates, including fallback sites.
    pub fn patch_candidates(&self) -> usize {
        self.snapshot.patch_shapes.candidate_rips() as usize
    }

    /// Returns direct, relocated, straddler-fallback, and other-fallback counts.
    pub fn decision_counts(&self) -> [usize; 4] {
        [
            self.snapshot
                .decision_count(LiteinstPatchDecision::DirectPun) as usize,
            self.snapshot
                .decision_count(LiteinstPatchDecision::Relocated) as usize,
            self.snapshot
                .decision_count(LiteinstPatchDecision::PtraceStraddlerFallback)
                as usize,
            self.snapshot
                .decision_count(LiteinstPatchDecision::PtraceOtherFallback) as usize,
        ]
    }

    /// Returns the five dispatch-path counts in [`LiteinstDispatchPath`] order.
    pub fn dispatch_path_counts(&self) -> [u64; 5] {
        [
            self.snapshot
                .path_count(LiteinstDispatchPath::FirstSiteSigsys),
            self.snapshot
                .path_count(LiteinstDispatchPath::PtraceInstallation),
            self.snapshot
                .path_count(LiteinstDispatchPath::CachelineStraddlerFallback),
            self.snapshot
                .path_count(LiteinstDispatchPath::UnpatchableOrOtherFallback),
            self.snapshot.path_count(LiteinstDispatchPath::DirectHook),
        ]
    }

    /// Returns candidates with a decoded instruction shape.
    pub fn classified_candidates(&self) -> usize {
        self.snapshot.patch_shapes.classified_candidates() as usize
    }

    /// Returns decoded candidates whose patch prefix crosses a cache line.
    pub fn cacheline_straddlers(&self) -> usize {
        self.snapshot.patch_shapes.cacheline_straddlers() as usize
    }

    /// Returns decoded candidates whose patch prefix stays within a cache line.
    pub fn non_straddling(&self) -> usize {
        self.snapshot.patch_shapes.non_straddling() as usize
    }

    /// Returns instruction-length counts ordered as 5+, 4, 3, 2, and 1 byte.
    pub fn instruction_length_counts(&self) -> [usize; 5] {
        let lengths = self.snapshot.patch_shapes.instruction_lengths();
        [
            lengths[4..].iter().sum::<u64>() as usize,
            lengths[3] as usize,
            lengths[2] as usize,
            lengths[1] as usize,
            lengths[0] as usize,
        ]
    }

    /// Returns straddler counts for boundaries after 1, 2, 3, and 4 bytes.
    pub fn straddle_prefix_counts(&self) -> [usize; 4] {
        let prefixes = self.snapshot.patch_shapes.straddle_after();
        [
            prefixes[0] as usize,
            prefixes[1] as usize,
            prefixes[2] as usize,
            prefixes[3] as usize,
        ]
    }
}

impl fmt::Display for LiteinstBackendStatsSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot.fmt(formatter)
    }
}

impl BackendStatsSource for LiteinstBackendStatsSource {
    type Snapshot = LiteinstBackendStatsSnapshot;

    fn backend_stats(&self) -> Self::Snapshot {
        self.snapshot.clone()
    }
}

fn count<K: Copy + Eq + Ord>(snapshot: &CounterSnapshot<K>, key: K) -> u64 {
    snapshot
        .counts()
        .iter()
        .find_map(|(candidate, count)| (*candidate == key).then_some(*count))
        .unwrap_or(0)
}

fn write_buckets(formatter: &mut fmt::Formatter<'_>, buckets: &[u64]) -> fmt::Result {
    for (index, count) in buckets.iter().enumerate() {
        if index != 0 {
            formatter.write_str(",")?;
        }
        write!(formatter, "{}={count}", index + 1)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use reverie::InstructionPatchShape;
    use reverie::PatchShapeCollector;

    use super::*;

    #[test]
    fn display_is_deterministic_and_contains_no_raw_identity() {
        let mut shapes = PatchShapeCollector::default();
        shapes.record_site(
            0x7fff_1234_5678,
            true,
            Some(InstructionPatchShape::new(2, None)),
        );
        let source = LiteinstBackendStatsSource {
            snapshot: LiteinstBackendStatsSnapshot {
                patch_shapes: shapes.snapshot(),
                patch_decisions: CounterSnapshot::new([(LiteinstPatchDecision::Relocated, 1)]),
                dispatch_paths: CounterSnapshot::new([
                    (LiteinstDispatchPath::FirstSiteSigsys, 1),
                    (LiteinstDispatchPath::PtraceInstallation, 1),
                    (LiteinstDispatchPath::DirectHook, 9),
                ]),
            },
        };

        let rendered = source.snapshot().to_string();
        assert_eq!(rendered, source.snapshot().to_string());
        assert!(rendered.contains("distinct_rips_patched=1"));
        assert!(rendered.contains("paths[first_site_sigsys=1"));
        assert!(rendered.contains("direct_hook=9"));
        assert!(!rendered.contains("0x7fff"));
        assert!(!rendered.contains("pid="));
        assert!(!rendered.contains("time="));
    }
}
