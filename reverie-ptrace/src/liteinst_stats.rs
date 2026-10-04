/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Aggregate statistics for dynamically installed LiteInst patch sites.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use reverie::CounterSnapshot;
use reverie::InstructionPatchShape;
use reverie::LiteinstDispatchPath;
use reverie::PatchShapeCollector;
use reverie::PatchShapeStats;

/// Aggregate characteristics of distinct LiteInst patch-site instruction pointers.
///
/// Instruction lengths of five bytes or more share one bucket because five
/// bytes is the direct-jump patch width. A cache-line straddler is an original
/// instruction whose first five bytes cross a line; therefore its boundary is
/// necessarily after a one-, two-, three-, or four-byte prefix.
#[derive(Clone, Debug, Default)]
pub struct LiteinstInstrumentationStats {
    candidate_sites: std::collections::BTreeSet<(u64, u64, u64)>,
    patch_shapes: PatchShapeCollector,
    patch_decisions: [u64; 4],
    dispatch_paths: BTreeMap<LiteinstDispatchPath, u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiteinstPatchOutcome {
    /// Reserved for the planner's RapidPreferred path; the current host uses
    /// replace-first relocation for syscall instructions.
    #[allow(dead_code)]
    DirectPunPatched,
    RelocatedPatched,
    PtraceStraddlerBail,
    PtraceOtherFallback,
}

/// Cloneable observer for instrumentation statistics owned by a running tracer.
#[derive(Clone, Debug)]
pub struct LiteinstInstrumentationStatsHandle {
    inner: Arc<Mutex<LiteinstInstrumentationStats>>,
}

impl LiteinstInstrumentationStatsHandle {
    pub(crate) fn from_shared(inner: Arc<Mutex<LiteinstInstrumentationStats>>) -> Self {
        Self { inner }
    }

    /// Returns a consistent snapshot of all sites installed so far.
    pub fn snapshot(&self) -> LiteinstInstrumentationStats {
        self.inner
            .lock()
            .expect("LiteInst instrumentation statistics lock poisoned")
            .clone()
    }
}

impl LiteinstInstrumentationStats {
    #[cfg(test)]
    pub(crate) fn record_site(
        &mut self,
        rip: u64,
        outcome: LiteinstPatchOutcome,
        shape: Option<(usize, Option<usize>)>,
    ) {
        self.record_process_site(0, 0, rip, outcome, shape);
    }

    pub(crate) fn record_process_site(
        &mut self,
        process_identity: u64,
        execution_generation: u64,
        rip: u64,
        outcome: LiteinstPatchOutcome,
        shape: Option<(usize, Option<usize>)>,
    ) {
        if !self
            .candidate_sites
            .insert((process_identity, execution_generation, rip))
        {
            return;
        }
        let (decision_index, patched) = match outcome {
            LiteinstPatchOutcome::DirectPunPatched => (0, true),
            LiteinstPatchOutcome::RelocatedPatched => (1, true),
            LiteinstPatchOutcome::PtraceStraddlerBail => (2, false),
            LiteinstPatchOutcome::PtraceOtherFallback => (3, false),
        };
        self.patch_decisions[decision_index] += 1;
        let shape = shape.map(|(instruction_len, straddle_prefix)| {
            InstructionPatchShape::new(
                u8::try_from(instruction_len).expect("validated x86 instruction length"),
                straddle_prefix.map(|prefix| {
                    u8::try_from(prefix).expect("validated cache-line straddle prefix")
                }),
            )
        });
        self.patch_shapes.record_process_site(
            process_identity,
            execution_generation,
            rip,
            patched,
            shape,
        );
    }

    pub(crate) fn record_first_site_seccomp(&mut self) {
        self.record_dispatch_path(LiteinstDispatchPath::FirstSiteSeccomp);
    }

    pub(crate) fn record_ptrace_installation(&mut self) {
        self.record_dispatch_path(LiteinstDispatchPath::PtraceInstallation);
    }

    pub(crate) fn record_cacheline_straddler_fallback(&mut self) {
        self.record_dispatch_path(LiteinstDispatchPath::CachelineStraddlerFallback);
    }

    pub(crate) fn record_unpatchable_or_other_fallback(&mut self) {
        self.record_dispatch_path(LiteinstDispatchPath::UnpatchableOrOtherFallback);
    }

    pub(crate) fn record_direct_hook(&mut self) {
        self.record_dispatch_path(LiteinstDispatchPath::DirectHook);
    }

    fn record_dispatch_path(&mut self, path: LiteinstDispatchPath) {
        *self.dispatch_paths.entry(path).or_insert(0) += 1;
    }

    /// Returns the number of distinct instruction pointers successfully patched.
    pub fn distinct_rips(&self) -> usize {
        self.patch_shapes.snapshot().patched_rips() as usize
    }

    /// Returns distinct patch candidates, including safe straddler bailouts.
    pub fn patch_candidates(&self) -> usize {
        self.candidate_sites.len()
    }

    /// Returns direct, relocated, straddler-bail, and other-fallback counts.
    pub const fn decision_counts(&self) -> [u64; 4] {
        self.patch_decisions
    }

    /// Returns the ptrace-host dispatch paths, excluding in-guest observations.
    pub fn ptrace_host_dispatch_paths(&self) -> CounterSnapshot<LiteinstDispatchPath> {
        CounterSnapshot::new(
            self.dispatch_paths
                .iter()
                .map(|(path, count)| (*path, *count)),
        )
    }

    /// Returns the exact aggregate patch-site shape distribution.
    pub fn patch_shape_stats(&self) -> PatchShapeStats {
        self.patch_shapes.snapshot()
    }

    /// Returns candidates with a decoded instruction shape.
    pub fn classified_candidates(&self) -> usize {
        self.patch_shapes.snapshot().classified_candidates() as usize
    }

    /// Returns the number of patch-site instructions crossing a cache line.
    pub fn cacheline_straddlers(&self) -> usize {
        self.patch_shapes.snapshot().cacheline_straddlers() as usize
    }

    /// Returns the number of non-straddling patch-site instructions.
    pub fn non_straddling(&self) -> usize {
        self.patch_shapes.snapshot().non_straddling() as usize
    }

    /// Returns instruction-length counts ordered as 5+, 4, 3, 2, and 1 byte.
    pub fn instruction_length_counts(&self) -> [usize; 5] {
        let exact = self.patch_shapes.snapshot();
        let lengths = exact.instruction_lengths();
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
        let exact = self.patch_shapes.snapshot();
        let prefixes = exact.straddle_after();
        [
            prefixes[0] as usize,
            prefixes[1] as usize,
            prefixes[2] as usize,
            prefixes[3] as usize,
        ]
    }

    /// Prints one stable instrumentation-summary line to standard error.
    pub fn print(&self) {
        eprintln!("{self}");
    }
}

pub(crate) fn with_liteinst_stats<R>(
    stats: Option<&Arc<Mutex<LiteinstInstrumentationStats>>>,
    record: impl FnOnce(&mut LiteinstInstrumentationStats) -> R,
) -> Option<R> {
    let stats = stats?;
    Some(record(
        &mut stats
            .lock()
            .expect("LiteInst instrumentation statistics lock poisoned"),
    ))
}

impl fmt::Display for LiteinstInstrumentationStats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let decisions = self.decision_counts();
        let paths = self.ptrace_host_dispatch_paths();
        let lengths = self.instruction_length_counts();
        let prefixes = self.straddle_prefix_counts();
        write!(
            formatter,
            "LiteInst instrumentation stats: distinct_rips_patched={} patch_candidates={} decisions[direct_pun={},relocated={},ptrace_straddler={},ptrace_other={}] paths[first_site_seccomp={},ptrace_installation={},cacheline_straddler={},unpatchable_or_other={},direct_hook={}] classified_candidates={} cacheline_straddlers={} non_straddling={} instruction_lengths[5+={},4={},3={},2={},1={}] straddle_prefix[1={},2={},3={},4={}]",
            self.distinct_rips(),
            self.patch_candidates(),
            decisions[0],
            decisions[1],
            decisions[2],
            decisions[3],
            paths.count(&LiteinstDispatchPath::FirstSiteSeccomp),
            paths.count(&LiteinstDispatchPath::PtraceInstallation),
            paths.count(&LiteinstDispatchPath::CachelineStraddlerFallback),
            paths.count(&LiteinstDispatchPath::UnpatchableOrOtherFallback),
            paths.count(&LiteinstDispatchPath::DirectHook),
            self.classified_candidates(),
            self.cacheline_straddlers(),
            self.non_straddling(),
            lengths[0],
            lengths[1],
            lengths[2],
            lengths[3],
            lengths[4],
            prefixes[0],
            prefixes[1],
            prefixes[2],
            prefixes[3],
        )
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::LiteinstInstrumentationStats;
    use super::LiteinstPatchOutcome;
    use super::with_liteinst_stats;

    #[test]
    fn disabled_collection_does_not_run_stats_only_classification() {
        let classified = Cell::new(false);
        let result = with_liteinst_stats(None, |_| classified.set(true));

        assert!(result.is_none());
        assert!(!classified.get());
    }

    #[test]
    fn aggregates_all_requested_buckets_and_deduplicates_rips() {
        let mut stats = LiteinstInstrumentationStats::default();
        stats.record_site(
            0x1000,
            LiteinstPatchOutcome::DirectPunPatched,
            Some((1, None)),
        );
        stats.record_site(
            0x2000,
            LiteinstPatchOutcome::PtraceStraddlerBail,
            Some((2, Some(1))),
        );
        stats.record_site(
            0x3000,
            LiteinstPatchOutcome::PtraceStraddlerBail,
            Some((3, Some(2))),
        );
        stats.record_site(
            0x4000,
            LiteinstPatchOutcome::PtraceStraddlerBail,
            Some((4, Some(3))),
        );
        stats.record_site(
            0x5000,
            LiteinstPatchOutcome::PtraceStraddlerBail,
            Some((5, Some(4))),
        );
        stats.record_site(
            0x6000,
            LiteinstPatchOutcome::RelocatedPatched,
            Some((15, None)),
        );
        stats.record_site(0x5000, LiteinstPatchOutcome::PtraceOtherFallback, None);
        stats.record_site(0x7000, LiteinstPatchOutcome::PtraceOtherFallback, None);
        stats.record_first_site_seccomp();
        stats.record_ptrace_installation();
        stats.record_cacheline_straddler_fallback();
        stats.record_unpatchable_or_other_fallback();
        stats.record_direct_hook();
        stats.record_direct_hook();

        assert_eq!(stats.distinct_rips(), 2);
        assert_eq!(stats.patch_candidates(), 7);
        assert_eq!(stats.decision_counts(), [1, 1, 4, 1]);
        let paths = stats.ptrace_host_dispatch_paths();
        assert_eq!(
            paths.count(&reverie::LiteinstDispatchPath::FirstSiteSeccomp),
            1
        );
        assert_eq!(
            paths.count(&reverie::LiteinstDispatchPath::PtraceInstallation),
            1
        );
        assert_eq!(
            paths.count(&reverie::LiteinstDispatchPath::CachelineStraddlerFallback),
            1
        );
        assert_eq!(
            paths.count(&reverie::LiteinstDispatchPath::UnpatchableOrOtherFallback),
            1
        );
        assert_eq!(paths.count(&reverie::LiteinstDispatchPath::DirectHook), 2);
        assert_eq!(stats.classified_candidates(), 6);
        assert_eq!(stats.cacheline_straddlers(), 4);
        assert_eq!(stats.non_straddling(), 2);
        assert_eq!(stats.instruction_length_counts(), [2, 1, 1, 1, 1]);
        assert_eq!(stats.straddle_prefix_counts(), [1, 1, 1, 1]);
        assert_eq!(
            stats.to_string(),
            "LiteInst instrumentation stats: distinct_rips_patched=2 patch_candidates=7 decisions[direct_pun=1,relocated=1,ptrace_straddler=4,ptrace_other=1] paths[first_site_seccomp=1,ptrace_installation=1,cacheline_straddler=1,unpatchable_or_other=1,direct_hook=2] classified_candidates=6 cacheline_straddlers=4 non_straddling=2 instruction_lengths[5+=2,4=1,3=1,2=1,1=1] straddle_prefix[1=1,2=1,3=1,4=1]"
        );
    }

    #[test]
    fn equal_rips_in_different_processes_or_exec_generations_remain_distinct() {
        let mut stats = LiteinstInstrumentationStats::default();
        for (process, generation) in [(11, 0), (12, 0), (11, 1)] {
            stats.record_process_site(
                process,
                generation,
                0x4000,
                LiteinstPatchOutcome::RelocatedPatched,
                Some((2, None)),
            );
        }
        stats.record_process_site(
            11,
            0,
            0x4000,
            LiteinstPatchOutcome::RelocatedPatched,
            Some((2, None)),
        );

        assert_eq!(stats.patch_candidates(), 3);
        assert_eq!(stats.distinct_rips(), 3);
        assert_eq!(stats.decision_counts(), [0, 3, 0, 0]);
    }
}
