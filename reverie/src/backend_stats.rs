/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Common, lazily collected statistics for Reverie backends.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Maximum encoded length of an x86 instruction.
pub const MAX_X86_INSTRUCTION_LENGTH: usize = 15;

/// Whether a caller wants a backend to collect an end-of-run statistics snapshot.
///
/// The caller decides this once, before starting the backend. Backends should not
/// allocate collectors or update counters when this request is disabled.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendStatsRequest(bool);

impl BackendStatsRequest {
    /// A request that disables statistics collection.
    pub const DISABLED: Self = Self(false);

    /// A request that enables statistics collection.
    pub const ENABLED: Self = Self(true);

    /// Creates a request from a caller-owned enablement decision.
    pub const fn new(enabled: bool) -> Self {
        Self(enabled)
    }

    /// Returns whether statistics collection is enabled.
    pub const fn is_enabled(self) -> bool {
        self.0
    }

    /// Takes a snapshot only when collection is enabled.
    ///
    /// In particular, a disabled request does not call
    /// [`BackendStatsSource::backend_stats`].
    pub fn collect<S>(self, source: &S) -> Option<S::Snapshot>
    where
        S: BackendStatsSource,
    {
        self.is_enabled().then(|| source.backend_stats())
    }
}

/// A stable, displayable end-of-run statistics snapshot.
pub trait BackendStatsSnapshot: fmt::Display {
    /// Canonical backend name used by command-line selection and log output.
    const BACKEND_NAME: &'static str;
}

/// A backend-owned source of a typed end-of-run statistics snapshot.
pub trait BackendStatsSource {
    /// Snapshot returned by this source.
    type Snapshot: BackendStatsSnapshot;

    /// Captures the backend statistics accumulated so far.
    fn backend_stats(&self) -> Self::Snapshot;
}

/// Decoded shape of one candidate patch site.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstructionPatchShape {
    instruction_length: u8,
    straddle_after: Option<u8>,
}

impl InstructionPatchShape {
    /// Creates a decoded patch-site shape.
    ///
    /// `straddle_after` is the number of instruction bytes before a cache-line
    /// boundary and must fall strictly inside the decoded instruction. A backend
    /// whose patch is narrower than the instruction must enforce that additional
    /// patch-width constraint before constructing this value.
    pub fn new(instruction_length: u8, straddle_after: Option<u8>) -> Self {
        assert!(
            (1..=MAX_X86_INSTRUCTION_LENGTH as u8).contains(&instruction_length),
            "x86 instruction length must be between 1 and 15 bytes"
        );
        if let Some(prefix) = straddle_after {
            assert!(
                (1..instruction_length).contains(&prefix),
                "cache-line straddle prefix must fall inside the instruction"
            );
        }
        Self {
            instruction_length,
            straddle_after,
        }
    }

    /// Returns the decoded instruction length.
    pub const fn instruction_length(self) -> u8 {
        self.instruction_length
    }

    /// Returns the cache-line boundary prefix, when the patch crosses a line.
    pub const fn straddle_after(self) -> Option<u8> {
        self.straddle_after
    }
}

/// Aggregate shape of distinct patch-site instruction pointers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchShapeStats {
    candidate_rips: u64,
    patched_rips: u64,
    classified_candidates: u64,
    cacheline_straddlers: u64,
    non_straddling: u64,
    instruction_lengths: [u64; MAX_X86_INSTRUCTION_LENGTH],
    straddle_after: [u64; MAX_X86_INSTRUCTION_LENGTH],
}

impl PatchShapeStats {
    /// Returns the number of distinct candidate instruction pointers.
    pub const fn candidate_rips(&self) -> u64 {
        self.candidate_rips
    }

    /// Returns the number of distinct successfully patched instruction pointers.
    pub const fn patched_rips(&self) -> u64 {
        self.patched_rips
    }

    /// Returns the number of candidates with a decoded instruction shape.
    pub const fn classified_candidates(&self) -> u64 {
        self.classified_candidates
    }

    /// Returns the number of decoded candidates crossing a cache line.
    pub const fn cacheline_straddlers(&self) -> u64 {
        self.cacheline_straddlers
    }

    /// Returns the number of decoded candidates not crossing a cache line.
    pub const fn non_straddling(&self) -> u64 {
        self.non_straddling
    }

    /// Returns exact instruction-length buckets ordered from one through fifteen bytes.
    pub const fn instruction_lengths(&self) -> &[u64; MAX_X86_INSTRUCTION_LENGTH] {
        &self.instruction_lengths
    }

    /// Returns cache-line prefix buckets ordered from one through fifteen bytes.
    pub const fn straddle_after(&self) -> &[u64; MAX_X86_INSTRUCTION_LENGTH] {
        &self.straddle_after
    }
}

/// Deduplicating collector for [`PatchShapeStats`].
#[derive(Clone, Debug, Default)]
pub struct PatchShapeCollector {
    candidate_sites: BTreeSet<(u64, u64, u64)>,
    patched_sites: BTreeSet<(u64, u64, u64)>,
    stats: PatchShapeStats,
}

impl PatchShapeCollector {
    /// Records one patch decision for an instruction pointer.
    ///
    /// This convenience method is for a single process and execution generation.
    /// Backends that aggregate a process tree or survive exec must instead use
    /// [`Self::record_process_site`] so equal virtual addresses remain distinct.
    pub fn record_site(&mut self, rip: u64, patched: bool, shape: Option<InstructionPatchShape>) {
        self.record_process_site(0, 0, rip, patched, shape);
    }

    /// Records one patch decision identified by process, exec generation, and RIP.
    ///
    /// Repeated decisions for the same three-part identity are ignored. The
    /// identities are retained only for deduplication and never enter the
    /// aggregate snapshot or its display output.
    pub fn record_process_site(
        &mut self,
        process_identity: u64,
        execution_generation: u64,
        rip: u64,
        patched: bool,
        shape: Option<InstructionPatchShape>,
    ) {
        let identity = (process_identity, execution_generation, rip);
        if !self.candidate_sites.insert(identity) {
            return;
        }
        self.stats.candidate_rips += 1;
        if patched {
            self.patched_sites.insert(identity);
            self.stats.patched_rips += 1;
        }

        let Some(shape) = shape else {
            return;
        };
        self.stats.classified_candidates += 1;
        self.stats.instruction_lengths[usize::from(shape.instruction_length) - 1] += 1;
        match shape.straddle_after {
            Some(prefix) => {
                self.stats.cacheline_straddlers += 1;
                self.stats.straddle_after[usize::from(prefix) - 1] += 1;
            }
            None => self.stats.non_straddling += 1,
        }
    }

    /// Returns a consistent copy of the aggregate counters.
    pub fn snapshot(&self) -> PatchShapeStats {
        self.stats.clone()
    }
}

/// Deterministically ordered counts keyed by a backend-owned enum or newtype.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CounterSnapshot<K> {
    counts: Vec<(K, u64)>,
}

impl<K: Ord> CounterSnapshot<K> {
    /// Creates a snapshot, sorting keys and combining duplicate entries.
    pub fn new(counts: impl IntoIterator<Item = (K, u64)>) -> Self {
        let mut merged = BTreeMap::new();
        for (key, count) in counts {
            *merged.entry(key).or_insert(0_u64) += count;
        }
        Self {
            counts: merged.into_iter().collect(),
        }
    }

    /// Returns the ordered `(key, count)` entries.
    pub fn counts(&self) -> &[(K, u64)] {
        &self.counts
    }

    /// Returns the sum of all counters.
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|(_, count)| count).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct FakeSource {
        snapshots: Cell<usize>,
    }

    struct FakeSnapshot;

    impl fmt::Display for FakeSnapshot {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fake")
        }
    }

    impl BackendStatsSnapshot for FakeSnapshot {
        const BACKEND_NAME: &'static str = "fake";
    }

    impl BackendStatsSource for FakeSource {
        type Snapshot = FakeSnapshot;

        fn backend_stats(&self) -> Self::Snapshot {
            self.snapshots.set(self.snapshots.get() + 1);
            FakeSnapshot
        }
    }

    #[test]
    fn disabled_request_does_not_call_snapshot_source() {
        let source = FakeSource {
            snapshots: Cell::new(0),
        };

        assert!(BackendStatsRequest::DISABLED.collect(&source).is_none());
        assert_eq!(source.snapshots.get(), 0);
        assert!(BackendStatsRequest::ENABLED.collect(&source).is_some());
        assert_eq!(source.snapshots.get(), 1);
    }

    #[test]
    fn patch_shape_collector_deduplicates_rips_and_uses_exact_buckets() {
        let mut collector = PatchShapeCollector::default();
        collector.record_site(0x1000, true, Some(InstructionPatchShape::new(2, None)));
        collector.record_site(0x103f, false, Some(InstructionPatchShape::new(5, Some(1))));
        collector.record_site(0x103f, true, Some(InstructionPatchShape::new(7, None)));
        collector.record_site(0x2000, false, None);

        let stats = collector.snapshot();
        assert_eq!(stats.candidate_rips(), 3);
        assert_eq!(stats.patched_rips(), 1);
        assert_eq!(stats.classified_candidates(), 2);
        assert_eq!(stats.cacheline_straddlers(), 1);
        assert_eq!(stats.non_straddling(), 1);
        assert_eq!(stats.instruction_lengths()[1], 1);
        assert_eq!(stats.instruction_lengths()[4], 1);
        assert_eq!(stats.instruction_lengths().iter().sum::<u64>(), 2);
        assert_eq!(stats.straddle_after()[0], 1);
        assert_eq!(stats.straddle_after().iter().sum::<u64>(), 1);
    }

    #[test]
    fn patch_shape_collector_keeps_equal_rips_distinct_across_processes_and_execs() {
        let mut collector = PatchShapeCollector::default();
        for (process, generation) in [(11, 0), (12, 0), (11, 1)] {
            collector.record_process_site(
                process,
                generation,
                0x4000,
                true,
                Some(InstructionPatchShape::new(2, None)),
            );
        }
        collector.record_process_site(
            11,
            0,
            0x4000,
            true,
            Some(InstructionPatchShape::new(2, None)),
        );

        let stats = collector.snapshot();
        assert_eq!(stats.candidate_rips(), 3);
        assert_eq!(stats.patched_rips(), 3);
        assert_eq!(stats.instruction_lengths()[1], 3);
    }

    #[test]
    fn counter_snapshot_sorts_and_combines_typed_keys() {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        enum Path {
            Fast,
            Slow,
        }

        let snapshot = CounterSnapshot::new([(Path::Slow, 2), (Path::Fast, 7), (Path::Slow, 3)]);

        assert_eq!(snapshot.counts(), &[(Path::Fast, 7), (Path::Slow, 5)]);
        assert_eq!(snapshot.total(), 12);
    }

    #[test]
    #[should_panic(expected = "cache-line straddle prefix must fall inside the instruction")]
    fn patch_shape_rejects_boundary_at_instruction_end() {
        InstructionPatchShape::new(5, Some(5));
    }
}
