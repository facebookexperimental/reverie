/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Aggregate statistics for dynamically installed LiteInst patch sites.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

/// Aggregate characteristics of distinct LiteInst patch-site instruction pointers.
///
/// Instruction lengths of five bytes or more share one bucket because five
/// bytes is the direct-jump patch width. A cache-line straddler is an original
/// instruction whose first five bytes cross a line; therefore its boundary is
/// necessarily after a one-, two-, three-, or four-byte prefix.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiteinstInstrumentationStats {
    candidate_rips: BTreeSet<u64>,
    patched_rips: BTreeSet<u64>,
    direct_pun_patched: usize,
    relocated_patched: usize,
    ptrace_straddler_bail: usize,
    ptrace_other_fallback: usize,
    instruction_len_5_plus: usize,
    instruction_len_4: usize,
    instruction_len_3: usize,
    instruction_len_2: usize,
    instruction_len_1: usize,
    classified_candidates: usize,
    non_straddling: usize,
    straddle_after_1: usize,
    straddle_after_2: usize,
    straddle_after_3: usize,
    straddle_after_4: usize,
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
    pub(crate) fn record_site(
        &mut self,
        rip: u64,
        outcome: LiteinstPatchOutcome,
        shape: Option<(usize, Option<usize>)>,
    ) {
        if !self.candidate_rips.insert(rip) {
            return;
        }
        match outcome {
            LiteinstPatchOutcome::DirectPunPatched => {
                self.direct_pun_patched += 1;
                self.patched_rips.insert(rip);
            }
            LiteinstPatchOutcome::RelocatedPatched => {
                self.relocated_patched += 1;
                self.patched_rips.insert(rip);
            }
            LiteinstPatchOutcome::PtraceStraddlerBail => self.ptrace_straddler_bail += 1,
            LiteinstPatchOutcome::PtraceOtherFallback => self.ptrace_other_fallback += 1,
        }
        let Some((instruction_len, straddle_prefix)) = shape else {
            return;
        };
        self.classified_candidates += 1;
        match instruction_len {
            1 => self.instruction_len_1 += 1,
            2 => self.instruction_len_2 += 1,
            3 => self.instruction_len_3 += 1,
            4 => self.instruction_len_4 += 1,
            5.. => self.instruction_len_5_plus += 1,
            0 => unreachable!("x86 instructions cannot be empty"),
        }
        match straddle_prefix {
            None => self.non_straddling += 1,
            Some(1) => self.straddle_after_1 += 1,
            Some(2) => self.straddle_after_2 += 1,
            Some(3) => self.straddle_after_3 += 1,
            Some(4) => self.straddle_after_4 += 1,
            Some(prefix) => {
                unreachable!("a five-byte patch prefix cannot straddle after byte {prefix}")
            }
        }
    }

    /// Returns the number of distinct instruction pointers successfully patched.
    pub fn distinct_rips(&self) -> usize {
        self.patched_rips.len()
    }

    /// Returns distinct patch candidates, including safe straddler bailouts.
    pub fn patch_candidates(&self) -> usize {
        self.candidate_rips.len()
    }

    /// Returns direct, relocated, straddler-bail, and other-fallback counts.
    pub const fn decision_counts(&self) -> [usize; 4] {
        [
            self.direct_pun_patched,
            self.relocated_patched,
            self.ptrace_straddler_bail,
            self.ptrace_other_fallback,
        ]
    }

    /// Returns candidates with a decoded instruction shape.
    pub const fn classified_candidates(&self) -> usize {
        self.classified_candidates
    }

    /// Returns the number of patch-site instructions crossing a cache line.
    pub const fn cacheline_straddlers(&self) -> usize {
        self.straddle_after_1
            + self.straddle_after_2
            + self.straddle_after_3
            + self.straddle_after_4
    }

    /// Returns the number of non-straddling patch-site instructions.
    pub const fn non_straddling(&self) -> usize {
        self.non_straddling
    }

    /// Returns instruction-length counts ordered as 5+, 4, 3, 2, and 1 byte.
    pub const fn instruction_length_counts(&self) -> [usize; 5] {
        [
            self.instruction_len_5_plus,
            self.instruction_len_4,
            self.instruction_len_3,
            self.instruction_len_2,
            self.instruction_len_1,
        ]
    }

    /// Returns straddler counts for boundaries after 1, 2, 3, and 4 bytes.
    pub const fn straddle_prefix_counts(&self) -> [usize; 4] {
        [
            self.straddle_after_1,
            self.straddle_after_2,
            self.straddle_after_3,
            self.straddle_after_4,
        ]
    }

    /// Prints one stable instrumentation-summary line to standard error.
    pub fn print(&self) {
        eprintln!("{self}");
    }
}

impl fmt::Display for LiteinstInstrumentationStats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LiteInst instrumentation stats: distinct_rips_patched={} patch_candidates={} decisions[direct_pun={},relocated={},ptrace_straddler={},ptrace_other={}] classified_candidates={} cacheline_straddlers={} non_straddling={} instruction_lengths[5+={},4={},3={},2={},1={}] straddle_prefix[1={},2={},3={},4={}]",
            self.distinct_rips(),
            self.patch_candidates(),
            self.direct_pun_patched,
            self.relocated_patched,
            self.ptrace_straddler_bail,
            self.ptrace_other_fallback,
            self.classified_candidates,
            self.cacheline_straddlers(),
            self.non_straddling,
            self.instruction_len_5_plus,
            self.instruction_len_4,
            self.instruction_len_3,
            self.instruction_len_2,
            self.instruction_len_1,
            self.straddle_after_1,
            self.straddle_after_2,
            self.straddle_after_3,
            self.straddle_after_4,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::LiteinstInstrumentationStats;
    use super::LiteinstPatchOutcome;

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

        assert_eq!(stats.distinct_rips(), 2);
        assert_eq!(stats.patch_candidates(), 7);
        assert_eq!(stats.decision_counts(), [1, 1, 4, 1]);
        assert_eq!(stats.classified_candidates(), 6);
        assert_eq!(stats.cacheline_straddlers(), 4);
        assert_eq!(stats.non_straddling(), 2);
        assert_eq!(stats.instruction_length_counts(), [2, 1, 1, 1, 1]);
        assert_eq!(stats.straddle_prefix_counts(), [1, 1, 1, 1]);
        assert_eq!(
            stats.to_string(),
            "LiteInst instrumentation stats: distinct_rips_patched=2 patch_candidates=7 decisions[direct_pun=1,relocated=1,ptrace_straddler=4,ptrace_other=1] classified_candidates=6 cacheline_straddlers=4 non_straddling=2 instruction_lengths[5+=2,4=1,3=1,2=1,1=1] straddle_prefix[1=1,2=1,3=1,4=1]"
        );
    }
}
