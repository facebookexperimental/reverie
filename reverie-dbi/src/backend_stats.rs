/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed end-of-run statistics owned by the DynamoRIO (DBI) backend.
//!
//! Unlike the in-process LiteInst provider, DBI accumulates its counters inside
//! a separate, DynamoRIO-instrumented client process (see `native/client.c`).
//! Each instrumented process emits **one fixed-size binary record** at
//! `event_exit`, and the launcher decodes and commutatively aggregates every
//! record from the whole process tree into a single [`DbiBackendStatsSnapshot`].
//!
//! This module owns three things that make that possible without any text
//! parsing (the historical `reverie-dbi: tool=... branches=...` stderr line):
//!
//! * the typed schema ([`DbiBackendStatsSnapshot`], [`DbiTranslationStats`],
//!   [`DbiRuntimeKind`]) and its [`reverie::BackendStatsSource`] adapter;
//! * a stable, C-emittable wire ABI ([`encode_process_record`],
//!   [`decode_process_record`]) that the native client writes verbatim;
//! * an order-independent [`DbiBackendStatsAggregator`] that folds records from
//!   an arbitrary number of processes in any arrival order.
//!
//! Aggregation is deliberately commutative: additive counters are summed, peak
//! gauges are max-reduced, and the per-process memory-determinism digest is
//! XOR-folded. No physical pid, virtual identity, or arrival order ever reaches
//! the [`fmt::Display`] output, so the rendered snapshot is reproducible.

use std::fmt;

use reverie::BackendStatsSnapshot;
use reverie::BackendStatsSource;
use reverie::CounterSnapshot;

/// Eight-byte magic prefixing every wire record: `RVDBISTA` (Reverie DBI stats).
pub const WIRE_MAGIC: [u8; 8] = *b"RVDBISTA";

/// Current wire-format version. Bump on any incompatible layout change.
pub const WIRE_VERSION: u16 = 1;

/// Flag bit set when the process reported DynamoRIO `dr_get_stats` translation data.
pub const WIRE_FLAG_DR_STATS_PRESENT: u32 = 1 << 0;

/// Exact byte length of one wire-v1 process record.
///
/// header(24) + image_generation(8) + identity(16) + scalar counters(40)
/// + translation stats(56) = 144 bytes.
pub const WIRE_RECORD_LEN: usize = 144;

/// Which built-in DBI client runtime produced a process record.
///
/// Mirrors `reverie_dbi_runtime_name` in the native client. `Ord` so a
/// [`CounterSnapshot`] over these keys renders in a deterministic order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DbiRuntimeKind {
    /// The default determinism runtime (`PrototypeTool`).
    PrototypeTool,
    /// The exact whole-program branch counter (`Counter1`).
    Counter1,
    /// The per-thread local syscall counter (`CounterLocal`).
    CounterLocal,
    /// A runtime whose wire code did not match a known kind.
    Unknown,
}

impl DbiRuntimeKind {
    /// Decodes the one-byte wire encoding of a runtime kind.
    ///
    /// Any unrecognized code decodes to [`DbiRuntimeKind::Unknown`] rather than
    /// failing the whole record: a newer client reporting an extra runtime must
    /// still contribute its additive counters.
    pub const fn from_wire(code: u8) -> Self {
        match code {
            0 => Self::PrototypeTool,
            1 => Self::Counter1,
            2 => Self::CounterLocal,
            _ => Self::Unknown,
        }
    }

    /// Encodes this runtime kind as its one-byte wire code.
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::PrototypeTool => 0,
            Self::Counter1 => 1,
            Self::CounterLocal => 2,
            Self::Unknown => 255,
        }
    }

    /// Returns a short, stable label for display output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::PrototypeTool => "prototype",
            Self::Counter1 => "counter1",
            Self::CounterLocal => "counter_local",
            Self::Unknown => "unknown",
        }
    }
}

/// One instrumented process's contribution, decoded from a wire record.
///
/// The `process_identity`/`parent_identity` fields exist only so the aggregator
/// could deduplicate or attribute records during debugging; they are **never**
/// summed and **never** rendered. Everything else is a raw per-process counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DbiProcessRecord {
    /// Which client runtime produced this record.
    pub runtime_kind: DbiRuntimeKind,
    /// Whether DynamoRIO translation stats are populated in this record.
    pub dr_stats_present: bool,
    /// DynamoRIO application-image generation (incremented per followed exec).
    pub image_generation: u64,
    /// Virtual (deterministic) process id. Identity only; never aggregated or shown.
    pub process_identity: u64,
    /// Virtual (deterministic) parent process id. Identity only; never aggregated or shown.
    pub parent_identity: u64,
    /// Counted control-flow branches (the DBI branch clock).
    pub branches: u64,
    /// Syscalls intercepted by the client.
    pub syscalls: u64,
    /// Syscalls whose result the client rewrote or suppressed.
    pub rewritten: u64,
    /// Reads served from the deterministic stdin path.
    pub stdin_reads: u64,
    /// Per-process memory-determinism digest (0 when not computed).
    pub memory_hash: u64,
    /// DynamoRIO basic blocks built (translated) for this process.
    pub basic_blocks_built: u64,
    /// Application threads DynamoRIO created for this process.
    pub threads_created: u64,
    /// Synchronization attempts that did not land at a safe spot.
    pub synchronization_retries: u64,
    /// Native (non-instrumented) signals DynamoRIO delivered.
    pub native_signals: u64,
    /// Times execution exited the code cache back to the dispatcher.
    pub code_cache_exits: u64,
    /// Peak simultaneously live application threads for this process.
    pub peak_threads: u64,
    /// Peak reachable code-cache blocks (a proxy for code-cache size) for this process.
    pub peak_reachable_cache_blocks: u64,
}

impl Default for DbiProcessRecord {
    fn default() -> Self {
        Self {
            runtime_kind: DbiRuntimeKind::PrototypeTool,
            dr_stats_present: false,
            image_generation: 0,
            process_identity: 0,
            parent_identity: 0,
            branches: 0,
            syscalls: 0,
            rewritten: 0,
            stdin_reads: 0,
            memory_hash: 0,
            basic_blocks_built: 0,
            threads_created: 0,
            synchronization_retries: 0,
            native_signals: 0,
            code_cache_exits: 0,
            peak_threads: 0,
            peak_reachable_cache_blocks: 0,
        }
    }
}

/// A wire-decoding failure. Callers must treat any of these as an error rather
/// than silently dropping a record, so a corrupt or truncated stream is loud.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The record was shorter than one fixed-size wire-v1 record.
    Truncated {
        /// Bytes actually available.
        available: usize,
        /// Bytes a single record requires.
        required: usize,
    },
    /// The leading magic did not match [`WIRE_MAGIC`].
    BadMagic,
    /// The version field named an unsupported wire format.
    UnsupportedVersion(u16),
    /// The record self-described a length this decoder cannot honor.
    BadRecordLength(u16),
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                available,
                required,
            } => write!(
                formatter,
                "DBI stats record truncated: {available} of {required} bytes"
            ),
            Self::BadMagic => formatter.write_str("DBI stats record has an invalid magic prefix"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "DBI stats record has unsupported version {version}"
                )
            }
            Self::BadRecordLength(length) => {
                write!(
                    formatter,
                    "DBI stats record self-reports invalid length {length}"
                )
            }
        }
    }
}

impl std::error::Error for WireError {}

/// Encodes one process record as its fixed-size wire-v1 byte layout.
///
/// The layout is little-endian and matches the record the native client writes
/// in `event_exit`. Keeping this in Rust lets the codec round-trip tests pin the
/// exact bytes the C side must produce.
pub fn encode_process_record(record: &DbiProcessRecord) -> [u8; WIRE_RECORD_LEN] {
    let mut out = [0_u8; WIRE_RECORD_LEN];
    let mut cursor = 0;

    out[cursor..cursor + 8].copy_from_slice(&WIRE_MAGIC);
    cursor += 8;
    out[cursor..cursor + 2].copy_from_slice(&WIRE_VERSION.to_le_bytes());
    cursor += 2;
    out[cursor..cursor + 2].copy_from_slice(&(WIRE_RECORD_LEN as u16).to_le_bytes());
    cursor += 2;
    let flags = if record.dr_stats_present {
        WIRE_FLAG_DR_STATS_PRESENT
    } else {
        0
    };
    out[cursor..cursor + 4].copy_from_slice(&flags.to_le_bytes());
    cursor += 4;
    out[cursor] = record.runtime_kind.to_wire();
    cursor += 1;
    // seven bytes of reserved padding keep the u64 fields eight-byte aligned.
    cursor += 7;

    for value in [
        record.image_generation,
        record.process_identity,
        record.parent_identity,
        record.branches,
        record.syscalls,
        record.rewritten,
        record.stdin_reads,
        record.memory_hash,
        record.basic_blocks_built,
        record.threads_created,
        record.synchronization_retries,
        record.native_signals,
        record.code_cache_exits,
        record.peak_threads,
        record.peak_reachable_cache_blocks,
    ] {
        out[cursor..cursor + 8].copy_from_slice(&value.to_le_bytes());
        cursor += 8;
    }

    debug_assert_eq!(cursor, WIRE_RECORD_LEN);
    out
}

/// Decodes one process record from the front of `bytes`.
///
/// Returns the decoded record and the number of bytes consumed, so a caller can
/// decode a concatenation of records. A bad magic, version, self-reported
/// length, or a short buffer is a hard [`WireError`], never a silent skip.
pub fn decode_process_record(bytes: &[u8]) -> Result<(DbiProcessRecord, usize), WireError> {
    if bytes.len() < WIRE_RECORD_LEN {
        return Err(WireError::Truncated {
            available: bytes.len(),
            required: WIRE_RECORD_LEN,
        });
    }
    if bytes[0..8] != WIRE_MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let record_len = u16::from_le_bytes([bytes[10], bytes[11]]);
    if record_len as usize != WIRE_RECORD_LEN {
        return Err(WireError::BadRecordLength(record_len));
    }
    let flags = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let runtime_kind = DbiRuntimeKind::from_wire(bytes[16]);
    // bytes[17..24] are reserved padding.

    let mut cursor = 24;
    let mut next_u64 = || {
        let value = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        value
    };

    let record = DbiProcessRecord {
        runtime_kind,
        dr_stats_present: flags & WIRE_FLAG_DR_STATS_PRESENT != 0,
        image_generation: next_u64(),
        process_identity: next_u64(),
        parent_identity: next_u64(),
        branches: next_u64(),
        syscalls: next_u64(),
        rewritten: next_u64(),
        stdin_reads: next_u64(),
        memory_hash: next_u64(),
        basic_blocks_built: next_u64(),
        threads_created: next_u64(),
        synchronization_retries: next_u64(),
        native_signals: next_u64(),
        code_cache_exits: next_u64(),
        peak_threads: next_u64(),
        peak_reachable_cache_blocks: next_u64(),
    };

    debug_assert_eq!(cursor, WIRE_RECORD_LEN);
    Ok((record, WIRE_RECORD_LEN))
}

/// DynamoRIO translation and code-cache statistics, aggregated over a process tree.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DbiTranslationStats {
    basic_blocks_built: u64,
    threads_created: u64,
    synchronization_retries: u64,
    native_signals: u64,
    code_cache_exits: u64,
    peak_threads_per_process: u64,
    peak_reachable_code_cache_blocks_per_process: u64,
    process_images_with_stats: u64,
    process_images_without_stats: u64,
}

impl DbiTranslationStats {
    /// Total basic blocks DynamoRIO built (translated) across all processes.
    pub const fn basic_blocks_built(&self) -> u64 {
        self.basic_blocks_built
    }

    /// Total application threads DynamoRIO created across all processes.
    pub const fn threads_created(&self) -> u64 {
        self.threads_created
    }

    /// Total synchronization attempts that missed a safe spot.
    pub const fn synchronization_retries(&self) -> u64 {
        self.synchronization_retries
    }

    /// Total native signals DynamoRIO delivered.
    pub const fn native_signals(&self) -> u64 {
        self.native_signals
    }

    /// Total code-cache exits back to the dispatcher.
    pub const fn code_cache_exits(&self) -> u64 {
        self.code_cache_exits
    }

    /// Largest per-process peak live-thread count (max-reduced, not summed).
    pub const fn peak_threads_per_process(&self) -> u64 {
        self.peak_threads_per_process
    }

    /// Largest per-process peak reachable code-cache block count (a code-cache
    /// size proxy; max-reduced, not summed).
    pub const fn peak_reachable_code_cache_blocks_per_process(&self) -> u64 {
        self.peak_reachable_code_cache_blocks_per_process
    }

    /// Process images that reported DynamoRIO translation stats.
    pub const fn process_images_with_stats(&self) -> u64 {
        self.process_images_with_stats
    }

    /// Process images that could not report DynamoRIO translation stats (e.g. a
    /// copied runtime after vfork).
    pub const fn process_images_without_stats(&self) -> u64 {
        self.process_images_without_stats
    }
}

/// Stable DBI statistics captured after one backend run over a whole process tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbiBackendStatsSnapshot {
    process_images: u64,
    counted_branches: u64,
    intercepted_syscalls: u64,
    rewritten_syscalls: u64,
    stdin_reads: u64,
    memory_hash_fold: u64,
    translation: DbiTranslationStats,
    runtime_kinds: CounterSnapshot<DbiRuntimeKind>,
}

impl DbiBackendStatsSnapshot {
    /// Number of instrumented process images aggregated into this snapshot.
    pub const fn process_images(&self) -> u64 {
        self.process_images
    }

    /// Total counted control-flow branches (the DBI branch clock) across the tree.
    pub const fn counted_branches(&self) -> u64 {
        self.counted_branches
    }

    /// Total syscalls intercepted across the tree.
    pub const fn intercepted_syscalls(&self) -> u64 {
        self.intercepted_syscalls
    }

    /// Total syscalls whose result the client rewrote or suppressed.
    pub const fn rewritten_syscalls(&self) -> u64 {
        self.rewritten_syscalls
    }

    /// Total deterministic stdin reads across the tree.
    pub const fn stdin_reads(&self) -> u64 {
        self.stdin_reads
    }

    /// Order-independent XOR fold of every process's memory-determinism digest.
    ///
    /// This is informational: it is a commutative fold, not a sum, so process
    /// arrival order cannot change it. It is zero when no process computed a
    /// digest.
    pub const fn memory_hash_fold(&self) -> u64 {
        self.memory_hash_fold
    }

    /// DynamoRIO translation and code-cache statistics for the tree.
    pub const fn translation(&self) -> &DbiTranslationStats {
        &self.translation
    }

    /// Per-runtime-kind process-image counts in deterministic key order.
    pub const fn runtime_kinds(&self) -> &CounterSnapshot<DbiRuntimeKind> {
        &self.runtime_kinds
    }
}

impl fmt::Display for DbiBackendStatsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DBI instrumentation stats: process_images={} branches={} syscalls={} rewritten={} stdin_reads={} memory_hash_fold={:016x} translation[basic_blocks_built={} threads_created={} synchronization_retries={} native_signals={} code_cache_exits={} peak_threads_per_process={} peak_reachable_code_cache_blocks_per_process={} images_with_stats={} images_without_stats={}] runtimes[",
            self.process_images,
            self.counted_branches,
            self.intercepted_syscalls,
            self.rewritten_syscalls,
            self.stdin_reads,
            self.memory_hash_fold,
            self.translation.basic_blocks_built,
            self.translation.threads_created,
            self.translation.synchronization_retries,
            self.translation.native_signals,
            self.translation.code_cache_exits,
            self.translation.peak_threads_per_process,
            self.translation
                .peak_reachable_code_cache_blocks_per_process,
            self.translation.process_images_with_stats,
            self.translation.process_images_without_stats,
        )?;
        for (index, (kind, count)) in self.runtime_kinds.counts().iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{}={count}", kind.label())?;
        }
        formatter.write_str("]")
    }
}

impl BackendStatsSnapshot for DbiBackendStatsSnapshot {
    const BACKEND_NAME: &'static str = "dbi";
}

/// Commutative accumulator that folds per-process records into one snapshot.
///
/// Folding is order-independent by construction: additive fields are summed,
/// peak gauges are max-reduced, the memory digest is XOR-folded, and runtime
/// kinds accumulate into a [`CounterSnapshot`], which itself sorts and combines
/// keys. Feeding the same multiset of records in any order yields an identical
/// snapshot.
#[derive(Clone, Debug, Default)]
pub struct DbiBackendStatsAggregator {
    process_images: u64,
    counted_branches: u64,
    intercepted_syscalls: u64,
    rewritten_syscalls: u64,
    stdin_reads: u64,
    memory_hash_fold: u64,
    basic_blocks_built: u64,
    threads_created: u64,
    synchronization_retries: u64,
    native_signals: u64,
    code_cache_exits: u64,
    peak_threads_per_process: u64,
    peak_reachable_code_cache_blocks_per_process: u64,
    process_images_with_stats: u64,
    process_images_without_stats: u64,
    runtime_kind_counts: Vec<(DbiRuntimeKind, u64)>,
}

impl DbiBackendStatsAggregator {
    /// Creates an empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one decoded process record into the running totals.
    pub fn record(&mut self, record: &DbiProcessRecord) {
        self.process_images += 1;
        self.counted_branches = self.counted_branches.saturating_add(record.branches);
        self.intercepted_syscalls = self.intercepted_syscalls.saturating_add(record.syscalls);
        self.rewritten_syscalls = self.rewritten_syscalls.saturating_add(record.rewritten);
        self.stdin_reads = self.stdin_reads.saturating_add(record.stdin_reads);
        self.memory_hash_fold ^= record.memory_hash;
        self.runtime_kind_counts.push((record.runtime_kind, 1));

        if record.dr_stats_present {
            self.process_images_with_stats += 1;
            self.basic_blocks_built = self
                .basic_blocks_built
                .saturating_add(record.basic_blocks_built);
            self.threads_created = self.threads_created.saturating_add(record.threads_created);
            self.synchronization_retries = self
                .synchronization_retries
                .saturating_add(record.synchronization_retries);
            self.native_signals = self.native_signals.saturating_add(record.native_signals);
            self.code_cache_exits = self
                .code_cache_exits
                .saturating_add(record.code_cache_exits);
            self.peak_threads_per_process = self.peak_threads_per_process.max(record.peak_threads);
            self.peak_reachable_code_cache_blocks_per_process = self
                .peak_reachable_code_cache_blocks_per_process
                .max(record.peak_reachable_cache_blocks);
        } else {
            self.process_images_without_stats += 1;
        }
    }

    /// Decodes and folds a concatenation of wire records from a byte stream.
    ///
    /// A trailing partial record or any malformed record is a hard error; the
    /// caller must not treat a corrupt tail as end-of-stream.
    pub fn absorb_wire_stream(&mut self, mut bytes: &[u8]) -> Result<usize, WireError> {
        let mut count = 0;
        while !bytes.is_empty() {
            let (record, consumed) = decode_process_record(bytes)?;
            self.record(&record);
            bytes = &bytes[consumed..];
            count += 1;
        }
        Ok(count)
    }

    /// Produces the aggregated snapshot.
    pub fn snapshot(&self) -> DbiBackendStatsSnapshot {
        DbiBackendStatsSnapshot {
            process_images: self.process_images,
            counted_branches: self.counted_branches,
            intercepted_syscalls: self.intercepted_syscalls,
            rewritten_syscalls: self.rewritten_syscalls,
            stdin_reads: self.stdin_reads,
            memory_hash_fold: self.memory_hash_fold,
            translation: DbiTranslationStats {
                basic_blocks_built: self.basic_blocks_built,
                threads_created: self.threads_created,
                synchronization_retries: self.synchronization_retries,
                native_signals: self.native_signals,
                code_cache_exits: self.code_cache_exits,
                peak_threads_per_process: self.peak_threads_per_process,
                peak_reachable_code_cache_blocks_per_process: self
                    .peak_reachable_code_cache_blocks_per_process,
                process_images_with_stats: self.process_images_with_stats,
                process_images_without_stats: self.process_images_without_stats,
            },
            runtime_kinds: CounterSnapshot::new(self.runtime_kind_counts.iter().copied()),
        }
    }

    /// Produces a [`BackendStatsSource`] over the aggregated snapshot.
    pub fn into_source(self) -> DbiBackendStatsSource {
        DbiBackendStatsSource {
            snapshot: self.snapshot(),
        }
    }
}

/// Backend-owned source for a typed DBI end-of-run snapshot.
#[derive(Clone, Debug)]
pub struct DbiBackendStatsSource {
    snapshot: DbiBackendStatsSnapshot,
}

impl DbiBackendStatsSource {
    /// Wraps an already-aggregated snapshot as a source.
    pub const fn from_snapshot(snapshot: DbiBackendStatsSnapshot) -> Self {
        Self { snapshot }
    }

    /// Returns the captured snapshot without recomputing it.
    pub const fn snapshot(&self) -> &DbiBackendStatsSnapshot {
        &self.snapshot
    }
}

impl fmt::Display for DbiBackendStatsSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot.fmt(formatter)
    }
}

impl BackendStatsSource for DbiBackendStatsSource {
    type Snapshot = DbiBackendStatsSnapshot;

    fn backend_stats(&self) -> Self::Snapshot {
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use reverie::BackendStatsRequest;

    use super::*;

    fn sample_record(seed: u64, dr_stats: bool) -> DbiProcessRecord {
        DbiProcessRecord {
            runtime_kind: DbiRuntimeKind::Counter1,
            dr_stats_present: dr_stats,
            image_generation: seed,
            process_identity: 1000 + seed,
            parent_identity: 1,
            branches: 100 * seed,
            syscalls: 10 * seed,
            rewritten: seed,
            stdin_reads: seed % 3,
            memory_hash: 0xdead_0000 ^ seed,
            basic_blocks_built: 7 * seed,
            threads_created: seed,
            synchronization_retries: seed / 2,
            native_signals: seed % 2,
            code_cache_exits: 3 * seed,
            peak_threads: seed,
            peak_reachable_cache_blocks: 40 * seed,
        }
    }

    #[test]
    fn wire_record_round_trips_exactly() {
        for dr_stats in [false, true] {
            let record = sample_record(5, dr_stats);
            let encoded = encode_process_record(&record);
            assert_eq!(encoded.len(), WIRE_RECORD_LEN);
            let (decoded, consumed) = decode_process_record(&encoded).unwrap();
            assert_eq!(consumed, WIRE_RECORD_LEN);
            assert_eq!(decoded, record);
        }
    }

    #[test]
    fn unknown_runtime_code_decodes_to_unknown_not_error() {
        let mut encoded = encode_process_record(&sample_record(1, true));
        encoded[16] = 200; // runtime kind byte
        let (decoded, _) = decode_process_record(&encoded).unwrap();
        assert_eq!(decoded.runtime_kind, DbiRuntimeKind::Unknown);
    }

    #[test]
    fn decode_rejects_bad_magic_version_and_truncation() {
        let good = encode_process_record(&sample_record(2, true));

        let mut bad_magic = good;
        bad_magic[0] ^= 0xff;
        assert_eq!(decode_process_record(&bad_magic), Err(WireError::BadMagic));

        let mut bad_version = good;
        bad_version[8] = 9;
        bad_version[9] = 0;
        assert_eq!(
            decode_process_record(&bad_version),
            Err(WireError::UnsupportedVersion(9))
        );

        let mut bad_len = good;
        bad_len[10] = 1; // record_len low byte -> 1
        bad_len[11] = 0;
        assert_eq!(
            decode_process_record(&bad_len),
            Err(WireError::BadRecordLength(1))
        );

        let truncated = &good[..WIRE_RECORD_LEN - 1];
        assert_eq!(
            decode_process_record(truncated),
            Err(WireError::Truncated {
                available: WIRE_RECORD_LEN - 1,
                required: WIRE_RECORD_LEN,
            })
        );
    }

    #[test]
    fn absorb_wire_stream_rejects_trailing_partial_record() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&encode_process_record(&sample_record(1, true)));
        stream.extend_from_slice(&encode_process_record(&sample_record(2, true))[..10]);
        let mut aggregator = DbiBackendStatsAggregator::new();
        assert!(aggregator.absorb_wire_stream(&stream).is_err());
    }

    #[test]
    fn aggregation_is_order_independent() {
        let records = [
            sample_record(1, true),
            sample_record(2, true),
            sample_record(3, false),
        ];

        let mut forward = DbiBackendStatsAggregator::new();
        for record in records.iter() {
            forward.record(record);
        }

        let mut reverse = DbiBackendStatsAggregator::new();
        for record in records.iter().rev() {
            reverse.record(record);
        }

        assert_eq!(forward.snapshot(), reverse.snapshot());
    }

    #[test]
    fn aggregation_sums_additive_and_maxes_peaks() {
        let mut aggregator = DbiBackendStatsAggregator::new();
        aggregator.record(&sample_record(1, true)); // peak_threads=1, blocks=40
        aggregator.record(&sample_record(4, true)); // peak_threads=4, blocks=160

        let snapshot = aggregator.snapshot();
        assert_eq!(snapshot.process_images(), 2);
        // additive: branches 100*1 + 100*4 = 500
        assert_eq!(snapshot.counted_branches(), 500);
        assert_eq!(snapshot.translation().basic_blocks_built(), 7 + 7 * 4);
        // peaks are max-reduced, not summed.
        assert_eq!(snapshot.translation().peak_threads_per_process(), 4);
        assert_eq!(
            snapshot
                .translation()
                .peak_reachable_code_cache_blocks_per_process(),
            160
        );
        // XOR fold is order independent: (0xdead0000^1) ^ (0xdead0000^4) = 5.
        assert_eq!(snapshot.memory_hash_fold(), 5);
    }

    #[test]
    fn dr_stats_absent_is_counted_and_excluded_from_translation_totals() {
        let mut aggregator = DbiBackendStatsAggregator::new();
        aggregator.record(&sample_record(2, false)); // no dr stats
        let snapshot = aggregator.snapshot();
        assert_eq!(snapshot.translation().process_images_with_stats(), 0);
        assert_eq!(snapshot.translation().process_images_without_stats(), 1);
        assert_eq!(snapshot.translation().basic_blocks_built(), 0);
        // non-translation counters still accumulate from the record.
        assert_eq!(snapshot.counted_branches(), 200);
    }

    #[test]
    fn runtime_kind_counts_are_deterministic() {
        let mut aggregator = DbiBackendStatsAggregator::new();
        let mut prototype = sample_record(1, true);
        prototype.runtime_kind = DbiRuntimeKind::PrototypeTool;
        let mut counter1 = sample_record(1, true);
        counter1.runtime_kind = DbiRuntimeKind::Counter1;
        aggregator.record(&counter1);
        aggregator.record(&prototype);
        aggregator.record(&counter1);

        let snapshot = aggregator.snapshot();
        // sorted by enum order: PrototypeTool(1), Counter1(2).
        assert_eq!(
            snapshot.runtime_kinds().counts(),
            &[
                (DbiRuntimeKind::PrototypeTool, 1),
                (DbiRuntimeKind::Counter1, 2)
            ]
        );
    }

    #[test]
    fn display_is_deterministic_and_contains_no_raw_identity() {
        let mut aggregator = DbiBackendStatsAggregator::new();
        aggregator.record(&sample_record(1, true));
        aggregator.record(&sample_record(2, true));
        let source = aggregator.into_source();

        let rendered = source.snapshot().to_string();
        assert_eq!(rendered, source.snapshot().to_string());
        assert!(rendered.contains("process_images=2"));
        assert!(rendered.contains("basic_blocks_built="));
        assert!(rendered.contains("peak_reachable_code_cache_blocks_per_process="));
        // No physical/virtual identity, pid, or wall-clock time leaks into Display.
        // (Check timestamp-style tokens specifically: the substring "time" would
        // false-collide with the legitimate "runtimes[" label.)
        assert!(!rendered.contains("identity"));
        assert!(!rendered.contains("pid"));
        assert!(!rendered.contains("timestamp"));
        assert!(!rendered.contains("clock"));
        assert!(!rendered.contains("epoch"));
        assert!(!rendered.contains("0x")); // no raw addresses
        assert!(!rendered.contains("1001")); // process_identity of sample_record(1)
        assert!(!rendered.contains("1002")); // process_identity of sample_record(2)
    }

    #[test]
    fn disabled_request_does_not_collect_snapshot() {
        let source = DbiBackendStatsAggregator::new().into_source();
        assert!(BackendStatsRequest::DISABLED.collect(&source).is_none());
        assert!(BackendStatsRequest::ENABLED.collect(&source).is_some());
    }
}
