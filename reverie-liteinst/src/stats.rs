/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed end-of-run statistics owned by the LiteInst backend.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::BackendStatsSnapshot;
use reverie::BackendStatsSource;
use reverie::CounterSnapshot;
use reverie::GlobalTool;
use reverie::InstructionPatchShape;
pub use reverie::LiteinstDispatchPath;
use reverie::PatchShapeCollector;
use reverie::PatchShapeStats;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use serde::Deserialize;
use serde::Serialize;

/// A distinct outcome for one candidate LiteInst patch site.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LiteinstPatchDecision {
    /// A direct pun patch was installed.
    DirectPun,
    /// A replace-first relocation patch was installed.
    Relocated,
    /// The original syscall site was retained because its patch crossed a cache line.
    StraddlerFallback,
    /// The original syscall site was retained for another unpatchable-site reason.
    OtherFallback,
}

/// Stable LiteInst statistics captured after one backend run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteinstBackendStatsSnapshot {
    process_reports: u64,
    patch_shapes: PatchShapeStats,
    patch_decisions: CounterSnapshot<LiteinstPatchDecision>,
    dispatch_paths: CounterSnapshot<LiteinstDispatchPath>,
}

impl LiteinstBackendStatsSnapshot {
    /// Number of process-local reports aggregated by the in-guest runtime.
    pub const fn process_reports(&self) -> u64 {
        self.process_reports
    }

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
        self.patch_decisions.count(&decision)
    }

    fn path_count(&self, path: LiteinstDispatchPath) -> u64 {
        self.dispatch_paths.count(&path)
    }
}

impl fmt::Display for LiteinstBackendStatsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LiteInst instrumentation stats: process_reports={} distinct_rips_patched={} patch_candidates={} decisions[direct_pun={},relocated={},straddler_fallback={},other_fallback={}] paths[",
            self.process_reports,
            self.patch_shapes.patched_rips(),
            self.patch_shapes.candidate_rips(),
            self.decision_count(LiteinstPatchDecision::DirectPun),
            self.decision_count(LiteinstPatchDecision::Relocated),
            self.decision_count(LiteinstPatchDecision::StraddlerFallback),
            self.decision_count(LiteinstPatchDecision::OtherFallback),
        )?;
        for (index, path) in LiteinstDispatchPath::ALL.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{path}={}", self.path_count(*path))?;
        }
        write!(
            formatter,
            "] classified_candidates={} cacheline_straddlers={} non_straddling={} instruction_lengths[",
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
        let dispatch_paths = stats.ptrace_host_dispatch_paths();
        Self {
            snapshot: LiteinstBackendStatsSnapshot {
                process_reports: 0,
                patch_shapes: stats.patch_shape_stats(),
                patch_decisions: CounterSnapshot::new([
                    (LiteinstPatchDecision::DirectPun, decisions[0]),
                    (LiteinstPatchDecision::Relocated, decisions[1]),
                    (LiteinstPatchDecision::StraddlerFallback, decisions[2]),
                    (LiteinstPatchDecision::OtherFallback, decisions[3]),
                ]),
                dispatch_paths,
            },
        }
    }

    /// Builds the source for a runtime-free (trap-only) LiteInst run.
    ///
    /// Trap-only sites are recorded through the same tracer-owned collector as
    /// the host hybrid; with patching off it stays empty.
    pub(crate) fn from_trap_only(stats: reverie_ptrace::LiteinstInstrumentationStats) -> Self {
        Self::from_ptrace_host_hybrid(stats)
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
                .decision_count(LiteinstPatchDecision::StraddlerFallback) as usize,
            self.snapshot
                .decision_count(LiteinstPatchDecision::OtherFallback) as usize,
        ]
    }

    /// Returns dispatch-path counts keyed by the shared exhaustive value.
    pub const fn dispatch_path_counts(&self) -> &CounterSnapshot<LiteinstDispatchPath> {
        self.snapshot.dispatch_paths()
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

struct GuestStatsCollector {
    coordinator: PathBuf,
    in_guest_sigsys: AtomicU64,
    in_guest_nested_sigsys: AtomicU64,
    in_guest_physical_sigsys: AtomicU64,
    fallback_completion_sigsys: AtomicU64,
    cacheline_straddler_fallback: AtomicU64,
    unpatchable_or_other_fallback: AtomicU64,
    fallback_refusal: AtomicU64,
}

impl GuestStatsCollector {
    fn counter(&self, path: LiteinstDispatchPath) -> &AtomicU64 {
        match path {
            LiteinstDispatchPath::InGuestSigsys => &self.in_guest_sigsys,
            LiteinstDispatchPath::InGuestNestedSigsys => &self.in_guest_nested_sigsys,
            LiteinstDispatchPath::InGuestPhysicalSigsys => &self.in_guest_physical_sigsys,
            LiteinstDispatchPath::FallbackCompletionSigsys => &self.fallback_completion_sigsys,
            LiteinstDispatchPath::CachelineStraddlerFallback => &self.cacheline_straddler_fallback,
            LiteinstDispatchPath::UnpatchableOrOtherFallback => &self.unpatchable_or_other_fallback,
            LiteinstDispatchPath::FallbackRefusal => &self.fallback_refusal,
            LiteinstDispatchPath::FirstSiteSeccomp
            | LiteinstDispatchPath::PtraceInstallation
            | LiteinstDispatchPath::DirectHook => {
                panic!("path is not counted by the in-guest dispatcher")
            }
        }
    }

    fn snapshot(&self, direct_hooks: u64) -> CounterSnapshot<LiteinstDispatchPath> {
        CounterSnapshot::new([
            (
                LiteinstDispatchPath::InGuestPhysicalSigsys,
                self.in_guest_physical_sigsys.load(Ordering::Relaxed),
            ),
            (
                LiteinstDispatchPath::FallbackCompletionSigsys,
                self.fallback_completion_sigsys.load(Ordering::Relaxed),
            ),
            (
                LiteinstDispatchPath::InGuestSigsys,
                self.in_guest_sigsys.load(Ordering::Relaxed),
            ),
            (
                LiteinstDispatchPath::InGuestNestedSigsys,
                self.in_guest_nested_sigsys.load(Ordering::Relaxed),
            ),
            (
                LiteinstDispatchPath::CachelineStraddlerFallback,
                self.cacheline_straddler_fallback.load(Ordering::Relaxed),
            ),
            (
                LiteinstDispatchPath::UnpatchableOrOtherFallback,
                self.unpatchable_or_other_fallback.load(Ordering::Relaxed),
            ),
            (LiteinstDispatchPath::DirectHook, direct_hooks),
            (
                LiteinstDispatchPath::FallbackRefusal,
                self.fallback_refusal.load(Ordering::Relaxed),
            ),
        ])
    }

    fn reset(&self) {
        self.in_guest_sigsys.store(0, Ordering::Relaxed);
        self.in_guest_nested_sigsys.store(0, Ordering::Relaxed);
        self.in_guest_physical_sigsys.store(0, Ordering::Relaxed);
        self.fallback_completion_sigsys.store(0, Ordering::Relaxed);
        self.cacheline_straddler_fallback
            .store(0, Ordering::Relaxed);
        self.unpatchable_or_other_fallback
            .store(0, Ordering::Relaxed);
        self.fallback_refusal.store(0, Ordering::Relaxed);
    }
}

static GUEST_STATS: OnceLock<GuestStatsCollector> = OnceLock::new();

#[derive(Clone, Copy)]
pub(crate) struct GuestStatsHooks {
    collector: Option<&'static GuestStatsCollector>,
    record_path: fn(Option<&'static GuestStatsCollector>, LiteinstDispatchPath),
    reset_after_fork: fn(Option<&'static GuestStatsCollector>),
}

impl GuestStatsHooks {
    pub(crate) const DISABLED: Self = Self {
        collector: None,
        record_path: disabled_record_path,
        reset_after_fork: disabled_reset_after_fork,
    };

    fn enabled(collector: &'static GuestStatsCollector) -> Self {
        Self {
            collector: Some(collector),
            record_path: enabled_record_path,
            reset_after_fork: enabled_reset_after_fork,
        }
    }

    pub(crate) fn is_enabled(self) -> bool {
        self.collector.is_some()
    }

    pub(crate) fn record_path(self, path: LiteinstDispatchPath) {
        (self.record_path)(self.collector, path);
    }

    pub(crate) fn reset_after_fork(self) {
        (self.reset_after_fork)(self.collector);
    }

    pub(crate) fn submit(
        self,
        tid: Tid,
        direct_hooks: u64,
        sites: Vec<LiteinstProcessSiteStats>,
    ) -> io::Result<()> {
        let Some(stats) = self.collector else {
            return Ok(());
        };
        let paths = stats.snapshot(direct_hooks);
        let client = BlockingRpcClient::<LiteinstStatsGlobal>::connect(&stats.coordinator, tid)
            .map_err(|error| io::Error::other(error.to_string()))?;
        client
            .try_send_rpc(LiteinstProcessStats { paths, sites })
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn disabled_record_path(
    _collector: Option<&'static GuestStatsCollector>,
    _path: LiteinstDispatchPath,
) {
}

fn disabled_reset_after_fork(_collector: Option<&'static GuestStatsCollector>) {}

fn enabled_record_path(
    collector: Option<&'static GuestStatsCollector>,
    path: LiteinstDispatchPath,
) {
    #[cfg(test)]
    ENABLED_STATS_PROBES.fetch_add(1, Ordering::Relaxed);
    collector
        .expect("enabled stats dispatch requires a collector")
        .counter(path)
        .fetch_add(1, Ordering::Relaxed);
}

fn enabled_reset_after_fork(collector: Option<&'static GuestStatsCollector>) {
    #[cfg(test)]
    ENABLED_STATS_PROBES.fetch_add(1, Ordering::Relaxed);
    collector
        .expect("enabled stats dispatch requires a collector")
        .reset();
}

#[cfg(test)]
static ENABLED_STATS_PROBES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn initialize_guest_stats(coordinator: &Path) -> io::Result<GuestStatsHooks> {
    GUEST_STATS
        .set(GuestStatsCollector {
            coordinator: coordinator.to_path_buf(),
            in_guest_sigsys: AtomicU64::new(0),
            in_guest_nested_sigsys: AtomicU64::new(0),
            in_guest_physical_sigsys: AtomicU64::new(0),
            fallback_completion_sigsys: AtomicU64::new(0),
            cacheline_straddler_fallback: AtomicU64::new(0),
            unpatchable_or_other_fallback: AtomicU64::new(0),
            fallback_refusal: AtomicU64::new(0),
        })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "LiteInst statistics initialized twice",
            )
        })?;
    Ok(GuestStatsHooks::enabled(
        GUEST_STATS
            .get()
            .expect("collector was initialized immediately above"),
    ))
}

/// One process-local patch-site observation sent only after an enabled run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct LiteinstProcessSiteStats {
    pub(crate) rip: u64,
    pub(crate) patched: bool,
    pub(crate) instruction_length: u8,
    pub(crate) straddle_after: u8,
}

/// One process-local, post-Tool-exit statistics message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct LiteinstProcessStats {
    pub(crate) paths: CounterSnapshot<LiteinstDispatchPath>,
    pub(crate) sites: Vec<LiteinstProcessSiteStats>,
}

/// Coordinator-side typed RPC target for per-process LiteInst snapshots.
#[derive(Debug, Default)]
pub(crate) struct LiteinstStatsGlobal {
    aggregation: Mutex<LiteinstStatsAggregation>,
}

#[derive(Debug, Default)]
struct LiteinstStatsAggregation {
    next_process_identity: u64,
    processes: Vec<(u64, LiteinstProcessStats)>,
}

#[reverie::global_tool]
impl GlobalTool for LiteinstStatsGlobal {
    type Request = LiteinstProcessStats;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, message: Self::Request) {
        // The request-envelope TID and message body are both guest-controlled.
        // Assign an opaque identity here solely to keep equal virtual RIPs from
        // different reports distinct; this is not an authenticated OS identity.
        let mut aggregation = self.aggregation.lock().unwrap();
        aggregation.next_process_identity += 1;
        let identity = aggregation.next_process_identity;
        aggregation.processes.push((identity, message));
    }
}

impl LiteinstStatsGlobal {
    pub(crate) fn into_source(self) -> LiteinstBackendStatsSource {
        let processes = self.aggregation.into_inner().unwrap().processes;
        let mut shapes = PatchShapeCollector::default();
        let mut reported_processes = BTreeSet::new();
        let mut seen_sites = BTreeSet::new();
        let mut decisions = [0_u64; 4];
        let mut paths = Vec::new();

        for (process_identity, process) in processes {
            reported_processes.insert(process_identity);
            paths.extend(process.paths.counts().iter().copied());
            for site in process.sites {
                if !seen_sites.insert((process_identity, site.rip)) {
                    continue;
                }
                let shape = (site.instruction_length != 0).then(|| {
                    InstructionPatchShape::new(
                        site.instruction_length,
                        (site.straddle_after != 0).then_some(site.straddle_after),
                    )
                });
                if site.patched {
                    decisions[1] += 1;
                } else if site.straddle_after != 0 {
                    decisions[2] += 1;
                } else {
                    decisions[3] += 1;
                }
                shapes.record_process_site(process_identity, 0, site.rip, site.patched, shape);
            }
        }

        LiteinstBackendStatsSource {
            snapshot: LiteinstBackendStatsSnapshot {
                process_reports: reported_processes.len() as u64,
                patch_shapes: shapes.snapshot(),
                patch_decisions: CounterSnapshot::new([
                    (LiteinstPatchDecision::DirectPun, decisions[0]),
                    (LiteinstPatchDecision::Relocated, decisions[1]),
                    (LiteinstPatchDecision::StraddlerFallback, decisions[2]),
                    (LiteinstPatchDecision::OtherFallback, decisions[3]),
                ]),
                dispatch_paths: CounterSnapshot::new(paths),
            },
        }
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
                process_reports: 0,
                patch_shapes: shapes.snapshot(),
                patch_decisions: CounterSnapshot::new([(LiteinstPatchDecision::Relocated, 1)]),
                dispatch_paths: CounterSnapshot::new([
                    (LiteinstDispatchPath::FirstSiteSeccomp, 1),
                    (LiteinstDispatchPath::PtraceInstallation, 1),
                    (LiteinstDispatchPath::DirectHook, 9),
                ]),
            },
        };

        let rendered = source.snapshot().to_string();
        assert_eq!(rendered, source.snapshot().to_string());
        assert!(rendered.contains("distinct_rips_patched=1"));
        assert!(rendered.contains("paths[first_site_seccomp=1"));
        assert!(rendered.contains("direct_hook=9"));
        assert!(!rendered.contains("0x7fff"));
        assert!(!rendered.contains("pid="));
        assert!(!rendered.contains("time="));
    }

    #[tokio::test]
    async fn aggregates_equal_rips_from_distinct_fork_processes_and_exact_hits() {
        let global = LiteinstStatsGlobal::default();
        for direct_hooks in [7, 11] {
            global
                .receive_rpc(
                    Tid::from_raw(7),
                    LiteinstProcessStats {
                        paths: CounterSnapshot::new([
                            (LiteinstDispatchPath::InGuestSigsys, 1),
                            (LiteinstDispatchPath::InGuestNestedSigsys, 2),
                            (LiteinstDispatchPath::CachelineStraddlerFallback, 3),
                            (LiteinstDispatchPath::UnpatchableOrOtherFallback, 4),
                            (LiteinstDispatchPath::DirectHook, direct_hooks),
                            (LiteinstDispatchPath::FallbackRefusal, 5),
                        ]),
                        sites: vec![LiteinstProcessSiteStats {
                            rip: 0x4000,
                            patched: true,
                            instruction_length: 2,
                            straddle_after: 0,
                        }],
                    },
                )
                .await;
        }

        let source = global.into_source();
        assert_eq!(source.patch_candidates(), 2);
        assert_eq!(source.snapshot().process_reports(), 2);
        assert_eq!(source.distinct_rips(), 2);
        assert_eq!(source.decision_counts(), [0, 2, 0, 0]);
        let paths = source.dispatch_path_counts();
        assert_eq!(paths.count(&LiteinstDispatchPath::FirstSiteSeccomp), 0);
        assert_eq!(paths.count(&LiteinstDispatchPath::PtraceInstallation), 0);
        assert_eq!(paths.count(&LiteinstDispatchPath::InGuestSigsys), 2);
        assert_eq!(paths.count(&LiteinstDispatchPath::InGuestNestedSigsys), 4);
        assert_eq!(
            paths.count(&LiteinstDispatchPath::CachelineStraddlerFallback),
            6
        );
        assert_eq!(
            paths.count(&LiteinstDispatchPath::UnpatchableOrOtherFallback),
            8
        );
        assert_eq!(paths.count(&LiteinstDispatchPath::DirectHook), 18);
        assert_eq!(paths.count(&LiteinstDispatchPath::FallbackRefusal), 10);
        assert_eq!(paths.total(), 48);
        let rendered = source.to_string();
        assert!(rendered.contains("first_site_seccomp=0"), "{rendered}");
        assert!(rendered.contains("in_guest_sigsys=2"), "{rendered}");
        assert!(rendered.contains("in_guest_nested_sigsys=4"), "{rendered}");
        assert!(!rendered.contains("pid="), "{rendered}");
        assert!(!rendered.contains("0x4000"), "{rendered}");
    }

    #[test]
    fn dispatch_path_wire_identity_is_name_not_variant_position() {
        for path in LiteinstDispatchPath::ALL {
            let encoded_path =
                bincode::serde::encode_to_vec(path, bincode::config::legacy()).unwrap();
            let encoded_name =
                bincode::serde::encode_to_vec(path.as_str(), bincode::config::legacy()).unwrap();
            assert_eq!(encoded_path, encoded_name, "{path}");
        }
    }

    #[test]
    fn process_report_round_trips_named_dispatch_paths() {
        let report = LiteinstProcessStats {
            paths: CounterSnapshot::new([
                (LiteinstDispatchPath::InGuestSigsys, 2),
                (LiteinstDispatchPath::DirectHook, 8),
                (LiteinstDispatchPath::FallbackRefusal, 3),
            ]),
            sites: Vec::new(),
        };

        let bytes = bincode::serde::encode_to_vec(&report, bincode::config::legacy()).unwrap();
        let (decoded, consumed): (LiteinstProcessStats, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::legacy()).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, report);
        assert_eq!(decoded.paths.count(&LiteinstDispatchPath::InGuestSigsys), 2);
        assert_eq!(decoded.paths.count(&LiteinstDispatchPath::DirectHook), 8);
        assert_eq!(
            decoded.paths.count(&LiteinstDispatchPath::FallbackRefusal),
            3
        );
        assert_eq!(decoded.paths.total(), 13);
    }

    fn deserialize_dispatch_paths(
        entries: &[(LiteinstDispatchPath, u64)],
    ) -> CounterSnapshot<LiteinstDispatchPath> {
        #[derive(Serialize)]
        struct RawSnapshot<'a> {
            counts: &'a [(LiteinstDispatchPath, u64)],
        }

        let bytes = bincode::serde::encode_to_vec(
            RawSnapshot { counts: entries },
            bincode::config::legacy(),
        )
        .unwrap();
        let (snapshot, consumed): (CounterSnapshot<LiteinstDispatchPath>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::legacy()).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(snapshot.counts(), entries);
        snapshot
    }

    #[test]
    fn deserialized_dispatch_paths_count_out_of_order_entries() {
        let snapshot = deserialize_dispatch_paths(&[
            (LiteinstDispatchPath::DirectHook, 8),
            (LiteinstDispatchPath::InGuestSigsys, 2),
        ]);

        assert_eq!(snapshot.count(&LiteinstDispatchPath::DirectHook), 8);
        assert_eq!(snapshot.count(&LiteinstDispatchPath::InGuestSigsys), 2);
        assert_eq!(snapshot.total(), 10);
    }

    #[test]
    fn deserialized_dispatch_paths_sum_duplicates_like_constructor() {
        for entries in [
            [
                (LiteinstDispatchPath::InGuestSigsys, 2),
                (LiteinstDispatchPath::DirectHook, 3),
                (LiteinstDispatchPath::DirectHook, 5),
            ],
            [
                (LiteinstDispatchPath::DirectHook, 3),
                (LiteinstDispatchPath::InGuestSigsys, 2),
                (LiteinstDispatchPath::DirectHook, 5),
            ],
        ] {
            let snapshot = deserialize_dispatch_paths(&entries);
            let normalized = CounterSnapshot::new(entries);

            assert_eq!(snapshot.count(&LiteinstDispatchPath::DirectHook), 8);
            assert_eq!(snapshot.count(&LiteinstDispatchPath::InGuestSigsys), 2);
            assert_eq!(snapshot.total(), 10);
            for path in LiteinstDispatchPath::ALL {
                assert_eq!(snapshot.count(path), normalized.count(path), "{path}");
            }
        }
    }

    #[test]
    fn deserialized_dispatch_paths_return_zero_for_missing_keys() {
        let snapshot = deserialize_dispatch_paths(&[(LiteinstDispatchPath::DirectHook, 8)]);
        assert_eq!(snapshot.count(&LiteinstDispatchPath::InGuestSigsys), 0);
        assert_eq!(snapshot.count(&LiteinstDispatchPath::DirectHook), 8);

        let empty = deserialize_dispatch_paths(&[]);
        for path in LiteinstDispatchPath::ALL {
            assert_eq!(empty.count(path), 0, "{path}");
        }
        assert_eq!(empty.total(), 0);
    }

    #[test]
    fn disabled_hooks_do_not_enter_enabled_stats_code() {
        let probes = ENABLED_STATS_PROBES.load(Ordering::Relaxed);
        let hooks = GuestStatsHooks::DISABLED;

        hooks.record_path(LiteinstDispatchPath::InGuestSigsys);
        hooks.record_path(LiteinstDispatchPath::InGuestNestedSigsys);
        hooks.reset_after_fork();

        assert_eq!(ENABLED_STATS_PROBES.load(Ordering::Relaxed), probes);
    }
}
