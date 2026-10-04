/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-of-run statistics for the KVM backend.
//!
//! Every backend that belongs to one guest process tree shares one collector.
//! Fork and `CLONE_THREAD` children therefore contribute to the same commutative
//! counters as the root. The caller takes the snapshot after the run loop has
//! joined those children, so the snapshot represents the completed tree rather
//! than whichever backend instance happened to survive.

use std::fmt;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::VcpuExit;
use reverie::BackendStatsSnapshot;
use reverie::CounterSnapshot;

/// A stable, coarse category for a KVM `VcpuExit`.
///
/// Every unmodelled exit collapses into [`KvmExitReason::Other`], so the mapping
/// remains total when `kvm-ioctls` adds variants. Declaration order is the
/// stable presentation order used by [`CounterSnapshot`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum KvmExitReason {
    /// A `VMCALL`/`VMMCALL` hypercall, including Reverie's syscall transport.
    Hypercall,
    /// A `HLT`, including process/thread parking.
    Hlt,
    /// A port I/O access (`IN`/`OUT`).
    Io,
    /// A memory-mapped I/O access.
    Mmio,
    /// A guest debug event.
    Debug,
    /// An interrupt window opened for pending interrupt delivery.
    IrqWindowOpen,
    /// The guest requested shutdown.
    Shutdown,
    /// `KVM_RUN` failed to enter the guest.
    FailEntry,
    /// The kernel reported an internal error.
    InternalError,
    /// A system event surfaced to userspace.
    SystemEvent,
    /// The run was interrupted by a signal delivered to the vCPU thread.
    Intr,
    /// Any other exit reason.
    Other,
}

impl KvmExitReason {
    const ALL: [Self; 12] = [
        Self::Hypercall,
        Self::Hlt,
        Self::Io,
        Self::Mmio,
        Self::Debug,
        Self::IrqWindowOpen,
        Self::Shutdown,
        Self::FailEntry,
        Self::InternalError,
        Self::SystemEvent,
        Self::Intr,
        Self::Other,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for KvmExitReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Hypercall => "hypercall",
            Self::Hlt => "hlt",
            Self::Io => "io",
            Self::Mmio => "mmio",
            Self::Debug => "debug",
            Self::IrqWindowOpen => "irq_window_open",
            Self::Shutdown => "shutdown",
            Self::FailEntry => "fail_entry",
            Self::InternalError => "internal_error",
            Self::SystemEvent => "system_event",
            Self::Intr => "intr",
            Self::Other => "other",
        })
    }
}

impl From<&VcpuExit<'_>> for KvmExitReason {
    fn from(exit: &VcpuExit<'_>) -> Self {
        match exit {
            VcpuExit::Hypercall(_) => Self::Hypercall,
            VcpuExit::Hlt => Self::Hlt,
            VcpuExit::IoIn(..) | VcpuExit::IoOut(..) => Self::Io,
            VcpuExit::MmioRead(..) | VcpuExit::MmioWrite(..) => Self::Mmio,
            VcpuExit::Debug(_) => Self::Debug,
            VcpuExit::IrqWindowOpen => Self::IrqWindowOpen,
            VcpuExit::Shutdown => Self::Shutdown,
            VcpuExit::FailEntry(..) => Self::FailEntry,
            VcpuExit::InternalError => Self::InternalError,
            VcpuExit::SystemEvent(..) => Self::SystemEvent,
            VcpuExit::Intr => Self::Intr,
            _ => Self::Other,
        }
    }
}

/// Shared process-tree vCPU-exit counters.
///
/// Relaxed increments are sufficient because each counter is commutative and
/// the KVM lifecycle joins every child worker before an end-of-run snapshot is
/// consumed. Disabled runs do not allocate this collector at all.
pub(crate) struct KvmExitCollector {
    counts: [AtomicU64; KvmExitReason::ALL.len()],
}

impl Default for KvmExitCollector {
    fn default() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl KvmExitCollector {
    pub(crate) fn record(&self, exit: &VcpuExit<'_>) {
        self.counts[KvmExitReason::from(exit).index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> KvmBackendStats {
        KvmBackendStats {
            exits: CounterSnapshot::new(KvmExitReason::ALL.into_iter().filter_map(|reason| {
                let count = self.counts[reason.index()].load(Ordering::Relaxed);
                (count != 0).then_some((reason, count))
            })),
        }
    }
}

/// A stable snapshot of all KVM vCPU exits in one completed guest process tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvmBackendStats {
    exits: CounterSnapshot<KvmExitReason>,
}

impl Default for KvmBackendStats {
    fn default() -> Self {
        Self {
            exits: CounterSnapshot::new([]),
        }
    }
}

impl KvmBackendStats {
    /// Returns deterministically ordered per-reason exit counts.
    pub const fn exits(&self) -> &CounterSnapshot<KvmExitReason> {
        &self.exits
    }

    /// Returns the total number of recorded vCPU exits in the process tree.
    pub fn total_exits(&self) -> u64 {
        self.exits.total()
    }

    /// Returns the recorded process-tree count for one exit reason.
    pub fn count(&self, reason: KvmExitReason) -> u64 {
        self.exits
            .counts()
            .iter()
            .find(|(candidate, _)| *candidate == reason)
            .map_or(0, |(_, count)| *count)
    }
}

impl fmt::Display for KvmBackendStats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "kvm backend: {} process-tree vCPU exit(s)",
            self.exits.total()
        )?;
        for (reason, count) in self.exits.counts() {
            write!(formatter, "\n  {reason}: {count}")?;
        }
        Ok(())
    }
}

impl BackendStatsSnapshot for KvmBackendStats {
    const BACKEND_NAME: &'static str = "kvm";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_counts_and_orders_exit_reasons() {
        let collector = KvmExitCollector::default();
        collector.record(&VcpuExit::Hlt);
        collector.record(&VcpuExit::IrqWindowOpen);
        collector.record(&VcpuExit::Hlt);
        collector.record(&VcpuExit::Intr);

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.total_exits(), 4);
        assert_eq!(snapshot.count(KvmExitReason::Hlt), 2);
        assert_eq!(snapshot.count(KvmExitReason::IrqWindowOpen), 1);
        assert_eq!(snapshot.count(KvmExitReason::Intr), 1);
        assert_eq!(snapshot.count(KvmExitReason::Hypercall), 0);
        assert_eq!(
            snapshot
                .exits()
                .counts()
                .iter()
                .map(|(reason, _)| *reason)
                .collect::<Vec<_>>(),
            vec![
                KvmExitReason::Hlt,
                KvmExitReason::IrqWindowOpen,
                KvmExitReason::Intr,
            ]
        );
    }

    #[test]
    fn empty_snapshot_has_kvm_identity() {
        assert_eq!(KvmBackendStats::BACKEND_NAME, "kvm");
        assert_eq!(KvmBackendStats::default().total_exits(), 0);
    }
}
