/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run-scoped process signal publication and scheduler-selected delivery.
//!
//! These operations do not borrow a Guest, resume instructions, or run a Tool
//! hook. Installation is atomic and precedes the first guest callback.

use std::fmt::Debug;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use crate::CallbackSignalSite;
use crate::ExitStatus;
use crate::ProcessAlarmSignalDisposition;
use crate::SignalEvent;
use crate::SignalProcessId;
use crate::SignalTaskIdentity;
use crate::syscalls::Errno;

/// Whether the Tool takes responsibility for recipient selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendSignalControlMode {
    /// Preserve the backend's existing selection behavior.
    Unchanged,
    /// Publication and return-to-user selection use the installed control.
    ToolControlled,
}

/// An actual process-pending publication; it says nothing about recipient masks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessSignalPublication {
    /// Exact lifetime whose shared pending queue committed the operation.
    pub process: SignalProcessId,
    /// Disposition/pending generation, not a delivery counter.
    pub pending_generation: u64,
    /// Whether the first pending event already occupied this standard signal.
    pub coalesced: bool,
    /// Disposition observed at publication, before any Tool filtering.
    pub disposition: ProcessAlarmSignalDisposition,
}

/// Publication errors retain the boundary between no effect and committed effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessSignalPublicationResult {
    /// No pending state or readiness changed.
    RejectedBeforeCommit(Errno),
    /// Shared pending state and readiness committed.
    Committed(ProcessSignalPublication),
    /// The pending operation committed but readiness failed. Never retry it.
    FailedAfterCommit {
        /// Committed effect.
        receipt: ProcessSignalPublication,
        /// Original readiness failure.
        errno: Errno,
    },
}

/// A scheduler-authorized terminal child transition.
///
/// Both process identities include their run-local generations, so a reused
/// numeric PID cannot inherit this completion. Times are Linux clock ticks,
/// not nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChildExitCompletion {
    /// Exact parent process lifetime receiving SIGCHLD.
    pub parent: SignalProcessId,
    /// Exact terminal child process lifetime.
    pub child: SignalProcessId,
    /// Complete wait status, including signal and core-dump provenance.
    pub status: ExitStatus,
    /// Whether the terminal status remains consumable by a wait syscall.
    pub waitable: bool,
    /// Virtual child uid reported through siginfo.
    pub uid: u32,
    /// Child user CPU time in signed Linux clock ticks.
    pub user_ticks: i64,
    /// Child system CPU time in signed Linux clock ticks.
    pub system_ticks: i64,
}

/// Effect committed by one child-completion publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChildExitPublicationEffect {
    /// SIGCHLD entered the shared process-pending set.
    Queued,
    /// SIGCHLD was already pending and retained its first complete siginfo.
    Coalesced,
    /// An explicit `SIG_IGN` suppressed SIGCHLD generation.
    SuppressedExplicitIgnore,
    /// A later ignored-disposition transition discarded the generation in
    /// which this child event was authorized before delayed publication ran.
    DiscardedByDispositionChange,
}

/// Receipt for an irreversible child-completion publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChildExitPublication {
    /// Exact completion whose effect committed.
    pub completion: ChildExitCompletion,
    /// Disposition/pending generation at the operation.
    pub pending_generation: u64,
    /// Whether publication queued, coalesced, or explicitly suppressed SIGCHLD.
    pub effect: ChildExitPublicationEffect,
}

/// Complete result of publishing one scheduler-authorized child completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChildExitPublicationResult {
    /// No pending state or signalfd readiness changed.
    RejectedBeforeCommit(Errno),
    /// The receipt's effect committed.
    Committed(ChildExitPublication),
    /// The effect committed before readiness failed. Never retry it.
    FailedAfterCommit {
        /// Retained irreversible publication receipt.
        receipt: ChildExitPublication,
        /// Original readiness failure.
        errno: Errno,
    },
}

/// One eligible task in an authoritative, process-transaction snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalRecipient {
    /// Exact live task, independent of numeric TID reuse.
    pub task: SignalTaskIdentity,
}

/// Authorization for one task's actual return-to-user selection.
///
/// The backend registers this permit before the Tool releases its callback.
/// Copying the value does not create another registered permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalDeliveryPermit {
    /// Exact process/task lifetime.
    pub task: SignalTaskIdentity,
    /// Run-local scheduler choice identity.
    pub sequence: u64,
    /// Parked syscall callback, or an ordinary user-return boundary.
    pub site: Option<CallbackSignalSite>,
}

/// Actual completion of a permitted boundary, before guest entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalBoundaryOutcome {
    /// A caught handler's frame, registers and mask are committed.
    Caught,
    /// No handler was installed; no interrupted wait may be invented.
    NoHandler,
    /// A committed guest exit, before physical worker joins or consuming hooks.
    /// The permit supplies the exact process/task lifetime; an individual exit
    /// must never be interpreted as permission to retire its live peers.
    Terminated {
        /// True only for the committed process-wide exit.
        group: bool,
        /// Winner status from the backend lifecycle table, in wait(2) encoding.
        wait_status: i32,
    },
    /// Successful exec replaced the selected callback's old image.
    ImageReplaced,
    /// Consuming logical task retirement cancelled the callback before entry.
    Cancelled,
    /// The run is terminal; its original error retains any partial signal effects.
    Failed,
}

/// A consuming notification, not an ordinary scheduler resource request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalBoundaryReceipt {
    /// Registered permit consumed by the backend.
    pub permit: SignalDeliveryPermit,
    /// Actual boundary outcome.
    pub outcome: SignalBoundaryOutcome,
}

/// Shared run-owned facade. Implementations must not retain a Tool or Guest.
///
/// Calls are synchronous. Except for the explicitly named failure forwarding
/// method, they must not call GlobalTool. No method may block on a guest
/// callback, execute ordinary host IO, or drop retired descriptors while a
/// signal/file-table guard is held. The caller supplies the causal scheduler
/// fence; a snapshot by itself is not deterministic admission.
pub trait ProcessSignalControl: Debug + Send + Sync {
    /// Publish a complete SIGALRM/SI_KERNEL event to an exact process lifetime.
    fn publish_alarm(
        &self,
        process: SignalProcessId,
        event: SignalEvent,
    ) -> ProcessSignalPublicationResult;

    /// Publish one scheduler-authorized terminal child transition.
    ///
    /// The caller supplies the causal scheduler fence. A committed or
    /// failed-after-commit result must never be retried; backends may return the
    /// retained receipt idempotently if an exact duplicate nevertheless arrives.
    /// This publication makes waitability visible but does not reap the backend
    /// child status. A Tool that schedules a consuming wait must still execute
    /// that wait through [`crate::Guest::inject`] before retiring Tool shadow
    /// state; publication is not a substitute for the backend wait syscall.
    ///
    /// KVM may take its run-wide child-publication lock alone for an idempotent
    /// duplicate preflight. Its committing path then acquires the exact parent's
    /// process-signal transaction before the run-wide registry and signal-state
    /// locks. A caller that holds a Tool scheduler mutex to make admission
    /// atomic must preserve that nested order: Tool scheduler -> backend parent
    /// transaction -> backend registry and signal state. No reverse path may
    /// acquire the Tool mutex while retaining those backend locks.
    /// An implementation used from that scheduler reservation must not call
    /// back into Tool code or wait for the fenced parent wait or other guest
    /// progress before returning.
    fn publish_child_exit(&self, _completion: ChildExitCompletion) -> ChildExitPublicationResult {
        ChildExitPublicationResult::RejectedBeforeCommit(Errno::ENOSYS)
    }

    /// Eligible live recipients for one pending signal, in ascending numeric
    /// TID order. The caller intersects these with its causally admitted task
    /// generations.
    fn signal_recipients(
        &self,
        process: SignalProcessId,
        signal: i32,
    ) -> Result<Vec<SignalRecipient>, Errno>;

    /// Eligible live recipients, in ascending numeric TID order. The caller
    /// intersects these with its causally admitted task generations.
    fn alarm_recipients(&self, process: SignalProcessId) -> Result<Vec<SignalRecipient>, Errno> {
        self.signal_recipients(process, libc::SIGALRM)
    }

    /// Register one selected task. A second outstanding permit is not a retry.
    fn reserve_delivery(&self, permit: SignalDeliveryPermit) -> Result<(), Errno>;

    /// Settle a permit that did not remove a signal (for example, a masked
    /// pending set after an authorized Tool operation). Exact duplicate receipts
    /// are acknowledged, never interpreted as a second operation.
    fn release_delivery(&self, permit: SignalDeliveryPermit) -> Result<(), Errno>;

    /// Forward a retained publication failure to the run owner. This may call
    /// GlobalTool, so the caller MUST release its scheduler mutex first.
    fn finish_publication_failure(&self, process: SignalProcessId) -> Result<(), Errno>;

    /// Forward one exact retained child-publication failure to the run owner.
    ///
    /// The receipt prevents a caller from acknowledging a different terminal
    /// publication. This may call GlobalTool, so the caller MUST release its
    /// scheduler mutex first.
    fn finish_child_exit_publication_failure(
        &self,
        _receipt: ChildExitPublication,
    ) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}

/// The single run-level installation carries both publication and selection.
#[derive(Clone, Debug)]
pub struct BackendSignalControl {
    /// Run-local weak backend facade.
    pub process: Arc<dyn ProcessSignalControl>,
}
