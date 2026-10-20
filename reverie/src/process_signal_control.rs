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

/// One retained parent-thread-death effect in a process shared-pending queue.
/// The sender and signal were frozen by the backend's logical death transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParentDeathSignalPublication {
    /// Exact receiving process generation.
    pub process: SignalProcessId,
    /// Linux standard signal selected by the registering guest task.
    pub signal: i32,
    /// Generation frozen when its real parent died.
    pub pending_generation: u64,
    /// The first standard event was retained instead of replaced.
    pub coalesced: bool,
    /// A disposition change, explicit ignore, or dead receiver discarded it.
    pub discarded: bool,
}

/// At-most-once acknowledgement for a real terminal or image boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParentDeathPublication {
    /// Exact scheduler permit and actual backend outcome authorizing publication.
    pub boundary: SignalBoundaryReceipt,
    /// Backend-generated batch identities, never supplied as send authority.
    pub batches: Vec<u64>,
    /// Effects in stable registered-task order, for existing wake selection.
    pub signals: Vec<ParentDeathSignalPublication>,
}

/// Parent-death publication never converts a partial commit into a retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ParentDeathPublicationResult {
    /// No batch was consumed and no signal effect occurred.
    RejectedBeforeCommit(Errno),
    /// Every retained effect was accounted for, including empty batches.
    Committed(ParentDeathPublication),
    /// Effects are retained; the run must become terminal after releasing locks.
    FailedAfterCommit {
        /// Exact effects already committed before the failure.
        receipt: ParentDeathPublication,
        /// Original failure, not a fabricated guest errno.
        errno: Errno,
    },
}

/// Immediate result of an original-callback parent-death preflight with no
/// guest-visible effects (retained-image exec may stage private callback state).
/// Neither result is a reusable permit for a later or rewritten syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentDeathSyscallAdmission {
    /// This exact live task/process generation has not entered the restricted
    /// delivery domain. This conveys no descriptor or I/O authority.
    Unenrolled,
    /// The enrolled original callback and raw operands are supported now.
    /// Actual backend injection still independently checks its own boundary.
    Admitted,
}

/// Shared run-owned facade. Implementations must not retain a Tool or Guest.
///
/// Calls are synchronous. Except for the explicitly named failure forwarding
/// method, they must not call GlobalTool. No method may block on a guest
/// callback, execute ordinary host IO, or drop retired descriptors while a
/// signal/file-table guard is held. The caller supplies the causal scheduler
/// fence; a snapshot by itself is not deterministic admission.
pub trait ProcessSignalControl: Debug + Send + Sync {
    /// Opt into the parent-thread-death protocol before starting any guest task.
    ///
    /// A controlled Tool promises to consume each real terminal/image batch
    /// before releasing its existing fence, and to admit recipient waits/mask
    /// transitions only in its supported delivery domain. This is distinct from
    /// merely selecting ordinary process signals. Older consumers remain refused
    /// by nonzero PR_SET_PDEATHSIG rather than silently losing future delivery.
    fn enable_parent_death_control(&self) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Sticky process-generation delivery domain: a nonzero setting has been
    /// admitted, even if a later SET(0) or exec reset clears that setting. A
    /// retained/pending death may still need delivery. Consumers check this
    /// before parking, and must refuse unsupported blocking capability there.
    fn parent_death_enrolled(&self, _process: SignalProcessId) -> Result<bool, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Publish only the backend-retained batch of this exact owned boundary.
    /// No caller supplies signal numbers, recipients or fabricated exit events.
    /// Call after validating the existing fence and before releasing it. This
    /// method cannot call Tool code or retain a sender transaction while taking
    /// a receiver transaction. Exact duplicate calls return the retained result.
    fn publish_parent_death(
        &self,
        _boundary: SignalBoundaryReceipt,
    ) -> ParentDeathPublicationResult {
        ParentDeathPublicationResult::RejectedBeforeCommit(Errno::ENOSYS)
    }

    /// Forward the retained partial failure only after the scheduler unlocks.
    fn finish_parent_death_failure(&self, _receipt: &ParentDeathPublication) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

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
