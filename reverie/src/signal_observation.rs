/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Identities and results for observing real pending-signal removals.

use serde::Deserialize;
use serde::Serialize;

use crate::Pid;
use crate::SignalEvent;
use crate::syscalls::Errno;

/// A process lifetime, independent of PID reuse and disposition generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalProcessId {
    /// Thread-group ID.
    pub tgid: Pid,
    /// Backend process-lifetime generation.
    pub generation: u64,
}

/// A live task identity, available before its first guest instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalTaskIdentity {
    /// Process lifetime.
    pub process: SignalProcessId,
    /// Task ID.
    pub tid: Pid,
    /// Backend task-lifetime generation.
    pub task_generation: u64,
}

/// Exact callback and unconsumed syscall boundary eligible for parked observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallbackSignalSite {
    /// Process lifetime.
    pub process: SignalProcessId,
    /// Task ID.
    pub tid: Pid,
    /// Backend task-lifetime generation.
    pub task_generation: u64,
    /// Monotonic callback identity within this task executor; the full site binds its lifetime.
    pub callback_nonce: u64,
    /// Backend identity of the saved syscall continuation.
    pub boundary_nonce: u64,
}

/// The pending queue actually selected, preserved through Tool replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PendingDomain {
    /// Thread-private pending set.
    Thread,
    /// Process-shared pending set.
    Process,
}

/// The operation that actually removed a pending event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalConsumer {
    /// Selection at a return-to-user boundary.
    ReturnToUser,
    /// A signalfd read, including a read that subsequently fails.
    SignalFd,
    /// rt_sigtimedwait, including a subsequent siginfo copyout failure.
    SignalTimedWait,
}

/// Identity allocated once at removal, never at publication or delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DequeueId {
    /// Process lifetime that owned the selected pending queue.
    pub process: SignalProcessId,
    /// Contiguous process-local removal sequence, starting at one.
    pub sequence: u64,
}

/// An irreversible pending-state removal with its original complete metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignalDequeue {
    /// Process lifetime.
    pub process: SignalProcessId,
    /// Contiguous removal sequence.
    pub sequence: u64,
    /// Actual consumer.
    pub consumer: SignalConsumer,
    /// Actual pending queue, independent of replacement signal provenance.
    pub domain: PendingDomain,
    /// Complete event removed from that queue.
    pub event: SignalEvent,
}

impl SignalDequeue {
    /// Returns the immutable removal identity.
    pub const fn id(self) -> DequeueId {
        DequeueId {
            process: self.process,
            sequence: self.sequence,
        }
    }
}

/// Scheduler-issued identity echoed by RPCs during one nested observation.
///
/// Possession is not a backend capability; the backend independently validates
/// the current callback, task, saved boundary and observation depth.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParkedObservationLease {
    /// Unique scheduler observation nonce; one admitted use per callback.
    /// Reusing a completed nonce is refused before removal. Fresh nonces need
    /// not be numerically increasing.
    pub nonce: u64,
}

/// Backend-owned single-use selected event, awaiting frame/default-action delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedSignalToken {
    /// Complete callback, task and process lifetime owning this reservation.
    pub site: CallbackSignalSite,
    /// Unique backend selection identity.
    pub selection_nonce: u64,
}

/// Committed selection outcomes, in their real dequeue order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalObservationStep {
    /// Current disposition ignores the selected event.
    Ignored {
        /// Actual removal.
        dequeue: DequeueId,
    },
    /// The Tool suppressed the selected event.
    Suppressed {
        /// Actual removal.
        dequeue: DequeueId,
    },
    /// The Tool replacement was requeued in its original domain.
    Reblocked {
        /// Actual removal.
        dequeue: DequeueId,
        /// Original queue ownership.
        domain: PendingDomain,
    },
    /// One caught event was reserved for the existing frame path.
    Caught {
        /// Actual removal.
        dequeue: DequeueId,
    },
    /// One fatal event was reserved for the existing default action.
    Fatal {
        /// Actual removal.
        dequeue: DequeueId,
    },
}

/// Why a sequential parked observation finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalObservationStop {
    /// Real pending sets currently contain no eligible signal.
    NoEligibleSignal,
    /// The original syscall must compute its real interruption result.
    /// Selection reserves the event and caught disposition, not a built frame.
    /// Returning posthook mask/altstack injections remain supported: the actual
    /// frame uses that current state, and the selected event is not requeued by
    /// a later mask change. Frame entry then applies the action mask/flags; return
    /// restores the mask and stack saved in the frame. The selected disposition
    /// cannot be changed before this reservation is consumed.
    Caught(PreparedSignalToken),
    /// The driver must apply the reserved real default action.
    Fatal(PreparedSignalToken),
}

/// Actual observation effects; this does not settle any scheduler wait.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParkedSignalObservation {
    /// Ordered dispositions of the actual removals.
    pub steps: Vec<SignalObservationStep>,
    /// Final eligibility/selection outcome.
    pub stop: SignalObservationStop,
}

/// Distinguishes refusal from a failure after irreversible removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalObservationFailure {
    /// No event was removed by this attempted operation.
    RejectedBeforeRemoval {
        /// Original errno.
        errno: Errno,
    },
    /// This removal remains committed and cannot be retried as a refusal.
    FailedAfterRemoval {
        /// Last committed removal.
        dequeue: DequeueId,
        /// Original errno.
        errno: Errno,
    },
    /// Terminal cancellation retains any committed effects in the backend ledger.
    CancelledAfterEffects {
        /// Last committed removal, if any.
        last_dequeue: Option<DequeueId>,
    },
}

/// Identifies a retained effect ledger through caught handoff and cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParkedSignalFailureContext {
    /// Complete original callback, task and process lifetime owning the ledger.
    pub site: CallbackSignalSite,
    /// Backend ledger identity.
    pub ledger_nonce: u64,
}
