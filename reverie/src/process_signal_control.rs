/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
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

/// The new parent of one child of an exiting process
/// ([`ProcessSignalControl::place_orphans`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OrphanReaper {
    /// A live process of this run, by exact lifetime: the child becomes its
    /// child, as when Linux's `find_new_reaper` picks a child subreaper.
    Process(SignalProcessId),
    /// The PID namespace's init, which the backend keeps outside the guest
    /// process tree. No guest process can wait for the child. Where the
    /// namespace init is the exited process itself, or the exit happens in a
    /// namespace whose init has exited, this is the only reaper accepted: the
    /// namespace is being torn down ([`ProcessSignalControl::place_orphans`]).
    NamespaceInit,
}

/// One placement in [`ProcessSignalControl::place_orphans`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrphanPlacement {
    /// Exact child lifetime of the exiting process.
    pub child: SignalProcessId,
    /// Its new parent.
    pub reaper: OrphanReaper,
}

/// What a placement did to one child.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PlacedOrphanEffect {
    /// A live child: its parent is now the reaper, for its waits, its later
    /// exit notification and `getppid`.
    Live,
    /// A child that had already exited (a zombie), now waitable by the reaper
    /// process. Its exit was announced to the reaper again with `SIGCHLD`, as
    /// Linux's `reparent_leader` does; the effect of that publication.
    Zombie(ChildExitPublicationEffect),
    /// A zombie the reaper process reaps at once: its `SIGCHLD` is ignored or
    /// carries `SA_NOCLDWAIT`.
    AutoReaped,
    /// A zombie that moved to the reaper process, whose announcement the
    /// backend could not publish. Only in
    /// [`OrphanPlacementResult::FailedAfterCommit`], which names the error.
    ZombieUnannounced,
    /// Adopted by the namespace init, live or exited. Where the namespace is
    /// being torn down (the exited process is its init, or exited after it),
    /// nothing moved: the child keeps its parent and goes with the teardown,
    /// and no guest process waits for it.
    NamespaceInit,
}

/// One child in an [`OrphanPlacementReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlacedOrphan {
    /// Exact child lifetime.
    pub child: SignalProcessId,
    /// Its new parent.
    pub reaper: OrphanReaper,
    /// What the placement did.
    pub effect: PlacedOrphanEffect,
}

/// Receipt for the placement of every child of one exited process.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrphanPlacementReceipt {
    /// Exact process lifetime whose exit left the children.
    pub exited: SignalProcessId,
    /// Each child, in the order of the placements, then any child the caller
    /// did not name (adopted by the namespace init), in ascending pid order.
    pub placed: Vec<PlacedOrphan>,
}

/// Placement never converts a partial commit into a retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OrphanPlacementResult {
    /// No child moved and nothing was published.
    RejectedBeforeCommit(Errno),
    /// Every child moved, and every announcement committed.
    Committed(OrphanPlacementReceipt),
    /// Every child moved, but a reaper's `SIGCHLD` readiness failed after its
    /// pending state committed. Never retry it.
    FailedAfterCommit {
        /// Committed effect.
        receipt: OrphanPlacementReceipt,
        /// Original readiness failure.
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

    /// Publish one expiration of a Tool-owned POSIX timer to an exact process
    /// lifetime: a complete process-directed event for a standard signal
    /// (1 to 31, never SIGKILL or SIGSTOP) whose siginfo has `si_code`
    /// `SI_TIMER`, as Linux queues a `SIGEV_SIGNAL` timer's signal.
    ///
    /// The caller owns the timer, its deadline and the ordering of the
    /// expiration; the backend only publishes the pending signal, with the
    /// same shared pending ownership, standard-signal coalescing and
    /// disposition handling as [`Self::publish_alarm`]. No Tool hook, guest
    /// instruction, timer operation or wait completion is performed.
    /// Backends without a controlled signal queue keep the default `ENOSYS`.
    // TODO-HUMAN-REVIEW(PR-1019): Review the timer-expiry publication API.
    fn publish_timer_expiry(
        &self,
        _process: SignalProcessId,
        _event: SignalEvent,
    ) -> ProcessSignalPublicationResult {
        ProcessSignalPublicationResult::RejectedBeforeCommit(Errno::ENOSYS)
    }

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

    /// Opt into orphan placement before starting any guest task: from then
    /// on, a process's exit leaves its children waiting for
    /// [`Self::place_orphans`] rather than giving them to the namespace init
    /// at once. A Tool that opts in promises to place the children of every
    /// process exit it observes, before releasing the fence of that exit.
    /// The backend keeps the new parents in its own records, which its waits,
    /// child-exit notifications and `getppid` read; it never chooses one.
    fn enable_orphan_placement(&self) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Give each child of `exited` its new parent, as Linux's
    /// `forget_original_parent` does in `exit_notify`, with the parents the
    /// caller chose (for example, the nearest child subreaper).
    ///
    /// Every child named must be one the exit of `exited` left waiting for a
    /// parent; a child the caller does not name goes to the namespace init.
    /// A live child's waits, later exit notification and `getppid` then name
    /// its reaper. A child that had already exited becomes the reaper's
    /// zombie: the backend announces it with `SIGCHLD` (the child's siginfo),
    /// or reaps it at once if the reaper's `SIGCHLD` is ignored or carries
    /// `SA_NOCLDWAIT`, both decided from the reaper's disposition at this
    /// call, as Linux's `do_notify_parent` decides them. A reaper must be a
    /// live process of the run.
    ///
    /// Where the exited process is itself its PID namespace's init, or exits
    /// in a namespace whose init has already exited, Linux tears the
    /// namespace down (`zap_pid_ns_processes`) and the dying init reaps every
    /// orphan: any [`OrphanReaper::Process`] is refused (`EINVAL`), and each
    /// child, named or not, is placed with [`OrphanReaper::NamespaceInit`] as
    /// a no-op ([`PlacedOrphanEffect::NamespaceInit`]: nothing moves, nothing
    /// is announced, and no child exit needs to have been claimed first).
    ///
    /// The backend must already have recorded the exit (a backend records it
    /// before it reports the exit's terminal boundary); before that the call
    /// changes nothing and answers `EAGAIN`. Nothing moves unless every
    /// placement is valid (`EINVAL` otherwise, and `ESRCH` for a reaper that
    /// is gone). An exact duplicate returns the retained result. Like every
    /// method here it is synchronous, takes the backend's locks after the
    /// caller's, and calls no Tool code; the caller supplies the causal fence
    /// (the exit's own).
    fn place_orphans(
        &self,
        _exited: SignalProcessId,
        _placements: &[OrphanPlacement],
    ) -> OrphanPlacementResult {
        OrphanPlacementResult::RejectedBeforeCommit(Errno::ENOSYS)
    }

    /// Publish one parent-death signal the Tool decided to an exact process
    /// lifetime: a complete process-directed event for a signal the backend
    /// declares it publishes
    /// ([`BackendCapabilities::publishable_parent_death_signals`](crate::BackendCapabilities::publishable_parent_death_signals);
    /// it rejects any other before commit, `EINVAL`), whose siginfo has
    /// `si_code` `SI_USER`, as Linux's `group_send_sig_info` builds it for the
    /// exiting parent thread (its tgid in `si_pid`, its real uid in
    /// `si_uid`).
    ///
    /// The caller owns the parent-death registrations, decides when a parent
    /// thread exits and orders the sends; the backend only publishes the
    /// pending signal, with the same shared pending ownership,
    /// standard-signal coalescing and disposition handling as
    /// [`Self::publish_timer_expiry`]. `SIGKILL` is published the same way:
    /// it cannot be caught, blocked or ignored, so it ends the process at the
    /// first delivery boundary of any of its threads. No Tool hook, guest
    /// instruction or wait completion is performed. Backends without a
    /// controlled signal queue keep the default `ENOSYS`.
    fn publish_parent_death_signal(
        &self,
        _process: SignalProcessId,
        _event: SignalEvent,
    ) -> ProcessSignalPublicationResult {
        ProcessSignalPublicationResult::RejectedBeforeCommit(Errno::ENOSYS)
    }

    /// Opt into a guest's signals to other processes before starting any
    /// guest task.
    ///
    /// A backend that keeps its own signal queues refuses, by default, a
    /// guest `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`,
    /// `rt_tgsigqueueinfo` or `pidfd_send_signal` that names another
    /// process, and a process-directed signal to the guest's own process
    /// while that process has another thread. Either needs a thread other than the sender to take the
    /// signal, and only a Tool that selects recipients can order that.
    ///
    /// After this call, in [`BackendSignalControlMode::ToolControlled`]
    /// mode, the backend performs such a send as Linux's `do_send_sig_info`
    /// does, but chooses no thread and wakes none: it queues the signal on
    /// the target process's shared queue, or on the named thread's own
    /// queue, keeping a standard signal's first siginfo. A thread of the
    /// target takes it at a boundary the Tool authorizes
    /// ([`Self::reserve_delivery`]) or in a parked observation.
    ///
    /// The Tool, which forwards the guest's call, decides which sends to
    /// forward, and orders each one against the target's exit and exec, as
    /// it orders the publications here. The backend refuses by name, before
    /// any effect, a send that the target's exit or exec overlapped, and may
    /// keep refusing by name a send it cannot perform.
    ///
    /// `EBUSY` once installation has closed. In
    /// [`BackendSignalControlMode::Unchanged`] mode the call has no effect.
    /// Backends that keep no signal queues of their own keep the default
    /// `ENOSYS`.
    fn enable_cross_process_signals(&self) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
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

    /// Returns the signal sets of `task`, a live task of this run in any of
    /// its processes: what is pending for the task and for its process, its
    /// mask, and its process's ignored and caught signals, as Linux shows them
    /// in the task's `/proc/<pid>/task/<tid>/status` (`SigPnd`, `ShdPnd`,
    /// `SigBlk`, `SigIgn` and `SigCgt`); see [`crate::SignalSets`].
    ///
    /// This is [`crate::Guest::signal_sets`] for code that holds no `Guest`,
    /// such as a global tool. A backend that provides both answers from the
    /// same state, so the two agree for the same task at the same moment, and
    /// they differ from Linux in the same ways, which the backend documents.
    /// Only this method can answer `EAGAIN`, for a read that an exec of the
    /// task's process overlaps (below).
    ///
    /// It only reports state. It dequeues no signal, changes no mask, action
    /// or pending set, records nothing, and calls no Tool code. Like every
    /// method here it is synchronous and takes the backend's signal locks
    /// after any lock the caller holds (see [`Self::publish_child_exit`] for
    /// that order); no backend path may wait for a caller's lock while holding
    /// those.
    ///
    /// `task` names an exact task lifetime, so a task that later received the
    /// same numeric TID is not the task it names.
    /// `Err(FactError::Errno(ESRCH))` means that it names no live task of this
    /// run: an exited task, a reused TID with another generation, or a
    /// lifetime the backend never had. An exec never makes a live task read as
    /// gone: `Err(FactError::Errno(EAGAIN))` means that the task's process
    /// replaced its image while the sets were read, and asking again reads the
    /// new image. `Err(FactError::NotProvided)` is the default, for a backend
    /// that does not report this fact.
    ///
    /// The answer describes the moment of the call. Any task can change
    /// another's sets by signalling it, and any task of the process can change
    /// its actions, so a caller that needs a stable answer asks while the task,
    /// and every task that could do either, cannot run. Three changes need no
    /// task to run guest code, and such a caller rules them out as well:
    ///
    /// - a task that holds a delivery permit ([`Self::reserve_delivery`]) may
    ///   take its signal at any moment, which dequeues it and installs the
    ///   handler's mask;
    /// - a backend may retire an exiting task after the Tool has handled its
    ///   exit, so an answer of `Ok` can become `ESRCH` for a task whose exit
    ///   the caller has already seen;
    /// - an exec of the task's process makes a call that overlaps it wait for
    ///   the exec and then answer `EAGAIN`.
    fn signal_sets(
        &self,
        _task: SignalTaskIdentity,
    ) -> Result<crate::SignalSets, crate::FactError> {
        Err(crate::FactError::NotProvided)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A control that implements only the required methods, as a backend that
    /// keeps no readable signal state would.
    #[derive(Debug)]
    struct RequiredOnly;

    impl ProcessSignalControl for RequiredOnly {
        fn publish_alarm(
            &self,
            _process: SignalProcessId,
            _event: SignalEvent,
        ) -> ProcessSignalPublicationResult {
            ProcessSignalPublicationResult::RejectedBeforeCommit(Errno::ENOSYS)
        }

        fn signal_recipients(
            &self,
            _process: SignalProcessId,
            _signal: i32,
        ) -> Result<Vec<SignalRecipient>, Errno> {
            Ok(Vec::new())
        }

        fn reserve_delivery(&self, _permit: SignalDeliveryPermit) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        fn release_delivery(&self, _permit: SignalDeliveryPermit) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        fn finish_publication_failure(&self, _process: SignalProcessId) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
    }

    /// The default is the fact's "not provided", never an answer, and never
    /// an errno that would read as a statement about the task.
    #[test]
    fn a_control_that_reports_nothing_does_not_provide_signal_sets() {
        let task = SignalTaskIdentity {
            process: SignalProcessId {
                tgid: crate::Pid::from_raw(1),
                generation: 1,
            },
            tid: crate::Pid::from_raw(1),
            task_generation: 1,
        };
        let control: Arc<dyn ProcessSignalControl> = Arc::new(RequiredOnly);
        assert_eq!(
            control.signal_sets(task),
            Err(crate::FactError::NotProvided)
        );
    }
}
