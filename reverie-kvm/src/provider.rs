/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Linux syscall provider under `Guest::inject`, as reverie-kvm uses it:
//! the provider-neutral core [`LinuxProvider`] (with [`ProviderOutcome`]),
//! defined with its rules in Reverie's core as `reverie::provider`, and the
//! LinuxEmu-specific extensions [`LinuxEmuSignalControl`] and
//! [`LinuxEmuMemoryMap`] that today's executor still needs.
//!
//! The split is step 2 of the minimal provider seam
//! (<https://github.com/rrnewton/hermit/issues/4485>, epic
//! <https://github.com/rrnewton/hermit/issues/4492>); step U6a moved the core
//! to its own crate, and step E1 moved it into Reverie's core. The KVM
//! backend's injection adapter (`GuestSyscallExecutor` in `runtime.rs`) used
//! to be one 38-method trait mixing three different things. It is now split
//! by meaning:
//!
//! - [`LinuxProvider`]: what any kernel that executes Linux syscalls for a
//!   guest can answer, whether it is today's emulator, the host kernel, or a
//!   foreign user-space kernel. `KvmGuest::inject` (and `tail_inject`, which
//!   injects through it) executes the syscall only through this trait, with
//!   the provider's memory and error types fixed to [`GuestMemory`] and
//!   [`Error`].
//! - [`LinuxEmuSignalControl`] and [`LinuxEmuMemoryMap`]: the signal parking
//!   and receipt protocol and the brk-heap query of today's executor. They
//!   name the executor's own ledgers and tokens, so another provider could only
//!   refuse them. Every method has a refusing default, which is exactly what
//!   the pass-through `DirectSyscallExecutor` has always answered.
//! - Backend mechanics (the vCPU clock, CPUID interception, the run's failure
//!   subscription, the adapter's signal guard, the two injection admission
//!   checks, the traced-parent query behind `Guest::ppid`, and the completion
//!   of process actions) stay on the backend's `GuestSyscallExecutor` and are
//!   on no provider trait.
//!
//! The two extension traits are crate-private; nothing in Reverie's public
//! `Tool`, `Guest` or backend contract changes. The rules every provider is
//! held to (one provider per run, concurrency, the error model and the
//! determinism obligations) are stated on the `reverie::provider` module.

use reverie::SignalEvent;
pub(crate) use reverie::provider::LinuxProvider;
pub(crate) use reverie::provider::ProviderOutcome;
pub(crate) use reverie::provider::SyscallRequest as ProviderRequest;
use reverie::syscalls::Errno;

use crate::Error;
#[cfg(doc)]
use crate::GuestMemory;
use crate::Result;
use crate::executor::PendingSignal;

/// The signal parking and receipt protocol of today's executor (LinuxEmu).
///
/// These methods name the executor's own signal ledgers, callback sites,
/// leases and tokens; another provider (the host kernel, or a foreign kernel
/// that owns its own signal model) could only refuse them. They are kept apart
/// from [`LinuxProvider`] so that this protocol does not become the provider
/// contract. The expected end state is that the Tool owns signal policy and
/// the backend only pushes signal frames, which deletes most of this trait.
///
/// Every method has a refusing or empty default: `ENOSYS`, `None`, `false`,
/// or no effect. Those defaults are what a provider without this protocol
/// answers, and what the pass-through `DirectSyscallExecutor` has always
/// answered.
///
/// Four methods back `Guest` methods that nothing in Hermit calls:
/// [`LinuxEmuSignalControl::queue_child_exit_signal`],
/// [`LinuxEmuSignalControl::queue_process_alarm_signal`],
/// [`LinuxEmuSignalControl::captured_write_signal_site`] and
/// [`LinuxEmuSignalControl::parent_death_syscall_preflight`]. They are kept
/// here unchanged, because deleting the `Guest` methods changes Reverie's
/// public API.
///
/// Four further methods state provider-neutral intents but are kept here
/// until they can be generalised safely:
/// [`LinuxEmuSignalControl::defer_signal_delivery`] (make a signal pending),
/// [`LinuxEmuSignalControl::signal_task_identity`] (task identity),
/// [`LinuxEmuSignalControl::take_signal_for_observation`] (the next
/// deliverable signal) and [`LinuxEmuSignalControl::signal_disposition`].
pub(crate) trait LinuxEmuSignalControl: Send + Sync {
    /// Reserves signal-effect ledger capacity before an injected syscall
    /// executes. Refusal is a terminal backend failure, never a syscall errno.
    fn prepare_signal_effects(&mut self) -> std::result::Result<(), Errno> {
        Ok(())
    }

    /// Makes a Tool-chosen signal pending for delivery at the current
    /// resumable boundary. Refused with `ENOSYS` where there is no such
    /// boundary or during a dequeue notification.
    fn defer_signal_delivery(&mut self, _event: SignalEvent) -> std::result::Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Queues a child-exit signal through the executor's process-control
    /// primitive. Backs a `Guest` method with no Hermit caller.
    fn queue_child_exit_signal(&mut self, _event: SignalEvent) -> reverie::ChildExitSignalOutcome {
        reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ChildExitSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }

    /// Queues a process alarm signal through the executor's process-control
    /// primitive. Backs a `Guest` method with no Hermit caller.
    fn queue_process_alarm_signal(
        &mut self,
        _event: SignalEvent,
    ) -> reverie::ProcessAlarmSignalOutcome {
        reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }

    /// Whether the run installed Tool-controlled process signal control.
    fn signal_controlled(&self) -> bool {
        false
    }

    /// Records that a parked signal delivery finished.
    fn finish_parked_delivery(&mut self) {}

    /// The signal-control identity of the issuing task.
    fn signal_task_identity(&self) -> Option<reverie::SignalTaskIdentity> {
        None
    }

    /// Begins (or continues) a callback signal site for a new guest callback.
    fn begin_signal_callback(&mut self) -> Option<reverie::CallbackSignalSite> {
        None
    }

    /// The parked-signal site of the current callback, if it may park.
    fn parked_signal_site(&self) -> Option<reverie::CallbackSignalSite> {
        None
    }

    /// Forgets the retained request/result pair of the last polled read.
    fn invalidate_polled_read_attempt(&mut self) {}

    /// The parked site admitted for an original read that returned `EAGAIN`.
    fn polled_read_signal_site(
        &self,
        _call: reverie::syscalls::Read,
    ) -> Option<reverie::CallbackSignalSite> {
        None
    }

    /// The parked site admitted for a captured write. Backs a `Guest` method
    /// with no Hermit caller.
    fn captured_write_signal_site(
        &self,
        _call: reverie::syscalls::Write,
    ) -> Option<reverie::CallbackSignalSite> {
        None
    }

    /// Admits an original call under parent-death-signal enrollment. Backs a
    /// `Guest` method with no Hermit caller.
    fn parent_death_syscall_preflight(
        &self,
        _call: reverie::syscalls::Syscall,
    ) -> std::result::Result<reverie::ParentDeathSyscallAdmission, reverie::Error> {
        Err(Errno::ENOSYS.into())
    }

    /// Admits a parked-signal observation lease at `site`.
    fn admit_signal_observation(
        &mut self,
        _site: reverie::CallbackSignalSite,
        _lease: reverie::ParkedObservationLease,
    ) -> std::result::Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Whether a parked failure context still names the current callback.
    fn signal_failure_context_is_current(
        &self,
        _context: reverie::ParkedSignalFailureContext,
    ) -> bool {
        false
    }

    /// The first unacknowledged signal dequeue in the executor's ledger.
    fn signal_dequeue_front(&self) -> Option<reverie::SignalDequeue> {
        None
    }

    /// Polls for the next signal dequeue in the executor's ledger.
    fn poll_signal_dequeue(
        &self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<reverie::SignalDequeue>>> {
        std::task::Poll::Ready(Ok(self.signal_dequeue_front()))
    }

    /// Acknowledges a signal dequeue after the Tool was notified of it.
    fn acknowledge_signal_dequeue(
        &mut self,
        _effect: reverie::SignalDequeue,
    ) -> std::result::Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Retains a dequeue's operands across a cancelled notification.
    fn retain_signal_dequeue(&mut self, _effect: reverie::SignalDequeue) {}

    /// Retains the raw syscall result that accompanies pending dequeues.
    fn retain_signal_effect_result(&mut self, _raw: Option<i64>) {}

    /// The parked failure context of the current callback.
    fn signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
        None
    }

    /// Decorates a run failure with the executor's retained signal effects.
    fn with_signal_effects(&mut self, error: Error, _raw: Option<i64>) -> Error {
        error
    }

    /// Removes the next deliverable pending signal for a parked observation.
    fn take_signal_for_observation(&mut self) -> std::result::Result<Option<PendingSignal>, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Prepares a filtered replacement for a pending signal in `domain`.
    fn filter_signal_replacement(
        &mut self,
        _event: SignalEvent,
        _domain: crate::executor::PendingSignalDomain,
    ) -> std::result::Result<Option<PendingSignal>, Errno> {
        Err(Errno::ENOSYS)
    }

    /// The executor's current disposition of `signal`.
    fn signal_disposition(&self, _signal: i32) -> crate::executor::SignalDisposition {
        crate::executor::SignalDisposition::Terminate
    }

    /// Reserves delivery of an observed signal and returns its token.
    fn reserve_signal_delivery(
        &mut self,
        _pending: PendingSignal,
        _id: reverie::DequeueId,
        _fatal: bool,
    ) -> std::result::Result<reverie::PreparedSignalToken, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Whether a prepared signal token is a fatal delivery at the current
    /// callback.
    fn prepared_signal_is_fatal(&self, _token: reverie::PreparedSignalToken) -> bool {
        false
    }
}

/// The brk-heap query of today's executor (LinuxEmu).
///
/// Kept off [`LinuxProvider`] until it is generalised into a query of every
/// guest memory region, which a provider with a full memory map (or the host
/// kernel) could answer.
pub(crate) trait LinuxEmuMemoryMap: Send + Sync {
    /// The brk-managed heap region `[heap_base, program_break)` of the guest,
    /// when this executor backs a loaded static ELF. `None` for executors that
    /// do not model a heap (e.g. the direct pass-through executor). Used to
    /// report the guest heap region for deterministic memory-map logging.
    fn heap_region(&self) -> Option<(u64, u64)> {
        None
    }
}
