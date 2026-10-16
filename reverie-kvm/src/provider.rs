/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Linux syscall provider under `Guest::inject`: [`LinuxProvider`], the
//! provider-neutral core, and the LinuxEmu-specific extensions
//! [`LinuxEmuSignalControl`] and [`LinuxEmuMemoryMap`] that today's executor
//! still needs.
//!
//! This is step 2 of the minimal provider seam
//! (<https://github.com/rrnewton/hermit/issues/4485>, epic
//! <https://github.com/rrnewton/hermit/issues/4492>), after the memory
//! interfaces of [`crate::provider_memory`]. The KVM backend's injection
//! adapter (`GuestSyscallExecutor` in `runtime.rs`) used to be one 38-method
//! trait mixing three different things. It is now split by meaning:
//!
//! - [`LinuxProvider`]: what any kernel that executes Linux syscalls for a
//!   guest can answer, whether it is today's emulator, the host kernel, or a
//!   foreign user-space kernel. `KvmGuest::inject` (and `tail_inject`, which
//!   injects through it) executes the syscall only through this trait.
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
//! All three traits are crate-private; nothing in Reverie's public `Tool`,
//! `Guest` or backend contract changes.
//!
//! # Rules every provider is held to
//!
//! - **One provider per run.** The provider owns the run's Linux state: the
//!   file-descriptor table, the memory map and the task table. Calls are never
//!   routed per syscall to different providers, because that would split this
//!   state. The backend may reach the provider through a short-lived handle per
//!   guest callback, which is why the methods take `&mut self`; the handle is
//!   only a view of the one provider.
//! - **Concurrency.** [`LinuxProvider::execute`] runs on the issuing task's
//!   host thread. The provider must not assume that no other task executes
//!   at the same time. Calls are serialised only under a Tool that
//!   sequentialises guest threads, and only while the issuing task holds its
//!   scheduler turn; even then, a call the Tool classifies as external
//!   blocking (a blocking read, `rt_sigsuspend`) is injected in the
//!   background, off the run queue, and overlaps other tasks' turns and
//!   their `execute` calls. A Tool that does not sequentialise injects from
//!   every task's own thread concurrently, and threads the backend runs
//!   outside the Tool execute at any time. Provider state shared between
//!   tasks is therefore protected against concurrent guest tasks, Tool-owned
//!   tasks and host-owned workers alike, with a lock order the implementation
//!   documents. A provider may block the host thread, as a blocking read or a
//!   futex wait does, but must not hold backend admission across the block.
//! - **Error model.** A Linux error is an ordinary result: `-errno`. A broken
//!   backend or provider invariant is an `Err` that ends the run and is never
//!   encoded as an errno. A request the provider does not implement is
//!   answered with the errno Linux gives for a missing feature (normally
//!   `ENOSYS`) and records a typed refusal, which the backend reads through
//!   [`LinuxProvider::take_unsupported_refusal`] and reports loudly; the
//!   errno alone is not the report. This is the contract providers are held
//!   to; an implementation that does not yet meet it documents its
//!   deviation on its impl.
//! - **Determinism.** A result is a deterministic function of the provider's
//!   state, the request, the guest memory it reads and host-file contents.
//!   The provider must not read host time, host randomness or other
//!   host-varying state to produce a guest-visible value, and must not invent
//!   or sanitise values for determinism: time, randomness, credentials,
//!   `/proc` content and pid numbering belong to the Tool (Detcore). If a
//!   provider needs a fixed value to be faithful, such as its own pid
//!   numbering, the Tool supplies it through configuration.

use reverie::SignalEvent;
use reverie::syscalls::Errno;

use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::SyscallRequest;
use crate::executor::PendingSignal;

/// What one executed syscall produced.
///
/// Effects are already committed to the provider's state when the outcome is
/// returned.
///
/// Only [`ProviderOutcome::Return`] exists so far. The remaining outcomes (a
/// segment-base effect for `arch_prctl(ARCH_SET_FS/GS)`, a child created by
/// `fork`/`vfork`/`clone`/`clone3`, an exec, and an exit) are added in a later
/// step; until then an implementation reports them to its backend outside this
/// trait, after `execute` returns `Return` with the call's raw result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderOutcome {
    /// The raw Linux result: a nonnegative value, or `-errno` for a Linux
    /// error.
    Return(i64),
}

/// Executes Linux syscalls on behalf of guest tasks: the provider-neutral core
/// of the kernel under `Guest::inject`.
///
/// See the module documentation for the rules every method is held to (one
/// provider per run, concurrency, the error model and the determinism
/// obligations). This trait is not generic over the Tool: creating Tool state
/// for a new child is backend work.
pub(crate) trait LinuxProvider: Send + Sync {
    /// Executes `request` as the issuing task and returns its outcome.
    ///
    /// The request's arguments are guest values, exactly as the guest or the
    /// Tool issued them: guest addresses and guest file descriptors. `memory`
    /// is the issuing task's guest memory, through which the provider reads
    /// and writes the call's guest operands.
    ///
    /// Called only from the backend's injection path, after the backend's own
    /// admission checks, on the issuing task's host thread (see the module
    /// documentation's concurrency rule for what may run at the same time).
    ///
    /// - `Ok(ProviderOutcome::Return(-errno))` is a Linux error and is
    ///   returned to the Tool as that errno.
    /// - `Err` is a broken invariant that ends the run; the backend must not
    ///   turn it into a guest-visible errno. Until [`ProviderOutcome`] carries
    ///   exits and interruptions, two errors are dispositions rather than
    ///   failures: [`Error::ChildWaitGroupExit`] reports a thread-group exit
    ///   the provider already committed, and [`Error::TerminalReadCancelled`]
    ///   reports a blocking read that was cancelled and must produce no
    ///   syscall result.
    /// - A request the provider does not implement is answered as the module
    ///   documentation's error model says, with a typed refusal recorded for
    ///   [`LinuxProvider::take_unsupported_refusal`].
    fn execute(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Result<ProviderOutcome>;

    /// Takes the typed refusal recorded by the last [`LinuxProvider::execute`],
    /// when the provider declined that request as an operation it does not
    /// implement, and clears it.
    ///
    /// The backend reads it immediately after a successful `execute`, so a
    /// refusal always describes the request that produced it; a provider
    /// discards any refusal left by an earlier syscall when `execute` begins.
    /// Under the error model, `None` means the request was implemented,
    /// whatever its result. The refusal exists so that unsupported behaviour
    /// is reported loudly instead of passing as a plausible Linux errno.
    fn take_unsupported_refusal(&mut self) -> Option<reverie::UnsupportedRefusal> {
        None
    }
}

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
