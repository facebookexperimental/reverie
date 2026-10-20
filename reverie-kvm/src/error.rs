/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Arc;

use thiserror::Error;

/// Errors produced by the KVM backend prototype.
#[derive(Debug, Error)]
pub enum Error {
    /// Native retirement failed without proving guest terminal completion.
    #[error("KVM terminal file retirement {operation} failed (errno {errno})")]
    TerminalFileRetirement {
        /// Failed host/protocol operation.
        operation: &'static str,
        /// Original errno, or EPROTO for a malformed private frame.
        errno: i32,
    },

    /// A parent-thread-death operation cannot be represented or published.
    /// This is terminal backend capability/failure, never a guest errno.
    #[error("KVM parent-thread-death {operation} failed (errno {errno})")]
    ParentDeathSignal {
        /// Exact failed capability or publication operation.
        operation: &'static str,
        /// Original Linux-style failure, retained without collapsing precision.
        errno: i32,
    },

    /// Admission or retirement of guest execution could not be completed.
    #[error("KVM entry control failed during {operation}: {source}")]
    EntryControl {
        /// Host operation whose failure made admission terminal.
        operation: &'static str,
        /// Original host error, including its errno where one exists.
        #[source]
        source: std::io::Error,
    },
    /// A process-pending operation committed before readiness failed.
    #[error("process signal publication committed {receipt:?}, then failed: {errno}")]
    ProcessSignalPublication {
        /// Irreversible publication identity.
        receipt: reverie::ProcessSignalPublication,
        /// Original carrier error.
        errno: reverie::syscalls::Errno,
    },
    /// A child-completion operation committed before readiness failed.
    #[error("child-exit publication committed {receipt:?}, then failed: {errno}")]
    ChildExitPublication {
        /// Exact irreversible child-completion receipt.
        receipt: reverie::ChildExitPublication,
        /// Original carrier error.
        errno: reverie::syscalls::Errno,
    },
    /// A peer or the Tool scheduler has made this run terminal. This internal
    /// outcome is never a successful guest status or a syscall errno.
    #[error("KVM execution stopped after a fatal run failure")]
    RunAborted,

    /// An inherited-stdin read was physically retired after an already
    /// committed thread/group cancellation. This private disposition must be
    /// consumed before producing a syscall result or resuming a Tool callback.
    #[error("inherited stdin read retired after terminal cancellation")]
    TerminalReadCancelled,

    /// The consumer cannot yet release its scheduler turn safely around this
    /// external zero-count read. This is a terminal backend refusal, never a
    /// successful read or a Linux syscall errno.
    #[error(
        "unsupported KVM zero-count read on guest fd {fd}: potentially blocking external endpoint requires consumer scheduling support"
    )]
    PotentiallyBlockingZeroRead {
        /// The guest's low-word descriptor, including inherited stdin aliases.
        fd: i32,
    },

    /// A process-family wait observed its caller's already committed group
    /// exit. This private dispatch control must be consumed nonreturningly by
    /// Direct/Tool drivers before failure publication or any syscall result.
    #[error("child wait retired by committed group exit {status:?}")]
    ChildWaitGroupExit {
        /// Winner validated against the caller's exact live task generation.
        status: reverie::ExitStatus,
    },

    /// A native reader control operation failed. This is never a guest errno.
    /// An unjoined reader retains its endpoint and storage until process exit.
    #[error(
        "inherited stdin reader {operation} failed: {source} (terminal exit: {terminal_exit:?})"
    )]
    TerminalReadControl {
        /// Public pthread operation or ownership invariant that failed.
        operation: &'static str,
        /// Original host error.
        #[source]
        source: std::io::Error,
        /// First group exit, if it preceded the control failure.
        terminal_exit: Option<reverie::ExitStatus>,
    },

    /// A process exited while it still owned a logical child whose Linux
    /// reaper is the traced root acting as PID-namespace init. Orphans of an
    /// outside namespace init are reparented; transferring wait ownership into
    /// an in-tree init's executor is deliberately fail-closed.
    #[error(
        "KVM process {process:?} exited with child {child:?} still requiring unsupported reparenting"
    )]
    DescendantReparentingUnsupported {
        /// Exiting process generation.
        process: reverie::SignalProcessId,
        /// Direct child generation that still needs a reaper.
        child: reverie::SignalProcessId,
    },

    /// A child reached its terminal boundary after its exact parent generation
    /// disappeared without recording a family transition. This is distinct
    /// from unsupported reparenting: no child can be named as its own parent.
    #[error(
        "KVM process {process:?} cannot complete because parent generation {parent:?} lost its family transition"
    )]
    ParentGenerationUnavailable {
        /// Exiting child process generation.
        process: reverie::SignalProcessId,
        /// Exact parent generation that disappeared.
        parent: reverie::SignalProcessId,
    },

    /// A live parent and child lost their exact registered family edge before
    /// the child's terminal transition. This is an internal ledger invariant,
    /// not reparenting or a stale parent lifetime.
    #[error(
        "KVM process {process:?} cannot complete because its relation to live parent {parent:?} disappeared"
    )]
    ParentChildRelationUnavailable {
        /// Exiting child process generation.
        process: reverie::SignalProcessId,
        /// Exact live parent generation whose edge disappeared.
        parent: reverie::SignalProcessId,
    },

    /// A Tool-controlled backend wait removed a numeric child for which the
    /// exact-generation process-family ledger had no waitable zombie.
    #[error(
        "KVM parent {parent:?} reaped numeric child {child_pid} without a waitable exact family entry"
    )]
    FamilyWaitLedgerMismatch {
        /// Exact parent generation that executed the wait.
        parent: reverie::SignalProcessId,
        /// Numeric PID actually removed by the backend wait implementation.
        child_pid: i32,
    },

    /// A previous backend wait left its irreversible family-ledger effect
    /// pending when another syscall tried to begin.
    #[error(
        "KVM parent {parent:?} began another syscall with child {child_pid}'s wait-ledger effect pending"
    )]
    ChildWaitLedgerEffectPending {
        /// Exact parent generation that owns the pending effect.
        parent: reverie::SignalProcessId,
        /// Numeric PID removed by the originating backend wait.
        child_pid: i32,
    },

    /// Corrupt exact-generation family edges formed an ancestry cycle.
    #[error(
        "KVM process {process:?} cannot complete because family ancestry cycles at {ancestor:?}"
    )]
    ProcessFamilyAncestryCycle {
        /// Process whose terminal transition discovered the corruption.
        process: reverie::SignalProcessId,
        /// Revisited exact generation.
        ancestor: reverie::SignalProcessId,
    },

    /// One exact process generation appeared under two family parents.
    #[error(
        "KVM process {process:?} cannot complete because child {child:?} has family parents {first_parent:?} and {second_parent:?}"
    )]
    ProcessFamilyMultipleParents {
        /// Process whose terminal transition discovered the corruption.
        process: reverie::SignalProcessId,
        /// Exact generation with ambiguous ancestry.
        child: reverie::SignalProcessId,
        /// First exact parent in deterministic key order.
        first_parent: reverie::SignalProcessId,
        /// Second exact parent in deterministic key order.
        second_parent: reverie::SignalProcessId,
    },

    /// Terminal failure with irreversible pending-state effects retained intact.
    #[error("{cause}; committed signal effects: {} removals, {} publication receipts", dequeues.len(), publications.len())]
    SignalEffects {
        /// Original failure, never replaced by a cancellation fiction.
        #[source]
        cause: Arc<Error>,
        /// Complete actual removals, including an unacknowledged prefix.
        dequeues: Vec<reverie::SignalDequeue>,
        /// Process-wide contiguous acknowledgment watermark captured in this
        /// retained ledger; it can include another owner's acknowledgment.
        acknowledged_through: u64,
        /// Actual typed publication outcomes, including post-publication failure.
        publications: Vec<reverie::ProcessAlarmSignalOutcome>,
        /// Original injected syscall result, including an errno after removal.
        raw_result: Option<i64>,
        /// Original callback ledger, retained after the handler future is dropped.
        context: Option<Box<reverie::ParkedSignalFailureContext>>,
    },

    /// A guest worker panicked. Caught paths publish this before physical join;
    /// the ordinary join fallback also uses this cause for an unreported panic.
    #[error("guest thread panicked during teardown")]
    GuestWorkerPanic,

    /// A shared typed failure retained until the root has joined all children.
    #[error("{0}")]
    SharedFailure(#[source] std::sync::Arc<Error>),

    /// A typed worker failure with its original guest thread identity.
    #[error("unexpected vCPU exit: KVM worker cleanup failed: thread {tid}: {error}")]
    WorkerFailure {
        /// Guest thread whose physical join returned this failure.
        tid: i32,
        /// Original typed cause retained by the worker-error cache.
        #[source]
        error: std::sync::Arc<Error>,
    },

    /// Cleanup failed in addition to the original execution failure.
    #[error("{primary}; {}", cleanup.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    WithCleanup {
        /// Original typed cause, also exposed through the source chain.
        #[source]
        primary: Arc<Error>,
        /// Additional failures, without replacing the original cause.
        cleanup: Vec<Arc<Error>>,
    },

    /// A typed cleanup cause with the operation that failed.
    #[error("{phase}: {error}")]
    Cleanup {
        /// Cleanup operation.
        phase: &'static str,
        /// Original typed cleanup error.
        #[source]
        error: Arc<Error>,
    },

    /// A guest branch counter is unavailable or its accounting cannot be trusted.
    #[error("guest clock failed: {0}")]
    GuestClock(String),

    /// Reusing a completed initial ELF requires resetting pending KVM transport state.
    #[error("initial ELF reinstallation after execution is unsupported; create a fresh KvmBackend")]
    InitialElfReinstallationUnsupported,

    /// A public run on this backend was dropped before it finished. Its guest
    /// threads are cancelled, and its children handed to a reaper, only when
    /// the backend drops, so the backend admits no further run or image.
    #[error("a dropped KVM run has not been retired; create a fresh KvmBackend")]
    AbandonedRunNotRetired,

    /// A host filesystem operation failed while preparing the guest.
    #[error("host filesystem operation failed: {0}")]
    HostIo(#[from] std::io::Error),

    /// A post-exec tool hook rejected the new guest image.
    #[error("Reverie post-exec hook failed: {0}")]
    PostExec(reverie::syscalls::Errno),

    /// A shared Reverie tool callback failed.
    #[error("Reverie tool failed: {0}")]
    Reverie(#[source] reverie::Error),

    /// A KVM ioctl or vCPU operation failed.
    #[error("KVM operation failed: {0}")]
    Kvm(#[from] kvm_ioctls::Error),

    /// The guest-memory mapping could not be created.
    #[error("failed to allocate guest memory: {0}")]
    MemoryMapping(#[source] std::io::Error),

    /// A writable syscall alias could not be physically retired. This is a
    /// terminal backend failure, never a guest errno. A process-lifetime ledger
    /// owns the exact refused range and its backing until host process exit;
    /// repeated independent failed VMs can accumulate retained resources.
    #[error(
        "writable alias munmap at {address:#x} for {length} bytes failed: {source} (ownership retained until process exit; record {retention_id:#x})"
    )]
    WriteAliasCleanup {
        /// Original munmap error, including its errno.
        #[source]
        source: std::io::Error,
        /// Start of the confirmed-owned range whose cleanup was refused.
        address: usize,
        /// Length of that range in bytes.
        length: usize,
        /// Stable identity of the process-lifetime ownership record.
        retention_id: usize,
    },

    /// An ordinary shared-file history requires an unsupported backend capability.
    /// This is terminal, not a Linux syscall errno or fabricated guest SIGBUS.
    #[error("unsupported KVM shared-file operation {operation}: {reason}")]
    SharedFileCapability {
        /// Operation refused before its unsupported memory effect.
        operation: &'static str,
        /// Exact capability boundary, independent of host timing retries.
        reason: &'static str,
    },

    /// A fault-contained copy involving mutable ordinary-file backing stopped.
    /// The recorded prefix is real and is never rolled back or reported as a
    /// complete copy; source preserves the actual host errno on a failed call.
    #[error(
        "shared-file {operation} at {address:#x} copied {transferred}/{requested} bytes after {prior_transferred} earlier vector bytes: {source}"
    )]
    SharedFileCopy {
        /// Copy direction or initialization operation.
        operation: &'static str,
        /// First guest address of the complete requested copy.
        address: u64,
        /// Complete requested byte count.
        requested: usize,
        /// Actual prefix transferred, including earlier stable chunks.
        transferred: usize,
        /// Bytes completed by preceding vector elements, independent of this segment.
        prior_transferred: usize,
        /// Kernel error, or an explicit short-copy diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// Live backing replacement requires KVM to observe host mmap changes.
    #[error("KVM does not support synchronous host memory-map updates")]
    SynchronousMmuUnsupported,

    /// A prepared page was paired with a close token from another mapping.
    #[error("KVM mapping publication used an unrelated entry gate")]
    MappingPublicationGateMismatch,

    /// The ELF image could not be parsed.
    #[error("failed to parse ELF image: {0}")]
    ElfParse(#[from] goblin::error::Error),

    /// This host cannot run guests with Reverie's canonical process image.
    #[error("unsupported host: {0}")]
    UnsupportedHost(String),

    /// The ELF image cannot run in the minimal KVM process personality.
    #[error("unsupported ELF image: {0}")]
    UnsupportedElf(String),

    /// Guest memory must be non-empty and page aligned.
    #[error("invalid guest memory layout: base={guest_base:#x}, size={size:#x}")]
    InvalidMemoryLayout {
        /// First guest-physical address in the mapping.
        guest_base: u64,
        /// Mapping size in bytes.
        size: usize,
    },

    /// Linux process identifiers must be positive.
    #[error("invalid KVM root guest PID {0}")]
    InvalidGuestPid(i32),

    /// A guest-memory access fell outside the registered mapping.
    #[error(
        "guest memory access is out of bounds: address={address:#x}, length={length:#x}, mapping={guest_base:#x}..{guest_end:#x}"
    )]
    InvalidGuestAddress {
        /// First byte requested by the caller.
        address: u64,
        /// Requested number of bytes.
        length: usize,
        /// First guest-physical address in the mapping.
        guest_base: u64,
        /// Address immediately after the mapping.
        guest_end: u64,
    },

    /// A host-side user copy crossed an unmapped or `PROT_NONE` guest page.
    // TODO-HUMAN-REVIEW(PR-132): Review the guest user-access error API.
    #[error("guest user memory access is denied: address={address:#x}, length={length:#x}")]
    GuestMemoryAccessDenied {
        /// First byte requested by the caller.
        address: u64,
        /// Requested number of bytes.
        length: usize,
    },

    /// The transport frame named a number outside the architecture syscall table.
    #[error("invalid x86-64 syscall number {0}")]
    InvalidSyscallNumber(u64),

    /// Syscall frames must use addresses accepted by KVM's hypercall ABI.
    #[error("invalid syscall frame address {0:#x}")]
    InvalidSyscallFrameAddress(u64),

    /// The host kernel cannot forward the selected hypercall to userspace.
    #[error("KVM userspace hypercall exits are not supported")]
    HypercallExitUnsupported,

    /// The virtual CPU exposes neither the Intel nor AMD hypercall instruction.
    #[error("the virtual CPU exposes neither vmcall nor vmmcall")]
    HypercallInstructionUnsupported,

    /// The host cannot execute every instruction advertised by the fixed CPU profile.
    // TODO-HUMAN-REVIEW(PR-129): Review fail-closed CPUID capability validation.
    #[error("host cannot support deterministic CPUID profile: {0}")]
    UnsupportedCpuidProfile(String),

    /// The guest used a hypercall number other than the syscall transport.
    #[error("unexpected guest hypercall number {0}")]
    UnexpectedHypercall(u64),

    /// The bounded bootstrap area cannot allocate another thread transport.
    // TODO-HUMAN-REVIEW(PR-172): Review the fixed KVM guest-thread limit.
    #[error("KVM guest thread limit exceeded by tid {0}")]
    GuestThreadLimitExceeded(i32),

    /// Full-owner dequeue observation cannot cover deliberately uninstrumented workers.
    #[error("KVM signal dequeue observation requires Tool-owned threads")]
    SignalObservationRequiresToolThreads,

    /// Host metadata timestamps would reach the guest without a Tool to
    /// rewrite them: the run has no Tool, or its threads are host-owned.
    #[error("KVM host metadata timestamps require a Tool that owns every guest thread")]
    HostMetadataTimestampsRequireToolThreads,

    /// Replacing the process image from a guest thread is not implemented.
    #[error("KVM guest threads cannot replace the process image")]
    GuestThreadExecUnsupported,

    /// Exec cancelled its siblings, but one of their consuming hooks failed.
    /// The Tool owner must finish consuming its own state before returning this
    /// error; no old or replacement guest continuation remains available.
    #[error(transparent)]
    ExecWorkerTeardown(Box<Error>),

    /// The fixed long-mode bootstrap layout does not fit in guest memory.
    #[error("guest memory is too small for the long-mode bootstrap")]
    LongModeMemoryTooSmall,

    /// No static ELF has been installed on this backend.
    #[error("no static ELF is installed")]
    StaticElfNotInstalled,

    /// KVM accepted only part of the long-mode MSR table.
    #[error("KVM installed {actual} of {expected} long-mode MSRs")]
    IncompleteMsrSetup {
        /// Number of MSRs supplied.
        expected: usize,
        /// Number of MSRs accepted.
        actual: usize,
    },

    /// The guest raised an x86 exception while running a loaded ELF image.
    #[error("guest exception vector {vector} at {instruction_pointer:#x} (CR2={fault_address:#x})")]
    GuestException {
        /// Architectural exception vector.
        vector: u8,
        /// Guest instruction pointer saved by the exception frame.
        instruction_pointer: u64,
        /// Guest CR2 value, meaningful for page faults.
        fault_address: u64,
    },

    /// The vCPU stopped for an event this prototype does not handle.
    #[error("unexpected vCPU exit: {0}")]
    UnexpectedVcpuExit(String),
}

impl Error {
    /// Original typed cause beneath shared ownership and cleanup aggregation.
    pub fn primary(&self) -> &Self {
        match self {
            Self::SignalEffects { cause: error, .. }
            | Self::SharedFailure(error)
            | Self::WorkerFailure { error, .. }
            | Self::WithCleanup { primary: error, .. }
            | Self::Cleanup { error, .. } => error.primary(),
            Self::ExecWorkerTeardown(error) => error.primary(),
            _ => self,
        }
    }

    pub(crate) fn retains_primary(&self, primary: &std::sync::Arc<Error>) -> bool {
        match self {
            Self::SignalEffects { cause: error, .. }
            | Self::SharedFailure(error)
            | Self::WorkerFailure { error, .. }
            | Self::WithCleanup { primary: error, .. }
            | Self::Cleanup { error, .. } => {
                std::sync::Arc::ptr_eq(error, primary) || error.retains_primary(primary)
            }
            Self::ExecWorkerTeardown(error) => error.retains_primary(primary),
            _ => false,
        }
    }

    /// Identity of the primary worker cause, never a secondary cleanup error.
    pub(crate) fn worker_tid(&self) -> Option<i32> {
        match self {
            Self::WorkerFailure { tid, .. } => Some(*tid),
            Self::SignalEffects { cause: error, .. }
            | Self::SharedFailure(error)
            | Self::WithCleanup { primary: error, .. }
            | Self::Cleanup { error, .. } => error.worker_tid(),
            Self::ExecWorkerTeardown(error) => error.worker_tid(),
            _ => None,
        }
    }

    pub(crate) fn cleanup(self, phase: &'static str) -> Self {
        Self::Cleanup {
            phase,
            error: Arc::new(self),
        }
    }

    pub(crate) fn with_cleanup(self, cleanup: Vec<Error>) -> Self {
        if cleanup.is_empty() {
            self
        } else {
            Self::WithCleanup {
                primary: Arc::new(self),
                cleanup: cleanup.into_iter().map(Arc::new).collect(),
            }
        }
    }

    pub(crate) fn combine(mut errors: Vec<Error>) -> crate::Result<()> {
        if errors.is_empty() {
            Ok(())
        } else {
            let primary = errors.remove(0);
            Err(primary.with_cleanup(errors))
        }
    }

    /// Compose the final result after all publishers and owned joins returned.
    /// The first published Arc is authoritative. Shared aggregate children stay
    /// shared, so separating a cancellation marker cannot discard a real hook
    /// error or clone a non-Clone host error into a different cause.
    pub(crate) fn complete_after_failure(self, first: Arc<Error>, first_tid: i32) -> Self {
        assert!(!matches!(first.primary(), Error::RunAborted));
        #[derive(Clone)]
        enum Context {
            Worker(i32),
            Cleanup(&'static str),
            Exec,
        }
        struct Cause {
            error: Arc<Error>,
            context: Vec<Context>,
        }
        impl Cause {
            fn into_error(self) -> Error {
                self.context.into_iter().rev().fold(
                    Error::SharedFailure(self.error),
                    |error, context| match context {
                        Context::Worker(tid) => Error::WorkerFailure {
                            tid,
                            error: Arc::new(error),
                        },
                        Context::Cleanup(phase) => error.cleanup(phase),
                        Context::Exec => Error::ExecWorkerTeardown(Box::new(error)),
                    },
                )
            }
            fn worker_tid(&self) -> Option<i32> {
                self.context
                    .iter()
                    .find_map(|context| match context {
                        Context::Worker(tid) => Some(*tid),
                        _ => None,
                    })
                    .or_else(|| self.error.worker_tid())
            }
        }
        fn split(
            error: Arc<Error>,
            first: &Arc<Error>,
            context: &mut Vec<Context>,
            causes: &mut Vec<Cause>,
        ) {
            if Arc::ptr_eq(&error, first) || !split_aggregate(&error, first, context, causes) {
                causes.push(Cause {
                    error,
                    context: context.clone(),
                });
            }
        }
        // Return false for an opaque cause. Exec's existing boxed API remains
        // intact: its wrapper is reproduced only when the child is an aggregate
        // or shared reference; otherwise the original complete Arc is retained.
        fn split_aggregate(
            error: &Error,
            first: &Arc<Error>,
            context: &mut Vec<Context>,
            causes: &mut Vec<Cause>,
        ) -> bool {
            match error {
                Error::RunAborted => {}
                Error::SharedFailure(error) => split(error.clone(), first, context, causes),
                Error::WithCleanup { primary, cleanup } => {
                    split(primary.clone(), first, context, causes);
                    for error in cleanup {
                        split(error.clone(), first, context, causes);
                    }
                }
                Error::WorkerFailure { tid, error } => {
                    context.push(Context::Worker(*tid));
                    split(error.clone(), first, context, causes);
                    context.pop();
                }
                Error::Cleanup { phase, error } => {
                    context.push(Context::Cleanup(phase));
                    split(error.clone(), first, context, causes);
                    context.pop();
                }
                Error::ExecWorkerTeardown(error) => {
                    context.push(Context::Exec);
                    let split = split_aggregate(error, first, context, causes);
                    context.pop();
                    return split;
                }
                _ => return false,
            }
            true
        }
        let mut causes = Vec::new();
        split(Arc::new(self), &first, &mut Vec::new(), &mut causes);
        // Prefer the already present worker context for the published identity
        // over a context-free notification alias. A canceled peer carrying the
        // same cause cannot supply its own TID as the cause's identity. Other
        // real errors retain their order, regardless of host completion/TID.
        let selected = causes
            .iter()
            .enumerate()
            .filter(|(_, cause)| {
                Arc::ptr_eq(&cause.error, &first)
                    && cause.worker_tid().is_none_or(|tid| tid == first_tid)
            })
            .max_by_key(|(index, cause)| {
                (
                    cause.worker_tid() == Some(first_tid),
                    std::cmp::Reverse(*index),
                )
            })
            .map(|(index, _)| index);
        let primary = selected
            .map(|index| causes.remove(index).into_error())
            .unwrap_or_else(|| Error::SharedFailure(first.clone()));
        let cleanup = causes
            .into_iter()
            .filter(|cause| !Arc::ptr_eq(&cause.error, &first))
            .map(Cause::into_error)
            .collect();
        primary.with_cleanup(cleanup)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn signal_effects_preserve_first_failure_and_cancellation_evidence() {
        let first = Arc::new(Error::GuestClock("original".to_owned()));
        let context = reverie::ParkedSignalFailureContext {
            site: reverie::CallbackSignalSite {
                process: reverie::SignalProcessId {
                    tgid: reverie::Pid::from_raw(1),
                    generation: 2,
                },
                tid: reverie::Pid::from_raw(1),
                task_generation: 3,
                callback_nonce: 7,
                boundary_nonce: 8,
            },
            ledger_nonce: 8,
        };
        let ledger = |cause| Error::SignalEffects {
            cause: Arc::new(cause),
            dequeues: Vec::new(),
            acknowledged_through: 17,
            publications: Vec::new(),
            raw_result: Some(-14),
            context: Some(Box::new(context)),
        };
        let worker = ledger(Error::WorkerFailure {
            tid: 3,
            error: first.clone(),
        });
        assert!(worker.retains_primary(&first));
        assert_eq!(worker.worker_tid(), Some(3));
        assert!(matches!(worker.primary(), Error::GuestClock(message) if message == "original"));
        let cancelled = ledger(Error::RunAborted);
        assert!(matches!(cancelled.primary(), Error::RunAborted));
        let completed = cancelled.complete_after_failure(first.clone(), 3);
        assert!(completed.retains_primary(&first));
        assert!(matches!(completed.primary(), Error::GuestClock(message) if message == "original"));
        let Error::WithCleanup { cleanup, .. } = completed else {
            panic!("ledger lost")
        };
        assert_eq!(cleanup.len(), 1);
        let Error::SharedFailure(retained) = cleanup[0].as_ref() else {
            panic!("ledger not retained")
        };
        assert!(matches!(retained.as_ref(), Error::SignalEffects {
            acknowledged_through: 17, raw_result: Some(-14), context: Some(actual), ..
        } if **actual == context));
    }

    #[test]
    fn worker_diagnostic_and_primary_survive_exec_and_cleanup_wrappers() {
        let cause = Arc::new(Error::Reverie(reverie::syscalls::Errno::EIO.into()));
        let error = Error::ExecWorkerTeardown(Box::new(Error::WorkerFailure {
            tid: 2,
            error: cause.clone(),
        }));
        assert_eq!(
            error.to_string(),
            "unexpected vCPU exit: KVM worker cleanup failed: thread 2: Reverie tool failed: -5 EIO (I/O error)"
        );
        assert!(
            matches!(error.primary(), Error::Reverie(reverie::Error::Errno(errno))
            if *errno == reverie::syscalls::Errno::EIO)
        );
        assert!(error.retains_primary(&cause));
        assert_eq!(error.worker_tid(), Some(2));
        let error = error.with_cleanup(vec![Error::GuestClock("secondary".to_owned())]);
        assert!(error.retains_primary(&cause));
        assert_eq!(error.worker_tid(), Some(2));
        assert!(matches!(error.primary(), Error::Reverie(_)));
    }
}
