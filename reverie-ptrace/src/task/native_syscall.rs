/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Call-local observation transport. No syscall-family policy lives here.

use std::cell::RefCell;

use reverie::native_syscall::*;
use reverie::reserved_input::*;

use super::*;

/// Backend-private proof: the caller cannot manufacture a stopped grant or
/// substitute a different request merely by sharing an operation completion.
#[derive(Debug)]
struct NativeRequestTicket {
    generation: safeptrace::TraceeGeneration,
    task: InputTaskId,
    grant: u64,
    request: NativeSyscallRequest,
    mode: u64,
    entry_abi: Option<NativeSyscallAbi>,
    instruction_abi: NativeSyscallAbi,
}

#[derive(Debug, Clone, Copy)]
enum NativeRequestSource {
    Entry,
    Instruction,
}

impl NativeRequestTicket {
    fn check_request(
        &self,
        mode: u64,
        source: NativeRequestSource,
        actual: NativeSyscallRequest,
    ) -> Result<(), &'static str> {
        let expected_abi = match source {
            NativeRequestSource::Entry => self.entry_abi,
            NativeRequestSource::Instruction => Some(self.instruction_abi),
        };
        if mode != self.mode
            || expected_abi != Some(actual.abi)
            || actual.number != self.request.number
            || actual.args != self.request.args
        {
            return Err("native-request-ownership-mismatch");
        }
        Ok(())
    }
}

pub(super) struct NativeCallContext {
    pub(super) input: Option<NativeInputCall>,
    pub(super) operation: Option<NativeOperation>,
    purpose: NativeSyscallPurpose,
    activity: Option<Result<NativeCallActivity, String>>,
    attempt: StdMutex<Option<Arc<NativeAttempt>>>,
}
impl NativeCallContext {
    pub(super) fn application(operation: Option<NativeOperation>) -> Self {
        Self {
            input: None,
            activity: operation.as_ref().map(|owner| {
                owner
                    .begin_native_attempt()
                    .map(NativeCallActivity)
                    .map_err(|error| error.to_string())
            }),
            operation,
            purpose: NativeSyscallPurpose::Application,
            attempt: StdMutex::new(None),
        }
    }
    pub(super) fn internal() -> Self {
        Self {
            purpose: NativeSyscallPurpose::BackendPrivate,
            ..Self::application(None)
        }
    }
    pub(super) fn with_input(input: NativeInputCall, operation: Option<NativeOperation>) -> Self {
        Self {
            input: Some(input),
            ..Self::application(operation)
        }
    }
    pub(super) fn preparation_word(&self, task: &Stopped, address: usize) -> Option<u64> {
        match &self.input {
            Some(input) => input.preparation_word(task, address),
            None => task.read_value(Addr::<u64>::from_raw(address)?).ok(),
        }
    }
}

struct NativeCallActivity(NativeOperationAttempt);
impl Drop for NativeCallActivity {
    fn drop(&mut self) {
        // This conditional fact is stronger than future Drop: only a call for
        // which no transport transition was attempted can complete here.
        self.0.cancelled_before_transition();
    }
}

/// Completion belonging to one cancelled ordinary syscall callback. Helpers
/// never fetch this carrier; its dispatcher moves it into a local before any
/// held-signal or debugger callback can execute.
pub(super) struct DeferredNativeCall {
    pub(super) callback: u64,
    pub(super) owner: safeptrace::TraceeGeneration,
    pub(super) pending: Arc<AtomicBool>,
    pub(super) context: NativeCallContext,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    Prepared,
    TransitionStarted,
    Issued,
    Unobserved,
    Settled,
}

/// Observer-free retention, installed before preparation can yield. It keeps
/// the exact old native owner and each attempt's mechanical completion only.
/// An operation shared with another live generation cannot be closed by this
/// owner's retirement.
pub(super) struct NativeOperationOwner {
    owner: safeptrace::TerminalCleanup,
    completion: NativeOperationCompletion,
    activity: Option<NativeOperationAttempt>,
}

pub(super) struct NativeAttempt {
    owner: safeptrace::TerminalCleanup,
    call: NativeSyscallCall,
    activity: Option<NativeOperationAttempt>,
    observers: Vec<Arc<dyn NativeSyscallObserver>>,
    state: StdMutex<AttemptState>,
}
impl NativeAttempt {
    fn event(
        &self,
        event: NativeSyscallEvent,
        facts: Option<&dyn NativeSyscallFacts>,
    ) -> Result<(), reverie::Error> {
        {
            let mut state = self.state.lock().unwrap();
            match (event, *state) {
                (
                    NativeSyscallEvent::ResumeIssued,
                    AttemptState::Prepared | AttemptState::TransitionStarted,
                ) => {
                    *state = AttemptState::Issued;
                }
                (NativeSyscallEvent::ResumeIssued, _) => return Ok(()),
                (
                    NativeSyscallEvent::ResultUnobserved,
                    AttemptState::Issued | AttemptState::TransitionStarted,
                ) => {
                    *state = AttemptState::Unobserved;
                }
                (NativeSyscallEvent::ResultUnobserved, _) => return Ok(()),
                (_, AttemptState::Settled) => return Ok(()),
                _ => {
                    *state = AttemptState::Settled;
                    if let Some(activity) = &self.activity {
                        activity.effects_ended();
                    }
                }
            }
        }
        // No registry or attempt lock spans a Tool callback.
        for observer in &self.observers {
            observer.observe(&self.call, event, facts)?;
        }
        Ok(())
    }
}

struct PtraceNativeFacts<'a, L: Tool + 'static> {
    guest: &'a TracedTask<L>,
    stop: &'a Stopped,
    authority: Result<NativeSyscallAuthority, InputUnavailable>,
    pins: RefCell<Vec<PinnedInputDescriptor>>,
}
impl<'a, L: Tool + 'static> PtraceNativeFacts<'a, L> {
    fn new(guest: &'a TracedTask<L>, stop: &'a Stopped) -> Self {
        let authority = guest
            .input_control()
            .zip(guest.reserved_input_task)
            .ok_or_else(|| InputUnavailable::new("input-native-identity-unavailable"))
            .and_then(|(control, task)| control.native_syscall_authority(task));
        Self {
            guest,
            stop,
            authority,
            pins: RefCell::new(Vec::new()),
        }
    }
}
impl<L: Tool + 'static> NativeSyscallFacts for PtraceNativeFacts<'_, L> {
    fn control(&self) -> Option<ReservedInputControl> {
        self.guest.input_control()
    }
    fn task(&self) -> Option<InputTaskId> {
        self.guest.reserved_input_task
    }
    fn authority(&self) -> Result<NativeSyscallAuthority, InputUnavailable> {
        self.authority.clone()
    }
    fn descriptor(&self, fd: i32) -> Result<InputDescriptorFacts, InputUnavailable> {
        let pin = self
            .guest
            .inspect_reserved_input_descriptor_at(self.stop, fd)?;
        let facts = pin.facts().clone();
        self.pins.borrow_mut().push(pin);
        Ok(facts)
    }
    fn descriptors(&self) -> Result<NativeDescriptorSnapshot, InputUnavailable> {
        let snapshot = self.guest.inspect_input_descriptors_at(self.stop)?;
        let descriptors = snapshot
            .descriptors
            .iter()
            .map(|pin| pin.facts().clone())
            .collect();
        self.pins.borrow_mut().extend(snapshot.descriptors);
        Ok(NativeDescriptorSnapshot {
            descriptors,
            mountinfo: snapshot.mountinfo,
        })
    }
}

impl FatalSession {
    /// The caller supplies an already authenticated effects-ended boundary for
    /// this exact retained generation. No host observation or wait happens here.
    pub(super) fn complete_native_effects(
        &self,
        owner: &safeptrace::TerminalCleanup,
    ) -> Result<(), reverie::Error> {
        let retired = {
            let mut operations = self.native_operations.lock().unwrap();
            let mut retired = Vec::new();
            let mut index = 0;
            while index < operations.len() {
                if operations[index].owner.same_generation(owner) {
                    retired.push(operations.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            for operation in &retired {
                if !operations
                    .iter()
                    .any(|other| other.completion.same_operation(&operation.completion))
                {
                    operation.completion.close_after_native_owner_retired();
                }
                // Actual old-owner retirement ends even a preparing request;
                // no old-image call may be issued after this boundary.
                if let Some(activity) = &operation.activity {
                    activity.effects_ended();
                }
            }
            retired
        };
        // Keep all mechanical completion publication before observer events,
        // with neither registry nor retention lock across a Tool callback.
        drop(retired);
        let attempts = self
            .native_attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|attempt| attempt.owner.same_generation(owner))
            .cloned()
            .collect::<Vec<_>>();
        for attempt in attempts {
            let prepared = *attempt.state.lock().unwrap() == AttemptState::Prepared;
            attempt.event(
                if prepared {
                    NativeSyscallEvent::ProvedNotRun
                } else {
                    NativeSyscallEvent::EffectsComplete
                },
                None,
            )?;
        }
        self.prune_native_attempts();
        Ok(())
    }

    fn prune_native_attempts(&self) {
        self.native_attempts
            .lock()
            .unwrap()
            .retain(|attempt| *attempt.state.lock().unwrap() != AttemptState::Settled);
    }
}

impl<L: Tool + 'static> TracedTask<L> {
    pub(super) fn retain_native_operation_owner(
        &self,
        context: Option<&NativeCallContext>,
    ) -> Result<(), TraceError> {
        let Some(context) = context else {
            return Ok(());
        };
        let Some(operation) = &context.operation else {
            return Ok(());
        };
        let activity = match context.activity.as_ref() {
            Some(Ok(activity)) => activity.0.clone(),
            Some(Err(error)) => return Err(self.input_failure(error)),
            None => return Err(self.input_failure("native-operation-activity-missing")),
        };
        let mut operations = self
            .global_state
            .fatal_session
            .native_operations
            .lock()
            .unwrap();
        operations.retain(|owner| !owner.completion.effects_complete());
        operations.push(NativeOperationOwner {
            owner: self.assume_stopped().terminal_cleanup(),
            completion: operation.completion(),
            activity: Some(activity),
        });
        Ok(())
    }

    fn native_execution_mode(stop: &Stopped) -> Result<u64, TraceError> {
        let regs = stop.getregs()?;
        #[cfg(target_arch = "x86_64")]
        {
            Ok(regs.cs)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Ok(regs.pstate & 0x1f)
        }
    }

    fn instruction_abi_for_mode(mode: u64) -> NativeSyscallAbi {
        #[cfg(target_arch = "x86_64")]
        let native = (mode == 0x33).then_some(0xc000003e);
        #[cfg(target_arch = "aarch64")]
        let native = (mode == 0).then_some(0xc00000b7);
        native.map_or(NativeSyscallAbi::Unverified, |audit_arch| {
            NativeSyscallAbi::Linux { audit_arch }
        })
    }

    pub(super) fn bind_native_request_at_current_grant(
        &self,
        operation: &NativeOperation,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<NativeOperation, reverie::Error> {
        let control = self
            .input_control()
            .ok_or_else(|| anyhow::anyhow!("native-request-control-unavailable"))?;
        let task = self
            .reserved_input_task
            .ok_or_else(|| anyhow::anyhow!("native-request-task-unavailable"))?;
        let grant = control
            .native_request_grant(task)
            .map_err(anyhow::Error::new)?;
        let stop = self.assume_stopped();
        if !self
            .global_state
            .fatal_session
            .input_generations
            .lock()
            .unwrap()
            .iter()
            .any(|(owner, registered)| {
                *registered == task && owner.same_generation(&stop.terminal_cleanup())
            })
        {
            return Err(anyhow::anyhow!("native-request-registration-mismatch").into());
        }
        let mode = Self::native_execution_mode(&stop).map_err(anyhow::Error::new)?;
        let info = stop.getsyscallinfo().map_err(anyhow::Error::new)?;
        let entry_abi = matches!(
            info.operation,
            safeptrace::SyscallInfoOp::Entry { .. } | safeptrace::SyscallInfoOp::Seccomp { .. }
        )
        .then_some(NativeSyscallAbi::Linux {
            audit_arch: info.architecture,
        });
        let instruction_abi = Self::instruction_abi_for_mode(mode);
        // A constrained call may use the original entry or the backend's
        // native instruction after preparation. If those interpretations
        // differ, expose uncertainty to pre-release coverage without changing
        // either native route. The private ticket retains both exact facts.
        let abi = if entry_abi.is_none_or(|entry| entry == instruction_abi) {
            instruction_abi
        } else {
            NativeSyscallAbi::Unverified
        };
        let request = NativeSyscallRequest {
            abi,
            number: nr as u64,
            args: *host_linux::request(nr, args).args(),
        };
        if control
            .native_request_grant(task)
            .map_err(anyhow::Error::new)?
            != grant
        {
            return Err(anyhow::anyhow!("native-request-grant-changed").into());
        }
        let bound = operation.bind_request_from_backend(
            request,
            NativeRequestTicket {
                generation: stop.generation(),
                task,
                grant,
                request,
                mode,
                entry_abi,
                instruction_abi,
            },
        )?;
        // Retain the owner before release, even if cancellation/exec happens
        // before an injection context or its final observation is constructed.
        self.global_state
            .fatal_session
            .native_operations
            .lock()
            .unwrap()
            .push(NativeOperationOwner {
                owner: stop.terminal_cleanup(),
                completion: bound.completion(),
                activity: None,
            });
        Ok(bound)
    }

    fn validate_native_request(
        &self,
        stop: &Stopped,
        source: NativeRequestSource,
        actual: NativeSyscallRequest,
        operation: Option<&NativeOperation>,
    ) -> Result<(), TraceError> {
        let Some(operation) = operation.filter(|operation| operation.bound_request().is_some())
        else {
            return Ok(());
        };
        let ticket = operation
            .request_proof::<NativeRequestTicket>()
            .ok_or_else(|| self.input_failure("native-request-proof-unrecognized"))?;
        if ticket.generation != stop.generation() || self.reserved_input_task != Some(ticket.task) {
            return Err(self.input_failure("native-request-generation-changed"));
        }
        // The saved grant authenticates the binding cut, not a fabricated
        // current grant: it is expected to be released during background I/O.
        let _binding_grant = ticket.grant;
        ticket
            .check_request(Self::native_execution_mode(stop)?, source, actual)
            .map_err(|error| self.input_failure(error))
    }

    /// A new ordinary syscall-entry event proves the previous unobserved
    /// native attempt ended. This is not invoked for preparatory entry stops.
    pub(super) fn native_user_continuation(&self, stop: &Stopped) -> Result<(), TraceError> {
        let owner = stop.terminal_cleanup();
        let pending = self
            .global_state
            .fatal_session
            .native_attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|attempt| {
                attempt.owner.same_generation(&owner)
                    && *attempt.state.lock().unwrap() == AttemptState::Unobserved
            })
            .cloned()
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(());
        }
        let info = stop
            .getsyscallinfo()
            .map_err(|error| self.input_failure(error))?;
        if !matches!(
            info.operation,
            safeptrace::SyscallInfoOp::Entry { .. } | safeptrace::SyscallInfoOp::Seccomp { .. }
        ) {
            return Err(self.input_failure("native-continuation-entry-unproved"));
        }
        for attempt in pending {
            attempt
                .event(NativeSyscallEvent::EffectsComplete, None)
                .map_err(|error| self.input_failure(error))?;
        }
        self.global_state.fatal_session.prune_native_attempts();
        Ok(())
    }

    /// Backend-owned syscall instructions use a known opcode, but execution
    /// mode is checked on the actual stopped registers. An unfamiliar mode is
    /// retained as Unverified; it is not decoded as native or refused here.
    fn native_instruction_abi(&self, stop: &Stopped) -> Result<NativeSyscallAbi, TraceError> {
        let regs = stop.getregs()?;
        #[cfg(target_arch = "x86_64")]
        {
            // Linux's standard 64-bit user CS. A custom selector is not guessed
            // from its numeric value; the observer receives Unverified instead.
            if regs.cs != 0x33 {
                return Ok(NativeSyscallAbi::Unverified);
            }
            let mut opcode = [0; 2];
            let Some(ip) = Addr::<u8>::from_raw(regs.ip() as usize) else {
                return Ok(NativeSyscallAbi::Unverified);
            };
            if stop.read_exact(ip, &mut opcode).is_err() || opcode != [0x0f, 0x05] {
                return Ok(NativeSyscallAbi::Unverified);
            }
            Ok(NativeSyscallAbi::Linux {
                audit_arch: 0xc000003e,
            })
        }
        #[cfg(target_arch = "aarch64")]
        {
            // PSR_MODE32_BIT excludes AArch32; EL0t's mode bits are zero.
            if regs.pstate & 0x1f != 0 {
                return Ok(NativeSyscallAbi::Unverified);
            }
            let mut opcode = [0; 4];
            let Some(ip) = Addr::<u8>::from_raw(regs.ip() as usize) else {
                return Ok(NativeSyscallAbi::Unverified);
            };
            if stop.read_exact(ip, &mut opcode).is_err() || u32::from_le_bytes(opcode) != 0xd4000001
            {
                return Ok(NativeSyscallAbi::Unverified);
            }
            Ok(NativeSyscallAbi::Linux {
                audit_arch: 0xc00000b7,
            })
        }
    }

    pub(super) fn prepare_deferred_native<'a>(
        &self,
        stop: &Stopped,
        deferred: Option<&'a DeferredNativeCall>,
    ) -> Result<Option<&'a NativeCallContext>, TraceError> {
        let Some(deferred) = deferred else {
            return Ok(None);
        };
        if deferred.owner != stop.generation() {
            return Err(self.input_failure("native-tail-generation-changed"));
        }
        // A tracked preparatory transition already consumed this kernel entry.
        // Its own explicit physical context owns its observation. Re-observing
        // the old request here would invent a second native issue.
        if !deferred.pending.load(Ordering::Acquire) {
            return Ok(None);
        }
        if !L::observes_native_syscalls(&self.global_state.cfg)
            && deferred.context.operation.is_none()
        {
            return Ok(None);
        }
        let info = stop.getsyscallinfo().map_err(|error| {
            self.input_failure(format!("native-tail-entry-unavailable:{error}"))
        })?;
        let (number, args) = match info.operation {
            safeptrace::SyscallInfoOp::Entry { number, arguments }
            | safeptrace::SyscallInfoOp::Seccomp {
                number, arguments, ..
            } => (number, arguments),
            _ => return Err(self.input_failure("native-tail-entry-authority-mismatch")),
        };
        self.observe_native_at_stop_abi(
            stop,
            NativeSyscallAbi::Linux {
                audit_arch: info.architecture,
            },
            number,
            args,
            Some(&deferred.context),
            NativeRequestSource::Entry,
        )?;
        Ok(Some(&deferred.context))
    }

    pub(super) fn observe_native_entry(
        &self,
        stop: &Stopped,
        context: &NativeCallContext,
    ) -> Result<(), TraceError> {
        if !L::observes_native_syscalls(&self.global_state.cfg) && context.operation.is_none() {
            return Ok(());
        }
        let info = stop
            .getsyscallinfo()
            .map_err(|error| self.input_failure(format!("native-entry-observation:{error}")))?;
        let (number, arguments) = match info.operation {
            safeptrace::SyscallInfoOp::Entry { number, arguments }
            | safeptrace::SyscallInfoOp::Seccomp {
                number, arguments, ..
            } => (number, arguments),
            _ => return Err(self.input_failure("native-entry-operation-mismatch")),
        };
        self.observe_native_at_stop_abi(
            stop,
            NativeSyscallAbi::Linux {
                audit_arch: info.architecture,
            },
            number,
            arguments,
            Some(context),
            NativeRequestSource::Entry,
        )
    }

    pub(super) fn observe_native_at_stop(
        &self,
        stop: &Stopped,
        nr: u64,
        args: [u64; 6],
        context: Option<&NativeCallContext>,
    ) -> Result<(), TraceError> {
        if context.is_none_or(|context| {
            !L::observes_native_syscalls(&self.global_state.cfg) && context.operation.is_none()
        }) {
            return Ok(());
        }
        let abi = self.native_instruction_abi(stop)?;
        self.observe_native_at_stop_abi(
            stop,
            abi,
            nr,
            args,
            context,
            NativeRequestSource::Instruction,
        )
    }

    fn observe_native_at_stop_abi(
        &self,
        stop: &Stopped,
        abi: NativeSyscallAbi,
        nr: u64,
        args: [u64; 6],
        context: Option<&NativeCallContext>,
        source: NativeRequestSource,
    ) -> Result<(), TraceError> {
        let Some(context) = context else {
            return Ok(());
        };
        if !L::observes_native_syscalls(&self.global_state.cfg) && context.operation.is_none() {
            return Ok(());
        }
        // Validate before observer publication, page fill or native transition.
        // At an instruction stop compare the actual register payload, not the
        // earlier requested tuple. Entry operands come from GET_SYSCALL_INFO.
        let actual = match source {
            NativeRequestSource::Entry => NativeSyscallRequest {
                abi,
                number: nr,
                args,
            },
            NativeRequestSource::Instruction => {
                let regs = stop.getregs()?;
                let a = regs.args();
                NativeSyscallRequest {
                    abi,
                    number: regs.syscall(),
                    args: [a.0, a.1, a.2, a.3, a.4, a.5],
                }
            }
        };
        self.validate_native_request(stop, source, actual, context.operation.as_ref())?;
        if let Some(Err(error)) = &context.activity {
            return Err(self.input_failure(error));
        }
        if context.attempt.lock().unwrap().is_some() {
            return Err(self.input_failure("native-attempt-observed-twice"));
        }
        let serial = self
            .global_state
            .fatal_session
            .native_sequence
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(1)
            })
            .map_err(|_| self.input_failure("native-attempt-identity-exhausted"))?;
        let call = NativeSyscallCall {
            id: NativeSyscallId::from_backend_counter(serial),
            abi,
            number: actual.number,
            args: actual.args,
            purpose: context.purpose,
            operation_bound: context.operation.is_some(),
            input_receipt: context.input.as_ref().map(NativeInputCall::id),
            staged_image: context.input.as_ref().and_then(|input| input.image.clone()),
        };
        let facts = PtraceNativeFacts::new(self, stop);
        let mut observers = Vec::new();
        if L::observes_native_syscalls(&self.global_state.cfg)
            && let Some(observer) = self
                .process_state
                .observe_native_syscall(&self.thread_state, &facts, &call)
                .map_err(|error| self.input_failure(error))?
        {
            observers.push(observer);
        }
        if let Some(operation) = &context.operation
            && let Some(observer) = operation
                .observe(&facts, &call)
                .map_err(|error| self.input_failure(error))?
        {
            observers.push(observer);
        }
        drop(facts); // All pins close before input initialization or native resume.
        if observers.is_empty() && context.operation.is_none() {
            return Ok(());
        }
        let attempt = Arc::new(NativeAttempt {
            owner: stop.terminal_cleanup(),
            activity: context
                .activity
                .as_ref()
                .and_then(|activity| activity.as_ref().ok())
                .map(|activity| activity.0.clone()),
            call,
            observers,
            state: StdMutex::new(AttemptState::Prepared),
        });
        self.global_state
            .fatal_session
            .native_attempts
            .lock()
            .unwrap()
            .push(attempt.clone());
        *context.attempt.lock().unwrap() = Some(attempt);
        Ok(())
    }

    /// Called before the transport request. A failed request is conservatively
    /// unresolved until a decoder or native lifecycle proves the outcome.
    pub(super) fn native_transition_started(&self, context: Option<&NativeCallContext>) {
        if let Some(context) = context {
            if let Some(Ok(activity)) = &context.activity {
                activity.0.transition_started();
            }
            if let Some(attempt) = context.attempt.lock().unwrap().as_ref() {
                let mut state = attempt.state.lock().unwrap();
                if *state == AttemptState::Prepared {
                    *state = AttemptState::TransitionStarted;
                }
            }
        }
    }

    pub(super) fn native_resume_issued(
        &self,
        context: Option<&NativeCallContext>,
    ) -> Result<(), TraceError> {
        if let Some(entry) = &self.native_entry_pending {
            entry.store(false, Ordering::Release);
        }
        if let Some(attempt) = context.and_then(|context| context.attempt.lock().unwrap().clone()) {
            attempt
                .event(NativeSyscallEvent::ResumeIssued, None)
                .map_err(|error| self.input_failure(error))?;
        }
        Ok(())
    }

    pub(super) fn native_result_at_stop(
        &self,
        stop: &Stopped,
        context: Option<&NativeCallContext>,
        result: Result<i64, Errno>,
        ran: bool,
        seccomp_trapped: bool,
    ) -> Result<(), TraceError> {
        if let Some(attempt) = context.and_then(|context| context.attempt.lock().unwrap().clone()) {
            let facts = PtraceNativeFacts::new(self, stop);
            let event = if !ran || seccomp_trapped {
                NativeSyscallEvent::ProvedNotRun
            } else {
                NativeSyscallEvent::NativeResult(result)
            };
            attempt
                .event(event, Some(&facts))
                .map_err(|error| self.input_failure(error))?;
        }
        self.global_state.fatal_session.prune_native_attempts();
        Ok(())
    }

    pub(super) fn native_unobserved(
        &self,
        context: Option<&NativeCallContext>,
    ) -> Result<(), TraceError> {
        if let Some(attempt) = context.and_then(|context| context.attempt.lock().unwrap().clone()) {
            attempt
                .event(NativeSyscallEvent::ResultUnobserved, None)
                .map_err(|error| self.input_failure(error))?;
        }
        self.global_state.fatal_session.prune_native_attempts();
        Ok(())
    }

    pub(super) fn cancel_native_attempts(&self) -> Result<(), TraceError> {
        let Some(owner) = self.ptracer_waits.terminal_cleanup() else {
            return Ok(());
        };
        let attempts = self
            .global_state
            .fatal_session
            .native_attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|attempt| attempt.owner.same_generation(&owner))
            .cloned()
            .collect::<Vec<_>>();
        for attempt in attempts {
            let prepared = *attempt.state.lock().unwrap() == AttemptState::Prepared;
            attempt
                .event(
                    if prepared {
                        NativeSyscallEvent::ProvedNotRun
                    } else {
                        NativeSyscallEvent::ResultUnobserved
                    },
                    None,
                )
                .map_err(|error| self.input_failure(error))?;
        }
        self.global_state.fatal_session.prune_native_attempts();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
