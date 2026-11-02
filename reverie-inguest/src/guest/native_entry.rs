/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Actual native entry into the same ToolHost and concrete InGuest. These
//! methods do not install native services, own a scheduler or admit an image.

use super::native_state::DeferredNative;
use super::native_state::NativeCallbackLease;
use super::*;
use crate::tool_host::NativeCallbackOutcome;
use crate::tool_host::drive_native_callback;
use crate::tool_host::drive_native_ready;

/// A completed Tool callback, or its original still-active native continuation.
/// The latter retains the sole thread-state and scratch owner until the actual
/// native post-event or consuming exit owner completes it.
pub enum NativeCallResult<'owner, T: Tool, V> {
    /// All Guest borrows/futures ended and the original state was published.
    Return(V),
    /// The native owner must apply and complete this exact deferred operation.
    Deferred(DeferredNative<'owner, T>),
}

/// The actual instruction request supplied by the native entry owner.
pub enum NativeInstruction {
    /// The original EAX and ECX input registers.
    Cpuid { leaf: u32, subleaf: u32 },
    /// The actual RDTSC or RDTSCP instruction.
    Rdtsc(Rdtsc),
}

/// A Tool instruction answer. The original native context owner applies these
/// fields and preserves its remaining integer/FP/SIMD state.
pub enum NativeInstructionResult {
    /// EAX, EBX, ECX and EDX from the real Tool.
    Cpuid(reverie::CpuIdResult),
    /// The Tool's timestamp and optional auxiliary value.
    Rdtsc(reverie::RdtscResult),
}

/// The signal decision before the native owner commits the pending delivery.
pub enum NativeSignalResult {
    /// Deliver the same signal with either its authentic or replaced siginfo.
    Deliver {
        signal: reverie::Signal,
        info: [u8; reverie::SIGNAL_INFO_SIZE],
    },
    /// The Tool suppressed this signal.
    Suppress,
}

fn native_callback_error(reason: &'static str) -> Error {
    io::Error::other(reason).into()
}

impl<T: Tool, R: HostRuntime> ToolHost<T, R>
where
    T::GlobalState: 'static,
{
    /// Construct the one common Guest from an actual native lease and drive
    /// owned callback work. No registry/Tool-slot guard spans callbacks or I/O.
    /// The callback must return an owned result, never a Guest borrow/future.
    ///
    /// # Safety
    /// The actual native entry owner must have established its current image,
    /// task, service table, allocator backing, FS/TLS and native continuation
    /// contract. `services` belongs to this exact lease and remains live until
    /// every native use ends. A copied identity/handle or serialized phase flag
    /// is not that authority. No local or private-image dispatch may run here.
    /// The native post-event owner must retain and complete a Deferred result;
    /// an ordinary Rust return alone does not complete that operation.
    pub unsafe fn with_native_guest<'owner, V>(
        &self,
        mut callback: NativeCallbackLease<'owner, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
        work: impl FnOnce(
            &T,
            &mut InGuest<'_, T, R>,
            &TailResult,
        ) -> NativeCallbackOutcome<Result<V, Error>>,
    ) -> Result<NativeCallResult<'owner, T, V>, Error> {
        let identity = callback.identity();
        let outcome =
            unsafe { self.drive_native_guest(&mut callback, services, native_rpc, event, work)? };
        match outcome {
            NativeCallbackOutcome::Ready(value) => {
                let value = value?;
                unsafe { callback.complete(identity)? };
                Ok(NativeCallResult::Return(value))
            }
            NativeCallbackOutcome::Deferred { number, args } => Ok(NativeCallResult::Deferred(
                DeferredNative::new(callback, number, args),
            )),
            NativeCallbackOutcome::Unsupported(reason) => Err(native_callback_error(reason)),
        }
    }

    // One common callback/Guest/RPC/scoping body for consuming events and
    // intermediate native post steps. No registry entry or scratch reset.
    unsafe fn drive_native_guest<V>(
        &self,
        callback: &mut NativeCallbackLease<'_, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
        work: impl FnOnce(
            &T,
            &mut InGuest<'_, T, R>,
            &TailResult,
        ) -> NativeCallbackOutcome<Result<V, Error>>,
    ) -> Result<NativeCallbackOutcome<Result<V, Error>>, Error> {
        let owner = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        let invocation = services.invocation();
        invocation.ensure_current()?;
        let identity = callback.identity();
        if !callback.owned_by(owner)
            || identity != invocation.identity()
            || !Arc::ptr_eq(native_rpc.shared_config(), &self.rpc.shared_config())
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE).into());
        }

        // Selection of existing engine TLS/allocator scopes follows, rather
        // than substitutes for, the actual native owner's unsafe entry proof.
        // In particular, no process-global COMMITTED_STACKS reset is used.
        let outcome = {
            let _allocation = super::super::alloc::enter_dispatch();
            let _active = super::super::support::ToolCallbackGuard::enter();
            let (tool, state, lifecycle, scratch, copied_parent) = callback.dispatch_parts();
            // Move the actual inherited record into this callback's scopes,
            // not into a registry drop. If preparation or lifecycle entry
            // fails, its normal destructor still runs while these allocation
            // and Tool scopes are live, as in the native initializer.
            let copied_parent = copied_parent.take();
            native_rpc.prepare(invocation)?;
            let tail = TailResult::default();
            // Keep this route as a separate stable stack borrow: the Guest is
            // mutably borrowed by Tool handlers while sync global RPC borrows
            // this identical selected route, never the Guest itself.
            let application = native_rpc.application(invocation);
            let _route = super::super::native_rpc::NativeRpcScope::enter(&application, &tail);
            let mut guest = InGuest {
                event,
                tid: identity.tid(),
                // Native Guest::pid addresses the real host process (procfs,
                // memory/descriptor mechanisms). The Tool's virtual process
                // identity remains in its state and the native identity owner.
                pid: identity.physical_pid(),
                ppid: services.facts().parent,
                state,
                rpc: &self.rpc,
                native: Some(NativeGuestView {
                    services,
                    rpc: native_rpc.application(invocation),
                    scratch,
                    signal_info_replacement: None,
                }),
                tail: &tail,
                cpuid_interception: services.facts().cpuid_interception,
                fork_parent_state: None,
                runtime: &self.runtime,
                staged_signals: Vec::new(),
                staged_signal_delivery: false,
                in_syscall_handler: false,
                #[cfg(feature = "exec-native-injection")]
                exec: None,
                #[cfg(feature = "exec-native-injection")]
                mapping_driver: None,
                unsupported_refusal: None,
                injected_syscalls: 0,
            };
            let entry = enter_tool_callbacks(tool, &mut guest, lifecycle);
            // The inherited-parent branch runs one real thread-start and no
            // synthetic post-exec. Preserve its parent's lifetime through the
            // real lifecycle return (including failure), then destroy it
            // outside all registry/Tool-slot locks before the event handler.
            drop(copied_parent);
            match entry {
                Ok(()) => work(tool.as_ref().expect("pinned live Tool"), &mut guest, &tail),
                Err(EntryFailure::Tool(error)) => return Err(error),
                Err(EntryFailure::Ending(_)) => {
                    return Err(native_callback_error(
                        "a local signal ending reached native entry",
                    ));
                }
            }
        };
        // Every Tool future, Guest, global-route borrow and allocation scope
        // above has ended before any continuation/state owner is returned.
        invocation.ensure_current()?;
        Ok(outcome)
    }

    /// Continue the original deferred callback for the native owner's real
    /// returning post-event Tool work. In particular, parent-side child
    /// registration and failed-exec cancellation must keep the original state
    /// and scratch instead of completing it and entering a fresh callback.
    /// No registry/Tool-slot lock survives into the supplied work or its RPC.
    ///
    /// # Safety
    /// The actual original operation has returned on this same task/image,
    /// with its native continuation, selected services and original scratch
    /// still live. `work` is its real post-event bookkeeping, not another
    /// syscall delivery. It must end every original scratch use and commit
    /// its register/clone/exec/signal bookkeeping before returning Ready. A
    /// Deferred result must stay with the corresponding real native owner;
    /// a nonreturning exit must use the consuming exit API instead.
    pub unsafe fn with_native_post_event<'owner, V>(
        &self,
        deferred: DeferredNative<'owner, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
        work: impl FnOnce(
            &T,
            &mut InGuest<'_, T, R>,
            &TailResult,
        ) -> NativeCallbackOutcome<Result<V, Error>>,
    ) -> Result<NativeCallResult<'owner, T, V>, Error> {
        let owner = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        if !deferred.owned_by(owner) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE).into());
        }
        let callback = unsafe { deferred.into_post_event(services.invocation())? };
        // Reuse rather than NativeThreads::enter: that entry resets completed
        // scratch for the NEXT operation, which this post-event is not.
        unsafe { self.with_native_guest(callback, services, native_rpc, event, work) }
    }

    /// Drive one real returning post-event Tool step while the original
    /// deferred owner still retains its state and every scratch arena.
    ///
    /// Child registration and failed-exec cancellation can precede remaining
    /// C register/FD/evidence bookkeeping. They must not publish the callback
    /// early. This method neither completes nor replaces `deferred`; its real
    /// native owner must eventually call complete or a consuming exit API.
    ///
    /// # Safety
    /// The original operation has returned on this same task/image, with no
    /// Guest/future alive and all original scratch still owned by `deferred`.
    /// `work` is real post-event work from that invocation, not a new syscall.
    /// It must return a completed owned result, never initiate another native
    /// deferred operation. On error the native owner must fail the run and
    /// abandon/poison the original owner, not resume or retry its Guest.
    pub unsafe fn with_native_post_step<V>(
        &self,
        deferred: &mut DeferredNative<'_, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
        work: impl FnOnce(
            &T,
            &mut InGuest<'_, T, R>,
            &TailResult,
        ) -> NativeCallbackOutcome<Result<V, Error>>,
    ) -> Result<V, Error> {
        let owner = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        if !deferred.owned_by(owner) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE).into());
        }
        // drive_native_guest repeats current/config/Tool-owner checks before
        // and current-context validation after actual Tool/RPC work. Borrow
        // the original lease; do not consume it through into_post_event.
        let outcome = unsafe {
            self.drive_native_guest(deferred.callback_mut(), services, native_rpc, event, work)?
        };
        match outcome {
            NativeCallbackOutcome::Ready(result) => result,
            NativeCallbackOutcome::Deferred { .. } => Err(native_callback_error(
                "native post-event step requested a second deferred operation",
            )),
            NativeCallbackOutcome::Unsupported(reason) => Err(native_callback_error(reason)),
        }
    }

    /// Enter the actual subscribed syscall handler once. Native error/restart
    /// behavior is retained: this does not use the local ERESTARTSYS retry loop.
    ///
    /// # Safety
    /// All with_native_guest entry and deferred-completion contracts apply.
    /// The native owner must supply the original event and apply the returned
    /// result/deferred operation through its existing native bookkeeping.
    pub unsafe fn dispatch_native_syscall<'owner>(
        &self,
        callback: NativeCallbackLease<'owner, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
    ) -> Result<NativeCallResult<'owner, T, i64>, Error> {
        unsafe {
            self.with_native_guest(
                callback,
                services,
                native_rpc,
                event,
                |tool, guest, tail| {
                    self.dispatch_native_syscall_in_guest(tool, guest, tail, services, native_rpc)
                },
            )
        }
    }

    /// Run the existing native syscall dispatch inside this callback's one
    /// common Guest. Concrete Tool glue may prepare/finish its owned state
    /// around this call without completing/reentering the native lease.
    /// This does not drive lifecycle entry or publish/consume that lease.
    ///
    /// # Safety
    /// Call only from this same host's with_native_guest work closure, using
    /// its actual borrowed Tool, Guest, tail, selected services and RPC owner.
    /// No Guest/future may escape. The outer callback alone retains/completes
    /// any Deferred result after the real native operation/bookkeeping.
    pub unsafe fn dispatch_native_syscall_in_guest(
        &self,
        tool: &T,
        guest: &mut InGuest<'_, T, R>,
        tail: &TailResult,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
    ) -> NativeCallbackOutcome<Result<i64, Error>> {
        unsafe {
            self.dispatch_native_syscall_in_guest_with(
                tool,
                guest,
                tail,
                services,
                native_rpc,
                |_, outcome| outcome,
            )
        }
    }

    /// Run concrete Tool postprocessing inside the same admitted Guest,
    /// after its actual handler completes and before the unchanged native
    /// errno/forwarded-operation classification. The ordinary entry uses the
    /// identity postprocessor and retains its existing behavior.
    ///
    /// # Safety
    /// All dispatch_native_syscall_in_guest contracts apply. The postprocessor
    /// borrows only this callback's actual Guest; no future or borrowed state
    /// may escape it. It does not complete or replace the original lease.
    pub unsafe fn dispatch_native_syscall_in_guest_with(
        &self,
        tool: &T,
        guest: &mut InGuest<'_, T, R>,
        tail: &TailResult,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        postprocess: impl FnOnce(
            &mut InGuest<'_, T, R>,
            NativeCallbackOutcome<Result<i64, Error>>,
        ) -> NativeCallbackOutcome<Result<i64, Error>>,
    ) -> NativeCallbackOutcome<Result<i64, Error>> {
        let invocation = services.invocation();
        if let Some(result) =
            native_rpc.protect_operation(invocation, guest.event.number, &guest.event.args, true)
        {
            return NativeCallbackOutcome::Ready(Ok(result));
        }
        // Preserve the maintained native callback's conversion and
        // invalid-number refusal. A malformed native event is not a
        // guest syscall result and must not synthesize -ENOSYS.
        let number = Sysno::from(guest.event.number as i32);
        let args = guest.event.args;
        let syscall = Syscall::from_raw(
            number,
            SyscallArgs::new(
                args[0] as usize,
                args[1] as usize,
                args[2] as usize,
                args[3] as usize,
                args[4] as usize,
                args[5] as usize,
            ),
        );
        // Native interception is selected by its actual C owner.
        // Like the maintained native driver, every event reaching
        // this entry invokes Tool, independent of local hooks'
        // subscription table. Only Tool may request deferral here.
        #[cfg(feature = "native-entry-observer")]
        guest.observe_native_entry(NativeEntryStage::Syscall);
        guest.in_syscall_handler = true;
        let outcome = drive_native_callback(tool.handle_syscall_event(guest, syscall), tail);
        guest.in_syscall_handler = false;
        let outcome = postprocess(guest, outcome);
        match outcome {
            NativeCallbackOutcome::Ready(Err(Error::Errno(errno))) => {
                // Only the maintained syscall owner turns Linux
                // errno into the negative guest return. Do not
                // enter the local restart loop or poison completed
                // state. Instruction/signal errors remain fatal.
                NativeCallbackOutcome::Ready(Ok(-i64::from(errno.into_raw())))
            }
            NativeCallbackOutcome::Deferred { number, args } => {
                // Close/close_range still reached the Tool for accounting;
                // the actual forwarded/deferred operation spares the same
                // reserved primary descriptor, as before this factoring.
                match native_rpc.protect_operation(invocation, number, &args, false) {
                    Some(result) => NativeCallbackOutcome::Ready(Ok(result)),
                    None => NativeCallbackOutcome::Deferred { number, args },
                }
            }
            other => other,
        }
    }

    /// Drive the real instruction handler with this same concrete Guest. The
    /// native context owner retains its original output/commit protocol.
    ///
    /// # Safety
    /// All with_native_guest contracts apply, including real instruction
    /// delivery and caller-owned register/FP/SIMD state.
    pub unsafe fn dispatch_native_instruction<'owner>(
        &self,
        callback: NativeCallbackLease<'owner, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
        instruction: NativeInstruction,
    ) -> Result<NativeCallResult<'owner, T, NativeInstructionResult>, Error> {
        unsafe {
            self.with_native_guest(
                callback,
                services,
                native_rpc,
                event,
                |tool, guest, _tail| {
                    // The maintained instruction owner polls with a no-op waker and
                    // yield_now, without reading a tail result. Do not substitute the
                    // application callback's wake/park or local syscall-restart loop.
                    let result = match instruction {
                        NativeInstruction::Cpuid { leaf, subleaf } => {
                            drive_native_ready(tool.handle_cpuid_event(guest, leaf, subleaf))
                                .map(NativeInstructionResult::Cpuid)
                                .map_err(Error::from)
                        }
                        NativeInstruction::Rdtsc(request) => {
                            drive_native_ready(tool.handle_rdtsc_event(guest, request))
                                .map(NativeInstructionResult::Rdtsc)
                                .map_err(Error::from)
                        }
                    };
                    NativeCallbackOutcome::Ready(result)
                },
            )
        }
    }

    /// Drive an authentic native signal continuation. Signal masks, queued
    /// delivery and physical interrupted context stay with the native owner.
    /// Changing the signal number is still refused, not silently ignored.
    ///
    /// # Safety
    /// All with_native_guest contracts apply. The owned siginfo and signal
    /// number must be from this same actual native pending delivery.
    pub unsafe fn dispatch_native_signal<'owner>(
        &self,
        callback: NativeCallbackLease<'owner, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        event: &mut SyscallEvent,
        signal: i32,
    ) -> Result<NativeCallResult<'owner, T, NativeSignalResult>, Error> {
        let shown = reverie::Signal::try_from(signal)?;
        let original = services.facts().signal_info.ok_or(Errno::EINVAL)?;
        if i32::from_ne_bytes(original[..4].try_into().expect("siginfo signal field")) != signal {
            return Err(Errno::EINVAL.into());
        }
        unsafe {
            self.with_native_guest(
                callback,
                services,
                native_rpc,
                event,
                |tool, guest, tail| {
                    match drive_native_callback(tool.handle_signal_event(guest, shown), tail) {
                        NativeCallbackOutcome::Ready(Ok(Some(chosen))) if chosen == shown => {
                            let info = guest
                                .native
                                .as_ref()
                                .expect("native entry")
                                .signal_info_replacement
                                .unwrap_or(original);
                            NativeCallbackOutcome::Ready(Ok(NativeSignalResult::Deliver {
                                signal: shown,
                                info,
                            }))
                        }
                        NativeCallbackOutcome::Ready(Ok(Some(_))) => {
                            NativeCallbackOutcome::Ready(Err(native_callback_error(
                                "native signal-number transformation is unsupported",
                            )))
                        }
                        NativeCallbackOutcome::Ready(Ok(None)) => {
                            NativeCallbackOutcome::Ready(Ok(NativeSignalResult::Suppress))
                        }
                        NativeCallbackOutcome::Ready(Err(error)) => {
                            NativeCallbackOutcome::Ready(Err(error.into()))
                        }
                        NativeCallbackOutcome::Deferred { number, args } => {
                            // The existing signal continuation accepts the exact tail
                            // operation; native signal ownership decides its effects.
                            NativeCallbackOutcome::Deferred { number, args }
                        }
                        NativeCallbackOutcome::Unsupported(reason) => {
                            NativeCallbackOutcome::Unsupported(reason)
                        }
                    }
                },
            )
        }
    }
}
