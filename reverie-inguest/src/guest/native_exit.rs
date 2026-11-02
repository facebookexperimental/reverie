/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Consuming Tool lifecycle over the native owner's selected real RPC route.
//! Physical exit, signal delivery, RPC shutdown and evidence drain remain with
//! that owner. This module neither issues an exit nor creates replacement state.

use super::super::native_rpc::NativeBackgroundView;
use super::super::native_rpc::NativeRpcScope;
use super::native_state::DeferredNative;
use super::native_state::NativeThreadHandle;
use super::native_state::NativeThreadIdentity;
use super::*;
use crate::tool_host::NativeCallbackOutcome;
use crate::tool_host::drive_native_callback;

/// The actual lifecycle owner's selected connection. Background and
/// application routes remain distinct; failure never selects the other one.
pub enum NativeExitRpc<'callback, G: GlobalTool> {
    /// A genuine native application callback, using native-invoked I/O.
    Application(NativeApplicationRpc<'callback, G>),
    /// An admitted background callback, using its own per-thread Unix socket.
    Background(NativeBackgroundView<'callback, G>),
}

impl<G: GlobalTool + 'static> NativeExitRpc<'_, G> {
    fn prepare(&self, identity: NativeThreadIdentity, config: &Arc<G::Config>) -> io::Result<()> {
        match self {
            Self::Application(application) => {
                let invocation = application.invocation();
                invocation.ensure_current()?;
                if invocation.identity() != identity
                    || !Arc::ptr_eq(application.owner().shared_config(), config)
                {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
                application.owner().prepare(invocation)
            }
            Self::Background(background) => {
                background.ensure_current()?;
                if background.from() != identity.tid()
                    || !Arc::ptr_eq(background.shared_config(), config)
                {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
                Ok(())
            }
        }
    }

    fn enter<'scope>(&'scope self, tail: &'scope TailResult) -> NativeRpcScope<'scope> {
        match self {
            Self::Application(application) => NativeRpcScope::enter(application, tail),
            Self::Background(background) => NativeRpcScope::enter_background(background, tail),
        }
    }
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for NativeExitRpc<'_, G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        match self {
            Self::Application(application) => application.send_rpc(message).await,
            Self::Background(background) => background.send_rpc(message).await,
        }
    }
    fn try_send_rpc_sync(&self, message: G::Request) -> Result<G::Response, G::Request> {
        match self {
            Self::Application(application) => application.try_send_rpc_sync(message),
            Self::Background(background) => background.try_send_rpc_sync(message),
        }
    }
    fn config(&self) -> &G::Config {
        match self {
            Self::Application(application) => application.config(),
            Self::Background(background) => background.config(),
        }
    }
}

fn completed_exit(outcome: NativeCallbackOutcome<Result<(), Error>>) -> Result<(), Error> {
    match outcome {
        NativeCallbackOutcome::Ready(answer) => answer,
        NativeCallbackOutcome::Deferred { .. } => {
            Err(io::Error::other("native exit lifecycle unexpectedly tail-injected").into())
        }
        NativeCallbackOutcome::Unsupported(reason) => Err(io::Error::other(reason).into()),
    }
}

impl<T: Tool + 'static, R: HostRuntime> ToolHost<T, R>
where
    T::GlobalState: 'static,
{
    fn native_exit_tool(&self) -> io::Result<Arc<ToolProcess<T>>> {
        self.tool
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))
    }

    fn drive_native_exit_state(
        &self,
        tool: Arc<ToolProcess<T>>,
        state: T::ThreadState,
        tid: Pid,
        rpc: NativeExitRpc<'_, T::GlobalState>,
        status: reverie::ExitStatus,
    ) -> NativeCallbackOutcome<Result<(), Error>> {
        // No Tool-slot or registry guard survives into any lifecycle callback
        // or blocking RPC. The original state is consumed exactly once.
        let _allocation = super::super::alloc::enter_dispatch();
        let _active = super::super::support::ToolCallbackGuard::enter();
        let tail = TailResult::default();
        let _route = rpc.enter(&tail);
        drive_native_callback(tool.on_exit_thread(tid, &rpc, state, status), &tail)
    }

    /// Retire the original available state and drive its real thread-exit hook.
    ///
    /// # Safety
    /// The native task has really reached its consuming exit owner; all its
    /// callbacks, Guest borrows, deferred operations and scratch uses ended.
    /// The selected route must belong to that actual callback context. The
    /// caller retains physical exit and RPC/evidence teardown ownership and
    /// must not retry a consumed lifecycle on failure.
    pub unsafe fn dispatch_native_thread_exit(
        &self,
        handle: NativeThreadHandle,
        identity: NativeThreadIdentity,
        rpc: NativeExitRpc<'_, T::GlobalState>,
        status: reverie::ExitStatus,
    ) -> Result<(), Error> {
        completed_exit(unsafe {
            self.dispatch_native_thread_exit_outcome(handle, identity, rpc, status)
        }?)
    }

    /// The same consuming exit, exposing the actual completed Tool result
    /// separately from identity, RPC preparation and state-retirement failure.
    /// The caller owns the native protocol's treatment of a returned Tool
    /// error; Deferred/Unsupported are not successful lifecycle completion.
    ///
    /// # Safety
    /// All contracts of `dispatch_native_thread_exit` apply unchanged. This
    /// does not grant a retry or a replacement state after consumption.
    pub unsafe fn dispatch_native_thread_exit_outcome(
        &self,
        handle: NativeThreadHandle,
        identity: NativeThreadIdentity,
        rpc: NativeExitRpc<'_, T::GlobalState>,
        status: reverie::ExitStatus,
    ) -> Result<NativeCallbackOutcome<Result<(), Error>>, Error> {
        rpc.prepare(identity, &self.rpc.shared_config())?;
        let tool = self.native_exit_tool()?;
        let state = unsafe { self.retire_native_thread(handle, identity)? };
        Ok(self.drive_native_exit_state(tool, state, identity.tid(), rpc, status))
    }

    /// Consume the original active deferred lease at its actual nonreturning
    /// native exit continuation, then run the same Tool thread-exit lifecycle.
    ///
    /// # Safety
    /// All deferred retirement contracts apply. This is the genuine original
    /// native exit continuation, not an abandoned/failed operation. Native use
    /// of every scratch pointer has ended before this method consumes it.
    pub unsafe fn dispatch_native_deferred_thread_exit(
        &self,
        deferred: DeferredNative<'_, T>,
        identity: NativeThreadIdentity,
        rpc: NativeExitRpc<'_, T::GlobalState>,
        status: reverie::ExitStatus,
    ) -> Result<(), Error> {
        completed_exit(unsafe {
            self.dispatch_native_deferred_thread_exit_outcome(deferred, identity, rpc, status)
        }?)
    }

    /// Deferred counterpart of `dispatch_native_thread_exit_outcome`.
    /// It consumes the exact original callback/scratch owner, never a newly
    /// authenticated available-state lease.
    ///
    /// # Safety
    /// All contracts of `dispatch_native_deferred_thread_exit` apply unchanged.
    pub unsafe fn dispatch_native_deferred_thread_exit_outcome(
        &self,
        deferred: DeferredNative<'_, T>,
        identity: NativeThreadIdentity,
        rpc: NativeExitRpc<'_, T::GlobalState>,
        status: reverie::ExitStatus,
    ) -> Result<NativeCallbackOutcome<Result<(), Error>>, Error> {
        rpc.prepare(identity, &self.rpc.shared_config())?;
        let owner = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        if !deferred.owned_by(owner) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE).into());
        }
        let (tool, state) = unsafe { deferred.retire(identity)? };
        Ok(self.drive_native_exit_state(tool, state, identity.tid(), rpc, status))
    }

    /// Consume the same existing Tool only after its actual native thread
    /// lifecycles ended. The background finalizer keeps its original route.
    ///
    /// # Safety
    /// The real process/image owner has stopped all callbacks/continuations
    /// and consumed all thread states. Its ordinary background FS/TLS/stack
    /// and allocator entry are live. The caller still owns native shutdown,
    /// observer/counter publication, RPC drain and final process disposition.
    pub unsafe fn dispatch_native_process_exit(
        &self,
        pid: Pid,
        background: NativeBackgroundView<'_, T::GlobalState>,
        status: reverie::ExitStatus,
    ) -> Result<(), Error> {
        background.ensure_current()?;
        if pid != self.root_pid
            || background.from() != pid
            || !Arc::ptr_eq(background.shared_config(), &self.rpc.shared_config())
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE).into());
        }
        self.native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?
            .ensure_retired()?;
        let mut tool = {
            let mut slot = self
                .tool
                .try_lock()
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            let tool = slot
                .as_ref()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
            if Arc::strong_count(tool) != 1 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock).into());
            }
            let tool = slot
                .take()
                .expect("existing Tool checked under its short owner lock");
            match Arc::try_unwrap(tool) {
                Ok(tool) => tool,
                Err(tool) => {
                    *slot = Some(tool);
                    return Err(io::Error::from(io::ErrorKind::WouldBlock).into());
                }
            }
        };
        let _allocation = super::super::alloc::enter_dispatch();
        let _active = super::super::support::ToolCallbackGuard::enter();
        let tail = TailResult::default();
        let _route = NativeRpcScope::enter_background(&background, &tail);
        completed_exit(drive_native_callback(
            tool.on_exit_process(pid, &background, status),
            &tail,
        ))
    }
}
