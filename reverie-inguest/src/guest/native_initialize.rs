/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Once-only native Tool initialization using the actual admitted parent.
//! This selects common storage/RPC mechanisms; the native image owner still
//! supplies real admission, allocator/TLS and child/exec lifecycle facts.

use super::native_state::DeferredNative;
use super::native_state::NativeParentSnapshot;
use super::native_state::NativeThreadHandle;
use super::native_state::NativeThreadIdentity;
use super::native_state::NativeThreads;
use super::*;

type NativeInitializerOwner<'a, T> = (
    &'a NativeThreads<<T as Tool>::ThreadState>,
    Arc<ToolProcess<T>>,
);

impl<T: Tool, R: HostRuntime> ToolHost<T, R>
where
    T::GlobalState: 'static,
{
    pub(super) fn native_initializer_owner(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
    ) -> io::Result<NativeInitializerOwner<'_, T>> {
        services.invocation().ensure_current()?;
        let owner = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        if !Arc::ptr_eq(native_rpc.shared_config(), &self.rpc.shared_config()) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        // Pin the existing Tool, then release its slot before any Tool code,
        // clone/projection callback or synchronous coordinator exchange.
        let tool = self
            .tool
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        Ok((owner, tool))
    }

    /// Clone the real parent's state before its child-registration callback
    /// mutates its pedigree, retaining the original deferred callback owner.
    ///
    /// # Safety
    /// The actual returning native post-event owner must hold `deferred` from
    /// this exact invocation, with its native operation finished and no Rust
    /// Guest/future alive. `child` must be the actual published child identity,
    /// not a requested ID. `prepare` may set the existing Tool's clone fields
    /// at this same maintained boundary; it must not initialize/reseed a child,
    /// replace a Tool or reset process scratch. The original deferred owner
    /// must still pass through real child/exec bookkeeping and completion.
    pub unsafe fn snapshot_native_parent(
        &self,
        deferred: &mut DeferredNative<'_, T>,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        child: NativeThreadIdentity,
        prepare: impl FnOnce(&mut T::ThreadState) -> io::Result<()>,
    ) -> io::Result<NativeParentSnapshot<T::ThreadState>>
    where
        T::ThreadState: Clone,
    {
        let (owner, tool) = self.native_initializer_owner(services, native_rpc)?;
        let callback = deferred.callback_mut();
        if !callback.owned_by(owner)
            || callback.identity() != services.invocation().identity()
            || !Arc::ptr_eq(&callback.tool, &tool)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let snapshot = {
            let _allocation = super::super::alloc::enter_dispatch();
            let _active = super::super::support::ToolCallbackGuard::enter();
            let invocation = services.invocation();
            native_rpc.prepare(invocation)?;
            let tail = TailResult::default();
            let application = native_rpc.application(invocation);
            let _route = super::super::native_rpc::NativeRpcScope::enter(&application, &tail);
            callback.snapshot_child(child, prepare)?
        };
        let (current_owner, current_tool) = self.native_initializer_owner(services, native_rpc)?;
        if !std::ptr::eq(owner, current_owner) || !Arc::ptr_eq(&tool, &current_tool) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(snapshot)
    }

    fn initialize_native_state(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        parent: Option<NativeParentSnapshot<T::ThreadState>>,
        lifecycle: CallbackLifecycle,
        project: impl FnOnce(
            &mut T::ThreadState,
            Option<(reverie::Tid, &T::ThreadState)>,
        ) -> io::Result<()>,
    ) -> io::Result<NativeThreadHandle> {
        let (owner, tool) = self.native_initializer_owner(services, native_rpc)?;
        let invocation = services.invocation();
        let identity = invocation.identity();
        if let Some(parent) = &parent {
            owner.check_parent(parent, identity)?;
        }
        // The registry lock ends at reserve(). Initializing stays a distinct
        // unpublished phase while Tool/RPC runs, refusing duplicate admission
        // without locking out another native thread's actual callbacks.
        let reservation = owner.reserve(identity)?;
        let state = {
            let _allocation = super::super::alloc::enter_dispatch();
            let _active = super::super::support::ToolCallbackGuard::enter();
            native_rpc.prepare(invocation)?;
            let tail = TailResult::default();
            let application = native_rpc.application(invocation);
            let _route = super::super::native_rpc::NativeRpcScope::enter(&application, &tail);
            let parent = parent.as_ref().map(NativeParentSnapshot::parts);
            let mut state =
                tool.init_thread_state(reverie::Tid::from_raw(identity.tid().as_raw()), parent);
            // Tool-specific identity/parent-state projection stays with the
            // existing concrete core Tool owner. This common mechanism does
            // not implement Linux clone semantics or reseeding policy.
            project(&mut state, parent)?;
            state
        };
        // No Guest borrow, initializer callback, global route or allocation
        // scope remains while the state becomes available to its first event.
        let (current_owner, current_tool) = self.native_initializer_owner(services, native_rpc)?;
        if !std::ptr::eq(owner, current_owner) || !Arc::ptr_eq(&tool, &current_tool) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        if let Some(parent) = &parent {
            owner.check_parent(parent, identity)?;
        }
        reservation.publish(state, lifecycle)
    }

    /// Initialize the actual root of a newly admitted native image once.
    /// Its first common entry still performs thread-start then post-exec.
    ///
    /// # Safety
    /// The live native image owner must establish authentic config, native
    /// task/image, allocator backing and TLS before entry, and must not admit
    /// Guest until this returns a handle and its real first entry completes.
    /// This is not private/initial-image/successor authority. `project` keeps
    /// the maintained concrete Tool's identity projection at this boundary;
    /// it must not replace the Tool or manufacture a second initialization.
    pub unsafe fn initialize_native_image_thread(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        project: impl FnOnce(&mut T::ThreadState) -> io::Result<()>,
    ) -> io::Result<NativeThreadHandle> {
        self.initialize_native_state(
            services,
            native_rpc,
            None,
            CallbackLifecycle::new(true, true),
            |state, _| project(state),
        )
    }

    /// Initialize the one actual child from its consumed parent snapshot.
    /// Child admission retains thread-start without manufacturing post-exec.
    ///
    /// # Safety
    /// The same native entry requirements as initialize_native_image_thread
    /// apply. The image's real child owner must supply its current published
    /// identity and the queued snapshot from its actual parent's clone event.
    /// It retains existing copied-process guards and birth/exec ownership.
    /// `project` may invoke the concrete core Tool's maintained child methods
    /// with this original snapshot; no extension Linux policy belongs here.
    pub unsafe fn initialize_native_thread(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        parent: NativeParentSnapshot<T::ThreadState>,
        project: impl FnOnce(
            &mut T::ThreadState,
            Option<(reverie::Tid, &T::ThreadState)>,
        ) -> io::Result<()>,
    ) -> io::Result<NativeThreadHandle> {
        self.initialize_native_state(
            services,
            native_rpc,
            Some(parent),
            CallbackLifecycle::new(true, false),
            project,
        )
    }
}
