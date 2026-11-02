/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Affine native continuation transfer into an actual copied address space.
//!
//! The inherited registry and Tool slot are never locked. The original
//! callback already owns the Tool and its active state outside those locks.
//! A new registry receives the real child state and the original scratch;
//! the local fork/dispatch path and its process guards are unchanged.

use super::native_state::CopiedNativeParent;
use super::native_state::DeferredNative;
use super::native_state::NativeThreadHandle;
use super::native_state::NativeThreads;
use super::native_state::PostCompletedCopiedNativeParent;
use super::*;

/// The fresh process storage/connection owner and its actual one-use parent.
/// Moving these fields does not grant admission or consume the continuation.
pub struct CopiedNativeProcess<T: Tool, R: HostRuntime> {
    /// Fresh registry/runtime storage retaining the original Tool/config.
    pub host: ToolHost<T, R>,
    /// Fresh RPC storage retaining the actual inherited protected FD fact.
    pub rpc: NativeRpc<T::GlobalState>,
    /// The consumed original parent's state, scratch and deferred operation.
    pub parent: CopiedNativeParent<T>,
}

impl<T: Tool + 'static, R: HostRuntime> ToolHost<T, R>
where
    T::GlobalState: 'static,
{
    /// Transfer an existing native continuation to its real copied process.
    /// This does not construct a Tool, call a Tool policy selector, reset
    /// process scratch, or acquire either inherited registry/Tool-slot lock.
    ///
    /// All checks precede taking `deferred`. On refusal its original owner
    /// remains present; the caller must stop the child without attempting to
    /// complete/poison it through an inherited registry.
    ///
    /// # Safety
    /// The original native operation has really returned in a new independent
    /// copy-on-write address space on its child side. This is not a shared-VM
    /// child, a different thread in the same process, or an exec transition.
    /// The native owner must establish this from its actual operation/result
    /// and lifecycle, retain all existing copied-process restrictions, and
    /// supply the same live image with its actual child leader identity.
    /// No Rust Guest/future or native use of the original scratch may be live
    /// concurrently. `inherited_rpc` must be the original callback's actual
    /// connection owner, and `runtime` must be a fresh process-owned runtime.
    /// Its immutable authenticated route/config and published descriptor fact
    /// construct new RPC storage without entering its copied lock. No inherited
    /// connection frame is reused. Local consuming-fork policy is not
    /// selected by this native storage transfer. This grants no image or
    /// private-phase authority.
    pub unsafe fn rebind_copied_native_process(
        &self,
        deferred: &mut Option<DeferredNative<'_, T>>,
        services: &NativeServices<'_>,
        inherited_rpc: &NativeRpc<T::GlobalState>,
        runtime: R,
    ) -> io::Result<CopiedNativeProcess<T, R>> {
        let invocation = services.invocation();
        invocation.ensure_current()?;
        let child = invocation.identity();
        let inherited = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        let original = deferred
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        let parent = original.identity();
        if !original.owned_by(inherited)
            || child.physical_pid() == parent.physical_pid()
            || child.physical_pid() != child.physical_tid()
            || child.pid() != child.tid()
            || !child.same_image(parent)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let config = self.rpc.shared_config();
        if !Arc::ptr_eq(&config, inherited_rpc.shared_config()) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        // Existing native hosts adopt a legacy Tool once; selected ordinary
        // configurations retain their existing new_process/fork semantics.
        // Do not silently substitute this transfer for that consuming policy.
        if original.callback_tool().selected_configuration().is_some() {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        let (native_rpc, rpc) = inherited_rpc.for_copied_coordinator(parent, invocation)?;
        invocation.ensure_current()?;
        let parent = deferred
            .take()
            .expect("checked original native continuation")
            .into_copied_parent(child);
        let host = Self {
            tool: SpinMutex::new(Some(Arc::clone(&parent.tool))),
            rpc,
            root_pid: child.pid(),
            subscriptions: self.subscriptions.clone(),
            cpuid_interception: self.cpuid_interception,
            states: SpinMutex::new(HashMap::new()),
            native_threads: Some(NativeThreads::new()),
            ordinary_root_state: SpinMutex::new(None),
            runtime,
            #[cfg(feature = "exec-private-successor")]
            prepared_exec: SpinMutex::new(None),
            #[cfg(feature = "exec-native-injection")]
            native_exec_driver: None,
        };
        Ok(CopiedNativeProcess {
            host,
            rpc: native_rpc,
            parent,
        })
    }

    /// Finish the actual copied-child post-event without initializing its
    /// Tool state early. Some native owners deliver this returning event
    /// before the child's first subsequent application event, which owns the
    /// maintained initializer. Retain the whole original record through that
    /// gap; no inherited registry lock, Tool callback or socket I/O is used.
    ///
    /// Refusal leaves the affine parent in its original Option. Success takes
    /// it once and returns an unforgeable post-completed owner, not a flag that
    /// permits completing another callback or bypassing child initialization.
    ///
    /// # Safety
    /// The actual independent COW child has completed the original operation,
    /// all real post-event bookkeeping/register writes and every native use
    /// of its scratch. Its current image/task and live service table remain
    /// admitted. This must not be called at a synthetic post-event, on the
    /// parent side, or by a shared-VM/vfork child. The original copied parent
    /// must come from this fresh host's checked transfer, not a requested ID.
    pub unsafe fn complete_copied_native_post(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        parent: &mut Option<CopiedNativeParent<T>>,
    ) -> io::Result<PostCompletedCopiedNativeParent<T>> {
        let (_, tool) = self.native_initializer_owner(services, native_rpc)?;
        let original = parent
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        if services.invocation().identity() != original.child_identity()
            || !Arc::ptr_eq(&tool, &original.tool)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        services.invocation().ensure_current()?;
        Ok(PostCompletedCopiedNativeParent {
            parent: parent.take().expect("checked original copied post owner"),
        })
    }

    /// Run the later actual copied-child initializer after its real native
    /// post-event has completed. The existing eager initializer remains the
    /// sole Tool initialization implementation and retains the whole parent
    /// until the child's first real thread-start (without a new post-exec).
    ///
    /// Its temporary Active registry lease never escapes this method: the
    /// consumed witness already establishes native completion, so publishing
    /// that same initialized record does not replay an operation, manufacture
    /// another post-event or invoke a lifecycle hook. Original parent scratch
    /// remains retained for the real initializer/thread-start through the
    /// existing copied-parent record lifetime.
    ///
    /// # Safety
    /// This is the maintained later initialization boundary for the same live
    /// admitted COW child and authentic post-completed owner. All native
    /// allocator/TLS/task/image requirements and existing concrete Tool parent
    /// projection restrictions from initialize_copied_native_thread apply.
    pub unsafe fn initialize_postcompleted_copied_native_thread(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        parent: PostCompletedCopiedNativeParent<T>,
        prepare_parent: impl FnOnce(&mut T::ThreadState) -> io::Result<()>,
        project: impl FnOnce(&mut T::ThreadState, &T::ThreadState) -> io::Result<()>,
    ) -> io::Result<NativeThreadHandle> {
        let (handle, pending) = unsafe {
            self.initialize_copied_native_thread(
                services,
                native_rpc,
                parent.parent,
                prepare_parent,
                project,
            )?
        };
        unsafe {
            pending.complete(services.invocation())?;
        }
        Ok(handle)
    }

    /// Initialize the admitted copied child from the consumed original parent.
    /// The returned deferred owner still owns the exact original operation
    /// and its scratch; real native post-event bookkeeping must finish it.
    /// Child lifecycle remains thread-start once, without a new post-exec.
    ///
    /// # Safety
    /// The actual copied native owner must have completed the above transfer
    /// and all current allocator/TLS/task/image checks. `prepare_parent` and
    /// `project` supply only the existing concrete Tool's maintained parent
    /// and child projection; they may not replace the Tool or reset shared
    /// scratch. Existing copied-process/clone restrictions remain in force.
    pub unsafe fn initialize_copied_native_thread(
        &self,
        services: &NativeServices<'_>,
        native_rpc: &NativeRpc<T::GlobalState>,
        mut parent: CopiedNativeParent<T>,
        prepare_parent: impl FnOnce(&mut T::ThreadState) -> io::Result<()>,
        project: impl FnOnce(&mut T::ThreadState, &T::ThreadState) -> io::Result<()>,
    ) -> io::Result<(NativeThreadHandle, DeferredNative<'_, T>)> {
        let (owner, tool) = self.native_initializer_owner(services, native_rpc)?;
        let invocation = services.invocation();
        if invocation.identity() != parent.child_identity() || !Arc::ptr_eq(&tool, &parent.tool) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let reservation = owner.reserve(invocation.identity())?;
        let state = {
            let _allocation = super::super::alloc::enter_dispatch();
            let _active = super::super::support::ToolCallbackGuard::enter();
            native_rpc.prepare(invocation)?;
            let tail = TailResult::default();
            let application = native_rpc.application(invocation);
            let _route = super::super::native_rpc::NativeRpcScope::enter(&application, &tail);
            let parent_tid = reverie::Tid::from_raw(parent.parent_identity().tid().as_raw());
            let parent_state = parent.parent_state();
            prepare_parent(parent_state)?;
            let mut state = tool.init_thread_state(
                reverie::Tid::from_raw(invocation.identity().tid().as_raw()),
                Some((parent_tid, parent_state)),
            );
            project(&mut state, parent_state)?;
            state
        };
        let (current_owner, current_tool) = self.native_initializer_owner(services, native_rpc)?;
        if !std::ptr::eq(owner, current_owner) || !Arc::ptr_eq(&tool, &current_tool) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        reservation.publish_copied(state, parent)
    }
}
