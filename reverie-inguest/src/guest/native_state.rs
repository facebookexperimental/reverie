/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Exclusive callback state for a native in-process owner.
//!
//! The registry is held only while moving a record into or out of a lease.
//! No registry guard reaches Tool code, socket I/O or a native continuation.
//! This module supplies storage and lifetimes, not native admission or any
//! initial-image/successor authority.

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Pid;
use reverie::Tool;
use reverie::ToolProcess;

use super::super::native_rpc::NativeInvocation;
use super::CallbackLifecycle;
use super::LocalStack;
use crate::sync::SpinMutex;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Actual native process/thread/image facts, separate from Tool-visible IDs.
/// Copying these facts grants no callback or lifecycle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeThreadIdentity {
    physical_pid: Pid,
    physical_tid: Pid,
    pid: Pid,
    tid: Pid,
    image: u64,
}

impl NativeThreadIdentity {
    /// Retain facts already checked by a native image/thread owner.
    ///
    /// # Safety
    /// The caller must obtain these facts from the actual admitted native
    /// image and task, checking its live service table and image generation.
    /// Serialized configuration, requested IDs or a copied handle alone do
    /// not satisfy this contract. This creates no private-phase authority.
    pub unsafe fn from_admitted(
        physical_pid: Pid,
        physical_tid: Pid,
        pid: Pid,
        tid: Pid,
        image: u64,
    ) -> io::Result<Self> {
        if [physical_pid, physical_tid, pid, tid]
            .into_iter()
            .any(|id| id.as_raw() <= 0)
            || image == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self {
            physical_pid,
            physical_tid,
            pid,
            tid,
            image,
        })
    }

    /// The identity visible to the Tool for this process.
    pub fn pid(self) -> Pid {
        self.pid
    }

    /// The identity visible to the Tool for this thread.
    pub fn tid(self) -> Pid {
        self.tid
    }

    pub(super) fn same_image(self, other: Self) -> bool {
        self.image == other.image
    }

    /// The actual native process owning the callback, not a Tool-visible ID.
    pub fn physical_pid(self) -> Pid {
        self.physical_pid
    }

    /// The actual native thread owning the callback, not a Tool-visible ID.
    pub fn physical_tid(self) -> Pid {
        self.physical_tid
    }
}

/// An opaque registry locator. Its owner and sequence are checked on entry.
/// It carries no Rust pointer and is not admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeThreadHandle {
    owner: u64,
    sequence: u64,
}

/// A one-use clone of the actual parent's state, bound to this registry's
/// original parent sequence/image and the exact admitted child. There is no
/// public constructor or Clone implementation: copied numeric IDs do not
/// manufacture a parent snapshot.
pub struct NativeParentSnapshot<S> {
    owner: u64,
    parent_handle: NativeThreadHandle,
    parent: NativeThreadIdentity,
    child: NativeThreadIdentity,
    state: S,
}

impl<S> NativeParentSnapshot<S> {
    /// Admitted facts retained at the actual parent's clone boundary.
    pub fn parent_identity(&self) -> NativeThreadIdentity {
        self.parent
    }

    /// The one admitted child for which this snapshot was prepared.
    pub fn child_identity(&self) -> NativeThreadIdentity {
        self.child
    }

    pub(super) fn parts(&self) -> (reverie::Tid, &S) {
        (
            reverie::Tid::from_raw(self.parent.tid().as_raw()),
            &self.state,
        )
    }
}

/// Scratch retained by one actual callback/continuation, never by a process
/// global reset. Committed stack guards keep this same owner alive.
#[derive(Clone)]
pub struct CallbackScratch {
    committed: Arc<SpinMutex<Vec<Box<[u8]>>>>,
}

impl CallbackScratch {
    fn new() -> Self {
        Self {
            committed: Arc::new(SpinMutex::new(Vec::new())),
        }
    }

    /// A stack whose committed arena survives until this callback's real
    /// completion, or longer if an outstanding stack guard still owns it.
    pub fn stack(&self) -> LocalStack {
        LocalStack::with_callback_scratch(self.clone())
    }

    pub(super) fn retain(&self, arena: Box<[u8]>) {
        self.committed.lock().push(arena);
    }
}

pub(super) struct Record<S> {
    state: S,
    scratch: CallbackScratch,
    lifecycle: CallbackLifecycle,
    // The maintained copied-child initializer keeps its actual inherited
    // parent alive until the child's real lifecycle entry returns. Keeping
    // the whole record also retains the original scratch owner. It contains
    // no inherited registry guard or owner pointer.
    copied_parent: Option<Box<Record<S>>>,
}

enum Phase<S> {
    Initializing,
    InitializationFailed,
    Available(Box<Record<S>>),
    Active,
    // Keep the original state after an abandoned callback. Re-entry cannot
    // replace it with a default, and its lifecycle loss remains observable.
    Poisoned { _record: Box<Record<S>> },
    Retired,
}

struct Slot<S> {
    identity: NativeThreadIdentity,
    phase: Phase<S>,
}

struct Registry<S> {
    next: u64,
    slots: HashMap<u64, Slot<S>>,
}

pub(super) struct NativeThreads<S> {
    owner: u64,
    registry: SpinMutex<Registry<S>>,
}

impl<S> NativeThreads<S> {
    pub(super) fn new() -> Self {
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .expect("native callback owner sequence exhausted");
        Self {
            owner,
            registry: SpinMutex::new(Registry {
                next: 1,
                slots: HashMap::new(),
            }),
        }
    }

    pub(super) fn register(
        &self,
        identity: NativeThreadIdentity,
        state: S,
    ) -> io::Result<NativeThreadHandle> {
        self.register_with_lifecycle(identity, state, CallbackLifecycle::new(true, false))
    }

    pub(super) fn register_image(
        &self,
        identity: NativeThreadIdentity,
        state: S,
    ) -> io::Result<NativeThreadHandle> {
        self.register_with_lifecycle(identity, state, CallbackLifecycle::new(true, true))
    }

    fn register_with_lifecycle(
        &self,
        identity: NativeThreadIdentity,
        state: S,
        lifecycle: CallbackLifecycle,
    ) -> io::Result<NativeThreadHandle> {
        let mut registry = self
            .registry
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        if registry.slots.values().any(|slot| {
            !matches!(slot.phase, Phase::Retired)
                && slot.identity.physical_pid == identity.physical_pid
                && slot.identity.physical_tid == identity.physical_tid
        }) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        let sequence = registry.next;
        registry.next = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        registry.slots.insert(
            sequence,
            Slot {
                identity,
                phase: Phase::Available(Box::new(Record {
                    state,
                    scratch: CallbackScratch::new(),
                    lifecycle,
                    copied_parent: None,
                })),
            },
        );
        Ok(NativeThreadHandle {
            owner: self.owner,
            sequence,
        })
    }

    /// Reserve before Tool initialization, so neither a failed initializer nor
    /// a second caller can initialize the same admitted task/image twice.
    pub(super) fn reserve(
        &self,
        identity: NativeThreadIdentity,
    ) -> io::Result<NativeInitialization<'_, S>> {
        let mut registry = self
            .registry
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        if registry.slots.values().any(|slot| {
            slot.identity == identity
                || (!matches!(slot.phase, Phase::Retired)
                    && slot.identity.physical_pid == identity.physical_pid
                    && slot.identity.physical_tid == identity.physical_tid)
        }) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        let sequence = registry.next;
        registry.next = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        registry.slots.insert(
            sequence,
            Slot {
                identity,
                phase: Phase::Initializing,
            },
        );
        Ok(NativeInitialization {
            owner: self,
            handle: NativeThreadHandle {
                owner: self.owner,
                sequence,
            },
            identity,
            published: false,
        })
    }

    pub(super) fn check_parent(
        &self,
        parent: &NativeParentSnapshot<S>,
        child: NativeThreadIdentity,
    ) -> io::Result<()> {
        if parent.owner != self.owner || parent.child != child || parent.parent.image != child.image
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let mut registry = self
            .registry
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let slot = self.checked_slot(&mut registry, parent.parent_handle, parent.parent)?;
        match &slot.phase {
            // A genuine snapshot may outlive its parent's normal retirement.
            // The original sequence/image remains in this registry; no new
            // state or authority is reconstructed from a reused physical TID.
            Phase::Available(_) | Phase::Active | Phase::Retired => Ok(()),
            Phase::Initializing => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Phase::InitializationFailed | Phase::Poisoned { .. } => {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
        }
    }

    fn checked_slot<'a>(
        &self,
        registry: &'a mut Registry<S>,
        handle: NativeThreadHandle,
        identity: NativeThreadIdentity,
    ) -> io::Result<&'a mut Slot<S>> {
        if handle.owner != self.owner {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let slot = registry
            .slots
            .get_mut(&handle.sequence)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        if slot.identity != identity {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(slot)
    }

    fn enter(
        &self,
        handle: NativeThreadHandle,
        identity: NativeThreadIdentity,
    ) -> io::Result<StateLease<'_, S>> {
        let mut registry = self
            .registry
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let slot = self.checked_slot(&mut registry, handle, identity)?;
        match &slot.phase {
            Phase::Available(_) => {}
            Phase::Active | Phase::Initializing => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            Phase::InitializationFailed => return Err(io::Error::from_raw_os_error(libc::EIO)),
            Phase::Poisoned { .. } => return Err(io::Error::from_raw_os_error(libc::EIO)),
            Phase::Retired => return Err(io::Error::from_raw_os_error(libc::ESTALE)),
        }
        let Phase::Available(mut record) = std::mem::replace(&mut slot.phase, Phase::Active) else {
            unreachable!("available phase checked under the same registry guard")
        };
        // The previous callback has really completed. Outstanding stack
        // guards, if any, still own the previous scratch independently.
        record.scratch = CallbackScratch::new();
        drop(registry);
        Ok(StateLease {
            owner: self,
            handle,
            identity,
            record: Some(record),
            _same_thread: PhantomData,
        })
    }

    pub(super) fn ensure_retired(&self) -> io::Result<()> {
        let registry = self
            .registry
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        for slot in registry.slots.values() {
            match &slot.phase {
                Phase::Retired => {}
                Phase::Poisoned { .. } | Phase::InitializationFailed => {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                Phase::Available(_) | Phase::Active | Phase::Initializing => {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
            }
        }
        Ok(())
    }

    pub(super) fn retire(
        &self,
        handle: NativeThreadHandle,
        identity: NativeThreadIdentity,
    ) -> io::Result<S> {
        let mut registry = self
            .registry
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let slot = self.checked_slot(&mut registry, handle, identity)?;
        match &slot.phase {
            Phase::Available(_) => {}
            Phase::Active | Phase::Initializing => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            Phase::InitializationFailed => return Err(io::Error::from_raw_os_error(libc::EIO)),
            Phase::Poisoned { .. } => return Err(io::Error::from_raw_os_error(libc::EIO)),
            Phase::Retired => return Err(io::Error::from_raw_os_error(libc::ESTALE)),
        }
        let Phase::Available(record) = std::mem::replace(&mut slot.phase, Phase::Retired) else {
            unreachable!("available phase checked under the same registry guard")
        };
        Ok(record.state)
    }
}

pub(super) struct NativeInitialization<'owner, S> {
    owner: &'owner NativeThreads<S>,
    handle: NativeThreadHandle,
    identity: NativeThreadIdentity,
    published: bool,
}

impl<S> NativeInitialization<'_, S> {
    pub(super) fn publish(
        mut self,
        state: S,
        lifecycle: CallbackLifecycle,
    ) -> io::Result<NativeThreadHandle> {
        let mut registry = self.owner.registry.lock();
        let slot = self
            .owner
            .checked_slot(&mut registry, self.handle, self.identity)?;
        if !matches!(slot.phase, Phase::Initializing) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        slot.phase = Phase::Available(Box::new(Record {
            state,
            scratch: CallbackScratch::new(),
            lifecycle,
            copied_parent: None,
        }));
        self.published = true;
        Ok(self.handle)
    }
}

impl<S> Drop for NativeInitialization<'_, S> {
    fn drop(&mut self) {
        if !self.published {
            let mut registry = self.owner.registry.lock();
            let slot = registry
                .slots
                .get_mut(&self.handle.sequence)
                .expect("reserved native initializer slot");
            // Failure is terminal for this exact admitted identity. A later
            // caller cannot silently manufacture a default or rerun Tool init.
            slot.phase = Phase::InitializationFailed;
        }
    }
}

struct StateLease<'owner, S> {
    owner: &'owner NativeThreads<S>,
    handle: NativeThreadHandle,
    identity: NativeThreadIdentity,
    record: Option<Box<Record<S>>>,
    _same_thread: PhantomData<*mut ()>,
}

impl<S> StateLease<'_, S> {
    fn retire(mut self, identity: NativeThreadIdentity) -> io::Result<S> {
        let mut registry = self.owner.registry.lock();
        let slot = self
            .owner
            .checked_slot(&mut registry, self.handle, identity)?;
        if !matches!(slot.phase, Phase::Active) || identity != self.identity {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        slot.phase = Phase::Retired;
        Ok(self.record.take().expect("live callback record").state)
    }

    fn complete(mut self, identity: NativeThreadIdentity) -> io::Result<()> {
        let mut registry = self.owner.registry.lock();
        let slot = self
            .owner
            .checked_slot(&mut registry, self.handle, identity)?;
        if !matches!(slot.phase, Phase::Active) || identity != self.identity {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        slot.phase = Phase::Available(self.record.take().expect("live callback record"));
        Ok(())
    }
}

impl<S> Drop for StateLease<'_, S> {
    fn drop(&mut self) {
        if let Some(record) = self.record.take() {
            let mut registry = self.owner.registry.lock();
            // This lease is the sole owner of the active slot. Keep the
            // original record poisoned instead of silently publishing it.
            let slot = registry
                .slots
                .get_mut(&self.handle.sequence)
                .expect("live callback registry slot");
            slot.phase = Phase::Poisoned { _record: record };
        }
    }
}

type NativeDispatchParts<'a, T> = (
    &'a ToolProcess<T>,
    &'a mut <T as Tool>::ThreadState,
    &'a mut CallbackLifecycle,
    CallbackScratch,
    &'a mut Option<Box<Record<<T as Tool>::ThreadState>>>,
);

/// The one Tool pin and exclusive thread state held by a native callback.
/// No process registry or Tool-slot guard lives in this value.
pub struct NativeCallbackLease<'owner, T: Tool> {
    pub(super) tool: Arc<ToolProcess<T>>,
    state: StateLease<'owner, T::ThreadState>,
}

impl<'owner, T: Tool> NativeCallbackLease<'owner, T> {
    pub(super) fn new(
        tool: Arc<ToolProcess<T>>,
        owner: &'owner NativeThreads<T::ThreadState>,
        handle: NativeThreadHandle,
        identity: NativeThreadIdentity,
    ) -> io::Result<Self> {
        Ok(Self {
            tool,
            state: owner.enter(handle, identity)?,
        })
    }

    /// Borrow the existing Tool and the sole mutable state for common Guest
    /// construction; no new Tool or lifecycle callback is manufactured here.
    pub fn parts(&mut self) -> (&T, &mut T::ThreadState) {
        (
            self.tool.as_ref().as_ref().expect("pinned live Tool"),
            &mut self
                .state
                .record
                .as_mut()
                .expect("live callback record")
                .state,
        )
    }

    pub(super) fn owned_by(&self, owner: &NativeThreads<T::ThreadState>) -> bool {
        std::ptr::eq(self.state.owner, owner)
    }

    pub(super) fn snapshot_child(
        &mut self,
        child: NativeThreadIdentity,
        prepare: impl FnOnce(&mut T::ThreadState) -> io::Result<()>,
    ) -> io::Result<NativeParentSnapshot<T::ThreadState>>
    where
        T::ThreadState: Clone,
    {
        if child.image != self.state.identity.image {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let record = self
            .state
            .record
            .as_mut()
            .expect("live parent callback record");
        prepare(&mut record.state)?;
        Ok(NativeParentSnapshot {
            owner: self.state.owner.owner,
            parent_handle: self.state.handle,
            parent: self.state.identity,
            child,
            state: record.state.clone(),
        })
    }

    pub(super) fn dispatch_parts(&mut self) -> NativeDispatchParts<'_, T> {
        let record = self.state.record.as_mut().expect("live callback record");
        (
            &self.tool,
            &mut record.state,
            &mut record.lifecycle,
            record.scratch.clone(),
            &mut record.copied_parent,
        )
    }

    /// The actual identity checked when this callback entered.
    pub fn identity(&self) -> NativeThreadIdentity {
        self.state.identity
    }

    /// A stack owned by this callback, independent of every sibling callback.
    pub fn stack(&self) -> LocalStack {
        self.state
            .record
            .as_ref()
            .expect("live callback record")
            .scratch
            .stack()
    }

    /// Complete a callback only after all its native use of scratch finished.
    ///
    /// # Safety
    /// All common Guest borrows/futures must have ended and the native owner
    /// must have completed any deferred syscall/signal using this callback's
    /// storage. Merely returning from the Rust Tool is insufficient.
    pub unsafe fn complete(self, identity: NativeThreadIdentity) -> io::Result<()> {
        self.state.complete(identity)
    }
}

/// The original copied-address-space continuation, detached without locking
/// an inherited registry. No public constructor or Clone exists. The real
/// copied-child owner must initialize and publish it into one fresh registry;
/// it is not a parent snapshot for a requested or unrelated task.
pub struct CopiedNativeParent<T: Tool> {
    pub(super) tool: Arc<ToolProcess<T>>,
    parent: NativeThreadIdentity,
    child: NativeThreadIdentity,
    record: Box<Record<T::ThreadState>>,
    number: i64,
    args: [u64; 6],
    _same_thread: PhantomData<*mut ()>,
}

/// The original copied-parent record after its actual child-side post-event
/// has stopped using the deferred operation and scratch. It still owns the
/// same Tool, state and arenas until the later real child initialization and
/// thread-start. No public constructor, Clone or serialized flag can create
/// this witness; shared-VM children cannot obtain its prerequisite parent.
pub struct PostCompletedCopiedNativeParent<T: Tool> {
    pub(super) parent: CopiedNativeParent<T>,
}

impl<T: Tool> CopiedNativeParent<T> {
    pub(super) fn parent_identity(&self) -> NativeThreadIdentity {
        self.parent
    }

    pub(super) fn child_identity(&self) -> NativeThreadIdentity {
        self.child
    }

    pub(super) fn parent_state(&mut self) -> &mut T::ThreadState {
        &mut self.record.state
    }
}

impl<'owner, S> NativeInitialization<'owner, S> {
    pub(super) fn publish_copied<T: Tool<ThreadState = S>>(
        mut self,
        state: S,
        parent: CopiedNativeParent<T>,
    ) -> io::Result<(NativeThreadHandle, DeferredNative<'owner, T>)> {
        if self.identity != parent.child {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let mut registry = self.owner.registry.lock();
        let slot = self
            .owner
            .checked_slot(&mut registry, self.handle, self.identity)?;
        if !matches!(slot.phase, Phase::Initializing) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        // Its original native operation already returned in this real child,
        // but still owns scratch through clone/exec/register bookkeeping. Do
        // not publish Available or call enter(), which would reset scratch.
        slot.phase = Phase::Active;
        drop(registry);
        self.published = true;
        let CopiedNativeParent {
            tool,
            record,
            number,
            args,
            ..
        } = parent;
        let callback = NativeCallbackLease {
            tool,
            state: StateLease {
                owner: self.owner,
                handle: self.handle,
                identity: self.identity,
                record: Some(Box::new(Record {
                    state,
                    scratch: record.scratch.clone(),
                    lifecycle: CallbackLifecycle::new(true, false),
                    copied_parent: Some(record),
                })),
                _same_thread: PhantomData,
            },
        };
        Ok((self.handle, DeferredNative::new(callback, number, args)))
    }
}

/// A deferred native operation owns the original active state lease and its
/// scratch after every Rust Guest/future has ended. It is affine and remains
/// on this callback's thread. Dropping it without completion poisons the slot.
pub struct DeferredNative<'owner, T: Tool> {
    callback: NativeCallbackLease<'owner, T>,
    number: i64,
    args: [u64; 6],
}

impl<'owner, T: Tool> DeferredNative<'owner, T> {
    pub(super) fn new(
        callback: NativeCallbackLease<'owner, T>,
        number: i64,
        args: [u64; 6],
    ) -> Self {
        Self {
            callback,
            number,
            args,
        }
    }

    pub(super) fn callback_mut(&mut self) -> &mut NativeCallbackLease<'owner, T> {
        &mut self.callback
    }

    /// Exact operation to apply through the native owner's existing deferred
    /// path, not a second raw-syscall implementation.
    pub fn operation(&self) -> (i64, [u64; 6]) {
        (self.number, self.args)
    }

    pub(super) fn owned_by(&self, owner: &NativeThreads<T::ThreadState>) -> bool {
        self.callback.owned_by(owner)
    }

    pub(super) fn identity(&self) -> NativeThreadIdentity {
        self.callback.identity()
    }

    pub(super) fn callback_tool(&self) -> &ToolProcess<T> {
        &self.callback.tool
    }

    // Only the checked copied-address-space constructor may detach this
    // original active record. Taking it makes StateLease::drop a no-op; the
    // inherited registry may contain a lock held by a vanished sibling.
    pub(super) fn into_copied_parent(self, child: NativeThreadIdentity) -> CopiedNativeParent<T> {
        let NativeCallbackLease { tool, mut state } = self.callback;
        CopiedNativeParent {
            tool,
            parent: state.identity,
            child,
            record: state
                .record
                .take()
                .expect("original copied callback record"),
            number: self.number,
            args: self.args,
            _same_thread: PhantomData,
        }
    }

    /// Reuse this exact active state and scratch during its genuine returning
    /// post-event. This does not open a new callback or clear its arenas.
    ///
    /// # Safety
    /// The original native operation has returned and the real post-event
    /// owner now needs Tool work for its child/failed-exec bookkeeping. The
    /// same task/image/context and all original scratch storage remain live.
    /// No replacement event or serialized completion flag is authority.
    pub(super) unsafe fn into_post_event(
        self,
        invocation: NativeInvocation<'_>,
    ) -> io::Result<NativeCallbackLease<'owner, T>> {
        invocation.ensure_current()?;
        if invocation.identity() != self.callback.identity() {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(self.callback)
    }

    /// Publish the original state only after the native operation and its
    /// bookkeeping have really completed. No numeric completion flag suffices.
    ///
    /// # Safety
    /// The actual native post-event owner must call this with the same live
    /// image/thread after its operation has stopped using all scratch. All
    /// returned registers, clone/exec/signal bookkeeping and original post
    /// latches must already be committed. The callback cannot be reconstructed.
    pub unsafe fn complete(self, invocation: NativeInvocation<'_>) -> io::Result<()> {
        invocation.ensure_current()?;
        if invocation.identity() != self.callback.identity() {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        unsafe { self.callback.complete(invocation.identity()) }
    }

    /// Transfer the original state to the actual consuming thread-exit owner
    /// when a nonreturning native operation retires this task instead.
    ///
    /// # Safety
    /// Native exit admission, no-future/no-scratch-use and quiescence must be
    /// established by the original native lifecycle owner. The returned state
    /// must pass through the existing Tool thread/process finalization once.
    pub unsafe fn retire(
        self,
        identity: NativeThreadIdentity,
    ) -> io::Result<(Arc<ToolProcess<T>>, T::ThreadState)> {
        let NativeCallbackLease { tool, state } = self.callback;
        Ok((tool, state.retire(identity)?))
    }
}
