/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Private callback lifetime and driver-owned failure registration.
//!
//! This module never publishes a Tool failure or settles executor effects.
//! Capturing returns a notification to send after the entry gate lock is gone.
//! The lexical scope guards must likewise be dropped outside entry/Tool locks.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use futures::FutureExt;
use futures::channel::oneshot;
use futures::future::Shared;

use super::PendingFailure;
use crate::Error;
use crate::Result;

pub(crate) type OwnerSubscription = Shared<oneshot::Receiver<()>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DriverLifecycle {
    Active,
    /// Capture registration was closed, not publication or effect settlement.
    Retired,
    /// The lexical owner was lost or attempted to retire a live callback.
    Abandoned,
}

/// Retained by origins, but never owns a pending cause or DriverState.
struct RetirementWitness {
    lifecycle: AtomicU8,
}

impl RetirementWitness {
    fn lifecycle(&self) -> DriverLifecycle {
        match self.lifecycle.load(Ordering::Acquire) {
            value if value == DriverLifecycle::Active as u8 => DriverLifecycle::Active,
            value if value == DriverLifecycle::Retired as u8 => DriverLifecycle::Retired,
            value if value == DriverLifecycle::Abandoned as u8 => DriverLifecycle::Abandoned,
            _ => unreachable!("invalid driver lifecycle"),
        }
    }

    // The driver's data mutex serializes every lifecycle transition with
    // capture, generation creation and callback destruction.
    fn close(&self, lifecycle: DriverLifecycle) {
        self.lifecycle.store(lifecycle as u8, Ordering::Release);
    }
}

struct Change {
    sender: oneshot::Sender<()>,
    receiver: OwnerSubscription,
}

impl Change {
    fn new() -> Self {
        let (sender, receiver) = oneshot::channel();
        Self {
            sender,
            receiver: receiver.shared(),
        }
    }
}

/// A private wake requests a pending/lifecycle recheck. It is not publication.
/// Dropping this value also disconnects receivers, so move it out of the gate
/// lock before either notifying or dropping it.
#[must_use = "notify only after releasing the entry gate and owner locks"]
pub(crate) struct OwnerNotification {
    previous: Option<Change>,
    // The upgrade may become the last owner after capture unlocks its mutex.
    // Its current sender must not be dropped while the caller holds the gate.
    keepalive: Option<Arc<DriverState>>,
}

impl OwnerNotification {
    pub(crate) fn notify(self) {
        let Self {
            previous,
            keepalive,
        } = self;
        if let Some(previous) = previous {
            let _ = previous.sender.send(());
            // Drop the old Shared receiver outside the owner lock too.
            drop(previous.receiver);
        }
        drop(keepalive);
    }
}

impl std::fmt::Debug for OwnerNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerNotification")
            .field("has_change", &self.previous.is_some())
            .field("keeps_owner_alive", &self.keepalive.is_some())
            .finish()
    }
}

struct OwnerData {
    next_callback: u64,
    callbacks: BTreeSet<u64>,
    pending: Vec<Arc<PendingFailure>>,
    change: Change,
    /// Whether anyone took the current `change` receiver since it was armed.
    /// Only then does a change complete it and arm the next one: nearly every
    /// change (a callback scope's end, on every guest syscall) has no watcher,
    /// and arming allocates a channel and a shared future.
    change_subscribed: bool,
    /// The generation of the last destroyed callback scope, kept so the next
    /// callback can reuse its allocation. It is reused only when this is the
    /// last reference to it (`Arc::get_mut`), so no origin, waiter or nested
    /// callback can observe the reuse; a reused generation gets a fresh
    /// identity and is reset to the state `Arc::new` would give it.
    spare_generation: Option<Arc<CallbackGeneration>>,
}

impl OwnerData {
    fn changed(&mut self) -> OwnerNotification {
        let previous = std::mem::take(&mut self.change_subscribed)
            .then(|| std::mem::replace(&mut self.change, Change::new()));
        OwnerNotification {
            previous,
            keepalive: None,
        }
    }

    /// Every subscriber goes through here, so the next change completes it.
    fn subscribe(&mut self) -> OwnerSubscription {
        self.change_subscribed = true;
        self.change.receiver.clone()
    }
}

struct DriverState {
    witness: Arc<RetirementWitness>,
    data: Mutex<OwnerData>,
    /// Whether `data.pending` is nonempty. Written under the `data` mutex
    /// with every change to `pending`, so [`DriverOwner::pending`], which
    /// every entry and callback checks and which is nearly always empty,
    /// can skip the mutex. A check that reads false is ordered before any
    /// capture still in progress, as it would be had it taken the mutex
    /// first.
    has_pending: AtomicBool,
}

/// One lexical guard per actual invocation/worker. Clone DriverOwner, not this.
#[must_use = "retain the lexical driver scope until registration is retired"]
pub(crate) struct DriverScope {
    state: Option<Arc<DriverState>>,
}

#[derive(Clone)]
pub(crate) struct DriverOwner {
    state: Arc<DriverState>,
}

/// Closing registration returns every queued cause to its existing owner.
/// Even a successful result says nothing about Tool publication or effects.
#[must_use = "retain pending causes and deliver the deferred notification"]
pub(crate) struct DriverRetirement {
    pub(crate) lifecycle: DriverLifecycle,
    pub(crate) pending: Vec<Arc<PendingFailure>>,
    pub(crate) notification: OwnerNotification,
    pub(crate) result: Result<()>,
}

impl DriverScope {
    pub(crate) fn new() -> Self {
        Self {
            state: Some(Arc::new(DriverState {
                witness: Arc::new(RetirementWitness {
                    lifecycle: AtomicU8::new(DriverLifecycle::Active as u8),
                }),
                data: Mutex::new(OwnerData {
                    next_callback: 0,
                    callbacks: BTreeSet::new(),
                    pending: Vec::new(),
                    change: Change::new(),
                    change_subscribed: false,
                    spare_generation: None,
                }),
                has_pending: AtomicBool::new(false),
            })),
        }
    }

    pub(crate) fn owner(&self) -> DriverOwner {
        DriverOwner {
            state: self.state.as_ref().unwrap().clone(),
        }
    }

    pub(crate) fn retire(mut self) -> DriverRetirement {
        let state = self.state.take().unwrap();
        let mut data = state.data.lock().unwrap();
        let (lifecycle, result) = if data.callbacks.is_empty() {
            (DriverLifecycle::Retired, Ok(()))
        } else {
            (
                DriverLifecycle::Abandoned,
                Err(protocol("driver retired with a live callback")),
            )
        };
        state.witness.close(lifecycle);
        let pending = std::mem::take(&mut data.pending);
        state.has_pending.store(false, Ordering::Release);
        let notification = data.changed();
        drop(data);
        DriverRetirement {
            lifecycle,
            pending,
            notification,
            result,
        }
    }
}

impl Drop for DriverScope {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        let notification = {
            let mut data = state.data.lock().unwrap();
            state.witness.close(DriverLifecycle::Abandoned);
            // A surviving DriverOwner can still take these causes. The
            // witness remains Abandoned if no owner survives; never success.
            data.changed()
        };
        notification.notify();
    }
}

impl DriverOwner {
    pub(crate) fn lifecycle(&self) -> DriverLifecycle {
        self.state.witness.lifecycle()
    }

    /// Subscribe before rechecking pending causes or lifecycle. Readiness,
    /// including a disconnected sender, authorizes only that recheck.
    pub(crate) fn subscribe(&self) -> OwnerSubscription {
        self.state.data.lock().unwrap().subscribe()
    }

    pub(crate) fn pending(&self) -> Vec<Arc<PendingFailure>> {
        if !self.state.has_pending.load(Ordering::Acquire) {
            return Vec::new();
        }
        self.state.data.lock().unwrap().pending.clone()
    }

    /// Transfer obligations to this driver's outer error path, not a peer.
    #[cfg(test)]
    pub(crate) fn take_pending(&self) -> Vec<Arc<PendingFailure>> {
        let mut data = self.state.data.lock().unwrap();
        self.state.has_pending.store(false, Ordering::Release);
        std::mem::take(&mut data.pending)
    }

    pub(crate) fn origin(&self) -> OperationOrigin {
        OperationOrigin {
            owner: Arc::downgrade(&self.state),
            witness: self.state.witness.clone(),
            callback: None,
        }
    }

    pub(crate) fn begin_callback(&self, parent: Option<&OperationOrigin>) -> Result<CallbackScope> {
        let mut data = self.state.data.lock().unwrap();
        if self.lifecycle() != DriverLifecycle::Active {
            return Err(protocol(
                "callback started after driver registration closed",
            ));
        }
        let parent = match parent {
            None => None,
            Some(origin) => {
                if !Arc::ptr_eq(&origin.witness, &self.state.witness) {
                    return Err(protocol("nested callback belongs to another driver"));
                }
                let Some(callback) = &origin.callback else {
                    return Err(protocol("nested callback has no enclosing generation"));
                };
                let mut enclosing = Some(callback.as_ref());
                while let Some(generation) = enclosing {
                    if generation.destroyed.load(Ordering::Acquire)
                        || !data.callbacks.contains(&generation.id)
                    {
                        return Err(protocol("nested callback used a destroyed generation"));
                    }
                    enclosing = generation.parent.as_deref();
                }
                Some(callback.clone())
            }
        };
        let id = data
            .next_callback
            .checked_add(1)
            .ok_or_else(|| protocol("callback identity exhausted"))?;
        // Reuse the last destroyed generation's allocation only while nothing
        // else refers to it: then no one can tell it from a new one. Its old
        // parent is moved out here and dropped after the owner lock.
        let mut released = None;
        let mut spare = data.spare_generation.take();
        let callback = match spare.as_mut().and_then(Arc::get_mut) {
            Some(reused) => {
                released = reused.reset(id, parent);
                spare.take().expect("reused spare generation")
            }
            // A shared spare stays with its other holders.
            None => Arc::new(CallbackGeneration::new(id, parent)),
        };
        data.next_callback = id;
        data.callbacks.insert(id);
        drop(data);
        drop(released);
        drop(spare);
        Ok(CallbackScope {
            origin: OperationOrigin {
                callback: Some(callback),
                ..self.origin()
            },
        })
    }
}

struct CallbackGeneration {
    id: u64,
    destroyed: AtomicBool,
    /// Created by the first waiter only. Almost no callback is ever awaited,
    /// and creating the channel and its shared receiver for every callback
    /// cost three allocations per guest syscall. The scope's destructor
    /// stores `destroyed` before it takes this lock, and a waiter rechecks
    /// `destroyed` after it releases this lock, so either the waiter sees the
    /// destruction or the destructor finds and completes its channel.
    destroyed_notification: Mutex<Option<DestroyedNotification>>,
    parent: Option<Arc<CallbackGeneration>>,
}

struct DestroyedNotification {
    sender: Option<oneshot::Sender<()>>,
    receiver: OwnerSubscription,
}

impl CallbackGeneration {
    fn new(id: u64, parent: Option<Arc<CallbackGeneration>>) -> Self {
        Self {
            id,
            destroyed: AtomicBool::new(false),
            destroyed_notification: Mutex::new(None),
            parent,
        }
    }

    /// Give a uniquely owned generation the state [`CallbackGeneration::new`]
    /// would, returning its previous parent for the caller to drop outside
    /// its locks.
    fn reset(
        &mut self,
        id: u64,
        parent: Option<Arc<CallbackGeneration>>,
    ) -> Option<Arc<CallbackGeneration>> {
        self.id = id;
        *self.destroyed.get_mut() = false;
        *self
            .destroyed_notification
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        std::mem::replace(&mut self.parent, parent)
    }

    /// Subscribe before rechecking `destroyed`.
    fn subscribe_destroyed(&self) -> OwnerSubscription {
        let mut notification = self
            .destroyed_notification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        notification
            .get_or_insert_with(|| {
                let (sender, receiver) = oneshot::channel();
                DestroyedNotification {
                    sender: Some(sender),
                    receiver: receiver.shared(),
                }
            })
            .receiver
            .clone()
    }

    /// Called after `destroyed` was stored. Returns the sender to complete
    /// once the caller holds no lock.
    fn take_destroyed_sender(&self) -> Option<oneshot::Sender<()>> {
        self.destroyed_notification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
            .and_then(|notification| notification.sender.take())
    }
}

/// Drop this guard only after dropping the owned callback future and its
/// nested/inline futures. The guard does not own or drop those futures itself.
/// Unwind records destruction; neither path settles effects or calls a Tool.
#[must_use = "keep the scope outside and alive through its owned callback future"]
pub(crate) struct CallbackScope {
    origin: OperationOrigin,
}

impl CallbackScope {
    pub(crate) fn origin(&self) -> OperationOrigin {
        self.origin.clone()
    }
}

impl std::fmt::Debug for CallbackScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackScope")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Drop for CallbackScope {
    fn drop(&mut self) {
        let generation = self.origin.callback.take().unwrap();
        let mut released = None;
        let notification = self.origin.owner.upgrade().map(|owner| {
            let mut data = owner.data.lock().unwrap();
            let removed = data.callbacks.remove(&generation.id);
            debug_assert!(removed, "unique callback scope was already removed");
            generation.destroyed.store(true, Ordering::Release);
            // Keep this generation for the next callback's allocation. The
            // one it replaces is dropped below, outside the owner lock.
            released = data.spare_generation.replace(generation.clone());
            data.changed()
        });
        // The lexical driver may already have been abandoned and destroyed.
        // The retained generation still records actual callback destruction.
        generation.destroyed.store(true, Ordering::Release);
        if let Some(sender) = generation.take_destroyed_sender() {
            let _ = sender.send(());
        }
        drop(generation);
        drop(released);
        if let Some(notification) = notification {
            notification.notify();
        }
    }
}

/// No strong path from an origin back to DriverState. PendingFailure may own
/// this value while the driver owns that pending failure without a cycle.
#[derive(Clone)]
pub(crate) struct OperationOrigin {
    owner: Weak<DriverState>,
    witness: Arc<RetirementWitness>,
    callback: Option<Arc<CallbackGeneration>>,
}

impl std::fmt::Debug for OperationOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationOrigin")
            .field("lifecycle", &self.lifecycle())
            .field(
                "callback",
                &self.callback.as_ref().map(|callback| callback.id),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct CaptureRejected {
    pub(crate) failure: Arc<PendingFailure>,
    #[cfg(test)]
    pub(crate) lifecycle: DriverLifecycle,
    #[cfg(test)]
    pub(crate) owner_available: bool,
    /// Defer this even when rejecting capture: it may retain the last owner.
    pub(crate) notification: OwnerNotification,
}

impl OperationOrigin {
    /// Observe the existing driver without registering a new callback or
    /// acquiring a publisher. The caller must retain this only for its own
    /// operation lifetime; origins and pending failures still point weakly.
    pub(crate) fn driver_owner(&self) -> Option<DriverOwner> {
        self.owner.upgrade().map(|state| DriverOwner { state })
    }

    /// Subscribe before inspecting lifecycle. Disconnection is only a reason
    /// to recheck abandonment, never evidence of completed publication.
    pub(crate) fn subscribe(&self) -> Option<OwnerSubscription> {
        self.owner
            .upgrade()
            .map(|owner| owner.data.lock().unwrap().subscribe())
    }

    pub(crate) fn lifecycle(&self) -> DriverLifecycle {
        self.witness.lifecycle()
    }

    /// An identity is meaningful only together with this driver's identity.
    #[cfg(test)]
    pub(crate) fn callback_id(&self) -> Option<u64> {
        self.callback.as_ref().map(|callback| callback.id)
    }

    pub(crate) fn same_driver(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.witness, &other.witness)
    }

    /// Origins without callback receipts do not identify a callback.
    #[cfg(test)]
    pub(crate) fn same_callback(&self, other: &Self) -> bool {
        self.same_driver(other)
            && match (&self.callback, &other.callback) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }

    /// No callback means there is no callback destruction to await. Driver
    /// retirement and executor settlement must still be checked independently.
    #[cfg(test)]
    pub(crate) fn callback_dropped(&self) -> bool {
        let mut callback = self.callback.as_deref();
        while let Some(generation) = callback {
            if !generation.destroyed.load(Ordering::Acquire) {
                return false;
            }
            callback = generation.parent.as_deref();
        }
        true
    }

    pub(crate) async fn wait_callback_drop(&self) -> Result<()> {
        let mut callback = self.callback.clone();
        while let Some(generation) = callback {
            if !generation.destroyed.load(Ordering::Acquire) {
                let destroyed = generation.subscribe_destroyed();
                if !generation.destroyed.load(Ordering::Acquire) {
                    let _ = destroyed.await;
                    if !generation.destroyed.load(Ordering::Acquire) {
                        return Err(protocol("callback notification lost before destruction"));
                    }
                }
            }
            callback = generation.parent.clone();
        }
        Ok(())
    }

    /// Call while capturing the gate's pending cause. No notification is sent
    /// here: the returned notification must be delivered after the gate lock.
    /// Rejection returns the same typed Arc; the caller still owns that cause.
    pub(crate) fn capture(
        &self,
        failure: Arc<PendingFailure>,
    ) -> std::result::Result<OwnerNotification, CaptureRejected> {
        #[cfg(test)]
        {
            self.capture_inner(failure, || {})
        }
        #[cfg(not(test))]
        {
            self.capture_inner(failure)
        }
    }

    fn capture_inner(
        &self,
        failure: Arc<PendingFailure>,
        #[cfg(test)] after_unlock: impl FnOnce(),
    ) -> std::result::Result<OwnerNotification, CaptureRejected> {
        let Some(owner) = self.owner.upgrade() else {
            return Err(CaptureRejected {
                failure,
                #[cfg(test)]
                lifecycle: self.lifecycle(),
                #[cfg(test)]
                owner_available: false,
                notification: OwnerNotification {
                    previous: None,
                    keepalive: None,
                },
            });
        };
        let mut data = owner.data.lock().unwrap();
        let lifecycle = self.lifecycle();
        if lifecycle != DriverLifecycle::Active {
            drop(data);
            #[cfg(test)]
            after_unlock();
            return Err(CaptureRejected {
                failure,
                #[cfg(test)]
                lifecycle,
                #[cfg(test)]
                owner_available: true,
                notification: OwnerNotification {
                    previous: None,
                    keepalive: Some(owner),
                },
            });
        }
        let mut notification = if data
            .pending
            .iter()
            .any(|pending| Arc::ptr_eq(pending, &failure))
        {
            OwnerNotification {
                previous: None,
                keepalive: None,
            }
        } else {
            data.pending.push(failure);
            owner.has_pending.store(true, Ordering::Release);
            data.changed()
        };
        drop(data);
        #[cfg(test)]
        after_unlock();
        notification.keepalive = Some(owner);
        Ok(notification)
    }
}

fn protocol(operation: &'static str) -> Error {
    Error::EntryControl {
        operation,
        source: std::io::Error::other(operation),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Wake;
    use std::task::Waker;

    use super::*;

    fn cause() -> Arc<PendingFailure> {
        super::super::EntryGate::new().poison(None, protocol("owner capture control"))
    }

    fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn an_unwatched_owner_change_arms_and_completes_nothing() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let origin = owner.origin();
        // Read the armed receiver directly, which does not subscribe.
        let armed = owner.state.data.lock().unwrap().change.receiver.clone();
        let notification = origin.capture(cause()).unwrap();
        assert!(
            notification.previous.is_none(),
            "an unwatched change was armed"
        );
        notification.notify();
        let data = owner.state.data.lock().unwrap();
        assert!(futures::future::Shared::ptr_eq(
            &armed,
            &data.change.receiver
        ));
        assert!(!data.change_subscribed);
        drop(data);
        assert!(armed.peek().is_none(), "an unwatched change completed");
        drop(scope.retire());
    }

    #[test]
    fn an_owner_subscriber_taken_between_changes_sees_the_next_one() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let origin = owner.origin();
        origin.capture(cause()).unwrap().notify();
        let mut subscription = Box::pin(owner.subscribe());
        let waker = futures::task::noop_waker();
        assert!(poll(subscription.as_mut(), &waker).is_pending());
        let notification = origin.capture(cause()).unwrap();
        assert!(notification.previous.is_some());
        notification.notify();
        assert!(poll(subscription.as_mut(), &waker).is_ready());
        assert!(!owner.state.data.lock().unwrap().change_subscribed);
        drop(scope.retire());
    }

    #[test]
    fn capture_defers_last_owner_drop_after_retirement_and_rejection() {
        struct Observe {
            gate: Arc<super::super::EntryGate>,
            wakes: AtomicUsize,
            gate_was_unlocked: AtomicBool,
        }
        impl Wake for Observe {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                if self.gate.state.try_lock().is_err() {
                    self.gate_was_unlocked.store(false, Ordering::Release);
                }
                self.wakes.fetch_add(1, Ordering::Release);
            }
        }

        for case in ["accepted", "duplicate", "rejected"] {
            for notify in [false, true] {
                let scope = DriverScope::new();
                let owner = scope.owner();
                let origin = owner.origin();
                let failure = cause();
                if case == "duplicate" {
                    origin.capture(failure.clone()).unwrap().notify();
                }
                let scope = if case == "rejected" {
                    let retirement = scope.retire();
                    retirement.result.unwrap();
                    assert!(retirement.pending.is_empty());
                    retirement.notification.notify();
                    None
                } else {
                    Some(scope)
                };
                let gate = super::super::EntryGate::new();
                let observed = Arc::new(Observe {
                    gate: gate.clone(),
                    wakes: AtomicUsize::new(0),
                    gate_was_unlocked: AtomicBool::new(true),
                });
                let controller_observed = observed.clone();
                let expected = failure.clone();
                let (unlocked, at_unlock) = std::sync::mpsc::channel();
                let (owner_dropped, after_drop) = std::sync::mpsc::channel();
                let (released, after_release) = std::sync::mpsc::channel();
                let timeout = std::time::Duration::from_secs(2);
                let controller = std::thread::spawn(move || {
                    at_unlock.recv_timeout(timeout).unwrap();
                    if let Some(scope) = scope {
                        let retirement = scope.retire();
                        retirement.result.unwrap();
                        assert_eq!(retirement.pending.len(), 1);
                        assert!(Arc::ptr_eq(&retirement.pending[0], &expected));
                        retirement.notification.notify();
                    }
                    // The waiter must observe the fresh generation created by
                    // retirement, not a sender already returned to capture.
                    let waker = Waker::from(controller_observed);
                    let mut changed = Box::pin(owner.subscribe());
                    assert!(poll(changed.as_mut(), &waker).is_pending());
                    drop(owner);
                    owner_dropped.send(()).unwrap();
                    after_release.recv_timeout(timeout).unwrap();
                    // It is disconnection from final owner destruction, not
                    // a Tool publication or an explicit current-generation send.
                    assert!(matches!(
                        poll(changed.as_mut(), &waker),
                        Poll::Ready(Err(_))
                    ));
                });

                let locked = gate.state.lock().unwrap();
                let captured = origin.capture_inner(failure.clone(), || {
                    // Precisely after owner-data unlock, before capture can
                    // release its Weak upgrade or return to the gate caller.
                    unlocked.send(()).unwrap();
                    after_drop.recv_timeout(timeout).unwrap();
                });
                let wakes_before_unlock = observed.wakes.load(Ordering::Acquire);
                let owners_before_unlock = origin.owner.strong_count();
                let (notification, rejection) = match captured {
                    Ok(notification) => (notification, None),
                    Err(rejected) => (
                        rejected.notification,
                        Some((
                            rejected.failure,
                            rejected.lifecycle,
                            rejected.owner_available,
                        )),
                    ),
                };
                drop(locked);
                if notify {
                    notification.notify();
                } else {
                    drop(notification);
                }
                // Measure the disconnect before permitting the controller's
                // final poll. Shared::poll registers that poll's waker, then
                // wakes it again when it stores the completed result.
                let disconnect_wakes = observed.wakes.load(Ordering::Acquire);
                released.send(()).unwrap();
                controller.join().unwrap();

                assert_eq!(wakes_before_unlock, 0, "{case}, notify={notify}");
                assert_eq!(
                    owners_before_unlock, 1,
                    "capture must retain the last owner"
                );
                assert_eq!(disconnect_wakes, 1, "{case}, notify={notify}");
                assert_eq!(observed.wakes.load(Ordering::Acquire), 2);
                assert!(observed.gate_was_unlocked.load(Ordering::Acquire));
                assert!(origin.owner.upgrade().is_none());
                assert_eq!(origin.lifecycle(), DriverLifecycle::Retired);
                match rejection {
                    Some((cause, lifecycle, available)) => {
                        assert_eq!(case, "rejected");
                        assert!(Arc::ptr_eq(&cause, &failure));
                        assert_eq!(lifecycle, DriverLifecycle::Retired);
                        assert!(available);
                    }
                    None => assert_ne!(case, "rejected"),
                }
            }
        }
    }

    #[test]
    fn capture_records_before_deferred_notification_and_retains_arcs() {
        struct Observe {
            owner: DriverOwner,
            gate: Arc<super::super::EntryGate>,
            wakes: AtomicUsize,
        }
        impl Wake for Observe {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                assert!(self.owner.state.data.try_lock().is_ok());
                assert!(self.gate.state.try_lock().is_ok());
                self.wakes.fetch_add(1, Ordering::Relaxed);
            }
        }
        let scope = DriverScope::new();
        let owner = scope.owner();
        let origin = owner.origin();
        let gate = super::super::EntryGate::new();
        let observed = Arc::new(Observe {
            owner: owner.clone(),
            gate: gate.clone(),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(observed.clone());
        let mut changed = Box::pin(owner.subscribe());
        assert!(poll(changed.as_mut(), &waker).is_pending());
        assert!(owner.pending().is_empty());
        let failure = cause();
        let notification = {
            let _gate = gate.state.lock().unwrap();
            origin.capture(failure.clone()).unwrap()
        };
        assert_eq!(observed.wakes.load(Ordering::Relaxed), 0);
        assert!(Arc::ptr_eq(&owner.pending()[0], &failure));
        origin.capture(failure.clone()).unwrap().notify();
        assert_eq!(owner.pending().len(), 1);
        assert_eq!(observed.wakes.load(Ordering::Relaxed), 0);
        notification.notify();
        assert_eq!(observed.wakes.load(Ordering::Relaxed), 1);
        assert!(poll(changed.as_mut(), &waker).is_ready());
        let taken = owner.take_pending();
        assert_eq!(taken.len(), 1);
        assert!(Arc::ptr_eq(&taken[0], &failure));
        assert!(owner.pending().is_empty());
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    #[test]
    fn nested_destruction_keeps_generation_and_parent_dependency() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let parent = owner.begin_callback(None).unwrap();
        let parent_origin = parent.origin();
        let retained = parent_origin.clone();
        let nested = owner.begin_callback(Some(&parent_origin)).unwrap();
        let nested_origin = nested.origin();
        assert!(nested_origin.same_driver(&parent_origin));
        assert!(!nested_origin.same_callback(&parent_origin));
        assert!(retained.same_callback(&parent_origin));
        let waker = Waker::noop();
        let mut done = Box::pin(nested_origin.wait_callback_drop());
        assert!(poll(done.as_mut(), waker).is_pending());
        drop(nested);
        assert!(!nested_origin.callback_dropped());
        assert!(poll(done.as_mut(), waker).is_pending());
        assert!(!parent_origin.callback_dropped());
        drop(parent);
        assert!(nested_origin.callback_dropped());
        assert!(poll(done.as_mut(), waker).is_ready());
        let next = owner.begin_callback(None).unwrap();
        assert!(!retained.same_callback(&next.origin()));
        assert!(retained.callback_dropped());
        assert!(!next.origin().callback_dropped());
        assert!(next.origin().callback_id().unwrap() > retained.callback_id().unwrap());
        drop(next);
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    fn spare(owner: &DriverOwner) -> Option<Arc<CallbackGeneration>> {
        owner.state.data.lock().unwrap().spare_generation.clone()
    }

    fn has_destroyed_channel(origin: &OperationOrigin) -> bool {
        origin
            .callback
            .as_ref()
            .unwrap()
            .destroyed_notification
            .lock()
            .unwrap()
            .is_some()
    }

    #[test]
    fn a_destroyed_generation_is_reused_only_when_nothing_else_holds_it() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let first = owner.begin_callback(None).unwrap();
        let first_id = first.origin().callback_id().unwrap();
        let first_ptr = Arc::as_ptr(first.origin.callback.as_ref().unwrap());
        drop(first);
        // Kept, not freed, and still recording its destruction.
        let kept = spare(&owner).unwrap();
        assert_eq!(Arc::as_ptr(&kept), first_ptr);
        assert!(kept.destroyed.load(Ordering::Acquire));
        drop(kept);

        // Sole holder: the next callback takes the allocation, with a new
        // identity and the state of a new generation.
        let second = owner.begin_callback(None).unwrap();
        let second_origin = second.origin();
        assert_eq!(
            Arc::as_ptr(second_origin.callback.as_ref().unwrap()),
            first_ptr
        );
        assert!(second_origin.callback_id().unwrap() > first_id);
        assert!(!second_origin.callback_dropped());
        assert!(!has_destroyed_channel(&second_origin));
        assert!(spare(&owner).is_none());

        // A retained origin (a memory view, a pending failure) holds the
        // generation, so the next callback must not reuse it: that origin
        // still names the destroyed callback.
        drop(second);
        let third = owner.begin_callback(None).unwrap();
        let third_origin = third.origin();
        assert!(!third_origin.same_callback(&second_origin));
        assert_ne!(
            Arc::as_ptr(third_origin.callback.as_ref().unwrap()),
            first_ptr
        );
        assert!(second_origin.callback_dropped());
        assert!(!third_origin.callback_dropped());
        drop(third);
        drop(third_origin);
        drop(second_origin);
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    #[test]
    fn a_reused_generation_drops_its_old_parent_and_takes_the_new_one() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let parent = owner.begin_callback(None).unwrap();
        let parent_origin = parent.origin();
        let nested = owner.begin_callback(Some(&parent_origin)).unwrap();
        drop(nested);
        assert!(spare(&owner).unwrap().parent.is_some());
        drop(parent);
        // The parent's scope replaced the nested spare, releasing its parent
        // reference; only the origin above and the new spare hold the parent.
        assert_eq!(
            Arc::strong_count(parent_origin.callback.as_ref().unwrap()),
            2
        );
        drop(parent_origin);
        let next = owner.begin_callback(None).unwrap();
        assert!(next.origin.callback.as_ref().unwrap().parent.is_none());
        let next_origin = next.origin();
        let nested = owner.begin_callback(Some(&next_origin)).unwrap();
        assert!(Arc::ptr_eq(
            nested
                .origin
                .callback
                .as_ref()
                .unwrap()
                .parent
                .as_ref()
                .unwrap(),
            next_origin.callback.as_ref().unwrap()
        ));
        drop(nested);
        drop(next);
        drop(next_origin);
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    #[test]
    fn an_unawaited_callback_creates_no_destruction_channel() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let callback = owner.begin_callback(None).unwrap();
        let origin = callback.origin();
        assert!(!has_destroyed_channel(&origin));
        drop(callback);
        assert!(!has_destroyed_channel(&origin));
        assert!(origin.callback_dropped());
        // A wait that starts after destruction completes without a channel.
        let mut done = Box::pin(origin.wait_callback_drop());
        assert!(matches!(
            poll(done.as_mut(), Waker::noop()),
            Poll::Ready(Ok(()))
        ));
        drop(done);
        assert!(!has_destroyed_channel(&origin));
        drop(origin);
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    #[test]
    fn a_waiter_subscribed_before_destruction_is_woken_by_it() {
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let scope = DriverScope::new();
        let owner = scope.owner();
        let callback = owner.begin_callback(None).unwrap();
        let origin = callback.origin();
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut done = Box::pin(origin.wait_callback_drop());
        assert!(poll(done.as_mut(), &waker).is_pending());
        assert!(has_destroyed_channel(&origin));
        drop(callback);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(poll(done.as_mut(), &waker), Poll::Ready(Ok(()))));
        drop(done);
        drop(origin);
        // The generation that had a channel is reused without it.
        let next = owner.begin_callback(None).unwrap();
        assert!(!has_destroyed_channel(&next.origin()));
        drop(next);
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    #[test]
    fn a_wait_racing_destruction_always_completes() {
        // Either the waiter subscribes first and the destructor completes its
        // channel, or the destructor stores `destroyed` first and the
        // waiter's recheck sees it. No interleaving may leave it pending.
        for _ in 0..200 {
            let scope = DriverScope::new();
            let owner = scope.owner();
            let callback = owner.begin_callback(None).unwrap();
            let origin = callback.origin();
            let barrier = Arc::new(Barrier::new(2));
            let destroyer_barrier = barrier.clone();
            let destroyer = std::thread::spawn(move || {
                destroyer_barrier.wait();
                drop(callback);
            });
            barrier.wait();
            futures::executor::block_on(origin.wait_callback_drop()).unwrap();
            destroyer.join().unwrap();
            assert!(origin.callback_dropped());
            drop(origin);
            let retirement = scope.retire();
            retirement.result.unwrap();
            retirement.notification.notify();
        }
    }

    #[test]
    fn scope_acknowledgement_follows_owned_future_destruction() {
        struct Probe(Arc<AtomicBool>);
        impl Drop for Probe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let scope = DriverScope::new();
        let owner = scope.owner();
        let callback = owner.begin_callback(None).unwrap();
        let origin = callback.origin();
        let released = Arc::new(AtomicBool::new(false));
        let callback_released = released.clone();
        let mut future = Box::pin(async move {
            let _probe = Probe(callback_released);
            std::future::pending::<()>().await;
        });
        assert!(poll(future.as_mut(), Waker::noop()).is_pending());
        assert!(!released.load(Ordering::Acquire));
        assert!(!origin.callback_dropped());
        drop(future);
        assert!(released.load(Ordering::Acquire));
        // The owner deliberately acknowledges only after its future ended.
        assert!(!origin.callback_dropped());
        drop(callback);
        assert!(origin.callback_dropped());
        assert_eq!(origin.lifecycle(), DriverLifecycle::Active);
        let retirement = scope.retire();
        retirement.result.unwrap();
        retirement.notification.notify();
    }

    #[test]
    fn retirement_preserves_both_sides_of_capture_race() {
        // Each deterministic side is covered separately, then exercise the
        // actual mutex race without demanding a particular host winner.
        for capture_first in [false, true] {
            let scope = DriverScope::new();
            let owner = scope.owner();
            let origin = owner.origin();
            let failure = cause();
            if capture_first {
                origin.capture(failure.clone()).unwrap().notify();
            }
            let retirement = scope.retire();
            assert_eq!(retirement.lifecycle, DriverLifecycle::Retired);
            retirement.result.unwrap();
            assert_eq!(retirement.pending.len(), usize::from(capture_first));
            if capture_first {
                assert!(Arc::ptr_eq(&retirement.pending[0], &failure));
            }
            retirement.notification.notify();
            let rejected = origin.capture(failure.clone()).unwrap_err();
            assert!(Arc::ptr_eq(&rejected.failure, &failure));
            assert_eq!(rejected.lifecycle, DriverLifecycle::Retired);
        }
        for _ in 0..32 {
            let scope = DriverScope::new();
            let owner = scope.owner();
            let origin = owner.origin();
            let failure = cause();
            let captured = failure.clone();
            let barrier = Arc::new(Barrier::new(2));
            let worker_barrier = barrier.clone();
            let worker = std::thread::spawn(move || {
                worker_barrier.wait();
                origin.capture(captured)
            });
            barrier.wait();
            let retirement = scope.retire();
            retirement.result.unwrap();
            retirement.notification.notify();
            match worker.join().unwrap() {
                Ok(notification) => {
                    notification.notify();
                    assert_eq!(retirement.pending.len(), 1);
                    assert!(Arc::ptr_eq(&retirement.pending[0], &failure));
                }
                Err(rejected) => {
                    assert!(retirement.pending.is_empty());
                    assert!(Arc::ptr_eq(&rejected.failure, &failure));
                    assert_eq!(rejected.lifecycle, DriverLifecycle::Retired);
                }
            }
            assert!(owner.pending().is_empty());
        }
    }

    #[test]
    fn live_callback_retirement_is_abandonment_not_destruction() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let callback = owner.begin_callback(None).unwrap();
        let origin = callback.origin();
        let failure = cause();
        origin.capture(failure.clone()).unwrap().notify();
        let retirement = scope.retire();
        assert_eq!(retirement.lifecycle, DriverLifecycle::Abandoned);
        assert!(matches!(retirement.result, Err(Error::EntryControl { .. })));
        assert!(Arc::ptr_eq(&retirement.pending[0], &failure));
        retirement.notification.notify();
        assert!(!origin.callback_dropped());
        assert_eq!(owner.lifecycle(), DriverLifecycle::Abandoned);
        assert!(matches!(
            owner.begin_callback(None),
            Err(Error::EntryControl { .. })
        ));
        let rejected = origin.capture(failure.clone()).unwrap_err();
        assert!(Arc::ptr_eq(&rejected.failure, &failure));
        assert_eq!(rejected.lifecycle, DriverLifecycle::Abandoned);
        drop(callback);
        assert!(origin.callback_dropped());
        assert_eq!(origin.lifecycle(), DriverLifecycle::Abandoned);
    }

    #[test]
    fn unwind_abandons_registration_but_preserves_pending_and_destruction() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let callback = owner.begin_callback(None).unwrap();
        let origin = callback.origin();
        let failure = cause();
        origin.capture(failure.clone()).unwrap().notify();
        let mut changed = Box::pin(owner.subscribe());
        assert!(poll(changed.as_mut(), Waker::noop()).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _scope = scope;
            let _callback = callback;
            panic!("controlled callback owner unwind");
        }));
        assert!(result.is_err());
        assert!(origin.callback_dropped());
        assert_eq!(origin.lifecycle(), DriverLifecycle::Abandoned);
        assert!(poll(changed.as_mut(), Waker::noop()).is_ready());
        assert!(Arc::ptr_eq(&owner.take_pending()[0], &failure));
    }

    #[test]
    fn origins_are_weak_and_misuse_returns_typed_protocol_errors() {
        let scope = DriverScope::new();
        let owner = scope.owner();
        let before = Arc::strong_count(&owner.state);
        let origin = owner.origin();
        let retained = origin.clone();
        assert_eq!(Arc::strong_count(&owner.state), before);
        let callback = owner.begin_callback(None).unwrap();
        let callback_origin = callback.origin();
        let other_scope = DriverScope::new();
        let other = other_scope.owner();
        assert!(matches!(
            other.begin_callback(Some(&callback_origin)),
            Err(Error::EntryControl { .. })
        ));
        assert!(matches!(
            owner.begin_callback(Some(&origin)),
            Err(Error::EntryControl { .. })
        ));
        drop(callback);
        assert!(matches!(
            owner.begin_callback(Some(&callback_origin)),
            Err(Error::EntryControl { .. })
        ));
        owner.state.data.lock().unwrap().next_callback = u64::MAX;
        assert!(matches!(
            owner.begin_callback(None),
            Err(Error::EntryControl {
                operation: "callback identity exhausted",
                ..
            })
        ));
        assert_eq!(owner.state.data.lock().unwrap().next_callback, u64::MAX);
        drop(other_scope);
        drop(other);
        let failure = cause();
        origin.capture(failure.clone()).unwrap().notify();
        drop(scope);
        drop(owner);
        assert!(retained.owner.upgrade().is_none());
        assert_eq!(retained.lifecycle(), DriverLifecycle::Abandoned);
        let rejected = retained.capture(failure.clone()).unwrap_err();
        assert!(!rejected.owner_available);
        assert_eq!(rejected.lifecycle, DriverLifecycle::Abandoned);
        assert!(Arc::ptr_eq(&rejected.failure, &failure));
    }
}
