/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Admission and retirement for one guest address space.
//!
//! Closing admission accounts for vCPU setup, running vCPUs, return cleanup,
//! and admitted host copies. It neither completes pending guest syscalls nor
//! waits for host operations using an already retained pointer. Those retained
//! operands are counted separately: an unchanged close may finish around them,
//! but a mapping publication must refuse while any remains live.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::panic::resume_unwind;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::MutexGuard;

use futures::FutureExt;
use futures::channel::oneshot;
use futures::future::Shared;

use crate::Error;
use crate::failure::FailureContext;

pub(crate) mod driver;
pub(crate) mod owner;
mod signal;

#[cfg(feature = "native-test-support")]
pub(crate) fn check_reserved_signal_handler() -> crate::Result<()> {
    signal::Mask::block()?.finish()
}

#[cfg(test)]
mod cleanup_tests;

type Change = Shared<oneshot::Receiver<()>>;
type GateResult<T> = Result<T, Arc<PendingFailure>>;

/// One installed guest-physical backing image. Every vCPU entry and short host
/// copy is admitted against exactly one generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MappingGeneration(u64);

impl MappingGeneration {
    pub(crate) const INITIAL: Self = Self(0);

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupPhase {
    BeforeWithdraw,
    AfterWithdraw,
    BeforeAcknowledge,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupIdentity {
    pub(crate) participant: u64,
    pub(crate) run: u64,
}

#[cfg(test)]
type CleanupHook = Box<dyn FnOnce(CleanupIdentity) + Send>;

/// Observations of actual admission, mask installation and receiver polling.
/// Test controllers arm this only after ordinary driver setup has completed.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct PrepareProbe {
    pub(crate) armed: std::sync::atomic::AtomicBool,
    pub(crate) mask_installs: std::sync::atomic::AtomicUsize,
    pub(crate) closed_admissions: std::sync::atomic::AtomicUsize,
    pub(crate) closed_waits: std::sync::atomic::AtomicUsize,
    pub(crate) pending_subscriptions: std::sync::atomic::AtomicUsize,
    subscription_notice: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    wait_notice: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    before_activate: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    cleanup: Mutex<[Option<CleanupHook>; 3]>,
    withdraw_contended: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(test)]
impl PrepareProbe {
    pub(crate) fn on_withdraw_contention(&self, hook: impl FnOnce() + Send + 'static) {
        let previous = self
            .withdraw_contended
            .lock()
            .unwrap()
            .replace(Box::new(hook));
        assert!(
            previous.is_none(),
            "entry control replaced a withdrawal observation"
        );
    }

    pub(crate) fn on_cleanup(
        &self,
        phase: CleanupPhase,
        hook: impl FnOnce(CleanupIdentity) + Send + 'static,
    ) {
        let previous = self.cleanup.lock().unwrap()[phase as usize].replace(Box::new(hook));
        assert!(previous.is_none(), "entry control replaced a cleanup hook");
    }

    fn cleanup_hook(&self, phase: CleanupPhase, identity: CleanupIdentity) {
        let hook = self.cleanup.lock().unwrap()[phase as usize].take();
        if let Some(hook) = hook {
            hook(identity);
        }
    }

    pub(crate) fn before_activate(&self, hook: impl FnOnce() + Send + 'static) {
        let previous = self.before_activate.lock().unwrap().replace(Box::new(hook));
        assert!(
            previous.is_none(),
            "entry control replaced an activation hook"
        );
    }

    fn activate_hook(&self) {
        let hook = self.before_activate.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// One notice per actual subscription that has been polled Pending after
    /// denied admission. Repeated polls keep their separate raw observation.
    pub(crate) fn set_subscription_notice(&self, sender: std::sync::mpsc::Sender<()>) {
        *self.subscription_notice.lock().unwrap() = Some(sender);
    }

    pub(crate) fn set_wait_notice(&self, sender: std::sync::mpsc::Sender<()>) {
        *self.wait_notice.lock().unwrap() = Some(sender);
    }

    pub(crate) fn increment(&self, counter: &std::sync::atomic::AtomicUsize) {
        if self.armed.load(std::sync::atomic::Ordering::Acquire) {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn pending_after_closed_admission(&self, observed: &std::sync::atomic::AtomicBool) {
        if self.armed.load(std::sync::atomic::Ordering::Acquire)
            && self
                .closed_admissions
                .load(std::sync::atomic::Ordering::Acquire)
                != 0
        {
            if !observed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                self.pending_subscriptions
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let sender = self.subscription_notice.lock().unwrap().clone();
                if let Some(sender) = sender {
                    let _ = sender.send(());
                }
            }
            self.closed_waits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let sender = self.wait_notice.lock().unwrap().clone();
            if let Some(sender) = sender {
                let _ = sender.send(());
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ObservedChange {
    change: Change,
    probe: Option<Arc<PrepareProbe>>,
    // Clones represent the same subscription and share its first-Pending bit.
    pending_observed: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
impl std::future::Future for ObservedChange {
    type Output = Result<(), oneshot::Canceled>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let result = std::future::Future::poll(std::pin::Pin::new(&mut self.change), cx);
        if result.is_pending()
            && let Some(probe) = &self.probe
        {
            probe.pending_after_closed_admission(&self.pending_observed);
        }
        result
    }
}

#[cfg(test)]
impl futures::future::FusedFuture for ObservedChange {
    fn is_terminated(&self) -> bool {
        futures::future::FusedFuture::is_terminated(&self.change)
    }
}

/// The issuing handle retains a callback generation independently of the
/// Mapping and of the optional run-wide publisher. Direct invocations have
/// an owner even when they have no FailureContext.
#[derive(Clone, Default)]
pub(crate) struct EntryOrigin {
    pub(crate) failure: Option<FailureContext>,
    pub(crate) operation: Option<owner::OperationOrigin>,
}

impl From<Option<FailureContext>> for EntryOrigin {
    fn from(failure: Option<FailureContext>) -> Self {
        Self {
            failure,
            operation: None,
        }
    }
}

/// Capturing a failure must not call a Tool while an inline RPC still owns
/// Tool locks. The driver drops that callback before publishing this cause.
/// Keep the issuing context even if a peer is first to observe the failure.
pub(crate) struct PendingFailure {
    pub(crate) origin: Option<crate::failure::FailureObservation>,
    pub(crate) operation: Option<owner::OperationOrigin>,
    primary: Arc<Error>,
    cleanup: Mutex<Vec<Arc<Error>>>,
    owner_registered: std::sync::atomic::AtomicBool,
}

impl PendingFailure {
    pub(crate) fn owner_registered(&self) -> bool {
        self.owner_registered
            .load(std::sync::atomic::Ordering::Acquire)
    }
    /// Keep the original shared identities when composing repeated observations.
    /// This is a snapshot; the owning driver must retain this PendingFailure
    /// itself until its final completion so later cleanup is still observable.
    pub(crate) fn causes(&self) -> Vec<Arc<Error>> {
        let mut causes = vec![self.primary.clone()];
        causes.extend(self.cleanup.lock().unwrap().iter().cloned());
        causes
    }

    pub(crate) fn error(&self) -> Error {
        let cleanup = self.cleanup.lock().unwrap().clone();
        if cleanup.is_empty() {
            Error::SharedFailure(self.primary.clone())
        } else {
            Error::WithCleanup {
                primary: self.primary.clone(),
                cleanup,
            }
        }
    }
}

impl std::fmt::Debug for PendingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingFailure")
            .field("primary", &self.primary)
            .field("cleanup", &self.cleanup)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The private unchanged-mapping close protocol has no production closer yet"
    )
)]
enum Admission {
    Open,
    Closing(u64),
    Closed(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Activity {
    Stopped,
    Setup,
    Running(libc::pthread_t),
    Retiring,
}

struct Member {
    run: u64,
    generation: Option<MappingGeneration>,
    activity: Activity,
    origin: EntryOrigin,
}

struct State {
    admission: Admission,
    // An ordinary shared-file image is supported only by its existing vCPU.
    // A quiescent close reserves this before any mapping can be installed.
    single_member_domain: bool,
    generation: MappingGeneration,
    next_member: u64,
    next_close: u64,
    members: BTreeMap<u64, Member>,
    copies: usize,
    retained_operands: usize,
    failure: Option<Arc<PendingFailure>>,
    sender: Option<oneshot::Sender<()>>,
    changed: Change,
    copy_changed: Arc<Condvar>,
    owner_notifications: Vec<owner::OwnerNotification>,
    retired_origins: Vec<EntryOrigin>,
    #[cfg(test)]
    copy_waits: usize,
    #[cfg(test)]
    copy_waiters: Vec<std::thread::ThreadId>,
}

struct ChangeSignal {
    sender: Option<oneshot::Sender<()>>,
    copies: Arc<Condvar>,
    owners: Vec<owner::OwnerNotification>,
    origins: Vec<EntryOrigin>,
}

impl State {
    fn check(&self) -> GateResult<()> {
        match &self.failure {
            Some(failure) => Err(failure.clone()),
            None => Ok(()),
        }
    }

    fn fail(&mut self, origin: impl Into<EntryOrigin>, error: Error) -> Arc<PendingFailure> {
        let origin = origin.into();
        if let Some(failure) = &self.failure {
            failure.cleanup.lock().unwrap().push(Arc::new(error));
            // The context can own the last run sender. Its destruction must
            // not invoke a notification waker while the entry lock is held.
            self.retired_origins.push(origin);
            return failure.clone();
        }
        let failure = Arc::new(PendingFailure {
            origin: origin.failure.as_ref().map(FailureContext::observe),
            operation: origin.operation.clone(),
            primary: Arc::new(error),
            cleanup: Mutex::new(Vec::new()),
            owner_registered: std::sync::atomic::AtomicBool::new(false),
        });
        self.retired_origins.push(origin);
        self.failure = Some(failure.clone());
        if let Some(operation) = &failure.operation {
            match operation.capture(failure.clone()) {
                Ok(notification) => {
                    failure
                        .owner_registered
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.owner_notifications.push(notification);
                }
                Err(rejected) => {
                    // A retained view can outlive its driver. Keep the typed
                    // cause and explicit origin lifetime in the gate; neither
                    // a lost owner nor closed registration permits publication
                    // through the old FailureContext.
                    debug_assert!(Arc::ptr_eq(&failure, &rejected.failure));
                    // The rejected registration may still hold the last
                    // strong driver reference. Its destruction can disconnect
                    // another subscriber, so defer that release as well.
                    self.owner_notifications.push(rejected.notification);
                }
            }
        }
        failure
    }

    /// The sender is consumed only after releasing the registry lock. A
    /// subscriber taken before a recheck therefore cannot miss this change.
    fn changed(&mut self) -> ChangeSignal {
        let (sender, receiver) = oneshot::channel();
        self.changed = receiver.shared();
        ChangeSignal {
            sender: self.sender.replace(sender),
            copies: self.copy_changed.clone(),
            owners: std::mem::take(&mut self.owner_notifications),
            origins: std::mem::take(&mut self.retired_origins),
        }
    }

    fn stopped(&self) -> bool {
        self.copies == 0
            && self
                .members
                .values()
                .all(|member| member.activity == Activity::Stopped)
    }
}

fn notify(change: ChangeSignal) {
    // Both kinds of waiter recheck the state under the registry lock. Notify
    // only after releasing it; no wake callback may run inside that lock.
    change.copies.notify_all();
    for owner in change.owners {
        owner.notify();
    }
    drop(change.origins);
    if let Some(sender) = change.sender {
        let _ = sender.send(());
    }
}

fn failure(operation: &'static str, source: std::io::Error) -> Error {
    Error::EntryControl { operation, source }
}

fn protocol_failure(operation: &'static str) -> Error {
    failure(operation, std::io::Error::other(operation))
}

pub(crate) struct EntryGate {
    state: Mutex<State>,
    #[cfg(test)]
    prepare_probe: Mutex<Option<Arc<PrepareProbe>>>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TestMemberState {
    pub(crate) id: u64,
    pub(crate) run: u64,
    pub(crate) generation: Option<MappingGeneration>,
    pub(crate) stopped: bool,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TestGateState {
    pub(crate) open: bool,
    pub(crate) closed: bool,
    pub(crate) generation: MappingGeneration,
    pub(crate) copies: usize,
    pub(crate) retained_operands: usize,
    pub(crate) copy_waits: usize,
    pub(crate) copy_waiters: Vec<std::thread::ThreadId>,
    pub(crate) members: Vec<TestMemberState>,
}

impl std::fmt::Debug for EntryGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().unwrap();
        f.debug_struct("EntryGate")
            .field("admission", &state.admission)
            .field("members", &state.members.len())
            .field("copies", &state.copies)
            .field("failure", &state.failure)
            .finish()
    }
}

impl EntryGate {
    #[cfg(test)]
    pub(crate) fn test_state(&self) -> TestGateState {
        let state = self.state.lock().unwrap();
        TestGateState {
            open: state.admission == Admission::Open,
            closed: matches!(state.admission, Admission::Closed(_)),
            generation: state.generation,
            copies: state.copies,
            retained_operands: state.retained_operands,
            copy_waits: state.copy_waits,
            copy_waiters: state.copy_waiters.clone(),
            members: state
                .members
                .iter()
                .map(|(&id, member)| TestMemberState {
                    id,
                    run: member.run,
                    generation: member.generation,
                    stopped: member.activity == Activity::Stopped,
                })
                .collect(),
        }
    }

    pub(crate) fn new() -> Arc<Self> {
        let (sender, receiver) = oneshot::channel();
        Arc::new(Self {
            #[cfg(test)]
            prepare_probe: Mutex::new(None),
            state: Mutex::new(State {
                admission: Admission::Open,
                single_member_domain: false,
                generation: MappingGeneration::INITIAL,
                next_member: 0,
                next_close: 0,
                members: BTreeMap::new(),
                copies: 0,
                retained_operands: 0,
                failure: None,
                sender: Some(sender),
                changed: receiver.shared(),
                copy_changed: Arc::new(Condvar::new()),
                owner_notifications: Vec::new(),
                retired_origins: Vec::new(),
                #[cfg(test)]
                copy_waits: 0,
                #[cfg(test)]
                copy_waiters: Vec::new(),
            }),
        })
    }

    #[cfg(not(test))]
    pub(crate) fn subscribe(&self) -> Change {
        self.state.lock().unwrap().changed.clone()
    }

    #[cfg(test)]
    pub(crate) fn subscribe(&self) -> ObservedChange {
        let change = self.state.lock().unwrap().changed.clone();
        let probe = self.prepare_probe.lock().unwrap().clone();
        ObservedChange {
            change,
            probe,
            pending_observed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    pub(crate) fn notify_unchanged_for_test(&self) {
        let sender = self.state.lock().unwrap().changed();
        notify(sender);
    }

    pub(crate) fn pending_failure(&self) -> Option<Arc<PendingFailure>> {
        self.state.lock().unwrap().failure.clone()
    }

    pub(crate) fn generation(&self) -> GateResult<MappingGeneration> {
        let state = self.state.lock().unwrap();
        state.check()?;
        Ok(state.generation)
    }

    /// Serialize an operation's admission with poison capture, then release
    /// the lock before any RPC, syscall, callback poll, or asynchronous wait.
    pub(crate) fn admit_operation(&self) -> GateResult<()> {
        self.state.lock().unwrap().check()
    }

    pub(crate) fn poison(
        &self,
        origin: impl Into<EntryOrigin>,
        error: Error,
    ) -> Arc<PendingFailure> {
        let (failure, sender) = {
            let mut state = self.state.lock().unwrap();
            let failure = state.fail(origin, error);
            (failure, state.changed())
        };
        notify(sender);
        failure
    }

    /// Registration while closed is allowed, but grants no entry or access.
    /// The ordinary shared-file domain is the exception: its existing member
    /// is exclusive, and bypassing the syscall-level refusal is terminal.
    pub(crate) fn register(self: &Arc<Self>) -> GateResult<Participant> {
        let result = {
            let mut state = self.state.lock().unwrap();
            state.check()?;
            if state.single_member_domain
                && (state.admission != Admission::Open || !state.members.is_empty())
            {
                Err(state.fail(
                    None,
                    protocol_failure(
                        "ordinary shared-file domain permits only its existing stopped participant",
                    ),
                ))
            } else {
                match state.next_member.checked_add(1) {
                    Some(id) => {
                        state.next_member = id;
                        state.members.insert(
                            id,
                            Member {
                                run: 0,
                                generation: None,
                                activity: Activity::Stopped,
                                origin: EntryOrigin::default(),
                            },
                        );
                        Ok(Participant {
                            gate: self.clone(),
                            id,
                            #[cfg(test)]
                            prepare_probe: None,
                        })
                    }
                    None => {
                        Err(state.fail(None, protocol_failure("participant identity exhausted")))
                    }
                }
            }
        };
        if result.is_err() {
            let sender = self.state.lock().unwrap().changed();
            notify(sender);
        }
        result
    }

    /// Quietly inspect the capability restriction before a fork or snapshot
    /// can create a new participant or copy a shared-file image.
    pub(crate) fn single_member_domain_active(&self) -> bool {
        self.state.lock().unwrap().single_member_domain
    }

    /// Close synchronously only when the sole participant is already stopped
    /// and no copy or retained host pointer exists. Unlike `try_close`, this
    /// never interrupts, waits, or notifies: `None` changes no state. Callers
    /// can therefore retain their allocation transaction during admission and
    /// construct any capability failure after releasing that transaction.
    ///
    /// The domain reservation and member check occur under the same lock, so
    /// registration cannot slip between the check and the first file mapping.
    pub(crate) fn try_close_quiescent_single(self: &Arc<Self>) -> GateResult<Option<Closed>> {
        self.try_close_quiescent_members(1)
    }

    /// Publish into an unexecuted arena without fabricating a stopped vCPU.
    /// This has the same copy, retained-pointer and domain checks as the live
    /// single-member path, but requires that no participant exists at all.
    /// The first real participant can register only after this close reopens.
    pub(crate) fn try_close_quiescent_unattached(self: &Arc<Self>) -> GateResult<Option<Closed>> {
        self.try_close_quiescent_members(0)
    }

    fn try_close_quiescent_members(self: &Arc<Self>, members: usize) -> GateResult<Option<Closed>> {
        let mut state = self.state.lock().unwrap();
        state.check()?;
        if state.admission != Admission::Open
            || state.members.len() != members
            || !state.stopped()
            || state.retained_operands != 0
            || state.generation.next().is_none()
        {
            return Ok(None);
        }
        let Some(id) = state.next_close.checked_add(1) else {
            return Ok(None);
        };
        let previous_domain = state.single_member_domain;
        state.next_close = id;
        state.admission = Admission::Closed(id);
        state.single_member_domain = true;
        Ok(Some(Closed {
            gate: self.clone(),
            id,
            published: false,
            previous_domain: Some(previous_domain),
            published_domain: true,
        }))
    }

    pub(crate) fn try_copy(
        self: &Arc<Self>,
        origin: impl Into<EntryOrigin>,
    ) -> GateResult<Option<CopyAccess>> {
        let state = self.state.lock().unwrap();
        state.check()?;
        if state.admission != Admission::Open {
            return Ok(None);
        }
        self.admit_copy(state, origin.into()).map(Some)
    }

    /// Synchronous memory APIs wait without holding address-state or backing
    /// locks. An existing enclosing allocation transaction may remain held;
    /// the unchanged-mapping closer never acquires that allocation lock.
    pub(crate) fn copy_blocking(
        self: &Arc<Self>,
        origin: impl Into<EntryOrigin>,
    ) -> GateResult<CopyAccess> {
        let origin = origin.into();
        let mut state = self.state.lock().unwrap();
        loop {
            state.check()?;
            if state.admission == Admission::Open {
                return self.admit_copy(state, origin);
            }
            let changed = state.copy_changed.clone();
            #[cfg(test)]
            {
                state.copy_waits += 1;
                state.copy_waiters.push(std::thread::current().id());
            }
            state = changed.wait(state).unwrap();
            #[cfg(test)]
            state
                .copy_waiters
                .retain(|thread| *thread != std::thread::current().id());
        }
    }

    fn admit_copy(
        self: &Arc<Self>,
        mut state: MutexGuard<'_, State>,
        origin: EntryOrigin,
    ) -> GateResult<CopyAccess> {
        let Some(copies) = state.copies.checked_add(1) else {
            let failure = state.fail(origin, protocol_failure("copy accounting exhausted"));
            let sender = state.changed();
            drop(state);
            notify(sender);
            return Err(failure);
        };
        state.copies = copies;
        Ok(CopyAccess {
            gate: self.clone(),
            origin,
            generation: state.generation,
            retired: false,
        })
    }

    /// Retain a host pointer after its short-copy admission ends. Closing still
    /// waits only for short copies, so ordinary unchanged fences do not wait on
    /// a blocking kernel operation. Mapping publication checks this count and
    /// fails before changing the backing image.
    pub(crate) fn retain_operand(
        self: &Arc<Self>,
        copy: &CopyAccess,
    ) -> GateResult<RetainedOperand> {
        assert!(Arc::ptr_eq(self, &copy.gate));
        let mut state = self.state.lock().unwrap();
        state.check()?;
        assert!(state.copies != 0, "retained operand requires a live copy");
        assert_eq!(state.generation, copy.generation);
        let Some(retained_operands) = state.retained_operands.checked_add(1) else {
            let failure = state.fail(
                copy.origin.clone(),
                protocol_failure("retained host operand accounting exhausted"),
            );
            let sender = state.changed();
            drop(state);
            notify(sender);
            return Err(failure);
        };
        state.retained_operands = retained_operands;
        Ok(RetainedOperand {
            gate: self.clone(),
            origin: copy.origin.clone(),
            generation: copy.generation,
        })
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The private unchanged-mapping close protocol has no production closer yet"
        )
    )]
    pub(crate) fn try_close(self: &Arc<Self>) -> GateResult<Option<Closing>> {
        self.try_close_with(|thread| {
            // SAFETY: the registry mutex remains held through pthread_kill.
            // Entry return withdraws this exact target under the same mutex
            // before the pthread-affine guard or participant can retire.
            let result = unsafe { libc::pthread_kill(thread, 64) };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(result))
            }
        })
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The private unchanged-mapping close protocol has no production closer yet"
        )
    )]
    fn try_close_with(
        self: &Arc<Self>,
        mut send: impl FnMut(libc::pthread_t) -> std::io::Result<()>,
    ) -> GateResult<Option<Closing>> {
        let mut state = self.state.lock().unwrap();
        state.check()?;
        if state.admission != Admission::Open {
            return Ok(None);
        }
        let Some(id) = state.next_close.checked_add(1) else {
            let error = state.fail(None, protocol_failure("close identity exhausted"));
            let sender = state.changed();
            drop(state);
            notify(sender);
            return Err(error);
        };
        state.next_close = id;
        state.admission = Admission::Closing(id);
        // Keep an operation's unwind from poisoning the registry mutex:
        // entry destructors still need it to withdraw and retire their target.
        let send_error = catch_unwind(AssertUnwindSafe(|| {
            state.members.values().find_map(|member| {
                if let Activity::Running(thread) = member.activity {
                    send(thread).err()
                } else {
                    None
                }
            })
        }));
        let send_error = match send_error {
            Ok(result) => result,
            Err(payload) => {
                state.fail(None, protocol_failure("interrupt running vCPU unwound"));
                let sender = state.changed();
                drop(state);
                notify(sender);
                resume_unwind(payload);
            }
        };
        let result = match send_error {
            Some(error) => Err(state.fail(None, failure("interrupt running vCPU", error))),
            None => Ok(Some(Closing {
                gate: self.clone(),
                id,
                complete: false,
            })),
        };
        let sender = state.changed();
        drop(state);
        notify(sender);
        result
    }
}

pub(crate) struct Participant {
    gate: Arc<EntryGate>,
    id: u64,
    #[cfg(test)]
    prepare_probe: Option<Arc<PrepareProbe>>,
}

impl Participant {
    #[cfg(test)]
    pub(crate) fn set_prepare_probe(&mut self, probe: Arc<PrepareProbe>) {
        *self.gate.prepare_probe.lock().unwrap() = Some(probe.clone());
        self.prepare_probe = Some(probe);
    }

    pub(crate) fn set_origin(&mut self, origin: impl Into<EntryOrigin>) {
        let mut state = self.gate.state.lock().unwrap();
        let member = state.members.get_mut(&self.id).unwrap();
        assert_eq!(member.activity, Activity::Stopped);
        member.origin = origin.into();
    }

    pub(crate) fn try_enter(&mut self) -> GateResult<Option<Entry<'_>>> {
        let mut state = self.gate.state.lock().unwrap();
        state.check()?;
        if state.admission != Admission::Open {
            return Ok(None);
        }
        let generation = state.generation;
        let member = state.members.get_mut(&self.id).unwrap();
        assert_eq!(member.activity, Activity::Stopped);
        let Some(run) = member.run.checked_add(1) else {
            let origin = member.origin.clone();
            let error = state.fail(origin, protocol_failure("entry identity exhausted"));
            let sender = state.changed();
            drop(state);
            notify(sender);
            return Err(error);
        };
        member.run = run;
        member.activity = Activity::Setup;
        drop(state);
        Ok(Some(Entry {
            participant: self,
            run,
            generation,
            acknowledged: false,
            _same_thread: PhantomData,
        }))
    }

    pub(crate) fn prepare(&mut self, fd: &kvm_ioctls::VcpuFd) -> GateResult<Option<RunEntry<'_>>> {
        #[cfg(test)]
        let probe = self.prepare_probe.clone();
        let Some(mut entry) = self.try_enter()? else {
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.increment(&probe.closed_admissions);
            }
            return Ok(None);
        };
        let mask = match signal::Mask::block() {
            Ok(mask) => mask,
            Err(error) => {
                entry.withdraw();
                entry.acknowledge(Err(error))?;
                unreachable!("failed mask setup acknowledged successfully");
            }
        };
        let mut guard = RunEntry {
            entry: Some(entry),
            mask: Some(mask),
        };
        // The test hook runs after mask blocking and outside the registry lock.
        // The real final admission check and mask ioctl remain together below.
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.activate_hook();
        }
        let admitted = guard.entry.as_mut().unwrap().activate(|| {
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.increment(&probe.mask_installs);
            }
            guard.mask.as_ref().unwrap().install(fd)
        });
        match admitted {
            Ok(true) => Ok(Some(guard)),
            Ok(false) => {
                guard.finish(Ok(()))?;
                Ok(None)
            }
            Err(error) => {
                // Retain a mask cleanup error alongside the original failure.
                let _ = guard.finish(Ok(()));
                Err(error)
            }
        }
    }
}

impl Drop for Participant {
    fn drop(&mut self) {
        let sender = {
            let mut state = self.gate.state.lock().unwrap();
            let member = state.members.get_mut(&self.id).unwrap();
            if member.activity == Activity::Stopped {
                state.members.remove(&self.id);
            } else {
                // Never leave a reusable pthread ID available to a sender,
                // and never report incomplete cleanup as a stopped member.
                member.activity = Activity::Retiring;
                let origin = member.origin.clone();
                state.fail(
                    origin,
                    protocol_failure("participant retired before entry cleanup"),
                );
            }
            state.changed()
        };
        notify(sender);
    }
}

/// This guard cannot move between pthreads and must not cross an async suspension.
/// Its caller owns signal blocking/restoration and clock cleanup. A lost guard
/// leaves failed accounting; it cannot manufacture a successful fence.
pub(crate) struct Entry<'a> {
    participant: &'a mut Participant,
    run: u64,
    generation: MappingGeneration,
    acknowledged: bool,
    _same_thread: PhantomData<Rc<()>>,
}

impl Entry<'_> {
    /// The final open check, KVM mask installation, and target publication
    /// occur under the registry lock. The supplied function must be only the
    /// synchronous ioctl; it must not invoke Tool code or wait for admission.
    pub(crate) fn activate(
        &mut self,
        install_mask: impl FnOnce() -> crate::Result<()>,
    ) -> GateResult<bool> {
        let mut state = self.participant.gate.state.lock().unwrap();
        state.check()?;
        let member = state.members.get(&self.participant.id).unwrap();
        assert_eq!(member.run, self.run);
        assert_eq!(member.activity, Activity::Setup);
        assert_eq!(state.generation, self.generation);
        if state.admission != Admission::Open {
            return Ok(false);
        }
        let installed = catch_unwind(AssertUnwindSafe(install_mask));
        let installed = match installed {
            Ok(result) => result,
            Err(payload) => {
                let origin = state.members[&self.participant.id].origin.clone();
                state.fail(
                    origin,
                    protocol_failure("install KVM temporary signal mask unwound"),
                );
                let sender = state.changed();
                drop(state);
                notify(sender);
                resume_unwind(payload);
            }
        };
        if let Err(error) = installed {
            let origin = state.members[&self.participant.id].origin.clone();
            let error = state.fail(origin, error);
            let sender = state.changed();
            drop(state);
            notify(sender);
            return Err(error);
        }
        let member = state.members.get_mut(&self.participant.id).unwrap();
        // SAFETY: this guard remains on the current thread until withdrawal
        // and signal cleanup. The numeric pthread identity never escapes the
        // serialized sender path.
        member.activity = Activity::Running(unsafe { libc::pthread_self() });
        member.generation = Some(self.generation);
        Ok(true)
    }

    /// Must precede the final drain. A closer cannot send after this returns.
    /// Retirement stays counted through the caller's mask restoration.
    pub(crate) fn withdraw(&mut self) {
        #[cfg(test)]
        let mut state = {
            let hook = self
                .participant
                .prepare_probe
                .as_ref()
                .and_then(|probe| probe.withdraw_contended.lock().unwrap().take());
            if let Some(hook) = hook {
                match self.participant.gate.state.try_lock() {
                    Ok(state) => state,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        // This observation runs without the gate mutex. The
                        // actual blocking acquisition below remains required.
                        hook();
                        self.participant.gate.state.lock().unwrap()
                    }
                    Err(std::sync::TryLockError::Poisoned(error)) => {
                        panic!("entry registry lock poisoned during withdrawal: {error}")
                    }
                }
            } else {
                self.participant.gate.state.lock().unwrap()
            }
        };
        #[cfg(not(test))]
        let mut state = self.participant.gate.state.lock().unwrap();
        let member = state.members.get_mut(&self.participant.id).unwrap();
        assert_eq!(member.run, self.run);
        assert!(matches!(
            member.activity,
            Activity::Setup | Activity::Running(_)
        ));
        member.activity = Activity::Retiring;
    }

    /// Called only after clock cleanup, withdrawal, final drain and restoration.
    pub(crate) fn acknowledge(mut self, cleanup: crate::Result<()>) -> GateResult<()> {
        let mut state = self.participant.gate.state.lock().unwrap();
        let member = state.members.get_mut(&self.participant.id).unwrap();
        assert_eq!(member.run, self.run);
        assert_eq!(member.activity, Activity::Retiring);
        member.activity = Activity::Stopped;
        let origin = member.origin.clone();
        if let Err(error) = cleanup {
            state.fail(origin, error);
        }
        self.acknowledged = true;
        let result = state.check();
        let sender = state.changed();
        drop(state);
        notify(sender);
        result
    }
}

impl Drop for Entry<'_> {
    fn drop(&mut self) {
        if self.acknowledged {
            return;
        }
        let sender = {
            let mut state = self.participant.gate.state.lock().unwrap();
            let member = state.members.get_mut(&self.participant.id).unwrap();
            assert_eq!(member.run, self.run);
            member.activity = Activity::Retiring;
            let origin = member.origin.clone();
            state.fail(origin, protocol_failure("entry cleanup was abandoned"));
            state.changed()
        };
        notify(sender);
    }
}

/// Owns the same-thread mask from setup through final withdrawal/drain/restore.
/// CountedVcpu must finish its clock interval before calling finish.
pub(crate) struct RunEntry<'a> {
    entry: Option<Entry<'a>>,
    mask: Option<signal::Mask>,
}

impl RunEntry<'_> {
    pub(crate) fn finish(mut self, clock: crate::Result<()>) -> GateResult<()> {
        self.cleanup(clock)
    }

    fn cleanup(&mut self, clock: crate::Result<()>) -> GateResult<()> {
        let mut entry = self.entry.take().unwrap();
        #[cfg(test)]
        let probe = entry.participant.prepare_probe.clone();
        #[cfg(test)]
        let identity = CleanupIdentity {
            participant: entry.participant.id,
            run: entry.run,
        };
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.cleanup_hook(CleanupPhase::BeforeWithdraw, identity);
        }
        entry.withdraw();
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.cleanup_hook(CleanupPhase::AfterWithdraw, identity);
        }
        let mask = self.mask.take().unwrap().finish();
        let cleanup = match (clock, mask) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(vec![cleanup])),
        };
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.cleanup_hook(CleanupPhase::BeforeAcknowledge, identity);
        }
        entry.acknowledge(cleanup)
    }
}

impl Drop for RunEntry<'_> {
    fn drop(&mut self) {
        if self.entry.is_some() {
            let _ = self.cleanup(Err(protocol_failure(
                "guest entry unwound or was abandoned",
            )));
        }
    }
}

pub(crate) struct CopyAccess {
    gate: Arc<EntryGate>,
    origin: EntryOrigin,
    generation: MappingGeneration,
    retired: bool,
}

impl CopyAccess {
    /// Retire the actual access now, while deferring every notification and
    /// the issuing context's destruction until the caller releases its locks.
    /// The returned token owns no memory or allocation transaction.
    pub(crate) fn retire_deferred(mut self) -> CopyRetirement {
        let change = self.retire();
        CopyRetirement {
            change: Some(change),
            origin: Some(std::mem::take(&mut self.origin)),
            _gate: self.gate.clone(),
        }
    }

    fn retire(&mut self) -> ChangeSignal {
        assert!(!self.retired, "copy retired twice");
        {
            let mut state = self.gate.state.lock().unwrap();
            if std::thread::panicking() {
                state.fail(self.origin.clone(), protocol_failure("host copy unwound"));
            }
            state.copies = state.copies.checked_sub(1).expect("copy retired twice");
            self.retired = true;
            state.changed()
        }
    }
}

impl Drop for CopyAccess {
    fn drop(&mut self) {
        if !self.retired {
            notify(self.retire());
        }
    }
}

/// Linear notification ownership after a copy's count has already retired.
/// Dropping an unqueued token remains safe and notifies as a fallback; a caller
/// holding memory locks must retain the token until after releasing them.
pub(crate) struct CopyRetirement {
    change: Option<ChangeSignal>,
    origin: Option<EntryOrigin>,
    _gate: Arc<EntryGate>,
}

impl std::fmt::Debug for CopyRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyRetirement")
            .field("notification_pending", &self.change.is_some())
            .finish_non_exhaustive()
    }
}

impl CopyRetirement {
    pub(crate) fn notify(mut self) {
        self.notify_pending();
    }

    fn notify_pending(&mut self) {
        if let Some(change) = self.change.take() {
            notify(change);
            // As with ordinary CopyAccess::drop, release the copy's own
            // issuing context after its retirement notification, not under
            // the gate mutex or while its caller still owns memory locks.
            drop(self.origin.take());
        }
    }
}

impl Drop for CopyRetirement {
    fn drop(&mut self) {
        self.notify_pending();
    }
}

pub(crate) struct RetainedOperand {
    gate: Arc<EntryGate>,
    origin: EntryOrigin,
    generation: MappingGeneration,
}

impl std::fmt::Debug for RetainedOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedOperand")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Drop for RetainedOperand {
    fn drop(&mut self) {
        let sender = {
            let mut state = self.gate.state.lock().unwrap();
            if std::thread::panicking() {
                state.fail(
                    self.origin.clone(),
                    protocol_failure("retained host operand unwound"),
                );
            }
            assert_eq!(state.generation, self.generation);
            state.retained_operands = state
                .retained_operands
                .checked_sub(1)
                .expect("retained host operand retired twice");
            state.changed()
        };
        notify(sender);
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The private unchanged-mapping close protocol has no production closer yet"
    )
)]
pub(crate) struct Closing {
    gate: Arc<EntryGate>,
    id: u64,
    complete: bool,
}

impl Closing {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The private unchanged-mapping close protocol has no production closer yet"
        )
    )]
    pub(crate) async fn finish(mut self) -> GateResult<Closed> {
        loop {
            let changed = {
                let mut state = self.gate.state.lock().unwrap();
                state.check()?;
                assert_eq!(state.admission, Admission::Closing(self.id));
                if state.stopped() {
                    state.admission = Admission::Closed(self.id);
                    self.complete = true;
                    return Ok(Closed {
                        gate: self.gate.clone(),
                        id: self.id,
                        published: false,
                        previous_domain: None,
                        published_domain: false,
                    });
                }
                state.changed.clone()
            };
            let _ = changed.await;
        }
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        if !self.complete {
            self.gate
                .poison(None, protocol_failure("unfinished close was abandoned"));
        }
    }
}

/// Exclusive stopped-address-space token. Dropping it reopens admission. A
/// mapping change is authorized only through [`Closed::publish`], which binds
/// the external change and the next admitted generation.
pub(crate) struct Closed {
    gate: Arc<EntryGate>,
    id: u64,
    published: bool,
    // Only a quiescent single-member close can change this capability. A
    // clean abandoned plan restores the previous state; a poisoned one cannot
    // reopen a usable mapping and keeps the conservative reservation.
    previous_domain: Option<bool>,
    published_domain: bool,
}

impl Closed {
    /// Stage the known final image's shared-file domain before publication.
    /// The reservation stays active until successful publication commits this
    /// value. In particular, retiring the last file view cannot admit another
    /// participant while the old image is still installed.
    pub(crate) fn set_single_member_domain(&mut self, active: bool) -> GateResult<()> {
        let state = self.gate.state.lock().unwrap();
        state.check()?;
        assert_eq!(state.admission, Admission::Closed(self.id));
        assert!(
            self.previous_domain.is_some(),
            "domain requires a quiescent single-member close"
        );
        assert!(!self.published, "domain must be staged before publication");
        self.published_domain = active;
        Ok(())
    }

    pub(crate) fn belongs_to(&self, gate: &Arc<EntryGate>) -> bool {
        Arc::ptr_eq(&self.gate, gate)
    }

    /// Publish exactly one prepared mapping image while every participant is
    /// stopped and short copies are drained. The operation runs without the
    /// registry mutex; admission remains closed through this token. Any error
    /// or unwind poisons the gate, so a partially changed external mapping can
    /// never be followed by guest re-entry.
    /// Success requires the memory owner's opaque installed-view receipt. Its
    /// private constructor binds generation advancement to retained backing and
    /// pointer-provenance metadata instead of trusting an arbitrary callback.
    pub(crate) fn publish(
        &mut self,
        origin: impl Into<EntryOrigin>,
        expected: MappingGeneration,
        operation: impl FnOnce(MappingGeneration) -> crate::Result<crate::memory::InstalledMapping>,
    ) -> GateResult<MappingGeneration> {
        let origin = origin.into();
        let next = {
            let mut state = self.gate.state.lock().unwrap();
            state.check()?;
            assert_eq!(state.admission, Admission::Closed(self.id));
            if state.generation != expected {
                let failure = state.fail(
                    origin.clone(),
                    protocol_failure("staged mapping generation changed before publication"),
                );
                let sender = state.changed();
                drop(state);
                drop(operation);
                notify(sender);
                return Err(failure);
            }
            if self.published {
                let failure = state.fail(
                    origin.clone(),
                    protocol_failure("mapping generation published twice"),
                );
                let sender = state.changed();
                drop(state);
                drop(operation);
                notify(sender);
                return Err(failure);
            }
            if state.retained_operands != 0 {
                let failure = state.fail(
                    origin.clone(),
                    protocol_failure("mapping publication has retained host operands"),
                );
                let sender = state.changed();
                drop(state);
                drop(operation);
                notify(sender);
                return Err(failure);
            }
            let Some(next) = state.generation.next() else {
                let failure = state.fail(
                    origin.clone(),
                    protocol_failure("mapping generation exhausted"),
                );
                let sender = state.changed();
                drop(state);
                drop(operation);
                notify(sender);
                return Err(failure);
            };
            next
        };

        let result = catch_unwind(AssertUnwindSafe(|| operation(next)));
        let installed = match result {
            Ok(Ok(installed)) => installed,
            Ok(Err(error)) => return Err(self.gate.poison(origin, error)),
            Err(payload) => {
                self.gate
                    .poison(origin, protocol_failure("mapping publication unwound"));
                resume_unwind(payload);
            }
        };
        if installed.generation() != next {
            return Err(self.gate.poison(
                origin,
                protocol_failure("installed mapping receipt has the wrong generation"),
            ));
        }
        let sender = {
            let mut state = self.gate.state.lock().unwrap();
            state.check()?;
            assert_eq!(state.admission, Admission::Closed(self.id));
            assert_eq!(state.generation.next(), Some(next));
            state.generation = next;
            self.published = true;
            if self.previous_domain.is_some() {
                state.single_member_domain = self.published_domain;
            }
            state.changed()
        };
        notify(sender);
        Ok(next)
    }
}

impl Drop for Closed {
    fn drop(&mut self) {
        let sender = {
            let mut state = self.gate.state.lock().unwrap();
            assert_eq!(state.admission, Admission::Closed(self.id));
            if std::thread::panicking() {
                state.fail(None, protocol_failure("closed operation unwound"));
            }
            if !self.published
                && state.failure.is_none()
                && let Some(previous) = self.previous_domain
            {
                state.single_member_domain = previous;
            }
            state.admission = Admission::Open;
            state.changed()
        };
        notify(sender);
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::Context;
    use std::task::Poll;

    use futures::executor::block_on;
    use futures::task::noop_waker;

    use super::*;

    fn poll<F: Future>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(&noop_waker()))
    }

    fn assert_quiescent_refusal_is_quiet(gate: &Arc<EntryGate>) {
        let before = gate.test_state();
        let bookkeeping = {
            let state = gate.state.lock().unwrap();
            (
                state.single_member_domain,
                state.next_close,
                state.next_member,
            )
        };
        let changed = gate.subscribe();
        assert!(gate.try_close_quiescent_single().unwrap().is_none());
        assert_eq!(gate.test_state(), before);
        let state = gate.state.lock().unwrap();
        assert_eq!(
            (
                state.single_member_domain,
                state.next_close,
                state.next_member
            ),
            bookkeeping
        );
        assert!(state.failure.is_none());
        drop(state);
        assert!(changed.now_or_never().is_none(), "quiet refusal notified");
    }

    #[test]
    fn quiescent_single_refuses_missing_or_multiple_members_without_effects() {
        let gate = EntryGate::new();
        assert_quiescent_refusal_is_quiet(&gate);
        let _first = gate.register().unwrap();
        let second = gate.register().unwrap();
        assert_quiescent_refusal_is_quiet(&gate);
        drop(second);
        let closed = gate.try_close_quiescent_single().unwrap().unwrap();
        assert!(gate.single_member_domain_active());
        assert!(gate.test_state().closed);
        drop(closed);
        assert!(!gate.single_member_domain_active());
        assert!(gate.test_state().open);
    }

    #[test]
    fn quiescent_single_refuses_setup_running_and_retiring_without_interrupt() {
        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        let mut entry = participant.try_enter().unwrap().unwrap();
        assert_quiescent_refusal_is_quiet(&gate);
        // This only records this thread's identity. The quiescent operation
        // must never send its reserved signal to the unmasked test thread.
        assert!(entry.activate(|| Ok(())).unwrap());
        assert_quiescent_refusal_is_quiet(&gate);
        entry.withdraw();
        assert_quiescent_refusal_is_quiet(&gate);
        entry.acknowledge(Ok(())).unwrap();
        drop(gate.try_close_quiescent_single().unwrap().unwrap());
    }

    #[test]
    fn quiescent_single_refuses_copies_retained_operands_and_other_closes() {
        let gate = EntryGate::new();
        let _participant = gate.register().unwrap();
        let copy = gate.try_copy(None).unwrap().unwrap();
        assert_quiescent_refusal_is_quiet(&gate);
        let retained = gate.retain_operand(&copy).unwrap();
        drop(copy);
        assert_quiescent_refusal_is_quiet(&gate);
        drop(retained);

        let closing = gate.try_close().unwrap().unwrap();
        assert_quiescent_refusal_is_quiet(&gate);
        let closed = block_on(closing.finish()).unwrap();
        assert_quiescent_refusal_is_quiet(&gate);
        drop(closed);
        drop(gate.try_close_quiescent_single().unwrap().unwrap());
    }

    #[test]
    fn quiescent_single_exhaustion_is_quiet_and_prior_failure_identity_survives() {
        for close_exhausted in [false, true] {
            let gate = EntryGate::new();
            let _participant = gate.register().unwrap();
            {
                let mut state = gate.state.lock().unwrap();
                if close_exhausted {
                    state.next_close = u64::MAX;
                } else {
                    state.generation = MappingGeneration(u64::MAX);
                }
            }
            assert_quiescent_refusal_is_quiet(&gate);
        }

        let gate = EntryGate::new();
        let _participant = gate.register().unwrap();
        let expected = gate.poison(None, protocol_failure("prior quiescent admission failure"));
        let before = gate.test_state();
        let changed = gate.subscribe();
        let Err(actual) = gate.try_close_quiescent_single() else {
            panic!("poisoned gate admitted quiescent publication");
        };
        assert!(Arc::ptr_eq(&expected, &actual));
        assert_eq!(actual.causes().len(), 1);
        assert_eq!(gate.test_state(), before);
        assert!(!gate.single_member_domain_active());
        assert!(changed.now_or_never().is_none());
    }

    #[test]
    fn quiescent_single_domain_commits_only_with_the_published_image() {
        let gate = EntryGate::new();
        let _participant = gate.register().unwrap();
        let mut closed = gate.try_close_quiescent_single().unwrap().unwrap();
        let first = closed
            .publish(None, MappingGeneration::INITIAL, |next| {
                Ok(crate::memory::InstalledMapping::gate_control(next))
            })
            .unwrap();
        drop(closed);
        assert!(gate.single_member_domain_active());

        let mut abandoned = gate.try_close_quiescent_single().unwrap().unwrap();
        abandoned.set_single_member_domain(false).unwrap();
        assert!(gate.single_member_domain_active());
        drop(abandoned);
        assert!(gate.single_member_domain_active());
        assert_eq!(gate.generation().unwrap(), first);

        let mut retirement = gate.try_close_quiescent_single().unwrap().unwrap();
        retirement.set_single_member_domain(false).unwrap();
        retirement
            .publish(None, first, |next| {
                assert!(gate.single_member_domain_active());
                Ok(crate::memory::InstalledMapping::gate_control(next))
            })
            .unwrap();
        assert!(!gate.single_member_domain_active());
        drop(retirement);
        let _second = gate.register().unwrap();
        assert_eq!(gate.test_state().members.len(), 2);
    }

    #[test]
    fn quiescent_unattached_publication_admits_only_its_first_real_participant() {
        let gate = EntryGate::new();
        let mut closed = gate.try_close_quiescent_unattached().unwrap().unwrap();
        assert!(gate.test_state().members.is_empty());
        assert!(gate.single_member_domain_active());
        closed
            .publish(None, MappingGeneration::INITIAL, |next| {
                Ok(crate::memory::InstalledMapping::gate_control(next))
            })
            .unwrap();
        drop(closed);
        let mut participant = gate.register().unwrap();
        assert_eq!(gate.test_state().members.len(), 1);
        let mut entry = participant.try_enter().unwrap().unwrap();
        assert_eq!(entry.generation, MappingGeneration(1));
        entry.withdraw();
        entry.acknowledge(Ok(())).unwrap();
        let Err(failure) = gate.register() else {
            panic!("ordinary shared-file arena admitted a second participant");
        };
        assert_eq!(gate.test_state().members.len(), 1);
        assert!(Arc::ptr_eq(&failure, &gate.pending_failure().unwrap()));
    }

    #[test]
    fn quiescent_unattached_requires_empty_quiet_arena_and_closed_registration_refuses() {
        let gate = EntryGate::new();
        let first = gate.register().unwrap();
        let before = gate.test_state();
        let changed = gate.subscribe();
        assert!(gate.try_close_quiescent_unattached().unwrap().is_none());
        assert_eq!(gate.test_state(), before);
        assert!(changed.now_or_never().is_none());
        drop(first);

        let copy = gate.try_copy(None).unwrap().unwrap();
        let before = gate.test_state();
        let changed = gate.subscribe();
        assert!(gate.try_close_quiescent_unattached().unwrap().is_none());
        assert_eq!(gate.test_state(), before);
        assert!(changed.now_or_never().is_none());
        let retained = gate.retain_operand(&copy).unwrap();
        drop(copy);
        let before = gate.test_state();
        let changed = gate.subscribe();
        assert!(gate.try_close_quiescent_unattached().unwrap().is_none());
        assert_eq!(gate.test_state(), before);
        assert!(changed.now_or_never().is_none());
        drop(retained);

        let closed = gate.try_close_quiescent_unattached().unwrap().unwrap();
        assert!(gate.register().is_err());
        assert!(gate.test_state().members.is_empty());
        drop(closed);
        assert!(gate.single_member_domain_active());
        assert!(gate.pending_failure().is_some());
    }

    #[test]
    fn quiescent_single_failed_publication_keeps_terminal_domain() {
        let gate = EntryGate::new();
        let _participant = gate.register().unwrap();
        let mut closed = gate.try_close_quiescent_single().unwrap().unwrap();
        closed.set_single_member_domain(false).unwrap();
        let failure = closed
            .publish(None, MappingGeneration::INITIAL, |_| {
                Err(protocol_failure("shared-file replacement failed"))
            })
            .unwrap_err();
        drop(closed);
        assert!(gate.single_member_domain_active());
        assert_eq!(gate.test_state().generation, MappingGeneration::INITIAL);
        let Err(refused) = gate.try_close_quiescent_single() else {
            panic!("failed shared-file publication admitted another close");
        };
        assert!(Arc::ptr_eq(&failure, &refused));
        assert!(gate.try_copy(None).is_err());
    }

    #[test]
    fn quiescent_single_registration_race_has_no_second_member_window() {
        let gate = EntryGate::new();
        let _first = gate.register().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let registering_gate = gate.clone();
        let registering_barrier = barrier.clone();
        let registering = std::thread::spawn(move || {
            registering_barrier.wait();
            registering_gate.register()
        });
        barrier.wait();
        let closed = gate.try_close_quiescent_single().unwrap();
        let registered = registering.join().unwrap();
        match closed {
            Some(closed) => {
                let Err(failure) = registered else {
                    panic!("registration crossed the single-member reservation");
                };
                assert_eq!(gate.test_state().members.len(), 1);
                assert!(Arc::ptr_eq(&gate.pending_failure().unwrap(), &failure));
                assert!(failure.primary.to_string().contains(
                    "ordinary shared-file domain permits only its existing stopped participant"
                ));
                drop(closed);
                assert!(gate.single_member_domain_active());
            }
            None => {
                let _second = registered.unwrap();
                assert_eq!(gate.test_state().members.len(), 2);
                assert!(!gate.single_member_domain_active());
                assert!(gate.pending_failure().is_none());
            }
        }
    }

    struct PublicationLockWake {
        gate: Arc<EntryGate>,
        allocation: Arc<Mutex<()>>,
        address: Arc<Mutex<()>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl std::task::Wake for PublicationLockWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let _allocation = self.allocation.try_lock().expect("wake held allocation");
            let _address = self.address.try_lock().expect("wake held address state");
            let _state = self
                .gate
                .state
                .try_lock()
                .expect("wake held entry registry");
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn copy_retirement_decrements_now_and_notifies_once_after_external_unlock() {
        for explicit_notify in [false, true] {
            let gate = EntryGate::new();
            let copy = gate.try_copy(None).unwrap().unwrap();
            let observer = Arc::new(PublicationLockWake {
                gate: gate.clone(),
                allocation: Arc::new(Mutex::new(())),
                address: Arc::new(Mutex::new(())),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let waker = std::task::Waker::from(observer.clone());
            let mut changed = pin!(gate.subscribe());
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let allocation = observer.allocation.lock().unwrap();
            let address = observer.address.lock().unwrap();
            let retirement = copy.retire_deferred();
            assert_eq!(gate.test_state().copies, 0);
            assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            drop((address, allocation));
            if explicit_notify {
                retirement.notify();
            } else {
                drop(retirement);
            }
            assert_eq!(
                gate.test_state().copies,
                0,
                "token decremented a retired copy again"
            );
            assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            // Shared::poll wakes its registered tasks when it observes Ready.
            // Use a non-counting waker only for this completion observation;
            // the Pending polls above still count the retirement's actual wake.
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                    .is_ready()
            );
            assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

            let ordinary = gate.try_copy(None).unwrap().unwrap();
            let mut next = pin!(gate.subscribe());
            assert!(
                next.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            drop(ordinary);
            assert_eq!(gate.test_state().copies, 0);
            assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert!(
                next.as_mut()
                    .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                    .is_ready()
            );
            assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn copy_retirement_retains_then_releases_its_gate_without_leaking_a_copy() {
        let gate = EntryGate::new();
        let weak = Arc::downgrade(&gate);
        let copy = gate.try_copy(None).unwrap().unwrap();
        let retirement = copy.retire_deferred();
        assert_eq!(gate.test_state().copies, 0);
        drop(gate);
        assert!(
            weak.upgrade().is_some(),
            "retirement lost its gate lifetime"
        );
        retirement.notify();
        assert!(weak.upgrade().is_none(), "retirement leaked its gate");
    }

    #[test]
    fn copy_retirement_preserves_unwind_cause_before_deferred_notification() {
        struct DeferredCopy {
            copy: Option<CopyAccess>,
            queue: Arc<Mutex<Vec<CopyRetirement>>>,
        }
        impl Drop for DeferredCopy {
            fn drop(&mut self) {
                let retirement = self.copy.take().unwrap().retire_deferred();
                self.queue.lock().unwrap().push(retirement);
            }
        }
        let gate = EntryGate::new();
        let queue = Arc::new(Mutex::new(Vec::new()));
        let changed = gate.subscribe();
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _copy = DeferredCopy {
                copy: Some(gate.try_copy(None).unwrap().unwrap()),
                queue: queue.clone(),
            };
            panic!("injected deferred copy unwind");
        }));
        assert!(result.is_err());
        assert_eq!(gate.test_state().copies, 0);
        let failure = gate.pending_failure().unwrap();
        assert!(failure.primary.to_string().contains("host copy unwound"));
        assert_eq!(failure.causes().len(), 1);
        assert!(changed.clone().now_or_never().is_none());
        let retirement = {
            let mut queue = queue.lock().unwrap();
            assert_eq!(queue.len(), 1);
            queue.pop().unwrap()
        };
        retirement.notify();
        assert!(changed.now_or_never().is_some());
        assert!(Arc::ptr_eq(&failure, &gate.pending_failure().unwrap()));
        assert_eq!(failure.causes().len(), 1);
    }

    #[test]
    fn publication_preoperation_failures_drop_owned_guards_before_notification() {
        for scenario in ["generation", "duplicate", "retained", "exhaustion", "prior"] {
            let gate = EntryGate::new();
            let retained = if scenario == "retained" {
                let copy = gate.try_copy(None).unwrap().unwrap();
                let retained = gate.retain_operand(&copy).unwrap();
                drop(copy);
                Some(retained)
            } else {
                None
            };
            if scenario == "exhaustion" {
                gate.state.lock().unwrap().generation = MappingGeneration(u64::MAX);
            }
            let mut closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
            if scenario == "duplicate" {
                closed
                    .publish(None, MappingGeneration::INITIAL, |next| {
                        Ok(crate::memory::InstalledMapping::gate_control(next))
                    })
                    .unwrap();
            }
            let expected = if scenario == "generation" {
                MappingGeneration(99)
            } else {
                gate.generation().unwrap()
            };
            let prior = (scenario == "prior")
                .then(|| gate.poison(None, protocol_failure("prior publication failure")));
            let observer = Arc::new(PublicationLockWake {
                gate: gate.clone(),
                allocation: Arc::new(Mutex::new(())),
                address: Arc::new(Mutex::new(())),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let waker = std::task::Waker::from(observer.clone());
            let mut changed = pin!(gate.subscribe());
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let allocation = observer.allocation.lock().unwrap();
            let address = observer.address.lock().unwrap();
            let called = std::cell::Cell::new(false);
            let called_ref = &called;
            let failure = closed
                .publish(None, expected, move |next| {
                    called_ref.set(true);
                    drop((address, allocation));
                    Ok(crate::memory::InstalledMapping::gate_control(next))
                })
                .unwrap_err();
            assert!(!called.get(), "rejected operation ran for {scenario}");
            assert!(observer.allocation.try_lock().is_ok());
            assert!(observer.address.try_lock().is_ok());
            assert_eq!(
                observer.calls.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(prior.is_none()),
                "unexpected wake count for {scenario}"
            );
            if let Some(prior) = prior {
                assert!(Arc::ptr_eq(&prior, &failure));
                assert_eq!(failure.causes().len(), 1);
                assert!(
                    changed
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            } else {
                assert!(
                    changed
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_ready()
                );
            }
            drop(retained);
            drop(closed);
        }
    }

    #[test]
    fn quiescent_publication_success_and_error_notify_after_owned_locks_drop() {
        for succeeds in [false, true] {
            let gate = EntryGate::new();
            let _participant = gate.register().unwrap();
            let mut closed = gate.try_close_quiescent_single().unwrap().unwrap();
            let observer = Arc::new(PublicationLockWake {
                gate: gate.clone(),
                allocation: Arc::new(Mutex::new(())),
                address: Arc::new(Mutex::new(())),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let waker = std::task::Waker::from(observer.clone());
            let mut changed = pin!(gate.subscribe());
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let allocation = observer.allocation.lock().unwrap();
            let address = observer.address.lock().unwrap();
            let result = closed.publish(None, MappingGeneration::INITIAL, move |next| {
                drop((address, allocation));
                if succeeds {
                    Ok(crate::memory::InstalledMapping::gate_control(next))
                } else {
                    Err(protocol_failure("injected shared-file install failure"))
                }
            });
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(gate.pending_failure().is_none(), succeeds);
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            drop(closed);
        }
    }

    #[test]
    fn closed_registration_does_not_admit_an_entry_or_copy() {
        let gate = EntryGate::new();
        let closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        let mut participant = gate.register().unwrap();
        assert!(participant.try_enter().unwrap().is_none());
        assert!(gate.try_copy(None).unwrap().is_none());
        let changed = gate.subscribe();
        drop(closed);
        assert!(changed.now_or_never().is_some());
        let mut entry = participant.try_enter().unwrap().unwrap();
        entry.withdraw();
        entry.acknowledge(Ok(())).unwrap();
        drop(gate.try_copy(None).unwrap().unwrap());
    }

    #[test]
    fn successful_publication_advances_exactly_one_admission_generation() {
        let gate = EntryGate::new();
        let expected = gate.generation().unwrap();
        let mut closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        let generation = closed
            .publish(None, expected, |next| {
                assert_eq!(next.get(), expected.get() + 1);
                Ok(crate::memory::InstalledMapping::gate_control(next))
            })
            .unwrap();
        assert_eq!(generation.get(), 1);
        assert_eq!(gate.test_state().generation, generation);
        drop(closed);

        let copy = gate.try_copy(None).unwrap().unwrap();
        assert_eq!(copy.generation, generation);
        drop(copy);
    }

    #[test]
    fn failed_or_unwound_publication_never_reopens_an_usable_gate() {
        for unwinds in [false, true] {
            let gate = EntryGate::new();
            let expected = gate.generation().unwrap();
            let mut closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                closed.publish(None, expected, |next| {
                    if unwinds {
                        panic!("injected mapping publication unwind");
                    }
                    let _ = next;
                    Err(protocol_failure("injected mapping publication failure"))
                })
            }));
            if unwinds {
                assert!(outcome.is_err());
            } else {
                assert!(outcome.unwrap().is_err());
            }
            assert_eq!(gate.test_state().generation, expected);
            assert!(gate.pending_failure().is_some());
            drop(closed);
            assert!(gate.try_copy(None).is_err());
            assert!(gate.try_close().is_err());
        }
    }

    #[test]
    fn stale_publication_generation_refuses_before_running_the_operation() {
        let gate = EntryGate::new();
        let stale = gate.generation().unwrap();
        let mut closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        closed
            .publish(None, stale, |next| {
                Ok(crate::memory::InstalledMapping::gate_control(next))
            })
            .unwrap();
        drop(closed);

        let mut closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        let called = std::cell::Cell::new(false);
        let result = closed.publish(None, stale, |next| {
            called.set(true);
            Ok(crate::memory::InstalledMapping::gate_control(next))
        });
        assert!(result.is_err());
        assert!(!called.get());
        assert_eq!(gate.test_state().generation.get(), 1);
        drop(closed);
        assert!(gate.try_copy(None).is_err());
    }

    #[test]
    fn blocking_copies_wake_on_reopen_and_retained_poison() {
        for poisoned in [false, true] {
            let gate = EntryGate::new();
            let closed = block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
            let waiting_gate = gate.clone();
            let (sender, receiver) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                sender
                    .send(waiting_gate.copy_blocking(None).map(drop))
                    .unwrap();
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            // Taking this same mutex after the counter changes proves the
            // production Condvar::wait released it, not merely that the worker
            // started or was about to call copy_blocking.
            loop {
                if gate.state.lock().unwrap().copy_waits != 0 {
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "copy never waited");
                std::thread::yield_now();
            }
            assert!(matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            if poisoned {
                let expected = gate.poison(None, protocol_failure("copy wait control"));
                let actual = receiver
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .unwrap_err();
                assert!(Arc::ptr_eq(&actual, &expected));
                // Poison wakes the waiter while admission is still closed.
                drop(closed);
            } else {
                drop(closed);
                receiver
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .unwrap();
            }
            worker.join().unwrap();
            assert_eq!(gate.state.lock().unwrap().copies, 0);
        }
    }

    #[test]
    fn close_waits_for_setup_and_copies_and_retirement() {
        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        let mut entry = participant.try_enter().unwrap().unwrap();
        let copy = gate.try_copy(None).unwrap().unwrap();
        let close = gate.try_close().unwrap().unwrap();
        let mut closed = pin!(close.finish());
        assert!(poll(closed.as_mut()).is_pending());
        assert!(
            !entry
                .activate(|| panic!("closed entry installed a KVM mask"))
                .unwrap()
        );
        drop(copy);
        assert!(poll(closed.as_mut()).is_pending());
        entry.withdraw();
        assert!(poll(closed.as_mut()).is_pending());
        entry.acknowledge(Ok(())).unwrap();
        let Poll::Ready(Ok(token)) = poll(closed.as_mut()) else {
            panic!("all entries and copies stopped but close remained pending");
        };
        drop(token);
        assert!(gate.admit_operation().is_ok());
    }

    #[test]
    fn withdrawal_prevents_a_later_send_but_does_not_acknowledge() {
        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        let mut entry = participant.try_enter().unwrap().unwrap();
        assert!(entry.activate(|| Ok(())).unwrap());
        entry.withdraw();
        let close = gate
            .try_close_with(|_| panic!("sent to an already withdrawn target"))
            .unwrap()
            .unwrap();
        let mut closed = pin!(close.finish());
        assert!(poll(closed.as_mut()).is_pending());
        entry.acknowledge(Ok(())).unwrap();
        assert!(poll(closed.as_mut()).is_ready());
    }

    #[test]
    fn failed_send_preserves_running_accounting_and_typed_cause() {
        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        let id = participant.id;
        let mut entry = participant.try_enter().unwrap().unwrap();
        assert!(entry.activate(|| Ok(())).unwrap());
        let changed = gate.subscribe();
        let failure =
            match gate.try_close_with(|_| Err(std::io::Error::from_raw_os_error(libc::ESRCH))) {
                Err(failure) => failure,
                Ok(_) => panic!("failed send reported a close"),
            };
        assert!(changed.now_or_never().is_some());
        assert!(matches!(
            gate.state.lock().unwrap().members[&id].activity,
            Activity::Running(_)
        ));
        assert!(
            matches!(failure.error().primary(), Error::EntryControl { source, .. } if source.raw_os_error() == Some(libc::ESRCH))
        );
        assert!(gate.admit_operation().is_err());
        assert!(gate.try_copy(None).is_err());
        entry.withdraw();
        assert!(entry.acknowledge(Ok(())).is_err());
        assert_eq!(
            gate.state.lock().unwrap().members[&id].activity,
            Activity::Stopped
        );
        assert!(gate.try_close().is_err());
    }

    #[test]
    fn abandoned_close_poison_is_sticky_and_wakes_existing_waiters() {
        let gate = EntryGate::new();
        let copy = gate.try_copy(None).unwrap().unwrap();
        let close = gate.try_close().unwrap().unwrap();
        let changed = gate.subscribe();
        drop(close);
        assert!(changed.now_or_never().is_some());
        assert!(gate.try_copy(None).is_err());
        drop(copy);
        assert!(gate.register().is_err());
        assert!(gate.try_close().is_err());
        assert!(gate.pending_failure().is_some());
    }

    #[test]
    fn abandoned_entry_withdraws_without_claiming_cleanup() {
        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        let id = participant.id;
        let mut entry = participant.try_enter().unwrap().unwrap();
        assert!(entry.activate(|| Ok(())).unwrap());
        drop(entry);
        drop(participant);
        let state = gate.state.lock().unwrap();
        assert_eq!(state.members[&id].activity, Activity::Retiring);
        assert!(!state.stopped());
        assert!(state.failure.is_some());
    }

    #[test]
    fn primary_failure_is_not_replaced_by_cleanup() {
        let gate = EntryGate::new();
        let first = gate.poison(
            None,
            failure("first", std::io::Error::from_raw_os_error(libc::EIO)),
        );
        let second = gate.poison(
            None,
            failure("cleanup", std::io::Error::from_raw_os_error(libc::EINVAL)),
        );
        assert!(Arc::ptr_eq(&first, &second));
        let error = second.error();
        assert!(
            matches!(error.primary(), Error::EntryControl { operation: "first", source } if source.raw_os_error() == Some(libc::EIO))
        );
        let Error::WithCleanup { cleanup, .. } = error else {
            panic!("lost cleanup cause");
        };
        assert_eq!(cleanup.len(), 1);
        assert!(
            matches!(cleanup[0].as_ref(), Error::EntryControl { operation: "cleanup", source } if source.raw_os_error() == Some(libc::EINVAL))
        );
    }

    #[test]
    fn identities_never_wrap_and_a_poison_cannot_look_open() {
        let gate = EntryGate::new();
        gate.state.lock().unwrap().next_member = u64::MAX;
        let changed = gate.subscribe();
        assert!(gate.register().is_err());
        assert!(changed.now_or_never().is_some());
        assert!(gate.admit_operation().is_err());
        assert!(gate.try_copy(None).is_err());
    }

    #[test]
    fn unwinding_control_operations_preserve_cleanup_and_failure() {
        use std::panic::AssertUnwindSafe;
        use std::panic::catch_unwind;

        const CHILD: &str = "REVERIE_KVM_ENTRY_UNWIND_CHILD";
        let Ok(case) = std::env::var(CHILD) else {
            let mut failures = Vec::new();
            for case in ["mask", "send"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "entry::tests::unwinding_control_operations_preserve_cleanup_and_failure",
                        "--nocapture",
                    ])
                    .env(CHILD, case)
                    .output()
                    .unwrap();
                if !output.status.success() {
                    failures.push(format!(
                        "{case}: status={}\n{}{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
            assert!(failures.is_empty(), "{}", failures.join("\n"));
            return;
        };

        fn mask_bits() -> u64 {
            // SAFETY: the query writes a live sigset and does not change it.
            unsafe {
                let mut mask: libc::sigset_t = std::mem::zeroed();
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                    0
                );
                (1..=64).fold(0, |bits, signal| {
                    bits | ((libc::sigismember(&mask, signal) as u64) << (signal - 1))
                })
            }
        }

        if case == "send" {
            // Leave signal 64 blocked in the original mask, so a missed drain
            // cannot disappear through the handler when that mask is restored.
            unsafe {
                let mut reserved: libc::sigset_t = std::mem::zeroed();
                assert_eq!(libc::sigemptyset(&mut reserved), 0);
                assert_eq!(libc::sigaddset(&mut reserved, 64), 0);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, &reserved, std::ptr::null_mut()),
                    0
                );
            }
        }
        let original_mask = mask_bits();
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        let origin = FailureContext::new(
            run.clone(),
            reverie::Pid::from_raw(37),
            reverie::Pid::from_raw(39),
        );
        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        participant.set_origin(Some(origin));
        let id = participant.id;
        let changed = gate.subscribe();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let entry = participant.try_enter().unwrap().unwrap();
            let mask = signal::Mask::block().unwrap();
            let mut guard = RunEntry {
                entry: Some(entry),
                mask: Some(mask),
            };
            match case.as_str() {
                "mask" => {
                    let _ = guard.entry.as_mut().unwrap().activate(|| {
                        panic!("mask operation unwound");
                    });
                }
                "send" => {
                    assert!(guard.entry.as_mut().unwrap().activate(|| Ok(())).unwrap());
                    let _ = gate.try_close_with(|thread| {
                        // Queue a real control signal before the injected unwind.
                        // Its drain must finish before the original mask returns.
                        assert_eq!(unsafe { libc::pthread_kill(thread, 64) }, 0);
                        panic!("send operation unwound");
                    });
                }
                _ => panic!("unknown unwind control"),
            }
            panic!("injected operation did not unwind");
        }));
        let payload = outcome.expect_err("operation panic was swallowed");
        let expected = if case == "mask" {
            "mask operation unwound"
        } else {
            "send operation unwound"
        };
        assert_eq!(payload.downcast_ref::<&str>().copied(), Some(expected));
        assert_eq!(mask_bits(), original_mask, "unwind changed the host mask");
        assert!(
            !gate.state.is_poisoned(),
            "cleanup would panic on registry lock"
        );
        assert!(
            changed.now_or_never().is_some(),
            "unwind lost the failure wake"
        );
        let pending = gate.pending_failure().unwrap();
        let operation = if case == "mask" {
            assert!(Arc::ptr_eq(
                &pending.origin.as_ref().unwrap().run.upgrade().unwrap(),
                &run
            ));
            "install KVM temporary signal mask unwound"
        } else {
            "interrupt running vCPU unwound"
        };
        assert!(
            matches!(pending.error().primary(), Error::EntryControl { operation: actual, .. } if *actual == operation)
        );
        let Error::WithCleanup { cleanup, .. } = pending.error() else {
            panic!("unwind cleanup cause was lost");
        };
        assert!(cleanup.iter().any(|error| matches!(
            error.primary(),
            Error::EntryControl {
                operation: "guest entry unwound or was abandoned",
                ..
            }
        )));
        assert!(run.primary().is_none(), "capture published a Tool callback");
        assert_eq!(
            gate.state.lock().unwrap().members[&id].activity,
            Activity::Stopped
        );
        assert!(gate.admit_operation().is_err());
        assert!(participant.try_enter().is_err());
        assert!(gate.try_copy(None).is_err());
        assert!(gate.try_close().is_err());
        // A second mask guard refuses a stale queued control signal.
        signal::Mask::block().unwrap().finish().unwrap();
        assert_eq!(mask_bits(), original_mask);
        drop(participant);
        assert!(gate.state.lock().unwrap().members.is_empty());
    }

    #[cfg(feature = "native-test-support")]
    #[test]
    fn running_vcpu_is_interrupted_and_retires_before_close_completes() {
        const CHILD: &str = "REVERIE_KVM_ENTRY_VCPU_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "entry::tests::running_vcpu_is_interrupted_and_retires_before_close_completes",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let kvm = kvm_ioctls::Kvm::new().expect("this control requires /dev/kvm");
        let vm = kvm.create_vm().unwrap();
        let mut memory = crate::GuestMemory::new(0, 4096).unwrap();
        // Real-mode MOV byte [0x100], 1 followed by JMP to itself. Observing
        // the store establishes guest execution before the controller closes.
        memory
            .write(0, &[0xc6, 0x06, 0x00, 0x01, 0x01, 0xeb, 0xfe])
            .unwrap();
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 4096,
            userspace_addr: memory.host_address(),
            flags: 0,
        };
        // SAFETY: memory retains this aligned mapping until after vCPU/VM
        // destruction, and this control never changes its address or length.
        unsafe { vm.set_user_memory_region(region).unwrap() };
        let mut vcpu = vm.create_vcpu(0).unwrap();
        let mut segments = vcpu.get_sregs().unwrap();
        segments.cs.base = 0;
        segments.cs.selector = 0;
        vcpu.set_sregs(&segments).unwrap();
        vcpu.set_regs(&kvm_bindings::kvm_regs {
            rip: 0,
            rflags: 2,
            ..Default::default()
        })
        .unwrap();

        let gate = EntryGate::new();
        let mut participant = gate.register().unwrap();
        let entry = participant.prepare(&vcpu).unwrap().unwrap();
        let controller_gate = gate.clone();
        let observer_memory = memory.clone();
        let (close_acquired, close_observed) = std::sync::mpsc::channel();
        let controller = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            // SAFETY: the owned Mapping stays alive and KVM alone writes this
            // byte. Volatile observation prevents a compiler-hoisted read of
            // externally modified memory; it supplies no snapshot guarantee.
            while unsafe {
                std::ptr::read_volatile((observer_memory.host_address() + 0x100) as *const u8)
            } == 0
            {
                if std::time::Instant::now() >= deadline {
                    let _ = controller_gate.try_close();
                    panic!("guest did not execute its marker before the control deadline");
                }
                std::thread::yield_now();
            }
            let closing = controller_gate.try_close().unwrap().unwrap();
            let token = block_on(closing.finish()).unwrap();
            close_acquired.send(()).unwrap();
            token
        });
        let result = vcpu.run();
        assert!(matches!(result, Err(error) if error.errno() == libc::EINTR));
        assert!(matches!(
            close_observed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        entry.finish(Ok(())).unwrap();
        close_observed
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let closed = controller.join().unwrap();
        assert!(participant.prepare(&vcpu).unwrap().is_none());
        drop(closed);
        participant
            .prepare(&vcpu)
            .unwrap()
            .unwrap()
            .finish(Ok(()))
            .unwrap();
        drop(vcpu);
        drop(vm);
        drop(memory);
    }
}
#[cfg(test)]
#[test]
fn captured_owner_is_visible_before_wake_outside_registry_lock() {
    use std::future::Future;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Wake;
    use std::task::Waker;

    struct InspectWake {
        gate: Arc<EntryGate>,
        owner: owner::DriverOwner,
        origin: owner::OperationOrigin,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Wake for InspectWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let state = self.gate.state.try_lock().expect("wake held entry lock");
            let pending = self.owner.pending();
            assert_eq!(pending.len(), 1);
            assert!(Arc::ptr_eq(&pending[0], state.failure.as_ref().unwrap()));
            assert!(
                pending[0]
                    .operation
                    .as_ref()
                    .unwrap()
                    .same_callback(&self.origin)
            );
            assert!(!self.origin.callback_dropped());
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let driver = owner::DriverScope::new();
    let owner = driver.owner();
    let callback = owner.begin_callback(None).unwrap();
    let origin = callback.origin();
    let gate = EntryGate::new();
    let observer = Arc::new(InspectWake {
        gate: gate.clone(),
        owner: owner.clone(),
        origin: origin.clone(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let waker = Waker::from(observer.clone());
    let mut changed = std::pin::pin!(owner.subscribe());
    assert!(matches!(
        changed.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Pending
    ));
    let failure = gate.poison(
        EntryOrigin {
            failure: None,
            operation: Some(origin.clone()),
        },
        protocol_failure("owner wake control"),
    );
    assert_eq!(observer.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        changed
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert!(!origin.callback_dropped());
    drop(callback);
    assert!(origin.callback_dropped());
    let retired = driver.retire();
    retired.result.unwrap();
    assert_eq!(retired.pending.len(), 1);
    assert!(Arc::ptr_eq(&retired.pending[0], &failure));
    retired.notification.notify();
}
