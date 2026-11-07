/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run-owned failure notification and typed cause retention.

pub(crate) mod owned_future;
pub(crate) mod tool_panics;

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;

use futures::FutureExt;
use futures::channel::oneshot;
use futures::future::BoxFuture;
use futures::future::Shared;
use futures::future::select;
use reverie::BackendFailure;
use reverie::GlobalTool;
use reverie::Pid;

use crate::Error;
use crate::error::ErrorExt;

pub(crate) type FailureSubscription = Shared<oneshot::Receiver<()>>;

/// The synchronous read owner must join its C reader before destroying the
/// actual Tool observer. A normal `select(...).await` drops its remaining
/// future inside the ready poll, before that owner can perform retirement.
/// Keep both observers in an always-pending driver and report its selection
/// through this facade without completing or unwinding the driver allocation.
struct TerminalReadWait {
    driver: BoxFuture<'static, ()>,
    completion: Arc<Mutex<Option<std::thread::Result<()>>>>,
}

impl TerminalReadWait {
    fn new<G: GlobalTool + 'static>(global: Weak<G>, mut local: FailureSubscription) -> Self {
        let completion = Arc::new(Mutex::new(None));
        let selected = completion.clone();
        let driver = async move {
            let global = global
                .upgrade()
                .expect("KVM terminal read outlived its GlobalState");
            let observer = catch_unwind(AssertUnwindSafe(|| global.wait_for_backend_failure()));
            let mut observer = match observer {
                Ok(observer) => observer,
                Err(payload) => {
                    *selected.lock().unwrap() = Some(Err(payload));
                    std::future::pending::<()>().await;
                    unreachable!("terminal observer driver completed");
                }
            };
            let mut stopped = false;
            std::future::poll_fn(|context| {
                if !stopped {
                    // Catch here, while both allocations remain owned by the
                    // driver. An unwind out of this async body could otherwise
                    // drop a panicking Tool observer before the C join.
                    let polled = catch_unwind(AssertUnwindSafe(|| {
                        if local.poll_unpin(context).is_ready()
                            || observer.as_mut().poll(context).is_ready()
                        {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }));
                    let outcome = match polled {
                        Ok(Poll::Pending) => None,
                        Ok(Poll::Ready(())) => Some(Ok(())),
                        Err(payload) => Some(Err(payload)),
                    };
                    if let Some(outcome) = outcome {
                        stopped = true;
                        *selected.lock().unwrap() = Some(outcome);
                    }
                }
                Poll::<()>::Pending
            })
            .await;
        }
        .boxed();
        Self { driver, completion }
    }
}

impl Future for TerminalReadWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let polled = self.driver.as_mut().poll(context);
        debug_assert!(polled.is_pending());
        let completion = self.completion.lock().unwrap().take();
        match completion {
            None => Poll::Pending,
            Some(Ok(())) => Poll::Ready(()),
            // The driver poll stack has returned and still owns the actual
            // observer. TerminalObserver catches this exact payload, joins the
            // C reader, then catches destruction of this facade separately.
            Some(Err(payload)) => std::panic::resume_unwind(payload),
        }
    }
}

pub(crate) struct RunFailure {
    primary: Mutex<Option<(Arc<Error>, BackendFailure)>>,
    panic_cleanup: Mutex<Vec<RetainedPanicCleanup>>,
    entry_failures: Mutex<Vec<Arc<crate::entry::PendingFailure>>>,
    reported_causes: Mutex<Vec<Arc<Error>>>,
    publication: Mutex<()>,
    published: AtomicBool,
    sender: Mutex<Option<oneshot::Sender<()>>>,
    receiver: FailureSubscription,
    report: Box<dyn Fn(BackendFailure) + Send + Sync>,
    terminal_wait: Box<dyn Fn(FailureSubscription) -> BoxFuture<'static, ()> + Send + Sync>,
}

struct RetainedPanicCleanup {
    // Completion transfers each diagnostic once, without releasing the
    // associated user panic payloads during folding or physical joins.
    error: Option<Arc<Error>>,
    _secondary_payloads: Vec<owned_future::PanicPayload>,
}

pub(crate) fn references_shared_error(error: &Error, target: &Arc<Error>) -> bool {
    let shared =
        |error: &Arc<Error>| Arc::ptr_eq(error, target) || references_shared_error(error, target);
    match error {
        Error::SignalEffects { cause, .. }
        | Error::SharedFailure(cause)
        | Error::WorkerFailure { error: cause, .. }
        | Error::Cleanup { error: cause, .. } => shared(cause),
        Error::WithCleanup { primary, cleanup } => shared(primary) || cleanup.iter().any(shared),
        Error::ExecWorkerTeardown(error) => references_shared_error(error, target),
        _ => false,
    }
}

fn shared_primary(error: &Error) -> Option<Arc<Error>> {
    match error {
        Error::SignalEffects { cause, .. }
        | Error::SharedFailure(cause)
        | Error::WorkerFailure { error: cause, .. }
        | Error::Cleanup { error: cause, .. }
        | Error::WithCleanup { primary: cause, .. } => {
            shared_primary(cause).or_else(|| Some(cause.clone()))
        }
        Error::ExecWorkerTeardown(error) => shared_primary(error),
        _ => None,
    }
}

impl RunFailure {
    pub(crate) fn new<G: GlobalTool + 'static>(global: &Arc<G>) -> Arc<Self> {
        let (sender, receiver) = oneshot::channel();
        let global = Arc::downgrade(global);
        let terminal_global = global.clone();
        Arc::new(Self {
            primary: Mutex::new(None),
            panic_cleanup: Mutex::new(Vec::new()),
            entry_failures: Mutex::new(Vec::new()),
            reported_causes: Mutex::new(Vec::new()),
            publication: Mutex::new(()),
            published: AtomicBool::new(false),
            sender: Mutex::new(Some(sender)),
            receiver: receiver.shared(),
            report: Box::new(move |event| {
                global
                    .upgrade()
                    .expect("KVM failure outlived its GlobalState")
                    .report_backend_failure(event);
            }),
            // Keep only a weak reference between reads. The public completion
            // path unwraps GlobalState after all owned callbacks have retired.
            terminal_wait: Box::new(move |local| {
                TerminalReadWait::new(terminal_global.clone(), local).boxed()
            }),
        })
    }

    pub(crate) fn subscribe(&self) -> FailureSubscription {
        self.receiver.clone()
    }

    /// An origin's registration may retire before another owned worker has
    /// finished appending cleanup to the poisoned Mapping. Preserve the live
    /// cause until public completion, after all owned joins have returned.
    pub(crate) fn retain_entry_failure(&self, failure: Arc<crate::entry::PendingFailure>) {
        let mut retained = self.entry_failures.lock().unwrap();
        if !retained.iter().any(|entry| Arc::ptr_eq(entry, &failure)) {
            retained.push(failure);
        }
    }

    pub(crate) fn primary(&self) -> Option<Arc<Error>> {
        self.primary
            .lock()
            .expect("KVM failure lock poisoned")
            .as_ref()
            .map(|(cause, _)| cause.clone())
    }

    #[cfg(test)]
    pub(crate) fn published_primary(&self) -> Option<Arc<Error>> {
        self.published
            .load(Ordering::Acquire)
            .then(|| self.primary())
            .flatten()
    }

    fn publish(&self, event: BackendFailure, error: Error) -> Error {
        if matches!(error.primary(), Error::RunAborted) {
            // A Tool subscriber may already be doing terminal cleanup while
            // the synchronous publisher is still returning. Do not sample its
            // unpublished primary or turn this cleanup marker into success.
            // Public completion attaches the retained cause after owned joins.
            return error;
        }
        // Select the first cause and its event in the same publication order.
        // Keep this lock only through the synchronous terminal hook and local
        // notification, never through a guest RPC or a physical join.
        let _publication = self
            .publication
            .lock()
            .expect("KVM failure publication lock poisoned");
        if self
            .primary()
            .is_some_and(|primary| error.retains_primary(&primary))
        {
            return error;
        }
        // Rechecking a captured entry cause must not publish it again merely
        // because a different cause won first place or a fresh typed snapshot
        // was needed to retain later cleanup. Match shared identity, never text.
        if self
            .reported_causes
            .lock()
            .unwrap()
            .iter()
            .any(|cause| error.retains_primary(cause))
        {
            return error;
        }
        let identity = shared_primary(&error);
        let error = Arc::new(error);
        self.primary
            .lock()
            .expect("KVM failure lock poisoned")
            .get_or_insert_with(|| (error.clone(), event));
        // This synchronous hook must close the Tool's terminal transaction
        // before either its subscribers or the local driver wake into cleanup.
        (self.report)(event);
        self.reported_causes
            .lock()
            .unwrap()
            .push(identity.unwrap_or_else(|| error.clone()));
        self.published.store(true, Ordering::Release);
        if let Some(sender) = self
            .sender
            .lock()
            .expect("KVM failure sender lock poisoned")
            .take()
        {
            let _ = sender.send(());
        }
        Error::SharedFailure(error)
    }

    /// Retain an already completed fork owner's diagnostics before it resumes
    /// its original panic. Publication and child completion belong to its
    /// caller; this transfer invokes no Tool hook and creates no notification.
    pub(crate) fn retain_panic_cleanup(
        &self,
        error: Error,
        secondary_payloads: Vec<owned_future::PanicPayload>,
    ) {
        let error = match error {
            Error::SharedFailure(error) => error,
            error => Arc::new(error),
        };
        let record = RetainedPanicCleanup {
            error: Some(error),
            _secondary_payloads: secondary_payloads,
        };
        self.panic_cleanup
            .lock()
            .expect("KVM panic cleanup lock poisoned")
            .push(record);
    }

    /// Called only after the run's owned workers and processes have returned.
    /// Terminal cleanup markers do not publish a second cause; retain the
    /// original typed cause here once its publisher has completed.
    pub(crate) fn complete<R>(&self, result: crate::Result<R>) -> crate::Result<R> {
        let causes = self.entry_failures.lock().unwrap().clone();
        let result = crate::entry::driver::fold_causes(
            result,
            causes.iter().flat_map(|failure| failure.causes()),
        );
        let first = self
            .primary
            .lock()
            .expect("KVM failure lock poisoned")
            .as_ref()
            .map(|(error, event)| (error.clone(), event.tid.as_raw()));
        let retained: Vec<_> = {
            let mut records = self
                .panic_cleanup
                .lock()
                .expect("KVM panic cleanup lock poisoned");
            records
                .iter_mut()
                .filter_map(|record| record.error.take())
                .collect()
        };
        let mut result = result;
        for error in retained {
            // A joined result may already carry this exact completed cause.
            // Equal text or an equal primary alone never establishes identity.
            if result
                .as_ref()
                .err()
                .is_some_and(|result| references_shared_error(result, &error))
            {
                continue;
            }
            result = Err(match result {
                Err(primary) => primary.with_cleanup(vec![Error::SharedFailure(error)]),
                Ok(_) => Error::SharedFailure(error),
            });
        }
        match (first, result) {
            (Some((primary, tid)), Err(error)) => Err(error.complete_after_failure(primary, tid)),
            (Some((primary, _)), Ok(_)) => Err(Error::SharedFailure(primary)),
            (None, result) => result,
        }
    }
}

#[derive(Clone)]
pub(crate) struct FailureContext {
    pub(crate) run: Arc<RunFailure>,
    process: Arc<ProcessFailure>,
    pid: Pid,
    tid: Pid,
}

/// Entry failures may outlive their driver and be retained by RunFailure.
/// An observer retains notification, never a callable publisher or a strong
/// back-reference that would form a cycle with that completed-cause storage.
pub(crate) struct FailureObservation {
    #[cfg(test)]
    pub(crate) run: std::sync::Weak<RunFailure>,
    receiver: FailureSubscription,
}

impl FailureObservation {
    pub(crate) fn subscribe(&self) -> FailureSubscription {
        self.receiver.clone()
    }
}

struct ProcessFailure {
    sender: Mutex<Option<oneshot::Sender<()>>>,
    receiver: FailureSubscription,
}

impl ProcessFailure {
    fn new() -> Arc<Self> {
        let (sender, receiver) = oneshot::channel();
        Arc::new(Self {
            sender: Mutex::new(Some(sender)),
            receiver: receiver.shared(),
        })
    }

    fn publish(&self) {
        if let Some(sender) = self
            .sender
            .lock()
            .expect("KVM process failure sender lock poisoned")
            .take()
        {
            let _ = sender.send(());
        }
    }
}

impl FailureContext {
    /// Whether `other` is this exact context: the same shared failure
    /// records and the same task. A clone of one is always the same.
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.run, &other.run)
            && Arc::ptr_eq(&self.process, &other.process)
            && self.pid == other.pid
            && self.tid == other.tid
    }

    pub(crate) fn observe(&self) -> FailureObservation {
        FailureObservation {
            #[cfg(test)]
            run: Arc::downgrade(&self.run),
            receiver: self.run.subscribe(),
        }
    }

    pub(crate) fn new(run: Arc<RunFailure>, pid: Pid, tid: Pid) -> Self {
        Self {
            run,
            process: ProcessFailure::new(),
            pid,
            tid,
        }
    }

    pub(crate) fn for_process(&self, pid: Pid) -> Self {
        Self::new(self.run.clone(), pid, pid)
    }

    pub(crate) fn for_thread(&self, tid: Pid) -> Self {
        Self {
            tid,
            ..self.clone()
        }
    }

    /// The initial owner must return every run failure. An independent process
    /// can finish ordinary work after another process fails, unless its Tool
    /// explicitly terminates the shared global state. Its RPCs still observe
    /// the run-wide notification at the actual request boundary.
    pub(crate) fn driver_subscription(&self, is_traced_tree_root: bool) -> FailureSubscription {
        if is_traced_tree_root {
            self.run.subscribe()
        } else {
            self.process.receiver.clone()
        }
    }

    /// A synchronous host read polls only this terminal observer on its
    /// original Rust worker. Preserve the ordinary driver's process scope;
    /// unrelated fork failures do not cancel it unless the Tool terminates
    /// global state. This is deliberately distinct from an RPC subscription.
    pub(crate) fn terminal_wait(&self, is_traced_tree_root: bool) -> BoxFuture<'static, ()> {
        (self.run.terminal_wait)(self.driver_subscription(is_traced_tree_root))
    }

    pub(crate) fn publish(&self, phase: &'static str, error: Error) -> Error {
        let real_failure = !matches!(error.primary(), Error::RunAborted);
        let error = self.run.publish(
            BackendFailure {
                pid: self.pid,
                tid: self.tid,
                phase,
            },
            error,
        );
        // The synchronous Tool terminal transition has returned before either
        // a process peer or an owned join can begin failure cleanup. A derived
        // cancellation marker must not create a new process failure.
        if real_failure {
            self.process.publish();
        }
        error
    }
}

/// A failure wait that can be polled again after it fires: it stays Ready.
/// An `async fn`'s future must not be polled after it completes, but a wait
/// kept for a thread's whole syscall loop is checked once per syscall.
pub(crate) struct StickyFailure<F> {
    wait: Option<F>,
}

impl<F: Future<Output = ()> + Unpin> StickyFailure<F> {
    pub(crate) fn new(wait: F) -> Self {
        Self { wait: Some(wait) }
    }
}

impl<F: Future<Output = ()> + Unpin> Future for StickyFailure<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let Some(wait) = self.wait.as_mut() else {
            return Poll::Ready(());
        };
        match Pin::new(wait).poll(context) {
            Poll::Ready(()) => {
                self.wait = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A [`StickyFailure`] that is polled again only after its own waker fired.
///
/// One thread keeps its Tool callbacks' failure wait for every callback, and
/// each guest syscall polls it several times (while capturing the syscall
/// boundary, and before and after each poll of the callback), nearly always
/// to learn that nothing has failed. Polling the wait polls its
/// subscriptions: a shared receiver that re-registers its waker under a lock,
/// and the GlobalTool's failure future. Here the wait is only ever polled with
/// this wrapper's own waker, which records the wake and then wakes the task
/// that polled last. Until that waker is woken, polling the wait again would
/// return Pending (the Future contract: a Pending wait wakes the waker it was
/// last polled with before it can complete), so the poll is skipped; it costs
/// one waker registration and one atomic swap instead. The task's waker is
/// registered before the swap, so a wake after the swap still reaches it.
/// Once the wait is Ready, every later poll is Ready, as with
/// [`StickyFailure`]. The same reasoning lets [`KeptRpcFailure`] skip polls.
pub(crate) struct GatedFailure<F> {
    wait: StickyFailure<F>,
    gate: Arc<FailureGate>,
    gate_waker: Waker,
}

struct FailureGate {
    /// Set when the wait wakes `gate_waker`, and initially, so the first poll
    /// polls the wait and registers `gate_waker` with its sources; cleared
    /// before each poll of the wait.
    woken: AtomicBool,
    /// The task that polled last.
    task: futures::task::AtomicWaker,
}

impl Wake for FailureGate {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Set before waking, so the poll this wake causes polls the wait.
        self.woken.store(true, Ordering::SeqCst);
        self.task.wake();
    }
}

impl<F: Future<Output = ()> + Unpin> GatedFailure<F> {
    pub(crate) fn new(wait: F) -> Self {
        let gate = Arc::new(FailureGate {
            woken: AtomicBool::new(true),
            task: futures::task::AtomicWaker::new(),
        });
        Self {
            wait: StickyFailure::new(wait),
            gate_waker: Waker::from(gate.clone()),
            gate,
        }
    }
}

impl<F: Future<Output = ()> + Unpin> Future for GatedFailure<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if this.wait.wait.is_none() {
            return Poll::Ready(());
        }
        this.gate.task.register(context.waker());
        if !this.gate.woken.swap(false, Ordering::SeqCst) {
            return Poll::Pending;
        }
        let (wait, gate_waker) = (&mut this.wait, &this.gate_waker);
        match catch_unwind(AssertUnwindSafe(|| {
            Pin::new(wait).poll(&mut Context::from_waker(gate_waker))
        })) {
            Ok(poll) => poll,
            Err(panic) => {
                // A panicking wait is polled again next time, as before.
                this.gate.woken.store(true, Ordering::SeqCst);
                std::panic::resume_unwind(panic);
            }
        }
    }
}

/// A failure wait one thread keeps for every RPC its Tool callbacks send,
/// instead of building one per RPC. Building one takes the GlobalTool's
/// failure waiter (Detcore locks its scheduler for it, and boxes the future)
/// and polls a fresh subscription. It is shared by reference with the guest
/// handle that sends the RPCs; the mutexes are for `Sync`, and neither is
/// held across an await.
///
/// The wait itself holds one waker, but a Tool may have several RPCs pending
/// at once (each in its own task under `FuturesUnordered`, say). So the wait
/// is only ever polled with `fan_out`, and each pending RPC registers its
/// own waker as an [`RpcFailureListener`]; a failure wakes all of them.
///
/// Because the wait's waker never changes, it only has to be polled again
/// after `fan_out` was woken: an RPC poll otherwise costs one slot update
/// and two atomic loads, not a poll of the wait's subscriptions.
pub(crate) struct KeptRpcFailure<F> {
    wait: Mutex<StickyFailure<F>>,
    listeners: Arc<RpcListeners>,
    fan_out: Waker,
    /// Set once the wait has reported Ready, or its poll panicked; set
    /// before the wait is released.
    fired: AtomicBool,
    /// Runs right after a poll that found the wait Ready releases it.
    #[cfg(test)]
    after_ready_release: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl<F: Future<Output = ()> + Unpin> KeptRpcFailure<F> {
    pub(crate) fn new(wait: F) -> Self {
        let listeners = Arc::new(RpcListeners::default());
        Self {
            wait: Mutex::new(StickyFailure::new(wait)),
            fan_out: Waker::from(listeners.clone()),
            listeners,
            fired: AtomicBool::new(false),
            #[cfg(test)]
            after_ready_release: Mutex::new(None),
        }
    }
}

impl<F> KeptRpcFailure<F> {
    /// Takes the wait, unless it is being polled elsewhere. Then it marks
    /// this listener deferred, so that poll wakes it when it releases the
    /// wait, and tries once more: the holder may have released it before
    /// seeing the mark.
    fn lock_wait(&self) -> Option<std::sync::MutexGuard<'_, StickyFailure<F>>> {
        let try_wait = || match self.wait.try_lock() {
            Ok(wait) => Some(wait),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        if let Some(wait) = try_wait() {
            return Some(wait);
        }
        self.listeners.deferred.store(true, Ordering::SeqCst);
        // Pairs with the fence in wake_deferred: either the holder sees the
        // mark after releasing the wait, or this retry sees it released.
        std::sync::atomic::fence(Ordering::SeqCst);
        try_wait()
    }

    /// After releasing the wait: wakes every listener if one was deferred.
    fn wake_deferred(&self) {
        std::sync::atomic::fence(Ordering::SeqCst);
        if self.listeners.deferred.swap(false, Ordering::SeqCst) {
            self.listeners.wake_by_ref();
        }
    }
}

/// The wakers of the RPCs currently listening to a [`KeptRpcFailure`], by
/// slot. A slot is free from its listener's drop until the next `listen`.
/// A wake takes the wakers out; each listener registers again when polled.
///
/// Cloning, waking and dropping a waker can run arbitrary code, which may
/// poll, register or drop another listener, so none of them happens while
/// `slots` is locked.
struct RpcListeners {
    slots: Mutex<ListenerSlots>,
    /// Set when `fan_out` is woken, and initially, so the wait is polled
    /// once to register `fan_out` with its sources; cleared before each poll
    /// of the wait.
    woken: AtomicBool,
    /// Set by a listener that found the wait being polled elsewhere; whoever
    /// releases the wait next wakes every listener.
    deferred: AtomicBool,
}

impl Default for RpcListeners {
    fn default() -> Self {
        Self {
            slots: Mutex::default(),
            woken: AtomicBool::new(true),
            deferred: AtomicBool::new(false),
        }
    }
}

#[derive(Default)]
struct ListenerSlots {
    wakers: Vec<Option<Waker>>,
    free: Vec<usize>,
}

impl RpcListeners {
    fn slots(&self) -> std::sync::MutexGuard<'_, ListenerSlots> {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Wake for RpcListeners {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Set before waking, so the poll each wake causes polls the wait.
        self.woken.store(true, Ordering::SeqCst);
        let wakers: Vec<Waker> = self
            .slots()
            .wakers
            .iter_mut()
            .filter_map(Option::take)
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }
}

/// What one RPC's poll of a [`KeptRpcFailure`] established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureCheck {
    /// A failure has been published.
    Failed,
    /// No failure as of this poll; the RPC's waker is registered for one.
    Clear,
    /// The wait was being polled elsewhere (by the poll whose waker polled
    /// this RPC in place), so neither is known. The RPC must not proceed;
    /// it is woken once that poll releases the wait.
    Unknown,
}

/// The polling side of [`KeptRpcFailure`], object-safe so a guest handle can
/// hold it without naming the wait's type. Use it through
/// [`RpcFailureListener`].
pub(crate) trait RpcFailure: Sync {
    /// Takes a listener slot.
    fn listen(&self) -> usize;
    /// Records the listener's waker, then checks the kept wait: Failed once
    /// a failure has been published, and on every poll after that.
    fn poll_failure(&self, listener: usize, context: &mut Context<'_>) -> FailureCheck;
    /// Frees the listener's slot.
    fn unlisten(&self, listener: usize);
}

impl<F: Future<Output = ()> + Unpin + Send> RpcFailure for KeptRpcFailure<F> {
    fn listen(&self) -> usize {
        let mut slots = self.listeners.slots();
        match slots.free.pop() {
            Some(listener) => listener,
            None => {
                slots.wakers.push(None);
                slots.wakers.len() - 1
            }
        }
    }

    fn poll_failure(&self, listener: usize, context: &mut Context<'_>) -> FailureCheck {
        // Register before polling, so a failure published during or after
        // the poll finds this waker.
        let registered = self.listeners.slots().wakers[listener]
            .as_ref()
            .is_some_and(|waker| waker.will_wake(context.waker()));
        if !registered {
            let waker = context.waker().clone();
            let replaced = self.listeners.slots().wakers[listener].replace(waker);
            drop(replaced);
        }
        if self.fired.load(Ordering::SeqCst) {
            return FailureCheck::Failed;
        }
        let Some(mut wait) = self.lock_wait() else {
            return FailureCheck::Unknown;
        };
        // Fired while this listener waited for the lock: `fired` is set
        // before the wait is released, so it is seen here.
        if self.fired.load(Ordering::SeqCst) {
            return FailureCheck::Failed;
        }
        // Not woken since the last poll of the wait: it would be Pending
        // again. A wake after this swap wakes the waker registered above.
        if !self.listeners.woken.swap(false, Ordering::SeqCst) {
            drop(wait);
            self.wake_deferred();
            return FailureCheck::Clear;
        }
        let polled = std::panic::catch_unwind(AssertUnwindSafe(|| {
            Pin::new(&mut *wait)
                .poll(&mut Context::from_waker(&self.fan_out))
                .is_ready()
        }));
        let ready = match polled {
            Ok(ready) => ready,
            Err(panic) => {
                // The wait cannot be polled again: terminal, as a failure,
                // and every listener must hear it before the panic goes on.
                self.fired.store(true, Ordering::SeqCst);
                drop(wait);
                self.listeners.deferred.store(false, Ordering::SeqCst);
                self.listeners.wake_by_ref();
                std::panic::resume_unwind(panic);
            }
        };
        if ready {
            // Before releasing the wait, so a listener that takes it next
            // sees the failure instead of a stale `woken`.
            self.fired.store(true, Ordering::SeqCst);
        }
        drop(wait);
        if ready {
            #[cfg(test)]
            if let Some(hook) = self.after_ready_release.lock().unwrap().as_ref() {
                hook();
            }
            // Once: a listener that got Unknown, or polled in place while
            // this poll completed the wait, may have no other wake coming.
            self.listeners.deferred.store(false, Ordering::SeqCst);
            self.listeners.wake_by_ref();
            FailureCheck::Failed
        } else {
            self.wake_deferred();
            FailureCheck::Clear
        }
    }

    fn unlisten(&self, listener: usize) {
        let removed = {
            let mut slots = self.listeners.slots();
            slots.free.push(listener);
            slots.wakers[listener].take()
        };
        drop(removed);
    }
}

/// One RPC's registration with a thread's [`KeptRpcFailure`], from before
/// its first poll until it completes or is dropped.
pub(crate) struct RpcFailureListener<'a> {
    failure: &'a dyn RpcFailure,
    listener: usize,
}

impl<'a> RpcFailureListener<'a> {
    pub(crate) fn new(failure: &'a dyn RpcFailure) -> Self {
        Self {
            failure,
            listener: failure.listen(),
        }
    }

    pub(crate) fn poll(&self, context: &mut Context<'_>) -> FailureCheck {
        self.failure.poll_failure(self.listener, context)
    }
}

impl Drop for RpcFailureListener<'_> {
    fn drop(&mut self) {
        self.failure.unlisten(self.listener);
    }
}

pub(crate) async fn wait_for_failure<G: GlobalTool>(
    global: &G,
    local: Option<FailureSubscription>,
) {
    let local = async {
        match local {
            Some(receiver) => {
                let _ = receiver.await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    let _ = select(std::pin::pin!(local), global.wait_for_backend_failure()).await;
}

/// Per-host-thread fault admission for actual guest-worker spawn controls.
/// The ordinary spawn and recovery path still receives the OS's real error.
#[cfg(test)]
pub(crate) mod spawn_refusal {
    use std::cell::RefCell;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    thread_local! {
        static NEXT: RefCell<Option<Arc<Probe>>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct ObservedError {
        pub(crate) raw_errno: Option<i32>,
        pub(crate) kind: std::io::ErrorKind,
        pub(crate) message: String,
    }

    impl ObservedError {
        pub(crate) fn read(error: &std::io::Error) -> Self {
            Self {
                raw_errno: error.raw_os_error(),
                kind: error.kind(),
                message: error.to_string(),
            }
        }
    }

    #[derive(Default)]
    pub(crate) struct Probe {
        consumed: AtomicUsize,
        error: Mutex<Option<ObservedError>>,
    }

    impl Probe {
        pub(crate) fn consumed(&self) -> usize {
            self.consumed.load(Ordering::SeqCst)
        }
        pub(crate) fn error(&self) -> Option<ObservedError> {
            self.error.lock().unwrap().clone()
        }
    }

    pub(crate) struct Guard {
        probe: Arc<Probe>,
        prior: Option<Arc<Probe>>,
        thread: std::thread::ThreadId,
    }

    impl Guard {
        pub(crate) fn arm(probe: Arc<Probe>) -> Self {
            assert_eq!(probe.consumed(), 0, "spawn refusal probe cannot be reused");
            assert!(probe.error().is_none());
            let prior = NEXT.with(|next| next.replace(Some(probe.clone())));
            Self {
                probe,
                prior,
                thread: std::thread::current().id(),
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            assert_eq!(
                self.thread,
                std::thread::current().id(),
                "spawn refusal guard must be polled and dropped on its admitting thread"
            );
            let pending = NEXT.with(|next| next.replace(self.prior.take()));
            assert!(
                pending
                    .as_ref()
                    .is_none_or(|pending| Arc::ptr_eq(pending, &self.probe))
            );
            // During an earlier assertion's unwind, restoration still occurs;
            // that original panic remains a test failure rather than aborting
            // while trying to diagnose the same failed setup twice.
            if !std::thread::panicking() {
                assert_eq!(
                    self.probe.consumed(),
                    1,
                    "exactly one actual spawn must consume refusal"
                );
                assert!(
                    self.probe.error().is_some(),
                    "Builder.spawn must really refuse"
                );
            }
        }
    }

    pub(super) fn prepare(
        builder: std::thread::Builder,
    ) -> (std::thread::Builder, Option<Arc<Probe>>) {
        let probe = NEXT.with(|next| next.take());
        if let Some(probe) = &probe {
            assert_eq!(probe.consumed.fetch_add(1, Ordering::SeqCst), 0);
            // Same impossible allocation as the existing real-OS helper
            // control. This does not synthesize an Err or consume child state.
            (builder.stack_size(usize::MAX / 2), Some(probe.clone()))
        } else {
            (builder, None)
        }
    }

    pub(super) fn refused(probe: Option<&Probe>, error: &std::io::Error) {
        if let Some(probe) = probe {
            let previous = probe
                .error
                .lock()
                .unwrap()
                .replace(ObservedError::read(error));
            assert!(previous.is_none(), "one-shot refusal recorded twice");
        }
    }

    pub(crate) fn is_armed() -> bool {
        NEXT.with(|next| next.borrow().is_some())
    }
}

/// Keep the initialized child state recoverable if the OS refuses the spawn.
/// A successful worker takes sole ownership before doing any child work.
pub(crate) fn spawn_owned<S, R, F>(
    builder: std::thread::Builder,
    state: S,
    run: F,
) -> std::result::Result<std::thread::JoinHandle<R>, (std::io::Error, S)>
where
    S: Send + 'static,
    R: Send + 'static,
    F: FnOnce(S) -> R + Send + 'static,
{
    #[cfg(test)]
    let (builder, refusal) = spawn_refusal::prepare(builder);
    let state = Arc::new(Mutex::new(Some(state)));
    let child_state = state.clone();
    match builder.spawn(move || {
        let state = child_state
            .lock()
            .expect("KVM child state lock poisoned")
            .take()
            .expect("KVM child state consumed twice");
        run(state)
    }) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            #[cfg(test)]
            spawn_refusal::refused(refusal.as_deref(), &error);
            let state = state
                .lock()
                .expect("KVM child state lock poisoned")
                .take()
                .expect("failed KVM spawn consumed child state");
            Err((error, state))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::Context;
    use std::task::Poll;

    use futures::task::noop_waker;

    use super::*;

    /// A wait kept across callbacks: polled Pending with a noop waker (as a
    /// boundary capture's now_or_never does), then with a callback's real
    /// waker, then the failure is published. The real waker must be woken,
    /// and the wait must report Ready on every later poll, never re-polling
    /// the finished wait.
    #[test]
    fn a_kept_failure_wait_stays_ready_after_it_fires() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl futures::task::ArcWake for Wakes {
            fn wake_by_ref(arc: &Arc<Self>) {
                arc.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (sender, receiver) = oneshot::channel::<()>();
        let subscription: FailureSubscription = receiver.shared();
        let mut kept = StickyFailure::new(Box::pin(async move {
            let _ = subscription.await;
        }));
        let noop = noop_waker();
        assert!(
            Pin::new(&mut kept)
                .poll(&mut Context::from_waker(&noop))
                .is_pending()
        );
        let wakes = Arc::new(Wakes::default());
        let waker = futures::task::waker(wakes.clone());
        assert!(
            Pin::new(&mut kept)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        sender.send(()).unwrap();
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "the real waker was not woken"
        );
        for _ in 0..3 {
            assert!(
                Pin::new(&mut kept)
                    .poll(&mut Context::from_waker(&noop))
                    .is_ready()
            );
        }
    }

    /// Counts its polls and is Ready once `ready` is set; it wakes the waker
    /// of its last poll when `fire` is called, as a subscription does.
    #[derive(Default)]
    struct CountedWait {
        polls: std::sync::atomic::AtomicUsize,
        ready: AtomicBool,
        panic_next: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl CountedWait {
        fn fire(&self) {
            self.ready.store(true, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }

        fn polls(&self) -> usize {
            self.polls.load(Ordering::SeqCst)
        }
    }

    fn counted_wait(
        wait: &Arc<CountedWait>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Unpin + 'static>> {
        let wait = wait.clone();
        Box::pin(std::future::poll_fn(move |context| {
            wait.polls.fetch_add(1, Ordering::SeqCst);
            if wait.panic_next.swap(false, Ordering::SeqCst) {
                panic!("controlled failure-wait poll panic");
            }
            if wait.ready.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
            *wait.waker.lock().unwrap() = Some(context.waker().clone());
            Poll::Pending
        }))
    }

    #[derive(Default)]
    struct TaskWakes(std::sync::atomic::AtomicUsize);
    impl futures::task::ArcWake for TaskWakes {
        fn wake_by_ref(arc: &Arc<Self>) {
            arc.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_gated_failure_polls_its_wait_only_after_the_wait_woke_it() {
        let wait = Arc::new(CountedWait::default());
        let mut gated = GatedFailure::new(counted_wait(&wait));
        let noop = noop_waker();
        // The first poll polls the wait, registering the gate's waker.
        assert!(
            Pin::new(&mut gated)
                .poll(&mut Context::from_waker(&noop))
                .is_pending()
        );
        assert_eq!(wait.polls(), 1);
        // Later polls, by any task, skip it until it wakes the gate.
        let wakes = Arc::new(TaskWakes::default());
        let waker = futures::task::waker(wakes.clone());
        for _ in 0..5 {
            assert!(
                Pin::new(&mut gated)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        assert_eq!(wait.polls(), 1);
        // A wake that does not complete the wait: one more poll of it, which
        // finds it Pending again.
        wait.waker.lock().unwrap().take().unwrap().wake();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1, "last task not woken");
        assert!(
            Pin::new(&mut gated)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(wait.polls(), 2);
        // The failure: the task that polled last is woken, the next poll
        // polls the wait and is Ready, and every later poll is Ready without
        // polling it.
        wait.fire();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2, "last task not woken");
        for _ in 0..3 {
            assert!(
                Pin::new(&mut gated)
                    .poll(&mut Context::from_waker(&noop))
                    .is_ready()
            );
        }
        assert_eq!(wait.polls(), 3);
    }

    #[test]
    fn a_gated_failure_repolls_a_wait_whose_poll_panicked() {
        let wait = Arc::new(CountedWait::default());
        let mut gated = GatedFailure::new(counted_wait(&wait));
        let noop = noop_waker();
        wait.panic_next.store(true, Ordering::SeqCst);
        let panicked = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut gated).poll(&mut Context::from_waker(&noop));
        }));
        assert!(panicked.is_err());
        assert!(
            Pin::new(&mut gated)
                .poll(&mut Context::from_waker(&noop))
                .is_pending()
        );
        assert_eq!(wait.polls(), 2);
    }

    #[test]
    fn a_gated_failure_published_from_another_thread_is_seen() {
        // Each round races publication on another thread against polls on
        // this one; the task must always end Ready.
        for _ in 0..200 {
            let (sender, receiver) = oneshot::channel::<()>();
            let subscription: FailureSubscription = receiver.shared();
            let mut gated = GatedFailure::new(Box::pin(async move {
                let _ = subscription.await;
            }));
            let publisher = std::thread::spawn(move || sender.send(()).unwrap());
            futures::executor::block_on(&mut gated);
            publisher.join().unwrap();
            assert!(
                Pin::new(&mut gated)
                    .poll(&mut Context::from_waker(&noop_waker()))
                    .is_ready()
            );
        }
    }

    /// Two RPCs listen to one kept wait with different wakers, as tasks of
    /// a `FuturesUnordered` would. B is polled last and then completes; a
    /// failure published after that must still wake A. Polling the wait
    /// with each RPC's own waker would leave only B's, dead, registered.
    #[test]
    fn a_kept_rpc_failure_wakes_every_pending_listener() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl futures::task::ArcWake for Wakes {
            fn wake_by_ref(arc: &Arc<Self>) {
                arc.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (sender, receiver) = oneshot::channel::<()>();
        let subscription: FailureSubscription = receiver.shared();
        let kept = KeptRpcFailure::new(Box::pin(async move {
            let _ = subscription.await;
        }));
        let wakes_a = Arc::new(Wakes::default());
        let waker_a = futures::task::waker(wakes_a.clone());
        let wakes_b = Arc::new(Wakes::default());
        let waker_b = futures::task::waker(wakes_b.clone());
        let a = RpcFailureListener::new(&kept);
        let b = RpcFailureListener::new(&kept);
        assert_eq!(
            a.poll(&mut Context::from_waker(&waker_a)),
            FailureCheck::Clear
        );
        assert_eq!(
            b.poll(&mut Context::from_waker(&waker_b)),
            FailureCheck::Clear
        );
        drop(b);
        sender.send(()).unwrap();
        assert_eq!(wakes_a.0.load(Ordering::SeqCst), 1, "A was not woken");
        assert_eq!(wakes_b.0.load(Ordering::SeqCst), 0, "B had completed");
        assert_eq!(
            a.poll(&mut Context::from_waker(&noop_waker())),
            FailureCheck::Failed
        );
        // A listener that arrives after the failure, reusing B's slot, sees
        // it at once.
        let late = RpcFailureListener::new(&kept);
        assert_eq!(late.listener, 1);
        assert_eq!(
            late.poll(&mut Context::from_waker(&noop_waker())),
            FailureCheck::Failed
        );
    }

    /// The kept wait is polled once to register its fan-out waker, and then
    /// only after that waker is woken, however often RPCs poll it.
    #[test]
    fn a_kept_rpc_failure_polls_its_wait_only_after_a_wake() {
        use std::sync::atomic::AtomicUsize;

        let (sender, receiver) = oneshot::channel::<()>();
        let subscription: FailureSubscription = receiver.shared();
        let polls = Arc::new(AtomicUsize::new(0));
        let counted = polls.clone();
        let mut subscription = Box::pin(async move {
            let _ = subscription.await;
        });
        let kept = KeptRpcFailure::new(Box::pin(std::future::poll_fn(move |context| {
            counted.fetch_add(1, Ordering::SeqCst);
            subscription.as_mut().poll(context)
        })));
        let listener = RpcFailureListener::new(&kept);
        let noop = noop_waker();
        for _ in 0..5 {
            assert_eq!(
                listener.poll(&mut Context::from_waker(&noop)),
                FailureCheck::Clear
            );
        }
        assert_eq!(polls.load(Ordering::SeqCst), 1, "polled without a wake");
        sender.send(()).unwrap();
        assert_eq!(
            listener.poll(&mut Context::from_waker(&noop)),
            FailureCheck::Failed
        );
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        for _ in 0..3 {
            assert_eq!(
                listener.poll(&mut Context::from_waker(&noop)),
                FailureCheck::Failed
            );
        }
        assert_eq!(polls.load(Ordering::SeqCst), 2, "polled after it fired");
    }

    type BoxWait = Pin<Box<dyn Future<Output = ()> + Send>>;

    /// The wait wakes its waker during its first poll, as a yielding future
    /// or a completing Shared does, and the waker it reaches polls listener
    /// B in place. B must get Unknown instead of blocking on the wait's lock
    /// or proceeding as if no failure were published, and must be woken once
    /// the outer poll releases the wait, whether it found the wait Pending
    /// or Ready.
    fn listener_polled_from_inside_the_wait(ready_on_first_poll: bool) {
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl futures::task::ArcWake for Wakes {
            fn wake_by_ref(arc: &Arc<Self>) {
                arc.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct PollsOther {
            kept: Arc<KeptRpcFailure<BoxWait>>,
            other: usize,
            other_wakes: Arc<Wakes>,
            seen: Mutex<Vec<FailureCheck>>,
        }
        impl Wake for PollsOther {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                let waker = futures::task::waker(self.other_wakes.clone());
                let check = self
                    .kept
                    .poll_failure(self.other, &mut Context::from_waker(&waker));
                self.seen.lock().unwrap().push(check);
            }
        }

        let mut first = true;
        let kept: Arc<KeptRpcFailure<BoxWait>> = Arc::new(KeptRpcFailure::new(Box::pin(
            std::future::poll_fn(move |context| {
                if std::mem::take(&mut first) {
                    context.waker().wake_by_ref();
                    if ready_on_first_poll {
                        return Poll::Ready(());
                    }
                }
                Poll::Pending
            }),
        )));
        let a = kept.listen();
        let b = kept.listen();
        let other_wakes = Arc::new(Wakes::default());
        let reentrant = Arc::new(PollsOther {
            kept: kept.clone(),
            other: b,
            other_wakes: other_wakes.clone(),
            seen: Mutex::new(Vec::new()),
        });
        let waker = Waker::from(reentrant.clone());
        let outer = kept.poll_failure(a, &mut Context::from_waker(&waker));
        let expected = if ready_on_first_poll {
            FailureCheck::Failed
        } else {
            FailureCheck::Clear
        };
        assert_eq!(outer, expected);
        assert_eq!(*reentrant.seen.lock().unwrap(), [FailureCheck::Unknown]);
        assert_eq!(
            other_wakes.0.load(Ordering::SeqCst),
            1,
            "B was not woken after the outer poll released the wait"
        );
        assert_eq!(
            kept.poll_failure(b, &mut Context::from_waker(&noop_waker())),
            expected
        );
        kept.unlisten(a);
        kept.unlisten(b);
    }

    #[test]
    fn a_kept_rpc_failure_defers_a_listener_polled_from_inside_its_wait() {
        listener_polled_from_inside_the_wait(false);
    }

    #[test]
    fn a_kept_rpc_failure_wakes_a_deferred_listener_when_its_wait_fires() {
        listener_polled_from_inside_the_wait(true);
    }

    /// A listener that takes the wait right after a poll found it Ready and
    /// released it (another host thread, say) sees Failed: the poll stored
    /// `fired` before releasing the wait, and the listener rechecks it.
    #[test]
    fn a_kept_rpc_failure_is_failed_for_the_next_holder_of_its_wait() {
        let kept: Arc<KeptRpcFailure<BoxWait>> =
            Arc::new(KeptRpcFailure::new(Box::pin(std::future::ready(()))));
        let a = kept.listen();
        let b = kept.listen();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (hooked, recorded) = (kept.clone(), seen.clone());
        *kept.after_ready_release.lock().unwrap() = Some(Box::new(move || {
            let check = hooked.poll_failure(b, &mut Context::from_waker(&noop_waker()));
            recorded.lock().unwrap().push(check);
        }));
        assert_eq!(
            kept.poll_failure(a, &mut Context::from_waker(&noop_waker())),
            FailureCheck::Failed
        );
        assert_eq!(*seen.lock().unwrap(), [FailureCheck::Failed]);
        kept.after_ready_release.lock().unwrap().take();
        kept.unlisten(a);
        kept.unlisten(b);
    }

    /// The wait's poll panics after listener B, checked in place, got
    /// Unknown. A Tool may catch that panic and keep B, so B must be woken
    /// and then see Failed, and the panicked wait is never polled again.
    #[test]
    fn a_kept_rpc_failure_whose_wait_panics_is_terminal_for_every_listener() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl futures::task::ArcWake for Wakes {
            fn wake_by_ref(arc: &Arc<Self>) {
                arc.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct ChecksOther {
            kept: Arc<KeptRpcFailure<BoxWait>>,
            other: usize,
            other_wakes: Arc<Wakes>,
            seen: Mutex<Vec<FailureCheck>>,
        }
        impl Wake for ChecksOther {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                let waker = futures::task::waker(self.other_wakes.clone());
                let check = self
                    .kept
                    .poll_failure(self.other, &mut Context::from_waker(&waker));
                self.seen.lock().unwrap().push(check);
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let counted = polls.clone();
        let kept: Arc<KeptRpcFailure<BoxWait>> = Arc::new(KeptRpcFailure::new(Box::pin(
            std::future::poll_fn(move |context| {
                counted.fetch_add(1, Ordering::SeqCst);
                context.waker().wake_by_ref();
                panic!("the wait's poll panics");
            }),
        )));
        let a = kept.listen();
        let b = kept.listen();
        let other_wakes = Arc::new(Wakes::default());
        let reentrant = Arc::new(ChecksOther {
            kept: kept.clone(),
            other: b,
            other_wakes: other_wakes.clone(),
            seen: Mutex::new(Vec::new()),
        });
        let waker = Waker::from(reentrant.clone());
        let caught = catch_unwind(AssertUnwindSafe(|| {
            kept.poll_failure(a, &mut Context::from_waker(&waker))
        }));
        assert!(caught.is_err(), "the panic must reach the caller");
        assert_eq!(*reentrant.seen.lock().unwrap(), [FailureCheck::Unknown]);
        assert_eq!(other_wakes.0.load(Ordering::SeqCst), 1, "B was not woken");
        for _ in 0..2 {
            assert_eq!(
                kept.poll_failure(b, &mut Context::from_waker(&noop_waker())),
                FailureCheck::Failed
            );
        }
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "the panicked wait was polled again"
        );
        kept.unlisten(a);
        kept.unlisten(b);
    }

    /// Dropping a replaced or removed waker can run a destructor that frees
    /// another listener; it must not run under the slots lock.
    #[test]
    fn a_kept_rpc_failure_drops_wakers_outside_its_lock() {
        use std::sync::atomic::AtomicUsize;

        struct FreesOther {
            kept: Arc<KeptRpcFailure<BoxWait>>,
            other: usize,
            dropped: Arc<AtomicUsize>,
        }
        impl Wake for FreesOther {
            fn wake(self: Arc<Self>) {
                unreachable!("the wait never fires");
            }
        }
        impl Drop for FreesOther {
            fn drop(&mut self) {
                self.kept.unlisten(self.other);
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }

        let kept: Arc<KeptRpcFailure<BoxWait>> =
            Arc::new(KeptRpcFailure::new(Box::pin(std::future::pending())));
        let dropped = Arc::new(AtomicUsize::new(0));
        let frees = |other| {
            Waker::from(Arc::new(FreesOther {
                kept: kept.clone(),
                other,
                dropped: dropped.clone(),
            }))
        };
        let a = kept.listen();
        let b = kept.listen();
        let c = kept.listen();
        let first = frees(b);
        assert_eq!(
            kept.poll_failure(a, &mut Context::from_waker(&first)),
            FailureCheck::Clear
        );
        drop(first);
        // Replacing A's waker drops the last clone of one that frees B.
        let second = frees(c);
        assert_eq!(
            kept.poll_failure(a, &mut Context::from_waker(&second)),
            FailureCheck::Clear
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        drop(second);
        // Freeing A drops the last clone of one that frees C.
        kept.unlisten(a);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert_eq!(kept.listeners.slots().free.len(), 3);
    }

    #[test]
    fn repeated_secondary_entry_snapshots_report_once_without_losing_late_cleanup() {
        use std::sync::atomic::AtomicUsize;
        let global = Arc::new(());
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let mut run = RunFailure::new(&global);
        Arc::get_mut(&mut run).unwrap().report = Box::new(move |_| {
            recorded.fetch_add(1, Ordering::SeqCst);
        });
        let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
        context.publish("first", Error::InvalidGuestPid(-17));
        let gate = crate::entry::EntryGate::new();
        let pending = gate.poison(None, Error::GuestClock("secondary".to_owned()));
        context.publish("secondary", pending.error());
        context.publish("same captured cause", pending.error());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        gate.poison(None, Error::GuestClock("late cleanup".to_owned()));
        let result = context.publish("new snapshot", pending.error());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        for cause in pending.causes() {
            assert!(references_shared_error(&result, &cause));
        }
        let other = Arc::new(Error::GuestClock("secondary".to_owned()));
        context.publish("same text distinct identity", Error::SharedFailure(other));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn completion_promotes_joined_worker_cause_without_duplicate_diagnostic() {
        let global = Arc::new(());
        let failure = RunFailure::new(&global);
        let event = BackendFailure {
            pid: Pid::from_raw(1),
            tid: Pid::from_raw(2),
            phase: "worker exit",
        };
        let published =
            failure.publish(event, Error::Reverie(reverie::syscalls::Errno::EIO.into()));
        let first = failure.primary().unwrap();
        // This is the exact production shape observed in the original
        // static_elf mode 1: the parked owner sees RunAborted while its physical
        // join returns the already-published worker failure.
        let joined = Error::RunAborted.with_cleanup(vec![Error::WorkerFailure {
            tid: 2,
            error: Arc::new(published),
        }]);
        assert!(
            !joined.retains_primary(&first),
            "publication predicate stays on the primary chain"
        );
        let error = failure.complete::<()>(Err(joined)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unexpected vCPU exit: KVM worker cleanup failed: thread 2: Reverie tool failed: -5 EIO (I/O error)"
        );
        assert!(error.retains_primary(&first));
        assert_eq!(error.worker_tid(), Some(2));
        assert!(std::ptr::eq(error.primary(), first.primary()));
        assert_eq!(failure.primary.lock().unwrap().as_ref().unwrap().1, event);

        let no_failure = RunFailure::new(&global);
        assert!(matches!(
            no_failure.complete::<()>(Err(Error::RunAborted)),
            Err(Error::RunAborted)
        ));

        // A canceled peer can return the root's published cause through its
        // own join handle. Its TID is propagation context, not the origin.
        let root_failure = RunFailure::new(&global);
        root_failure.publish(
            BackendFailure {
                pid: Pid::from_raw(1),
                tid: Pid::from_raw(1),
                phase: "root execution",
            },
            Error::InvalidGuestPid(-17),
        );
        let root_cause = root_failure.primary().unwrap();
        for direct_alias in [true, false] {
            let peer = Error::WorkerFailure {
                tid: 2,
                error: root_cause.clone(),
            };
            let result = if direct_alias {
                Error::SharedFailure(root_cause.clone()).with_cleanup(vec![peer])
            } else {
                peer
            };
            let error = root_failure.complete::<()>(Err(result)).unwrap_err();
            assert_eq!(error.to_string(), "invalid KVM root guest PID -17");
            assert_eq!(
                error.worker_tid(),
                None,
                "canceled peer replaced the root identity"
            );
            assert!(error.retains_primary(&root_cause));
            assert!(std::ptr::eq(error.primary(), root_cause.primary()));
        }
    }

    #[test]
    fn completion_keeps_distinct_shared_cleanup_causes_and_first_worker_identity() {
        fn references(error: &Error, target: &Arc<Error>) -> usize {
            fn shared(error: &Arc<Error>, target: &Arc<Error>) -> usize {
                if Arc::ptr_eq(error, target) {
                    1
                } else {
                    references(error, target)
                }
            }
            match error {
                Error::SharedFailure(error)
                | Error::WorkerFailure { error, .. }
                | Error::Cleanup { error, .. } => shared(error, target),
                Error::WithCleanup { primary, cleanup } => {
                    shared(primary, target)
                        + cleanup
                            .iter()
                            .map(|error| shared(error, target))
                            .sum::<usize>()
                }
                Error::ExecWorkerTeardown(error) => references(error, target),
                _ => 0,
            }
        }
        let global = Arc::new(());
        let failure = RunFailure::new(&global);
        let event = BackendFailure {
            pid: Pid::from_raw(1),
            tid: Pid::from_raw(9),
            phase: "worker execution",
        };
        failure.publish(event, Error::Reverie(reverie::syscalls::Errno::EIO.into()));
        let first = failure.primary().unwrap();
        // Equal diagnostic text is deliberately a different real cause.
        let lower_tid = Arc::new(Error::Reverie(reverie::syscalls::Errno::EIO.into()));
        let first_hook = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
            libc::ENOSPC,
        )));
        let second_hook = Arc::new(Error::Reverie(reverie::syscalls::Errno::EACCES.into()));
        let cancelled_hook = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
            libc::EPIPE,
        )));
        let worker = |error| Error::WorkerFailure { tid: 9, error };
        let aggregate = |primary, cleanup| Arc::new(Error::WithCleanup { primary, cleanup });
        let joined = Error::WorkerFailure {
            tid: 2,
            error: lower_tid.clone(),
        }
        .with_cleanup(vec![
            Error::RunAborted
                .with_cleanup(vec![
                    worker(aggregate(first.clone(), vec![first_hook.clone()])),
                    Error::ExecWorkerTeardown(Box::new(worker(aggregate(
                        first.clone(),
                        vec![second_hook.clone()],
                    )))),
                    Error::WorkerFailure {
                        tid: 10,
                        error: aggregate(Arc::new(Error::RunAborted), vec![cancelled_hook.clone()]),
                    },
                    Error::SharedFailure(first.clone()),
                ])
                .cleanup("owner cleanup"),
        ]);
        assert!(!joined.retains_primary(&first));
        let error = failure.complete::<()>(Err(joined)).unwrap_err();
        assert!(error.retains_primary(&first));
        assert!(std::ptr::eq(error.primary(), first.primary()));
        assert_eq!(
            error.worker_tid(),
            Some(9),
            "lower TID is not the first published cause"
        );
        for cause in [
            &first,
            &lower_tid,
            &first_hook,
            &second_hook,
            &cancelled_hook,
        ] {
            assert_eq!(
                references(&error, cause),
                1,
                "typed cause was lost or duplicated: {error:?}"
            );
        }
        assert_eq!(
            error.to_string().matches("EIO").count(),
            2,
            "same text is not cause identity"
        );
        assert!(
            !error
                .to_string()
                .contains("KVM execution stopped after a fatal run failure")
        );
        assert!(
            error.to_string().contains("thread 10:"),
            "cancelled worker's real hook context was lost"
        );
        assert_eq!(failure.primary.lock().unwrap().as_ref().unwrap().1, event);
    }

    #[test]
    fn independent_failure_subscribers_wake_before_and_after_publication() {
        let global = Arc::new(());
        let failure = RunFailure::new(&global);
        let mut first = failure.subscribe();
        let mut second = failure.subscribe();
        let first_wakes = Arc::new(Wakes::default());
        let second_wakes = Arc::new(Wakes::default());
        let waker1 = futures::task::waker(first_wakes.clone());
        let waker2 = futures::task::waker(second_wakes.clone());
        assert!(
            std::pin::Pin::new(&mut first)
                .poll(&mut Context::from_waker(&waker1))
                .is_pending()
        );
        assert!(
            std::pin::Pin::new(&mut second)
                .poll(&mut Context::from_waker(&waker2))
                .is_pending()
        );
        let context = FailureContext::new(failure.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let original = context.publish("setup", Error::GuestClock("original".to_owned()));
        assert!(matches!(original.primary(), Error::GuestClock(_)));
        assert!(first_wakes.0.load(Ordering::SeqCst) > 0);
        assert!(second_wakes.0.load(Ordering::SeqCst) > 0);
        assert_eq!(futures::executor::block_on(first), Ok(()));
        assert_eq!(futures::executor::block_on(second), Ok(()));
        assert_eq!(futures::executor::block_on(failure.subscribe()), Ok(()));
        context.publish("cleanup", Error::HostIo(std::io::Error::other("secondary")));
        assert!(matches!(
            failure.primary().unwrap().primary(),
            Error::GuestClock(_)
        ));
        drop(failure);
        drop(context);
        assert!(
            Arc::try_unwrap(global).is_ok(),
            "reporter retained global ownership"
        );
    }

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);
    impl futures::task::ArcWake for Wakes {
        fn wake_by_ref(value: &Arc<Self>) {
            value.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn terminal_read_wait_keeps_independent_process_failure_scope() {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let root = FailureContext::new(run.clone(), Pid::from_raw(71), Pid::from_raw(71));
        let child = root.for_process(Pid::from_raw(72));
        let worker = child.for_thread(Pid::from_raw(73));
        let unrelated = root.for_process(Pid::from_raw(74));
        let mut root_wait = root.terminal_wait(true);
        let mut child_wait = child.terminal_wait(false);
        let mut worker_wait = worker.terminal_wait(false);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for wait in [&mut root_wait, &mut child_wait, &mut worker_wait] {
            assert!(wait.as_mut().poll(&mut cx).is_pending());
        }

        unrelated.publish("independent failure", Error::InvalidGuestPid(-17));
        assert!(root_wait.as_mut().poll(&mut cx).is_ready());
        assert!(child_wait.as_mut().poll(&mut cx).is_pending());
        assert!(worker_wait.as_mut().poll(&mut cx).is_pending());
        worker.publish("RPC cancellation", Error::RunAborted);
        assert!(child_wait.as_mut().poll(&mut cx).is_pending());
        assert!(worker_wait.as_mut().poll(&mut cx).is_pending());

        child.publish(
            "local failure",
            Error::GuestClock("child failure".to_owned()),
        );
        assert!(child_wait.as_mut().poll(&mut cx).is_ready());
        assert!(worker_wait.as_mut().poll(&mut cx).is_ready());
        assert!(matches!(
            run.primary().unwrap().primary(),
            Error::InvalidGuestPid(-17)
        ));
        assert_eq!(
            run.primary.lock().unwrap().as_ref().unwrap().1.pid,
            Pid::from_raw(74)
        );
    }

    struct TerminalReadGlobal {
        sender: Mutex<Option<oneshot::Sender<()>>>,
        receiver: FailureSubscription,
        waits: std::sync::atomic::AtomicUsize,
    }

    impl Default for TerminalReadGlobal {
        fn default() -> Self {
            let (sender, receiver) = oneshot::channel();
            Self {
                sender: Mutex::new(Some(sender)),
                receiver: receiver.shared(),
                waits: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[reverie::global_tool]
    impl GlobalTool for TerminalReadGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _: Pid, _: ()) {}

        async fn wait_for_backend_failure(&self) {
            self.waits.fetch_add(1, Ordering::SeqCst);
            let _ = self.receiver.clone().await;
        }
    }

    #[test]
    fn terminal_read_wait_observes_sticky_global_terminal_and_releases_global_owner() {
        for before_subscription in [false, true] {
            let global = Arc::new(TerminalReadGlobal::default());
            let run = RunFailure::new(&global);
            let root = FailureContext::new(run.clone(), Pid::from_raw(71), Pid::from_raw(71));
            let child = root.for_process(Pid::from_raw(72));
            let mut first = child.terminal_wait(false);
            let mut second = child.terminal_wait(false);
            assert_eq!(
                Arc::strong_count(&global),
                1,
                "unpolled observer retained GlobalState"
            );
            let wakes = Arc::new(Wakes::default());
            let waker = futures::task::waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            if !before_subscription {
                assert!(first.as_mut().poll(&mut cx).is_pending());
                assert!(second.as_mut().poll(&mut cx).is_pending());
                assert_eq!(global.waits.load(Ordering::SeqCst), 2);
                assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            }
            global
                .sender
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            if !before_subscription {
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
            }
            assert!(first.as_mut().poll(&mut cx).is_ready());
            assert!(second.as_mut().poll(&mut cx).is_ready());
            assert_eq!(global.waits.load(Ordering::SeqCst), 2);
            assert!(
                run.primary().is_none(),
                "global terminal invented a backend cause"
            );
            drop(first);
            drop(second);
            assert!(
                Arc::try_unwrap(global).is_ok(),
                "read factory retained GlobalState"
            );
        }
    }

    #[test]
    fn dropping_pending_terminal_read_wait_releases_only_its_global_owner() {
        let global = Arc::new(TerminalReadGlobal::default());
        let run = RunFailure::new(&global);
        let root = FailureContext::new(run.clone(), Pid::from_raw(71), Pid::from_raw(71));
        let mut waiting = root.terminal_wait(true);
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&noop_waker()))
                .is_pending()
        );
        assert_eq!(Arc::strong_count(&global), 2);
        drop(waiting);
        assert!(run.primary().is_none());
        assert!(root.driver_subscription(true).now_or_never().is_none());
        assert!(
            Arc::try_unwrap(global).is_ok(),
            "disposed read retained GlobalState"
        );
    }

    #[derive(Default)]
    struct OrderedGlobal {
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }
    #[reverie::global_tool]
    impl GlobalTool for OrderedGlobal {
        type Request = ();
        type Response = ();
        type Config = ();
        async fn receive_rpc(&self, _: Pid, _: ()) {}
        fn report_backend_failure(&self, _: BackendFailure) {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            self.release.lock().unwrap().take().unwrap().recv().unwrap();
        }
    }

    #[test]
    fn process_failure_subscriptions_preserve_fork_and_thread_ownership() {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let root = FailureContext::new(run.clone(), Pid::from_raw(71), Pid::from_raw(71));
        let child = root.for_process(Pid::from_raw(72));
        let worker = child.for_thread(Pid::from_raw(73));
        let nested = child.for_process(Pid::from_raw(74));
        let independent_process = false;
        assert!(
            child
                .driver_subscription(independent_process)
                .now_or_never()
                .is_none()
        );
        assert!(
            worker
                .driver_subscription(independent_process)
                .now_or_never()
                .is_none()
        );
        assert!(root.driver_subscription(true).now_or_never().is_none());

        worker.publish("worker", Error::InvalidGuestPid(-17));
        assert_eq!(
            child
                .driver_subscription(independent_process)
                .now_or_never(),
            Some(Ok(()))
        );
        assert_eq!(
            worker
                .driver_subscription(independent_process)
                .now_or_never(),
            Some(Ok(()))
        );
        assert_eq!(root.driver_subscription(true).now_or_never(), Some(Ok(())));
        assert!(nested.driver_subscription(false).now_or_never().is_none());
        assert!(matches!(
            run.primary().unwrap().primary(),
            Error::InvalidGuestPid(-17)
        ));
        assert_eq!(
            run.primary.lock().unwrap().as_ref().unwrap().1.tid,
            Pid::from_raw(73)
        );

        // A derived cleanup marker does not mark a healthy independent process
        // as a second source of failure or wake its ordinary execution driver.
        nested.publish("RPC cancellation", Error::RunAborted);
        assert!(nested.driver_subscription(false).now_or_never().is_none());
        let first = run.primary().unwrap();
        nested.publish(
            "later process failure",
            Error::HostIo(std::io::Error::from_raw_os_error(libc::EPIPE)),
        );
        assert_eq!(
            nested.driver_subscription(false).now_or_never(),
            Some(Ok(()))
        );
        assert!(Arc::ptr_eq(&first, &run.primary().unwrap()));
        let later = child.for_process(Pid::from_raw(75));
        assert!(later.driver_subscription(false).now_or_never().is_none());
    }

    #[test]
    fn local_failure_wake_waits_for_synchronous_tool_terminal_transition() {
        let global = Arc::new(OrderedGlobal::default());
        let (entered, receive_entered) = std::sync::mpsc::channel();
        let (release, receive_release) = std::sync::mpsc::channel();
        *global.entered.lock().unwrap() = Some(entered);
        *global.release.lock().unwrap() = Some(receive_release);
        let failure = RunFailure::new(&global);
        let mut subscription = failure.subscribe();
        let context = FailureContext::new(failure.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let mut process_subscription = context.driver_subscription(false);
        let publisher = std::thread::spawn(move || {
            context.publish("worker", Error::GuestClock("primary".to_owned()))
        });
        let entered = receive_entered
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
        let pending = matches!(
            std::pin::Pin::new(&mut subscription).poll(&mut Context::from_waker(&noop_waker())),
            Poll::Pending
        );
        let unpublished = failure.published_primary().is_none();
        let process_pending = std::pin::Pin::new(&mut process_subscription)
            .poll(&mut Context::from_waker(&noop_waker()))
            .is_pending();
        release.send(()).unwrap();
        publisher.join().unwrap();
        assert!(
            entered && pending && unpublished,
            "local cleanup escaped before Tool publication completed"
        );
        assert_eq!(futures::executor::block_on(subscription), Ok(()));
        assert!(
            process_pending,
            "process cleanup escaped before Tool publication completed"
        );
        assert_eq!(futures::executor::block_on(process_subscription), Ok(()));
        assert!(failure.published_primary().is_some());
    }

    #[derive(Default)]
    struct ConcurrentGlobal {
        events: Mutex<Vec<BackendFailure>>,
        selected: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for ConcurrentGlobal {
        type Request = ();
        type Response = ();
        type Config = ();
        async fn receive_rpc(&self, _: Pid, _: ()) {}
        fn report_backend_failure(&self, event: BackendFailure) {
            if event.phase == "first worker" {
                self.selected
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release.lock().unwrap().take().unwrap().recv().unwrap();
            }
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn concurrent_publishers_pair_first_typed_cause_with_first_terminal_event() {
        let global = Arc::new(ConcurrentGlobal::default());
        let (selected, selected_receiver) = std::sync::mpsc::channel();
        let (release, release_receiver) = std::sync::mpsc::channel();
        *global.selected.lock().unwrap() = Some(selected);
        *global.release.lock().unwrap() = Some(release_receiver);
        let failure = RunFailure::new(&global);
        let first = FailureContext::new(failure.clone(), Pid::from_raw(11), Pid::from_raw(12));
        let second = FailureContext::new(failure.clone(), Pid::from_raw(21), Pid::from_raw(22));
        let first_worker = std::thread::spawn(move || {
            first.publish(
                "first worker",
                Error::GuestClock("first typed cause".to_owned()),
            )
        });
        let reached = selected_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
        let (attempted, attempted_receiver) = std::sync::mpsc::channel();
        let (finished, finished_receiver) = std::sync::mpsc::channel();
        let second_worker = std::thread::spawn(move || {
            attempted.send(()).unwrap();
            let result = second.publish(
                "second cleanup",
                Error::HostIo(std::io::Error::other("second typed cause")),
            );
            finished.send(()).unwrap();
            result
        });
        let attempted = attempted_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
        let second_waited = finished_receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err();
        let no_event = global.events.lock().unwrap().is_empty();
        let unpublished = failure.published_primary().is_none();
        // Release and reap both publishers before asserting any precondition.
        let _ = release.send(());
        let first_result = first_worker.join().unwrap();
        let second_result = second_worker.join().unwrap();
        assert!(reached && attempted && second_waited && no_event && unpublished);
        let events = global.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            BackendFailure {
                pid: Pid::from_raw(11),
                tid: Pid::from_raw(12),
                phase: "first worker",
            }
        );
        assert_eq!(
            events[1],
            BackendFailure {
                pid: Pid::from_raw(21),
                tid: Pid::from_raw(22),
                phase: "second cleanup",
            }
        );
        assert_eq!(
            failure.primary.lock().unwrap().as_ref().unwrap().1,
            events[0]
        );
        assert!(
            matches!(first_result.primary(), Error::GuestClock(message) if message == "first typed cause")
        );
        assert!(
            matches!(failure.primary().unwrap().primary(), Error::GuestClock(message) if message == "first typed cause")
        );
        assert!(
            matches!(second_result.primary(), Error::HostIo(error) if error.to_string() == "second typed cause")
        );
        assert_eq!(futures::executor::block_on(failure.subscribe()), Ok(()));
    }

    #[test]
    fn refused_host_spawn_returns_exact_initialized_owner() {
        let owner = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = owner.clone();
        // An impossible stack allocation deterministically refuses before a
        // host worker starts. No process limit or host configuration changes.
        let result = spawn_owned(
            std::thread::Builder::new().stack_size(usize::MAX / 2),
            state,
            |state| {
                state.fetch_add(1, Ordering::SeqCst);
            },
        );
        let (error, recovered) = match result {
            Err(failure) => failure,
            Ok(handle) => {
                handle.join().unwrap();
                panic!("impossible host stack unexpectedly spawned");
            }
        };
        assert!(error.raw_os_error().is_some());
        assert!(Arc::ptr_eq(&owner, &recovered));
        assert_eq!(owner.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&owner), 2);
    }
}

#[cfg(test)]
mod panic_cleanup_tests {
    use std::cell::Cell;
    use std::sync::Weak;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[derive(Default)]
    struct RecordingGlobal {
        events: Mutex<Vec<BackendFailure>>,
        run: Mutex<Option<Weak<RunFailure>>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for RecordingGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _: Pid, _: ()) {}

        fn report_backend_failure(&self, event: BackendFailure) {
            if let Some(run) = self.run.lock().unwrap().as_ref().and_then(Weak::upgrade) {
                assert!(run.panic_cleanup.try_lock().is_ok());
            }
            self.events.lock().unwrap().push(event);
        }
    }

    fn event() -> BackendFailure {
        BackendFailure {
            pid: Pid::from_raw(1),
            tid: Pid::from_raw(9),
            phase: "fork owner panic",
        }
    }

    fn references(error: &Error, target: &Arc<Error>) -> usize {
        let shared = |error: &Arc<Error>| {
            if Arc::ptr_eq(error, target) {
                1
            } else {
                references(error, target)
            }
        };
        match error {
            Error::SignalEffects { cause, .. }
            | Error::SharedFailure(cause)
            | Error::WorkerFailure { error: cause, .. }
            | Error::Cleanup { error: cause, .. } => shared(cause),
            Error::WithCleanup { primary, cleanup } => {
                shared(primary) + cleanup.iter().map(shared).sum::<usize>()
            }
            Error::ExecWorkerTeardown(error) => references(error, target),
            _ => 0,
        }
    }

    fn effects(cause: Arc<Error>) -> Error {
        Error::SignalEffects {
            cause,
            dequeues: Vec::new(),
            acknowledged_through: 17,
            publications: Vec::new(),
            raw_result: Some(-i64::from(libc::EFAULT)),
            context: Some(Box::new(reverie::ParkedSignalFailureContext {
                site: reverie::CallbackSignalSite {
                    process: reverie::SignalProcessId {
                        tgid: Pid::from_raw(4),
                        generation: 5,
                    },
                    tid: Pid::from_raw(6),
                    task_generation: 7,
                    callback_nonce: 8,
                    boundary_nonce: 9,
                },
                ledger_nonce: 10,
            })),
        }
    }

    #[test]
    fn no_retained_panic_cleanup_preserves_existing_completion() {
        let global = Arc::new(RecordingGlobal::default());
        let run = RunFailure::new(&global);
        let value = Arc::new(());
        assert!(Arc::ptr_eq(
            &run.complete(Ok(value.clone())).unwrap(),
            &value
        ));
        let cause = Arc::new(Error::GuestClock("unpublished".to_owned()));
        let error = run
            .complete::<()>(Err(Error::SharedFailure(cause.clone())))
            .unwrap_err();
        assert!(matches!(error, Error::SharedFailure(actual) if Arc::ptr_eq(&actual, &cause)));
        assert!(matches!(
            run.complete::<()>(Err(Error::RunAborted)),
            Err(Error::RunAborted)
        ));
        assert!(global.events.lock().unwrap().is_empty());

        run.publish(event(), Error::GuestClock("published".to_owned()));
        let first = run.primary().unwrap();
        let error = run.complete(Ok(())).unwrap_err();
        assert!(matches!(error, Error::SharedFailure(actual) if Arc::ptr_eq(&actual, &first)));
        assert_eq!(*global.events.lock().unwrap(), vec![event()]);
        assert!(run.panic_cleanup.lock().unwrap().is_empty());
    }

    #[test]
    fn retained_panic_cleanup_keeps_first_cause_wrappers_and_signal_effect_identity() {
        let global = Arc::new(RecordingGlobal::default());
        let run = RunFailure::new(&global);
        run.publish(event(), Error::GuestClock("first".to_owned()));
        let first = run.primary().unwrap();
        let cleanup = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)));
        let ledger = Arc::new(effects(Arc::new(Error::RunAborted)));
        let expected_context = match ledger.as_ref() {
            Error::SignalEffects {
                context: Some(context),
                ..
            } => **context,
            _ => unreachable!(),
        };
        run.retain_panic_cleanup(
            Error::WorkerFailure {
                tid: 9,
                error: first.clone(),
            }
            .with_cleanup(vec![
                Error::ExecWorkerTeardown(Box::new(Error::SharedFailure(cleanup.clone())))
                    .cleanup("fork consuming hook"),
                Error::RunAborted.with_cleanup(vec![Error::SharedFailure(ledger.clone())]),
            ]),
            Vec::new(),
        );
        let error = run.complete::<()>(Err(Error::RunAborted)).unwrap_err();
        assert!(error.retains_primary(&first));
        assert!(std::ptr::eq(error.primary(), first.primary()));
        assert_eq!(error.worker_tid(), Some(9));
        for cause in [&first, &cleanup, &ledger] {
            assert_eq!(
                references(&error, cause),
                1,
                "lost or duplicated cause: {error:?}"
            );
        }
        assert!(matches!(ledger.as_ref(), Error::SignalEffects {
            acknowledged_through: 17,
            raw_result: Some(value),
            context: Some(context),
            ..
        } if *value == -i64::from(libc::EFAULT) && **context == expected_context));
        let Error::WithCleanup {
            cleanup: causes, ..
        } = &error
        else {
            panic!("retained cleanup causes lost their aggregate");
        };
        assert_eq!(causes.len(), 2);
        let Error::Cleanup { phase, error } = causes[0].as_ref() else {
            panic!("fork cleanup phase wrapper was lost");
        };
        assert_eq!(*phase, "fork consuming hook");
        assert!(matches!(error.as_ref(), Error::ExecWorkerTeardown(inner)
            if references(inner, &cleanup) == 1));
        assert_eq!(*global.events.lock().unwrap(), vec![event()]);
    }

    #[test]
    fn retained_panic_cleanup_folds_two_distinct_records_once() {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        run.publish(event(), Error::GuestClock("same text".to_owned()));
        let first = run.primary().unwrap();
        let one = Arc::new(Error::GuestClock("same text".to_owned()));
        let two = Arc::new(Error::GuestClock("same text".to_owned()));
        run.retain_panic_cleanup(Error::SharedFailure(one.clone()), Vec::new());
        run.retain_panic_cleanup(Error::SharedFailure(two.clone()), Vec::new());
        let first_completion = run.complete::<()>(Err(Error::RunAborted)).unwrap_err();
        let repeated = run.complete::<()>(Err(first_completion)).unwrap_err();
        for cause in [&first, &one, &two] {
            assert_eq!(references(&repeated, cause), 1);
        }
        assert_eq!(repeated.to_string().matches("same text").count(), 3);
        let fresh = run.complete::<()>(Err(Error::RunAborted)).unwrap_err();
        assert_eq!(references(&fresh, &first), 1);
        assert_eq!(
            references(&fresh, &one),
            0,
            "record was transferred a second time"
        );
        assert_eq!(
            references(&fresh, &two),
            0,
            "record was transferred a second time"
        );
        let records = run.panic_cleanup.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.error.is_none()));
    }

    #[test]
    fn retained_panic_cleanup_skips_only_exact_already_returned_arcs() {
        for location in 0..6 {
            let global = Arc::new(());
            let run = RunFailure::new(&global);
            let shared = Arc::new(Error::GuestClock("same text".to_owned()));
            let distinct = Arc::new(Error::GuestClock("same text".to_owned()));
            run.retain_panic_cleanup(Error::SharedFailure(shared.clone()), Vec::new());
            run.retain_panic_cleanup(Error::SharedFailure(distinct.clone()), Vec::new());
            let joined = match location {
                0 => Error::SharedFailure(shared.clone()),
                1 => Error::RunAborted.with_cleanup(vec![Error::SharedFailure(shared.clone())]),
                2 => Error::WorkerFailure {
                    tid: 7,
                    error: shared.clone(),
                },
                3 => Error::SharedFailure(shared.clone()).cleanup("existing joined cleanup"),
                4 => Error::ExecWorkerTeardown(Box::new(Error::SharedFailure(shared.clone()))),
                5 => effects(shared.clone()),
                _ => unreachable!(),
            };
            let error = run.complete::<()>(Err(joined)).unwrap_err();
            assert_eq!(
                references(&error, &shared),
                1,
                "duplicate at wrapper {location}"
            );
            assert_eq!(
                references(&error, &distinct),
                1,
                "text-based loss at wrapper {location}"
            );
        }
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        run.publish(event(), Error::GuestClock("shared primary".to_owned()));
        let primary = run.primary().unwrap();
        let already_joined = Arc::new(Error::GuestClock("joined cleanup".to_owned()));
        let retained_cleanup = Arc::new(Error::GuestClock("retained cleanup".to_owned()));
        run.retain_panic_cleanup(
            Error::SharedFailure(primary.clone())
                .with_cleanup(vec![Error::SharedFailure(retained_cleanup.clone())]),
            Vec::new(),
        );
        let error = run
            .complete::<()>(Err(Error::SharedFailure(primary.clone())
                .with_cleanup(vec![Error::SharedFailure(already_joined.clone())])))
            .unwrap_err();
        for cause in [&primary, &already_joined, &retained_cleanup] {
            assert_eq!(
                references(&error, cause),
                1,
                "equal primary hid distinct cleanup"
            );
        }
    }

    struct SendOnlyPayload {
        drops: Arc<AtomicUsize>,
        _not_sync: Cell<u8>,
    }

    impl Drop for SendOnlyPayload {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CompletionValue {
        run: Weak<RunFailure>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for CompletionValue {
        fn drop(&mut self) {
            let run = self.run.upgrade().unwrap();
            assert!(run.panic_cleanup.try_lock().is_ok());
            assert!(run.primary.try_lock().is_ok());
            assert!(run.publication.try_lock().is_ok());
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn retained_send_only_payload_outlives_publication_and_completion() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RunFailure>();
        let global = Arc::new(RecordingGlobal::default());
        let run = RunFailure::new(&global);
        *global.run.lock().unwrap() = Some(Arc::downgrade(&run));
        let final_owner = run.clone();
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = Box::new(SendOnlyPayload {
            drops: drops.clone(),
            _not_sync: Cell::new(1),
        });
        let address = std::ptr::from_ref(payload.as_ref()) as usize;
        let cleanup = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
            libc::EPIPE,
        )));
        run.retain_panic_cleanup(Error::SharedFailure(cleanup.clone()), vec![payload]);
        assert!(
            global.events.lock().unwrap().is_empty(),
            "retention published a failure"
        );
        assert!(run.subscribe().now_or_never().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        run.publish(event(), Error::GuestClock("first".to_owned()));
        let first = run.primary().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let value_drops = Arc::new(AtomicUsize::new(0));
        let completed = match run.complete(Ok(CompletionValue {
            run: Arc::downgrade(&run),
            drops: value_drops.clone(),
        })) {
            Err(error) => error,
            Ok(_) => panic!("retained failure must make completion fail"),
        };
        assert_eq!(value_drops.load(Ordering::SeqCst), 1);
        assert_eq!(references(&completed, &first), 1);
        assert_eq!(references(&completed, &cleanup), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let completed = run.complete::<()>(Err(completed)).unwrap_err();
        assert_eq!(references(&completed, &first), 1);
        assert_eq!(references(&completed, &cleanup), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        {
            let records = run.panic_cleanup.lock().unwrap();
            assert_eq!(records.len(), 1);
            assert!(records[0].error.is_none());
            let retained = records[0]._secondary_payloads[0]
                .downcast_ref::<SendOnlyPayload>()
                .unwrap();
            assert_eq!(std::ptr::from_ref(retained) as usize, address);
        }
        drop(run);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(final_owner);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(references(&completed, &first), 1);
        assert_eq!(references(&completed, &cleanup), 1);
    }
}
