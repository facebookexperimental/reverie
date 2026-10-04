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

use futures::FutureExt;
use futures::channel::oneshot;
use futures::future::BoxFuture;
use futures::future::Shared;
use futures::future::select;
use reverie::BackendFailure;
use reverie::GlobalTool;
use reverie::Pid;

use crate::Error;

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
