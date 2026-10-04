/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Constructed callback/queue controls for the actual worker finish and join
//! methods. These do not enter KVM_RUN, inject a failed host spawn, or exercise
//! drive_handler, root/fork unwinding, or ordinary non-panic cleanup.

use std::cell::Cell;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::panic::resume_unwind;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use super::*;
use crate::failure::FailureContext;
use crate::failure::RunFailure;
use crate::failure::owned_future::PanicPayload;

struct PanickingWorkerConfig(Option<PanicPayload>);

impl Drop for PanickingWorkerConfig {
    fn drop(&mut self) {
        resume_unwind(self.0.take().unwrap());
    }
}

#[derive(Clone, Copy)]
enum ConfigurationCase {
    DeferredExecution,
    OrdinaryCompletion,
    OuterExecution,
}

fn configuration_panic_control(case: ConfigurationCase) {
    let mut backend = KvmBackend::new(0x10000).expect("worker configuration control requires KVM");
    backend.is_guest_thread = true;
    backend.thread_ownership = ThreadOwnership::Tool;
    let group = backend.thread_group.clone();
    let leader = ElfExecutor::new(crate::executor::native_loaded_state(Path::new("/")), false);
    let mut executor = leader.thread_child(2).unwrap();
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    backend.set_tool_failure(Some(FailureContext::new(
        run.clone(),
        Pid::from_raw(1),
        Pid::from_raw(2),
    )));
    let (configuration, configuration_address, configuration_drops) = payload();
    let execution = (!matches!(case, ConfigurationCase::OrdinaryCompletion)).then(payload);
    let expected_address = execution
        .as_ref()
        .map_or(configuration_address, |(_, address, _)| *address);
    let execution_drops = execution.as_ref().map(|(_, _, drops)| drops.clone());
    let worker = std::thread::spawn(move || -> GuestWorkerResult {
        let config = PanickingWorkerConfig(Some(configuration));
        match case {
            ConfigurationCase::OuterExecution => backend.finish_panicked_guest_worker_with_entry(
                &mut executor,
                2,
                execution.unwrap().0,
                None,
                |panics| panics.drop_value(config, "Tool worker configuration destruction"),
            ),
            ConfigurationCase::DeferredExecution | ConfigurationCase::OrdinaryCompletion => {
                let result = match execution {
                    Some((payload, _, _)) => backend
                        .tool_panic_owner()
                        .finish_worker_execution::<(ExitStatus, Vec<u8>, Vec<u8>)>(
                            crate::failure::owned_future::CaughtFuture {
                                output: None,
                                panics: vec![payload],
                            },
                            "Tool callback",
                        )
                        .map_err(|error| backend.report_tool_failure("Tool callback", error)),
                    None => Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new())),
                };
                let result = backend
                    .finish_worker_configuration(result, config)
                    .map_err(|error| backend.report_tool_failure("Tool worker completion", error));
                backend.finish_deferred_worker_panic(2, result)
            }
        }
    });
    group.add_worker_handle(2, worker);
    group.join_workers();
    let error = run.complete(group.teardown_result()).unwrap_err();
    assert!(matches!(error.primary(), Error::GuestWorkerPanic));
    assert_eq!(error.worker_tid(), Some(2));
    assert!(error.retains_primary(&run.primary().unwrap()));
    assert!(
        error
            .to_string()
            .contains("Tool worker configuration destruction")
    );
    assert_eq!(configuration_drops.load(Ordering::SeqCst), 0);
    if let Some(drops) = &execution_drops {
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    {
        let records = group.completed_worker_panics.lock().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            payload_address(record._join_payload.as_ref().unwrap()),
            expected_address
        );
        if execution_drops.is_some() {
            assert_eq!(record._cleanup_panics.len(), 1);
            assert_eq!(
                payload_address(&record._cleanup_panics[0]),
                configuration_address
            );
        } else {
            assert!(record._cleanup_panics.is_empty());
        }
    }
    drop(group);
    assert_eq!(configuration_drops.load(Ordering::SeqCst), 1);
    if let Some(drops) = execution_drops {
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn configuration_destructor_preserves_deferred_and_outer_execution_panics() {
    configuration_panic_control(ConfigurationCase::DeferredExecution);
    configuration_panic_control(ConfigurationCase::OuterExecution);
}

#[test]
fn configuration_destructor_after_normal_completion_returns_typed_worker_failure() {
    configuration_panic_control(ConfigurationCase::OrdinaryCompletion);
}

#[test]
fn unstarted_configuration_destructor_preserves_error_and_transfers_payload() {
    let mut child = KvmBackend::new(0x10000).expect("worker configuration control requires KVM");
    child.is_guest_thread = true;
    child.thread_ownership = ThreadOwnership::Tool;
    let child_panics = child.tool_panic_owner();
    let parent_panics = Arc::new(crate::failure::tool_panics::ToolPanics::default());
    let transfer = ChildToolPanicTransfer {
        parent: parent_panics.clone(),
        child: child_panics.clone(),
    };
    let mut executor =
        ElfExecutor::new(crate::executor::native_loaded_state(Path::new("/")), false);
    let original = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)));
    let returned = original.clone();
    let (configuration, configuration_address, configuration_drops) = payload();
    let config = PanickingWorkerConfig(Some(configuration));
    executor.retain_unstarted_tool_cleanup(Box::pin(async move {
        let transfer = transfer;
        let caught = crate::failure::owned_future::catch_owned_future(async {
            Err::<(), _>(Error::SharedFailure(returned))
        })
        .await;
        let result = child
            .tool_panic_owner()
            .finish(caught, "unstarted thread owner");
        let result = child.finish_worker_configuration(result, config);
        drop(transfer);
        result
    }));

    let error = futures::executor::block_on(
        crate::runtime::finish_unstarted_tool_cleanups_with_panics(&mut executor, &parent_panics),
    )
    .unwrap_err();
    assert!(std::ptr::eq(error.primary(), original.as_ref()));
    assert!(
        error
            .to_string()
            .contains("Tool worker configuration destruction")
    );
    assert!(!child_panics.worker_execution_panicked());
    assert!(!parent_panics.worker_execution_panicked());
    assert!(child_panics.take().is_empty());
    let payloads = parent_panics.take();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payload_address(&payloads[0]), configuration_address);
    assert_eq!(configuration_drops.load(Ordering::SeqCst), 0);
    drop(payloads);
    assert_eq!(configuration_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn configuration_panic_interrupts_natural_join_in_both_orders() {
    for failure_first in [true, false] {
        let mut backend =
            KvmBackend::new(0x10000).expect("worker configuration control requires KVM");
        backend.is_guest_thread = true;
        backend.thread_ownership = ThreadOwnership::Tool;
        let group = backend.thread_group.clone();
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        backend.set_tool_failure(Some(FailureContext::new(
            run.clone(),
            Pid::from_raw(1),
            Pid::from_raw(3),
        )));
        let sibling_group = group.clone();
        let sibling_finished = Arc::new(AtomicBool::new(false));
        let finished = sibling_finished.clone();
        group.add_worker_handle(
            2,
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + WAIT;
                while !sibling_group.cancelled.load(Ordering::Acquire) {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "deferred configuration panic left an earlier sibling running"
                    );
                    std::thread::yield_now();
                }
                finished.store(true, Ordering::Release);
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        let (configuration, configuration_address, configuration_drops) = payload();
        let (release, released) = mpsc::channel();
        let (done, completed) = mpsc::channel();
        group.add_worker_handle(
            3,
            std::thread::spawn(move || -> GuestWorkerResult {
                let _done = WorkerDone(done);
                released.recv_timeout(WAIT).unwrap();
                let result = backend
                    .finish_worker_configuration(
                        Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new())),
                        PanickingWorkerConfig(Some(configuration)),
                    )
                    .map_err(|error| backend.report_tool_failure("Tool worker completion", error));
                assert!(
                    backend
                        .tool_failure
                        .as_ref()
                        .unwrap()
                        .run
                        .primary()
                        .is_some()
                );
                assert!(
                    !backend
                        .thread_group
                        .failure_state
                        .lock()
                        .unwrap()
                        .worker_failed
                );
                assert!(
                    backend
                        .thread_group
                        .reported_worker_panics
                        .lock()
                        .unwrap()
                        .is_empty()
                );
                assert!(!backend.tool_panic_owner().worker_execution_panicked());
                backend.finish_deferred_worker_panic(3, result)
            }),
        );
        if failure_first {
            release.send(()).unwrap();
            completed
                .recv_timeout(WAIT)
                .expect("failed worker did not finish");
            assert!(!group.cancelled.load(Ordering::Acquire));
            group.begin_natural_join();
        } else {
            group.begin_natural_join();
            assert!(!group.cancelled.load(Ordering::Acquire));
            release.send(()).unwrap();
        }
        group.join_workers();
        assert!(sibling_finished.load(Ordering::Acquire));
        assert!(group.worker_handles.lock().unwrap().is_empty());
        assert!(group.take_worker_error_report(3));
        assert!(!group.take_worker_error_report(3));
        let error = run.complete(group.teardown_result()).unwrap_err();
        assert!(matches!(error.primary(), Error::GuestWorkerPanic));
        assert_eq!(error.worker_tid(), Some(3));
        assert!(error.retains_primary(&run.primary().unwrap()));
        assert_eq!(configuration_drops.load(Ordering::SeqCst), 0);
        {
            let records = group.completed_worker_panics.lock().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(
                payload_address(records[0]._join_payload.as_ref().unwrap()),
                configuration_address
            );
            assert!(records[0]._cleanup_panics.is_empty());
        }
        drop(group);
        assert_eq!(configuration_drops.load(Ordering::SeqCst), 1);
    }
}

const WAIT: Duration = Duration::from_secs(5);
const PARENT_TID: i32 = 2;
const CHILD_TID: i32 = 3;
const THREAD_STATE: u64 = 0x7374617465;

// Cell deliberately makes the payload Send but not Sync. The private record
// must support the same payload domain as std::thread::JoinHandle.
struct Payload {
    drops: Arc<AtomicUsize>,
    _send_only: Cell<u8>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn payload() -> (PanicPayload, usize, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let owned = Box::new(Payload {
        drops: drops.clone(),
        _send_only: Cell::new(0),
    });
    let address = std::ptr::from_ref(owned.as_ref()) as usize;
    (owned, address, drops)
}

fn payload_address(payload: &PanicPayload) -> usize {
    std::ptr::from_ref(
        payload
            .downcast_ref::<Payload>()
            .expect("original payload type"),
    ) as usize
}

struct ConstructedParentCallback {
    payload: Option<PanicPayload>,
    dropped: Arc<AtomicUsize>,
}

impl Future for ConstructedParentCallback {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

impl Drop for ConstructedParentCallback {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
        // This unwinds from the actual destructor of the owned future. The
        // enclosing worker catch receives this exact allocation.
        resume_unwind(self.payload.take().unwrap());
    }
}

struct HookObservation {
    run: Arc<RunFailure>,
    lifecycle: Arc<Mutex<TaskLifecycleTable>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
    pending: mpsc::Sender<()>,
    entered: AtomicUsize,
    consumed: AtomicUsize,
}

#[derive(Default)]
struct PendingExitTool {
    observed: Option<Arc<HookObservation>>,
}

#[reverie::tool]
impl Tool for PendingExitTool {
    type GlobalState = ();
    type ThreadState = u64;

    async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _global: &G,
        thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        let observed = self.observed.as_ref().unwrap();
        assert_eq!(tid.as_raw(), CHILD_TID);
        assert_eq!(thread_state, THREAD_STATE);
        assert_eq!(observed.entered.fetch_add(1, Ordering::SeqCst), 0);
        assert!(observed.run.published_primary().is_some());
        assert!(observed.lifecycle.lock().unwrap().get(PARENT_TID).is_some());
        assert!(observed.lifecycle.lock().unwrap().get(CHILD_TID).is_none());
        let mut release = observed.release.lock().unwrap().take().unwrap();
        let mut announced = false;
        std::future::poll_fn(|cx| match Pin::new(&mut release).poll(cx) {
            Poll::Pending => {
                if !announced {
                    announced = true;
                    // Announce only after the real consuming hook has polled
                    // Pending and registered its wakeup.
                    observed.pending.send(()).unwrap();
                }
                Poll::Pending
            }
            Poll::Ready(result) => Poll::Ready(result),
        })
        .await
        .expect("test releases the consuming hook");
        assert!(observed.lifecycle.lock().unwrap().get(PARENT_TID).is_some());
        assert_eq!(observed.consumed.fetch_add(1, Ordering::SeqCst), 0);
        Ok(())
    }
}

#[derive(Default)]
struct ConsumerCounts {
    polls: AtomicUsize,
    drops: AtomicUsize,
}

struct ChildConsumer {
    run: Arc<RunFailure>,
    lifecycle: Arc<Mutex<TaskLifecycleTable>>,
    counts: Arc<ConsumerCounts>,
    output: Option<Result<()>>,
    poll_panic: Option<PanicPayload>,
    drop_panic: Option<PanicPayload>,
}

impl Future for ChildConsumer {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(self.counts.polls.fetch_add(1, Ordering::SeqCst), 0);
        assert!(self.run.published_primary().is_some());
        assert!(self.lifecycle.lock().unwrap().get(PARENT_TID).is_some());
        if let Some(payload) = self.poll_panic.take() {
            resume_unwind(payload);
        }
        Poll::Ready(self.output.take().unwrap())
    }
}

impl Drop for ChildConsumer {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(payload) = self.drop_panic.take() {
            resume_unwind(payload);
        }
    }
}

struct WorkerDone(mpsc::Sender<()>);

impl Drop for WorkerDone {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

// Every assertion before joining has an unwind rescue: release the pending
// consumer and start gate, then wait a bounded time before attempting a join.
struct WorkerRescue {
    group: Arc<GuestThreadGroup>,
    gate: ChildStartGate,
    release: Option<oneshot::Sender<()>>,
    done: mpsc::Receiver<()>,
    finished: bool,
    joined: bool,
}

impl WorkerRescue {
    fn release(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }

    fn wait_finished(&mut self) {
        self.done.recv_timeout(WAIT).expect("worker did not finish");
        self.finished = true;
    }
}

impl Drop for WorkerRescue {
    fn drop(&mut self) {
        if self.joined {
            return;
        }
        let _ = self.gate.cancel_after_failure();
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if self.finished || self.done.recv_timeout(WAIT).is_ok() {
            let _ = catch_unwind(AssertUnwindSafe(|| self.group.join_workers()));
        } else {
            eprintln!("worker-panic test rescue timed out after releasing its owned gates");
        }
    }
}

fn contains_cause(error: &Error, wanted: &Arc<Error>) -> bool {
    let contains =
        |cause: &Arc<Error>| Arc::ptr_eq(cause, wanted) || contains_cause(cause.as_ref(), wanted);
    match error {
        Error::SignalEffects { cause, .. }
        | Error::SharedFailure(cause)
        | Error::WorkerFailure { error: cause, .. }
        | Error::Cleanup { error: cause, .. } => contains(cause),
        Error::WithCleanup { primary, cleanup } => {
            contains(primary) || cleanup.iter().any(contains)
        }
        Error::ExecWorkerTeardown(error) => contains_cause(error, wanted),
        _ => false,
    }
}

fn cleanup_panic_count(error: &Error) -> usize {
    match error {
        Error::Cleanup { phase, error }
            if *phase == "unstarted-child cleanup"
                && matches!(error.as_ref(), Error::GuestWorkerPanic) =>
        {
            1
        }
        Error::SignalEffects { cause, .. }
        | Error::SharedFailure(cause)
        | Error::WorkerFailure { error: cause, .. }
        | Error::Cleanup { error: cause, .. } => cleanup_panic_count(cause),
        Error::WithCleanup { primary, cleanup } => {
            cleanup_panic_count(primary)
                + cleanup
                    .iter()
                    .map(|error| cleanup_panic_count(error))
                    .sum::<usize>()
        }
        Error::ExecWorkerTeardown(error) => cleanup_panic_count(error),
        _ => 0,
    }
}

fn worker_finish_control(discard: bool, cleanup_panics: bool) {
    // No silent /dev/kvm skip: these backends own real resources, but no guest
    // instruction or vCPU run is needed to test the terminal owner protocol.
    let mut backend = KvmBackend::new(0x10000).expect("worker finish control requires /dev/kvm");
    let mut child_backend =
        KvmBackend::new(0x10000).expect("unstarted child control requires /dev/kvm");
    let group = backend.thread_group.clone();
    backend.is_guest_thread = true;
    backend.thread_ownership = ThreadOwnership::Tool;
    let parent_slot = group.reserve_transport_slot(PARENT_TID).unwrap();
    backend.thread_slot = Some(parent_slot);
    child_backend.thread_group = group.clone();
    child_backend.is_guest_thread = true;
    child_backend.thread_ownership = ThreadOwnership::Tool;
    child_backend.thread_slot = Some(group.reserve_transport_slot(CHILD_TID).unwrap());

    let state = crate::executor::native_loaded_state(Path::new("/"));
    let lifecycle = state.task_lifecycle.clone();
    let leader = ElfExecutor::new(state, false);
    let mut executor = leader.thread_child(PARENT_TID).unwrap();
    let mut child_executor = executor.thread_child(CHILD_TID).unwrap();
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let failure = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(PARENT_TID));
    backend.set_tool_failure(Some(failure.clone()));
    child_backend.set_tool_failure(Some(failure.for_thread(Pid::from_raw(CHILD_TID))));
    let (release, receiver) = oneshot::channel();
    let (pending, pending_receiver) = mpsc::channel();
    let hook = Arc::new(HookObservation {
        run: run.clone(),
        lifecycle: lifecycle.clone(),
        release: Mutex::new(Some(receiver)),
        pending,
        entered: AtomicUsize::new(0),
        consumed: AtomicUsize::new(0),
    });
    let tool = Arc::new(PendingExitTool {
        observed: Some(hook.clone()),
    });
    executor.retain_unstarted_tool_cleanup(Box::pin(async move {
        child_backend
            .finish_unstarted_tool(
                &mut child_executor,
                tool,
                (Pid::from_raw(1), Pid::from_raw(CHILD_TID)),
                &(),
                &(),
                THREAD_STATE,
                Some(Error::RunAborted),
            )
            .await
            .map(|_| ())
    }));

    let child_error = Arc::new(Error::GuestClock("typed child cleanup failure".to_owned()));
    let later_error = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)));
    let mut counts = Vec::new();
    let mut secondary_addresses = Vec::new();
    let mut secondary_drops = Vec::new();
    // The first consumer returns a real error before its optional destructor
    // panic. The next can panic in both poll and drop. The last proves that
    // a later owned consumer still runs and retains its distinct typed error.
    for index in 0..3 {
        let observed = Arc::new(ConsumerCounts::default());
        let mut consumer = ChildConsumer {
            run: run.clone(),
            lifecycle: lifecycle.clone(),
            counts: observed.clone(),
            output: Some(if index == 0 {
                Err(Error::SharedFailure(child_error.clone()))
            } else if index == 2 {
                Err(Error::SharedFailure(later_error.clone()))
            } else {
                Ok(())
            }),
            poll_panic: None,
            drop_panic: None,
        };
        if cleanup_panics && index == 1 {
            let (payload, address, drops) = payload();
            consumer.poll_panic = Some(payload);
            secondary_addresses.push(address);
            secondary_drops.push(drops);
        }
        if cleanup_panics && index < 2 {
            let (payload, address, drops) = payload();
            consumer.drop_panic = Some(payload);
            secondary_addresses.push(address);
            secondary_drops.push(drops);
        }
        executor.retain_unstarted_tool_cleanup(Box::pin(consumer));
        counts.push(observed);
    }

    let (parent_payload, parent_address, parent_drops) = payload();
    let callback_drops = Arc::new(AtomicUsize::new(0));
    let worker_callback_drops = callback_drops.clone();
    let worker_hook = hook.clone();
    let worker_lifecycle = lifecycle.clone();
    let (start_sender, start_receiver) = mpsc::channel();
    let gate = ChildStartGate::new(start_sender);
    let (done_sender, done_receiver) = mpsc::channel();
    let handle = std::thread::spawn(move || -> GuestWorkerResult {
        // Marks departure from this scope; the physical join still owns the
        // thread's final destruction, including its closure captures.
        let _done = WorkerDone(done_sender);
        let command = start_receiver.recv_timeout(WAIT).unwrap();
        assert_eq!(
            command,
            if discard {
                ChildStartCommand::CancelAfterFailure
            } else {
                ChildStartCommand::Start
            }
        );
        let callback = ConstructedParentCallback {
            payload: Some(parent_payload),
            dropped: worker_callback_drops,
        };
        let caught = catch_unwind(AssertUnwindSafe(|| {
            futures::executor::block_on(Box::pin(callback));
        }))
        .expect_err("constructed callback destructor must panic");
        assert_eq!(payload_address(&caught), parent_address);
        let resumed = catch_unwind(AssertUnwindSafe(|| {
            backend.finish_panicked_guest_worker(&mut executor, PARENT_TID, caught);
        }))
        .expect_err("production worker finish must resume the parent panic");
        assert_eq!(payload_address(&resumed), parent_address);
        assert!(executor.take_unstarted_tool_cleanup().is_empty());
        assert_eq!(worker_hook.consumed.load(Ordering::SeqCst), 1);
        assert!(worker_lifecycle.lock().unwrap().get(PARENT_TID).is_none());
        resume_unwind(resumed)
    });
    group.add_unstarted_worker(PARENT_TID, gate.clone(), handle);
    let mut rescue = WorkerRescue {
        group: group.clone(),
        gate: gate.clone(),
        release: Some(release),
        done: done_receiver,
        finished: false,
        joined: false,
    };
    if discard {
        let _ = gate.cancel_after_failure();
        assert!(gate.is_cancelled());
    } else {
        assert_eq!(gate.start(), Ok(true));
    }
    pending_receiver
        .recv_timeout(WAIT)
        .expect("exit hook never polled Pending");
    let primary = run
        .published_primary()
        .expect("publish before child consumption");
    assert!(matches!(primary.primary(), Error::GuestWorkerPanic));
    assert_eq!(callback_drops.load(Ordering::SeqCst), 1);
    assert_eq!(hook.entered.load(Ordering::SeqCst), 1);
    assert_eq!(hook.consumed.load(Ordering::SeqCst), 0);
    assert!(lifecycle.lock().unwrap().get(PARENT_TID).is_some());
    assert!(group.transport_slots.lock().unwrap()[parent_slot]);
    assert!(group.reported_worker_panics.lock().unwrap().is_empty());
    for count in &counts {
        assert_eq!(count.polls.load(Ordering::SeqCst), 0);
        assert_eq!(count.drops.load(Ordering::SeqCst), 0);
    }
    assert_eq!(parent_drops.load(Ordering::SeqCst), 0);
    for drops in &secondary_drops {
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    rescue.release();
    rescue.wait_finished();

    let reported = group
        .reported_worker_panics
        .lock()
        .unwrap()
        .get(&PARENT_TID)
        .expect("worker retained its complete typed cause")
        .error
        .clone();
    let diagnostic = if discard {
        let error = group
            .discard_unstarted_worker(PARENT_TID)
            .expect_err("discard must return the reported worker failure");
        assert!(matches!(&error, Error::SharedFailure(error) if Arc::ptr_eq(error, &reported)));
        assert!(!group.discard_unstarted_worker(PARENT_TID).unwrap());
        error
    } else {
        group.join_workers();
        let error = group
            .teardown_result()
            .expect_err("worker panic must remain a failure");
        assert!(
            matches!(&error, Error::WorkerFailure { tid: PARENT_TID, error }
            if Arc::ptr_eq(error, &reported))
        );
        group.join_workers();
        let repeated = group
            .teardown_result()
            .expect_err("repeated teardown must retain failure");
        assert!(
            matches!(&repeated, Error::WorkerFailure { tid: PARENT_TID, error }
            if Arc::ptr_eq(error, &reported))
        );
        assert!(contains_cause(&repeated, &primary));
        assert!(contains_cause(&repeated, &child_error));
        assert!(contains_cause(&repeated, &later_error));
        error
    };
    rescue.joined = true;
    assert!(contains_cause(&diagnostic, &primary));
    assert!(contains_cause(&diagnostic, &child_error));
    assert!(contains_cause(&diagnostic, &later_error));
    assert!(matches!(diagnostic.primary(), Error::GuestWorkerPanic));
    assert_eq!(cleanup_panic_count(&diagnostic), secondary_addresses.len());
    assert_eq!(hook.consumed.load(Ordering::SeqCst), 1);
    assert!(lifecycle.lock().unwrap().get(PARENT_TID).is_none());
    assert!(!group.transport_slots.lock().unwrap()[parent_slot]);
    assert!(group.worker_handles.lock().unwrap().is_empty());
    assert!(group.worker_start_gates.lock().unwrap().is_empty());
    assert!(group.reported_worker_panics.lock().unwrap().is_empty());
    for count in &counts {
        assert_eq!(count.polls.load(Ordering::SeqCst), 1);
        assert_eq!(count.drops.load(Ordering::SeqCst), 1);
    }
    {
        let completed = group.completed_worker_panics.lock().unwrap();
        assert_eq!(completed.len(), 1);
        assert!(Arc::ptr_eq(&completed[0].error, &reported));
        assert_eq!(
            payload_address(completed[0]._join_payload.as_ref().unwrap()),
            parent_address
        );
        assert_eq!(
            completed[0]
                ._cleanup_panics
                .iter()
                .map(payload_address)
                .collect::<Vec<_>>(),
            secondary_addresses
        );
    }
    assert_eq!(parent_drops.load(Ordering::SeqCst), 0);
    for drops in &secondary_drops {
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(rescue);
    drop(group);
    // Ordinary payload destruction occurs once at the final group owner, even
    // while cloned typed diagnostics remain alive. Panicking payload Drop at
    // this eventual boundary is explicitly outside these controls.
    assert_eq!(parent_drops.load(Ordering::SeqCst), 1);
    for drops in &secondary_drops {
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
    assert!(contains_cause(&diagnostic, &primary));
    assert!(contains_cause(&diagnostic, &child_error));
    assert!(contains_cause(&diagnostic, &later_error));
}

#[test]
fn caught_callback_drop_panic_drains_pending_tool_hook_before_worker_retirement() {
    worker_finish_control(false, false);
}

#[test]
fn joined_worker_retains_cleanup_poll_and_drop_panics_and_later_typed_errors() {
    worker_finish_control(false, true);
}

#[test]
fn discard_cancelled_worker_preserves_reported_cause_and_all_panic_payloads() {
    worker_finish_control(true, true);
}

#[test]
fn unexpected_worker_preserves_prior_and_cross_consumer_payload_order() {
    for prior_pending in [false, true] {
        let mut backend =
            KvmBackend::new(0x10000).expect("worker payload-order control requires /dev/kvm");
        backend.is_guest_thread = true;
        backend.thread_ownership = ThreadOwnership::Tool;
        let group = backend.thread_group.clone();
        let slot = group.reserve_transport_slot(PARENT_TID).unwrap();
        backend.thread_slot = Some(slot);
        let state = crate::executor::native_loaded_state(Path::new("/"));
        let lifecycle = state.task_lifecycle.clone();
        let leader = ElfExecutor::new(state, false);
        let mut executor = leader.thread_child(PARENT_TID).unwrap();
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        backend.set_tool_failure(Some(FailureContext::new(
            run.clone(),
            Pid::from_raw(1),
            Pid::from_raw(PARENT_TID),
        )));
        let owner = backend.tool_panic_owner();
        let mut addresses = Vec::new();
        let mut drops = Vec::new();
        if prior_pending {
            // Construct an already deferred payload to exercise collision
            // with the later outer catch. This does not reconstruct a typed
            // outcome that has already been lost by an unrelated unwind.
            let (prior, address, observed) = payload();
            owner.append(vec![prior]);
            addresses.push(address);
            drops.push(observed);
        }
        let (outer, address, observed) = payload();
        addresses.push(address);
        drops.push(observed);
        let child_error = Arc::new(Error::GuestClock("guarded child error".to_owned()));
        let mut counts = Vec::new();
        for index in 0..3 {
            let (panic, address, observed) = payload();
            addresses.push(address);
            drops.push(observed);
            let count = Arc::new(ConsumerCounts::default());
            let mut consumer = ChildConsumer {
                run: run.clone(),
                lifecycle: lifecycle.clone(),
                counts: count.clone(),
                output: Some(Ok(())),
                poll_panic: None,
                drop_panic: None,
            };
            if index == 1 {
                consumer.output = Some(Err(Error::SharedFailure(child_error.clone())));
                consumer.drop_panic = Some(panic);
                let child = Arc::new(crate::failure::tool_panics::ToolPanics::default());
                let transfer = ChildToolPanicTransfer {
                    parent: owner.clone(),
                    child: child.clone(),
                };
                executor.retain_unstarted_tool_cleanup(Box::pin(async move {
                    let transfer = transfer;
                    let caught = crate::failure::owned_future::catch_owned_future(consumer).await;
                    let result = child.finish(caught, "guarded child cleanup");
                    drop(transfer);
                    result
                }));
            } else {
                consumer.poll_panic = Some(panic);
                executor.retain_unstarted_tool_cleanup(Box::pin(consumer));
            }
            counts.push(count);
        }
        let callback_drops = Arc::new(AtomicUsize::new(0));
        let worker_callback_drops = callback_drops.clone();
        let (start, wait_start) = mpsc::channel();
        let gate = ChildStartGate::new(start);
        let (done, wait_done) = mpsc::channel();
        let handle = std::thread::spawn(move || -> GuestWorkerResult {
            let _done = WorkerDone(done);
            assert_eq!(
                wait_start.recv_timeout(WAIT).unwrap(),
                ChildStartCommand::Start
            );
            let caught = catch_unwind(AssertUnwindSafe(|| {
                futures::executor::block_on(Box::pin(ConstructedParentCallback {
                    payload: Some(outer),
                    dropped: worker_callback_drops,
                }));
            }))
            .expect_err("constructed callback destructor must panic");
            backend.finish_panicked_guest_worker(&mut executor, PARENT_TID, caught)
        });
        group.add_unstarted_worker(PARENT_TID, gate.clone(), handle);
        let mut rescue = WorkerRescue {
            group: group.clone(),
            gate: gate.clone(),
            release: None,
            done: wait_done,
            finished: false,
            joined: false,
        };
        assert_eq!(gate.start(), Ok(true));
        rescue.wait_finished();
        group.join_workers();
        rescue.joined = true;
        let diagnostic = group.teardown_result().unwrap_err();
        assert!(contains_cause(&diagnostic, &child_error));
        assert_eq!(cleanup_panic_count(&diagnostic), 2);
        assert_eq!(callback_drops.load(Ordering::SeqCst), 1);
        assert!(owner.take().is_empty());
        assert!(lifecycle.lock().unwrap().get(PARENT_TID).is_none());
        assert!(!group.transport_slots.lock().unwrap()[slot]);
        for count in &counts {
            assert_eq!(count.polls.load(Ordering::SeqCst), 1);
            assert_eq!(count.drops.load(Ordering::SeqCst), 1);
        }
        {
            let completed = group.completed_worker_panics.lock().unwrap();
            assert_eq!(completed.len(), 1);
            assert_eq!(
                payload_address(completed[0]._join_payload.as_ref().unwrap()),
                addresses[0]
            );
            assert_eq!(
                completed[0]
                    ._cleanup_panics
                    .iter()
                    .map(payload_address)
                    .collect::<Vec<_>>(),
                addresses[1..],
            );
        }
        for observed in &drops {
            assert_eq!(observed.load(Ordering::SeqCst), 0);
        }
        drop(rescue);
        drop(group);
        for observed in &drops {
            assert_eq!(observed.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn failed_spawn_transfer_guard_preserves_pending_payloads_on_future_drop() {
    for poll_before_drop in [false, true] {
        let parent = Arc::new(crate::failure::tool_panics::ToolPanics::default());
        let child = Arc::new(crate::failure::tool_panics::ToolPanics::default());
        let (first, first_address, first_drops) = payload();
        let (second, second_address, second_drops) = payload();
        parent.append(vec![first]);
        child.append(vec![second]);
        let transfer = ChildToolPanicTransfer {
            parent: parent.clone(),
            child: child.clone(),
        };
        // The production transfer guard is owned before the future can be
        // polled. Both an unpolled drop and a Pending drop must transfer once.
        let mut future = Box::pin(async move {
            let _transfer = transfer;
            std::future::pending::<()>().await;
        });
        if poll_before_drop {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        drop(future);
        assert!(child.take().is_empty());
        let owned = parent.take();
        assert_eq!(
            owned.iter().map(payload_address).collect::<Vec<_>>(),
            [first_address, second_address]
        );
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);
        assert_eq!(second_drops.load(Ordering::SeqCst), 0);
        assert!(parent.take().is_empty());
        drop(owned);
        assert_eq!(first_drops.load(Ordering::SeqCst), 1);
        assert_eq!(second_drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn a_reaper_joins_a_worker_whose_handle_lock_was_poisoned() {
    let runs = Arc::new(std::sync::Mutex::new(
        crate::executor::AbandonedRuns::default(),
    ));
    let group = Arc::new(GuestThreadGroup::default());
    let lifetime = Arc::new(());
    let (release, held) = mpsc::channel::<()>();
    let worker = {
        let lifetime = lifetime.clone();
        std::thread::spawn(move || {
            let _lifetime = lifetime;
            let _ = held.recv();
            Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
        })
    };
    group.add_worker_handle(4, worker);
    // An earlier panic poisoned the handle lock after worker 4 was added.
    {
        let group = group.clone();
        std::thread::spawn(move || {
            let _held = group.worker_handles.lock().unwrap();
            panic!("poisoning a dropped run's worker-handle lock");
        })
        .join()
        .unwrap_err();
    }
    assert!(group.worker_handles.is_poisoned());

    // The run is dropped, and the backend's drop hands worker 4 to its reaper.
    drop(crate::executor::RunAdmission::begin(&runs).unwrap());
    let dropping = std::time::Instant::now();
    assert!(crate::executor::AbandonedRuns::retire(&runs, &group));
    assert!(dropping.elapsed() < Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(50));
    assert!(group.has_unjoined_workers());
    assert_eq!(
        Arc::strong_count(&lifetime),
        2,
        "the worker ended while held"
    );
    assert_eq!(
        Arc::strong_count(&group),
        2,
        "the reaper let go of the worker before joining it"
    );

    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while Arc::strong_count(&group) != 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "the reaper never joined a worker behind a poisoned handle lock"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!group.has_unjoined_workers());
    assert_eq!(Arc::strong_count(&lifetime), 1);
}
