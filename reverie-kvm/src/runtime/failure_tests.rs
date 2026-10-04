/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use std::time::Instant;

use futures::channel::oneshot;

use super::*;
use crate::vm::GuestThreadGroup;

#[derive(Default)]
struct RpcGlobal {
    response: Mutex<Option<oneshot::Receiver<i64>>>,
    pending: AtomicBool,
    events: Mutex<Vec<(u8, i32, i32)>>,
    failures: AtomicUsize,
    failure_events: Mutex<Vec<reverie::BackendFailure>>,
    failure_required: AtomicBool,
    late_failure: Mutex<Option<FailureContext>>,
    terminate_on_failure: AtomicBool,
    terminal: AtomicBool,
    terminal_waker: futures::task::AtomicWaker,
}

#[reverie::global_tool]
impl GlobalTool for RpcGlobal {
    type Request = (u8, i32);
    type Response = i64;
    type Config = bool;

    async fn receive_rpc(&self, from: Pid, (kind, code): (u8, i32)) -> i64 {
        if kind != 0 {
            if let Some(failure) = self.late_failure.lock().unwrap().take() {
                let _: Result<()> = crate::vm::finish_host_worker_outcome(
                    Some(&failure),
                    Pid::from_raw(9),
                    Err(Error::GuestClock("late independent worker".to_owned())),
                    |_| {},
                );
            }
            assert!(
                !self.failure_required.load(Ordering::Acquire)
                    || self.failures.load(Ordering::Acquire) > 0,
                "consuming hook ran before fatal publication"
            );
            self.events
                .lock()
                .unwrap()
                .push((kind, from.as_raw(), code));
            return 0;
        }
        let mut response = self.response.lock().unwrap().take().unwrap();
        poll_fn(|cx| {
            let result = Pin::new(&mut response).poll(cx);
            if result.is_pending() {
                self.pending.store(true, Ordering::Release);
            }
            result
        })
        .await
        .expect("test controller dropped RPC response")
    }

    fn report_backend_failure(&self, event: reverie::BackendFailure) {
        self.failure_events.lock().unwrap().push(event);
        self.failures.fetch_add(1, Ordering::SeqCst);
        if self.terminate_on_failure.load(Ordering::Acquire) {
            self.terminal.store(true, Ordering::Release);
            self.terminal_waker.wake();
        }
    }

    async fn wait_for_backend_failure(&self) {
        poll_fn(|context| {
            self.terminal_waker.register(context.waker());
            if self.terminal.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

#[derive(Default)]
struct RpcTool;

#[reverie::tool]
impl Tool for RpcTool {
    type GlobalState = RpcGlobal;
    type ThreadState = i32;

    fn init_thread_state(&self, tid: Pid, _parent: Option<(Pid, &i32)>) -> i32 {
        tid.as_raw()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _call: reverie::syscalls::Syscall,
    ) -> std::result::Result<i64, reverie::Error> {
        Ok(guest.send_rpc((0, 0)).await)
    }

    async fn on_exit_thread<G: GlobalRPC<RpcGlobal>>(
        &self,
        tid: Pid,
        global: &G,
        state: i32,
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        assert_eq!(state, tid.as_raw(), "wrong consuming owner");
        global.send_rpc((1, conventional_exit_code(status))).await;
        if *global.config() && tid.as_raw() == 2 {
            Err(Errno::EIO.into())
        } else {
            Ok(())
        }
    }

    async fn on_exit_process<G: GlobalRPC<RpcGlobal>>(
        self,
        _pid: Pid,
        global: &G,
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        global.send_rpc((2, conventional_exit_code(status))).await;
        Ok(())
    }
}

struct NoGuestExecution;
impl GuestSyscallExecutor<RpcTool> for NoGuestExecution {
    fn read_clock(&self) -> Result<u64> {
        panic!("native RPC control read a guest clock")
    }
    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("native RPC control continued guest execution")
    }
}

fn wait_until(condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "native control did not reach its ordering boundary"
        );
        std::thread::yield_now();
    }
}

#[test]
fn peer_failure_cancellation_preserves_thread_status_and_primary_cause() {
    fn count_host_errno(error: &Error, expected: i32) -> usize {
        match error {
            Error::HostIo(error) => usize::from(error.raw_os_error() == Some(expected)),
            Error::SharedFailure(error)
            | Error::WorkerFailure { error, .. }
            | Error::Cleanup { error, .. } => count_host_errno(error, expected),
            Error::ExecWorkerTeardown(error) => count_host_errno(error, expected),
            Error::WithCleanup { primary, cleanup } => {
                count_host_errno(primary, expected)
                    + cleanup
                        .iter()
                        .map(|error| count_host_errno(error, expected))
                        .sum::<usize>()
            }
            _ => 0,
        }
    }
    for case in [
        "live peer",
        "pending thread status",
        "group status",
        "peer cleanup errors",
        "unstarted thread",
        "own execution error",
        "process owner",
        "ordinary cancellation",
    ] {
        let global = Arc::new(RpcGlobal::default());
        let pid = Pid::from_raw(1);
        let tid = Pid::from_raw(if case == "process owner" { 1 } else { 2 });
        let identity = (pid, tid);
        let failure = FailureContext::new(RunFailure::new(&global), pid, tid);
        let expected_peer = matches!(
            case,
            "live peer" | "pending thread status" | "group status" | "peer cleanup errors"
        );
        let (_response, receiver) = oneshot::channel();
        *global.response.lock().unwrap() = Some(receiver);
        let mut pending_rpc = expected_peer.then(|| {
            Box::pin(drive_handler(
                async { Ok::<i64, reverie::Error>(global.receive_rpc(tid, (0, 0)).await) },
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(Vec::new())),
                wait_for_failure(global.as_ref(), Some(failure.run.subscribe())),
            ))
        });
        if let Some(pending) = pending_rpc.as_mut() {
            assert!(pending.as_mut().now_or_never().is_none());
            assert!(global.pending.load(Ordering::Acquire));
        }
        let mut leader = Some(ElfExecutor::new(
            crate::executor::native_loaded_state(&std::env::current_dir().unwrap()),
            false,
        ));
        let mut failed_worker = leader.as_ref().unwrap().thread_child(3).unwrap();
        let mut executor = if pid == tid {
            leader.take().unwrap()
        } else {
            leader.as_ref().unwrap().thread_child(tid.as_raw()).unwrap()
        };
        // The real failing worker publishes before its task retirement. No
        // group cancellation flag is needed for a peer to observe that event.
        let result: Result<()> = crate::vm::finish_host_worker_outcome(
            Some(&failure),
            Pid::from_raw(3),
            Err(Error::InvalidGuestPid(-17)),
            |failed| {
                assert!(failed);
                failed_worker.retire_failed_thread();
            },
        );
        assert!(result.is_err());
        if let Some(pending) = pending_rpc {
            assert!(matches!(
                futures::executor::block_on(pending),
                HandlerOutcome::RunFailed,
            ));
        }
        let primary = failure.run.primary().unwrap();
        let event = global.failure_events.lock().unwrap()[0];
        assert_eq!(event.pid, pid);
        assert_eq!(event.tid, Pid::from_raw(3));

        if case == "pending thread status" {
            let memory = GuestMemory::new(0, 4096).unwrap();
            assert_eq!(
                executor.execute(
                    &SyscallRequest::new(libc::SYS_exit as u64, [37, 0, 0, 0, 0, 0]),
                    &memory,
                ),
                0,
            );
        }
        let group_status = (case == "group status").then_some(ExitStatus::Exited(61));
        let cleanup = case == "peer cleanup errors";
        let start_permitted = case != "unstarted thread";
        let outcome = match case {
            "own execution error" => Err(Error::Reverie(Errno::ENOTSUPP.into())),
            "ordinary cancellation" => Ok(ToolProcessExit {
                exit: executor.cancel_current_thread(),
                disposition: ToolExitDisposition::ExplicitCancellation,
            }),
            "peer cleanup errors" => Err(Error::RunAborted.with_cleanup(vec![Error::HostIo(
                std::io::Error::from_raw_os_error(libc::ENOSPC),
            )])),
            _ => Err(Error::RunAborted),
        };
        let cancelled_exit = retire_peer_cancelled_tool_worker(
            &mut executor,
            identity,
            start_permitted,
            group_status,
            &outcome,
        );
        assert_eq!(cancelled_exit.is_some(), expected_peer, "{case}");
        if cancelled_exit.is_none() {
            match &outcome {
                Ok(exit) => {
                    executor.retire_current_thread(exit.exit.status, exit.exit.group);
                }
                Err(_) => executor.retire_failed_thread(),
            }
        }
        let result = futures::executor::block_on(finish_tool_process_after_workers(
            &mut executor,
            Arc::new(RpcTool),
            identity,
            global.as_ref(),
            &cleanup,
            tid.as_raw(),
            outcome,
            cancelled_exit,
            Ok(()),
            Some(&failure),
        ));
        let expected_status = match case {
            "pending thread status" => 37,
            "group status" => 61,
            "live peer" | "peer cleanup errors" | "ordinary cancellation" => 0,
            _ => 255,
        };
        let mut expected_events = vec![(1, tid.as_raw(), expected_status)];
        if pid == tid {
            expected_events.push((2, pid.as_raw(), expected_status));
        }
        assert_eq!(*global.events.lock().unwrap(), expected_events, "{case}");
        if case != "ordinary cancellation" {
            assert!(
                result.is_err(),
                "cancellation cannot erase the error tree: {case}"
            );
        }
        assert_eq!(
            is_peer_cancelled_tool_worker(identity, start_permitted, &result),
            expected_peer,
            "the outer worker wrapper must preserve the same classification: {case}",
        );
        let error = failure.run.complete(result).unwrap_err();
        assert!(error.retains_primary(&primary), "{case}: {error:?}");
        assert!(matches!(error.primary(), Error::InvalidGuestPid(-17)));
        if cleanup {
            assert_eq!(count_host_errno(&error, libc::ENOSPC), 1);
            assert!(has_cleanup_eio(&error));
            assert_eq!(error.to_string().matches("EIO").count(), 1);
        }
        assert_eq!(global.failure_events.lock().unwrap()[0], event);
        if let Some(mut leader) = leader {
            leader.retire_current_thread(ExitStatus::SUCCESS, false);
            assert_eq!(
                leader.process_exit_status(),
                None,
                "healthy peer retirement cannot erase the real worker failure: {case}",
            );
        }
    }
}

// Install the response rescue and join ownership before the first ordering
// assertion. A precondition panic must reap the real worker as well as fail the
// test; it must not detach a live RPC waiter into the remaining test process.
struct RpcControlCleanup {
    response: Option<oneshot::Sender<i64>>,
    panic_release: Option<std::sync::mpsc::Sender<()>>,
    group: Arc<GuestThreadGroup>,
    joiner: Option<std::thread::JoinHandle<()>>,
}

impl RpcControlCleanup {
    fn rescue(&mut self) {
        if let Some(release) = self.panic_release.take() {
            let _ = release.send(());
        }
        if let Some(response) = self.response.take() {
            let _ = response.send(99);
        }
    }
}

impl Drop for RpcControlCleanup {
    fn drop(&mut self) {
        self.rescue();
        if let Some(joiner) = self.joiner.take() {
            // The original ordering assertion remains the test failure during
            // unwind. The production group also retains any worker panic.
            let _ = joiner.join();
        } else {
            self.group.join_workers();
        }
    }
}

fn joined_rpc_control(fail: bool, cleanup_fails: bool) {
    joined_rpc_control_with_panic(fail, cleanup_fails, false);
}

fn joined_rpc_control_with_panic(fail: bool, cleanup_fails: bool, worker_panics: bool) {
    let global = Arc::new(RpcGlobal::default());
    let (response, receiver) = oneshot::channel();
    *global.response.lock().unwrap() = Some(receiver);
    let failure = RunFailure::new(&global);
    let reporter = FailureContext::new(failure.clone(), Pid::from_raw(1), Pid::from_raw(3));
    let tool = Arc::new(RpcTool);
    let group = Arc::new(GuestThreadGroup::default());
    let mut cleanup = RpcControlCleanup {
        response: Some(response),
        panic_release: None,
        group: group.clone(),
        joiner: None,
    };
    let worker_global = global.clone();
    let worker_tool = tool.clone();
    let subscription = failure.subscribe();
    let worker_failure = failure.clone();
    let worker = std::thread::spawn(move || {
        let pid = Pid::from_raw(1);
        let tid = Pid::from_raw(2);
        let mut state = worker_tool.init_thread_state(tid, None);
        let signal = Arc::new(Mutex::new(None));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let mut executor = NoGuestExecution;
        let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
        let subscriptions = Subscription::none();
        let outcome = {
            let mut guest = KvmGuest::new(
                pid,
                tid,
                worker_tool.clone(),
                memory,
                &[],
                // No instruction executes; only send_rpc uses this guest.
                unsafe { std::mem::zeroed() },
                &mut state,
                &mut executor,
                worker_global.as_ref(),
                Some(worker_global.clone()),
                &cleanup_fails,
                &subscriptions,
                signal.clone(),
                starts.clone(),
                crate::bootstrap::TOOL_STACK_TOP,
                Arc::new(AtomicBool::new(false)),
            );
            futures::executor::block_on(drive_handler(
                worker_tool.handle_syscall_event(
                    &mut guest,
                    SyscallRequest::new(libc::SYS_getpid as u64, [0; 6])
                        .into_syscall()
                        .unwrap(),
                ),
                signal,
                starts,
                wait_for_failure(worker_global.as_ref(), Some(subscription)),
            ))
        };
        let status = if fail {
            assert!(
                matches!(outcome, HandlerOutcome::RunFailed),
                "watchdog/ordinary response is not fatal cancellation"
            );
            ExitStatus::Exited(255)
        } else {
            match outcome {
                HandlerOutcome::Returned(Ok(37)) => ExitStatus::Exited(37),
                _ => panic!("normal RPC/status changed"),
            }
        };
        let cleanup = futures::executor::block_on(notify_tool_exit(
            worker_tool,
            pid,
            tid,
            worker_global.as_ref(),
            &cleanup_fails,
            state,
            ToolExit {
                status,
                process_exited: false,
            },
            None,
        ));
        if fail {
            let primary =
                Error::SharedFailure(worker_failure.primary().expect("missing typed failure"));
            Err(primary.with_cleanup(cleanup.err().into_iter().collect()))
        } else {
            cleanup?;
            Ok((status, Vec::new(), Vec::new()))
        }
    });
    let worker_host_id = worker.thread().id();
    group.add_worker_handle(2, worker);
    let panic_retired = Arc::new(AtomicBool::new(false));
    if worker_panics {
        let (release, receiver) = std::sync::mpsc::channel();
        cleanup.panic_release = Some(release);
        let context = reporter.clone();
        let panic_group = group.clone();
        let panic_global = global.clone();
        let retired = panic_retired.clone();
        group.add_worker_handle(
            3,
            std::thread::spawn(move || {
                receiver.recv().unwrap();
                let marker = Arc::new(());
                let payload: Box<dyn std::any::Any + Send> = Box::new(marker.clone());
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::vm::finish_caught_worker_panic(
                        Some(&context),
                        &panic_group,
                        3,
                        Error::GuestWorkerPanic,
                        payload,
                        || {
                            assert_eq!(
                                *panic_global.failure_events.lock().unwrap(),
                                vec![reverie::BackendFailure {
                                    pid: Pid::from_raw(1),
                                    tid: Pid::from_raw(3),
                                    phase: "worker panic",
                                }]
                            );
                            retired.store(true, Ordering::Release);
                        },
                    )
                }));
                let payload = caught.unwrap_err();
                assert!(
                    Arc::ptr_eq(payload.downcast_ref::<Arc<()>>().unwrap(), &marker),
                    "caught worker panic replaced its original payload"
                );
                std::panic::resume_unwind(payload)
            }),
        );
    }
    wait_until(|| global.pending.load(Ordering::Acquire));
    let join_group = group.clone();
    let (joined, joined_receiver) = std::sync::mpsc::channel();
    cleanup.joiner = Some(std::thread::spawn(move || {
        join_group.join_workers();
        joined.send(()).unwrap();
    }));
    let joining_host_id = cleanup.joiner.as_ref().unwrap().thread().id();
    // The worker is parked in the actual Tool RPC, and the actual production
    // joiner owns its exact OS JoinHandle outside the group's registry. Other
    // workers can remain registered while this physical join is pending.
    wait_until(|| group.worker_join_owns_target(2, worker_host_id, joining_host_id));
    assert!(group.has_worker_handles());
    assert_eq!(global.failures.load(Ordering::SeqCst), 0);
    assert!(matches!(
        joined_receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    if worker_panics {
        cleanup.panic_release.take().unwrap().send(()).unwrap();
    } else if fail {
        reporter.publish(
            "controlled worker failure",
            Error::GuestClock("typed primary".to_owned()),
        );
    } else {
        cleanup.response.take().unwrap().send(37).unwrap();
    }
    let completed = joined_receiver.recv_timeout(Duration::from_secs(2)).is_ok();
    if !completed {
        // Rescue only reaps the failed control. The completed assertion remains
        // false, so moving publication after join/removing the subscription fails.
        cleanup.rescue();
    }
    cleanup.joiner.take().unwrap().join().unwrap();
    assert!(
        completed,
        "fatal publication did not release the actual join"
    );
    assert!(!group.worker_join_owns_target(2, worker_host_id, joining_host_id));
    let result = group.teardown_result();
    if fail {
        let error = result.unwrap_err();
        if worker_panics {
            assert!(matches!(error.primary(), Error::GuestWorkerPanic));
            assert!(
                error
                    .to_string()
                    .contains("thread 3: guest thread panicked during teardown")
            );
            assert!(error.retains_primary(&failure.primary().unwrap()));
            assert!(panic_retired.load(Ordering::Acquire));
            assert_eq!(
                global.failures.load(Ordering::SeqCst),
                1,
                "joining the caught panic published it a second time"
            );
            assert_eq!(
                error.to_string().matches("thread 3:").count(),
                1,
                "joining the caught panic cached it a second time: {error}"
            );
        } else {
            assert!(
                has_guest_clock_primary(&error),
                "typed worker cause was lost: {error:?}"
            );
            assert!(matches!(error.primary(), Error::GuestClock(_)));
        }
        assert!(
            error.to_string().contains("thread 2:"),
            "worker TID diagnostic was lost: {error:?}"
        );
        if cleanup_fails {
            assert!(has_cleanup_eio(&error), "cleanup cause was lost: {error:?}");
        }
        assert!(global.failures.load(Ordering::SeqCst) > 0);
    } else {
        result.unwrap();
        assert_eq!(global.failures.load(Ordering::SeqCst), 0);
    }
    let status = ExitStatus::Exited(if fail { 255 } else { 37 });
    futures::executor::block_on(notify_tool_exit(
        tool,
        Pid::from_raw(1),
        Pid::from_raw(1),
        global.as_ref(),
        &cleanup_fails,
        1,
        ToolExit {
            status,
            process_exited: true,
        },
        None,
    ))
    .unwrap();
    assert_eq!(
        *global.events.lock().unwrap(),
        vec![
            (1, 2, conventional_exit_code(status)),
            (1, 1, conventional_exit_code(status)),
            (2, 1, conventional_exit_code(status))
        ]
    );
    assert!(!group.has_worker_handles());
}

fn has_guest_clock_primary(error: &Error) -> bool {
    match error {
        Error::GuestClock(_) => true,
        Error::SharedFailure(error) | Error::WorkerFailure { error, .. } => {
            has_guest_clock_primary(error)
        }
        Error::WithCleanup { primary, .. } => has_guest_clock_primary(primary),
        _ => false,
    }
}
fn has_cleanup_eio(error: &Error) -> bool {
    match error {
        Error::Reverie(reverie::Error::Errno(errno)) => *errno == Errno::EIO,
        Error::SharedFailure(error) | Error::WorkerFailure { error, .. } => has_cleanup_eio(error),
        Error::WithCleanup { primary, cleanup } => {
            has_cleanup_eio(primary) || cleanup.iter().any(|error| has_cleanup_eio(error))
        }
        _ => false,
    }
}

#[test]
fn fatal_notification_releases_pending_tool_rpc_before_owned_join() {
    joined_rpc_control(true, false);
}
#[test]
fn fatal_worker_primary_survives_separate_consuming_hook_error() {
    joined_rpc_control(true, true);
}
#[test]
fn normal_rpc_keeps_status_and_worker_before_leader_hooks() {
    joined_rpc_control(false, false);
}

#[test]
fn caught_worker_panic_publishes_before_retirement_and_pending_rpc_join() {
    joined_rpc_control_with_panic(true, false, true);
}

#[test]
fn failure_precedes_ready_callback_and_keeps_child_start_gate_closed() {
    let global = Arc::new(RpcGlobal::default());
    let failure = RunFailure::new(&global);
    let reporter = FailureContext::new(failure.clone(), Pid::from_raw(1), Pid::from_raw(1));
    reporter.publish("setup", Error::GuestClock("setup".to_owned()));
    let (sender, receiver) = std::sync::mpsc::channel();
    let gate = ChildStartGate::new(sender);
    let starts = Arc::new(Mutex::new(vec![PendingChildStart::tool_thread(2, gate)]));
    let polled = AtomicBool::new(false);
    let outcome = futures::executor::block_on(drive_handler(
        async {
            polled.store(true, Ordering::SeqCst);
            37
        },
        Arc::new(Mutex::new(None)),
        starts.clone(),
        wait_for_failure(global.as_ref(), Some(failure.subscribe())),
    ));
    assert!(matches!(outcome, HandlerOutcome::RunFailed));
    assert!(!polled.load(Ordering::SeqCst));
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    starts.lock().unwrap().pop().unwrap().cancel();
    assert_eq!(receiver.recv().unwrap(), ChildStartCommand::Cancel);
}

struct NativeRpcCall;
impl native_test_support::NativeToolCallback<RpcTool> for NativeRpcCall {
    fn run<'a, G: Guest<RpcTool>>(
        &'a self,
        tool: &'a RpcTool,
        guest: &'a mut G,
    ) -> futures::future::BoxFuture<'a, std::result::Result<i64, reverie::Error>> {
        Box::pin(async move {
            tool.handle_syscall_event(
                guest,
                SyscallRequest::new(libc::SYS_getpid as u64, [0; 6])
                    .into_syscall()
                    .unwrap(),
            )
            .await
        })
    }
}

struct NativeStatusCall;
impl native_test_support::NativeToolCallback<RpcTool> for NativeStatusCall {
    fn run<'a, G: Guest<RpcTool>>(
        &'a self,
        _: &'a RpcTool,
        _: &'a mut G,
    ) -> futures::future::BoxFuture<'a, std::result::Result<i64, reverie::Error>> {
        Box::pin(async { Ok(73) })
    }
}

#[test]
fn independent_process_callbacks_preserve_completion_and_failure_scope() {
    use native_test_support::NativeCallbackOutcome;
    use native_test_support::NativeToolCallback;
    use native_test_support::NativeToolOwner;

    struct ReadyCallback {
        polled: Arc<AtomicBool>,
        during: Option<FailureContext>,
        published: Arc<Mutex<Option<Error>>>,
    }
    impl NativeToolCallback<RpcTool> for ReadyCallback {
        fn run<'a, G: Guest<RpcTool>>(
            &'a self,
            _: &'a RpcTool,
            guest: &'a mut G,
        ) -> futures::future::BoxFuture<'a, std::result::Result<i64, reverie::Error>> {
            Box::pin(async move {
                assert_eq!(guest.pid(), Pid::from_raw(72));
                assert_eq!(guest.ppid(), Some(Pid::from_raw(71)));
                self.polled.store(true, Ordering::Release);
                if let Some(context) = &self.during {
                    let result: Result<()> = crate::vm::finish_host_worker_outcome(
                        Some(context),
                        Pid::from_raw(79),
                        Err(Error::InvalidGuestPid(-17)),
                        |_| {},
                    );
                    *self.published.lock().unwrap() = Some(result.unwrap_err());
                }
                Ok(73)
            })
        }
    }

    for (case, own_process, global_terminal, during, rpc) in [
        ("independent completion", false, false, false, false),
        ("own process before callback", true, false, false, false),
        ("own process during callback", true, false, true, false),
        ("global terminal before callback", false, true, false, false),
        ("global terminal during callback", false, true, true, false),
        ("RPC after independent failure", false, false, false, true),
    ] {
        let global = Arc::new(RpcGlobal::default());
        global
            .terminate_on_failure
            .store(global_terminal, Ordering::Release);
        let (_response, receiver) = oneshot::channel();
        *global.response.lock().unwrap() = Some(receiver);
        let mut owner = NativeToolOwner::new(
            Pid::from_raw(71),
            Arc::new(RpcTool),
            71,
            global.clone(),
            false,
        )
        .unwrap();
        let mut child = owner
            .fork_child(Pid::from_raw(72), Arc::new(RpcTool), 72)
            .unwrap();
        let context = if own_process {
            child.failure_context_for_test()
        } else {
            owner.failure_context_for_test()
        };
        let run = context.run.clone();
        let published = Arc::new(Mutex::new(None));
        let polled = Arc::new(AtomicBool::new(false));
        let callback = ReadyCallback {
            polled: polled.clone(),
            during: during.then(|| context.clone()),
            published: published.clone(),
        };
        if !during {
            let result: Result<()> = crate::vm::finish_host_worker_outcome(
                Some(&context),
                Pid::from_raw(79),
                Err(Error::InvalidGuestPid(-17)),
                |_| {},
            );
            *published.lock().unwrap() = Some(result.unwrap_err());
        }
        let outcome = if rpc {
            futures::executor::block_on(child.run_callback(&NativeRpcCall))
        } else {
            futures::executor::block_on(child.run_callback(&callback))
        };
        let completed = !own_process && !global_terminal && !rpc;
        let child_result = if completed {
            assert!(
                matches!(outcome, Ok(NativeCallbackOutcome::Returned(Ok(73)))),
                "{case}"
            );
            Ok(ExitStatus::Exited(73))
        } else {
            if rpc {
                assert!(matches!(outcome, Err(Error::RunAborted)), "{case}");
                assert!(
                    !global.pending.load(Ordering::Acquire),
                    "failed RPC was admitted"
                );
                assert!(
                    global.response.lock().unwrap().is_some(),
                    "failed RPC consumed request state"
                );
            } else {
                assert!(
                    matches!(outcome, Ok(NativeCallbackOutcome::RunFailed)),
                    "{case}"
                );
            }
            Err(Error::RunAborted)
        };
        assert_eq!(
            polled.load(Ordering::Acquire),
            completed || during,
            "{case}"
        );
        let primary = run.primary().unwrap();
        let published = published.lock().unwrap().take().unwrap();
        let (child_result, root_result) = if own_process {
            (
                Err(Error::RunAborted.with_cleanup(vec![published])),
                Err(Error::RunAborted),
            )
        } else {
            (child_result, Err(published))
        };
        let child_error = futures::executor::block_on(child.finish(child_result)).unwrap_err();
        assert!(
            std::ptr::eq(child_error.primary(), primary.primary()),
            "{case}"
        );
        // The actual initial owner remains run-wide even when its numerical
        // PID is not 1 and the first failure belongs to a forked process.
        let root_polled = Arc::new(AtomicBool::new(false));
        let root_callback = ReadyCallback {
            polled: root_polled.clone(),
            during: None,
            published: Arc::new(Mutex::new(None)),
        };
        assert!(
            matches!(
                futures::executor::block_on(owner.run_callback(&root_callback)),
                Ok(NativeCallbackOutcome::RunFailed)
            ),
            "{case}"
        );
        assert!(
            !root_polled.load(Ordering::Acquire),
            "initial owner resumed after run failure"
        );
        let root_error = futures::executor::block_on(owner.finish(root_result)).unwrap_err();
        assert!(
            std::ptr::eq(root_error.primary(), primary.primary()),
            "{case}"
        );
        let child_status = if completed { 73 } else { 255 };
        assert_eq!(
            *global.events.lock().unwrap(),
            vec![
                (1, 72, child_status),
                (2, 72, child_status),
                (1, 71, 255),
                (2, 71, 255),
            ],
            "consuming RPC must remain usable after failure: {case}"
        );
        assert_eq!(
            *global.failure_events.lock().unwrap(),
            vec![reverie::BackendFailure {
                pid: Pid::from_raw(if own_process { 72 } else { 71 }),
                tid: Pid::from_raw(79),
                phase: "host-owned worker",
            }],
            "{case}"
        );
    }
}

#[test]
fn independent_process_select_cannot_discard_rpc_runtime_failure() {
    use native_test_support::NativeCallbackOutcome;
    use native_test_support::NativeToolCallback;
    use native_test_support::NativeToolOwner;

    struct SelectedRpc {
        alternative_selected: Arc<AtomicBool>,
    }
    impl NativeToolCallback<RpcTool> for SelectedRpc {
        fn run<'a, G: Guest<RpcTool>>(
            &'a self,
            _: &'a RpcTool,
            guest: &'a mut G,
        ) -> futures::future::BoxFuture<'a, std::result::Result<i64, reverie::Error>> {
            Box::pin(async move {
                assert_eq!(guest.pid(), Pid::from_raw(72));
                let request = pin!(guest.send_rpc((0, 0)));
                match futures::future::select(request, futures::future::ready(73)).await {
                    futures::future::Either::Left((response, _)) => Ok(response),
                    futures::future::Either::Right((alternative, _)) => {
                        self.alternative_selected.store(true, Ordering::Release);
                        Ok(alternative)
                    }
                }
            })
        }
    }

    for (failed, response_ready) in [(true, false), (false, false), (false, true)] {
        let global = Arc::new(RpcGlobal::default());
        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        *global.response.lock().unwrap() = Some(receiver);
        if response_ready {
            sender.take().unwrap().send(37).unwrap();
        }
        let owner = NativeToolOwner::new(
            Pid::from_raw(71),
            Arc::new(RpcTool),
            71,
            global.clone(),
            false,
        )
        .unwrap();
        let mut child = owner
            .fork_child(Pid::from_raw(72), Arc::new(RpcTool), 72)
            .unwrap();
        let context = owner.failure_context_for_test();
        let error = failed.then(|| {
            let result: Result<()> = crate::vm::finish_host_worker_outcome(
                Some(&context),
                Pid::from_raw(79),
                Err(Error::InvalidGuestPid(-17)),
                |_| {},
            );
            result.unwrap_err()
        });
        let alternative_selected = Arc::new(AtomicBool::new(false));
        let outcome = futures::executor::block_on(child.run_callback(&SelectedRpc {
            alternative_selected: alternative_selected.clone(),
        }));
        assert_eq!(
            alternative_selected.load(Ordering::Acquire),
            !response_ready,
            "the control must actually return through the ready alternative"
        );
        assert_eq!(
            global.pending.load(Ordering::Acquire),
            !failed && !response_ready
        );
        let child_status;
        let root_status;
        if failed {
            assert!(
                matches!(outcome, Err(Error::RunAborted)),
                "a ready alternative discarded the RPC's runtime failure"
            );
            assert!(
                global.response.lock().unwrap().is_some(),
                "terminal RPC must not enter request state"
            );
            let primary = context.run.primary().unwrap();
            let child_error =
                futures::executor::block_on(child.finish(Err(Error::RunAborted))).unwrap_err();
            let root_error =
                futures::executor::block_on(owner.finish(Err(error.unwrap()))).unwrap_err();
            assert!(std::ptr::eq(child_error.primary(), primary.primary()));
            assert!(std::ptr::eq(root_error.primary(), primary.primary()));
            assert_eq!(
                *global.failure_events.lock().unwrap(),
                vec![reverie::BackendFailure {
                    pid: Pid::from_raw(71),
                    tid: Pid::from_raw(79),
                    phase: "host-owned worker",
                }]
            );
            child_status = 255;
            root_status = 255;
        } else {
            child_status = if response_ready { 37 } else { 73 };
            root_status = 37;
            assert!(matches!(
                outcome,
                Ok(NativeCallbackOutcome::Returned(Ok(code))) if code == i64::from(child_status)
            ));
            assert!(global.response.lock().unwrap().is_none());
            if let Some(sender) = sender {
                assert!(sender.is_canceled(), "the losing ordinary RPC was retained");
            }
            assert_eq!(
                futures::executor::block_on(child.finish(Ok(ExitStatus::Exited(child_status))))
                    .unwrap()
                    .0,
                ExitStatus::Exited(child_status)
            );
            assert_eq!(
                futures::executor::block_on(owner.finish(Ok(ExitStatus::Exited(root_status))))
                    .unwrap()
                    .0,
                ExitStatus::Exited(root_status)
            );
            assert!(context.run.primary().is_none());
            assert!(global.failure_events.lock().unwrap().is_empty());
        }
        assert_eq!(
            *global.events.lock().unwrap(),
            vec![
                (1, 72, child_status),
                (2, 72, child_status),
                (1, 71, root_status),
                (2, 71, root_status),
            ]
        );
    }
}

#[test]
fn independent_process_select_then_await_keeps_failed_rpc_pending() {
    use native_test_support::NativeCallbackOutcome;
    use native_test_support::NativeToolCallback;
    use native_test_support::NativeToolOwner;

    struct SelectThenAwaitRpc {
        selected: Arc<AtomicBool>,
        resumed: Arc<AtomicBool>,
        response: Mutex<Option<oneshot::Sender<i64>>>,
    }
    impl NativeToolCallback<RpcTool> for SelectThenAwaitRpc {
        fn run<'a, G: Guest<RpcTool>>(
            &'a self,
            _: &'a RpcTool,
            guest: &'a mut G,
        ) -> futures::future::BoxFuture<'a, std::result::Result<i64, reverie::Error>> {
            Box::pin(async move {
                assert_eq!(guest.pid(), Pid::from_raw(72));
                let request = pin!(guest.send_rpc((0, 0)));
                let request =
                    match futures::future::select(request, futures::future::ready(73)).await {
                        futures::future::Either::Right((73, request)) => request,
                        _ => panic!("the control must first select the ready alternative"),
                    };
                self.selected.store(true, Ordering::Release);
                if let Some(response) = self.response.lock().unwrap().take() {
                    response.send(37).unwrap();
                }
                // Poll the same losing RPC again before returning to the
                // driver. A failed RPC must stay pending, not resume a completed
                // failure wait or enter its ordinary receive_rpc state.
                let response = request.await;
                self.resumed.store(true, Ordering::Release);
                Ok(response)
            })
        }
    }

    for failed in [true, false] {
        let global = Arc::new(RpcGlobal::default());
        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        *global.response.lock().unwrap() = Some(receiver);
        let owner = NativeToolOwner::new(
            Pid::from_raw(71),
            Arc::new(RpcTool),
            71,
            global.clone(),
            false,
        )
        .unwrap();
        let mut child = owner
            .fork_child(Pid::from_raw(72), Arc::new(RpcTool), 72)
            .unwrap();
        let context = owner.failure_context_for_test();
        let error = failed.then(|| {
            let result: Result<()> = crate::vm::finish_host_worker_outcome(
                Some(&context),
                Pid::from_raw(79),
                Err(Error::InvalidGuestPid(-17)),
                |_| {},
            );
            result.unwrap_err()
        });
        let selected = Arc::new(AtomicBool::new(false));
        let resumed = Arc::new(AtomicBool::new(false));
        let callback = SelectThenAwaitRpc {
            selected: selected.clone(),
            resumed: resumed.clone(),
            response: Mutex::new(if failed { None } else { sender.take() }),
        };
        let outcome = futures::executor::block_on(child.run_callback(&callback));
        assert!(selected.load(Ordering::Acquire));
        assert_eq!(resumed.load(Ordering::Acquire), !failed);
        assert_eq!(global.pending.load(Ordering::Acquire), !failed);
        assert_eq!(global.response.lock().unwrap().is_some(), failed);
        let status;
        if failed {
            assert!(matches!(outcome, Err(Error::RunAborted)));
            let primary = context.run.primary().unwrap();
            let child_error =
                futures::executor::block_on(child.finish(Err(Error::RunAborted))).unwrap_err();
            let root_error =
                futures::executor::block_on(owner.finish(Err(error.unwrap()))).unwrap_err();
            assert!(std::ptr::eq(child_error.primary(), primary.primary()));
            assert!(std::ptr::eq(root_error.primary(), primary.primary()));
            assert_eq!(
                *global.failure_events.lock().unwrap(),
                vec![reverie::BackendFailure {
                    pid: Pid::from_raw(71),
                    tid: Pid::from_raw(79),
                    phase: "host-owned worker",
                }]
            );
            status = 255;
        } else {
            assert!(matches!(
                outcome,
                Ok(NativeCallbackOutcome::Returned(Ok(37)))
            ));
            status = 37;
            assert_eq!(
                futures::executor::block_on(child.finish(Ok(ExitStatus::Exited(status))))
                    .unwrap()
                    .0,
                ExitStatus::Exited(status)
            );
            assert_eq!(
                futures::executor::block_on(owner.finish(Ok(ExitStatus::Exited(status))))
                    .unwrap()
                    .0,
                ExitStatus::Exited(status)
            );
            assert!(context.run.primary().is_none());
            assert!(global.failure_events.lock().unwrap().is_empty());
        }
        assert_eq!(
            *global.events.lock().unwrap(),
            vec![
                (1, 72, status),
                (2, 72, status),
                (1, 71, status),
                (2, 71, status)
            ]
        );
    }
}

struct NativeControlCleanup {
    response: Option<oneshot::Sender<i64>>,
    release: Option<std::sync::mpsc::Sender<()>>,
    owner: Option<std::thread::JoinHandle<()>>,
}

impl NativeControlCleanup {
    fn rescue(&mut self) {
        if let Some(response) = self.response.take() {
            let _ = response.send(99);
        }
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for NativeControlCleanup {
    fn drop(&mut self) {
        self.rescue();
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

#[test]
fn host_owned_returned_error_releases_root_rpc_and_owned_join_with_worker_identity() {
    use native_test_support::NativeCallbackOutcome;
    use native_test_support::NativeToolOwner;
    let global = Arc::new(RpcGlobal::default());
    let (response, receiver) = oneshot::channel();
    *global.response.lock().unwrap() = Some(receiver);
    global.failure_required.store(true, Ordering::Release);
    let (release, release_receiver) = std::sync::mpsc::channel();
    let (completed, result_receiver) = std::sync::mpsc::channel();
    let mut cleanup = NativeControlCleanup {
        response: Some(response),
        release: Some(release),
        owner: None,
    };
    let worker_global = global.clone();
    cleanup.owner = Some(std::thread::spawn(move || {
        let mut owner =
            NativeToolOwner::new(Pid::from_raw(1), Arc::new(RpcTool), 1, worker_global, false)
                .unwrap();
        owner.spawn_host_worker(Pid::from_raw(3), move || {
            release_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("controller did not release the host producer");
            Err(Error::GuestClock("host returned cause".to_owned()))
        });
        let outcome = futures::executor::block_on(owner.run_callback(&NativeRpcCall)).unwrap();
        assert!(
            matches!(outcome, NativeCallbackOutcome::RunFailed),
            "a rescue response is not terminal cancellation"
        );
        let result = futures::executor::block_on(owner.finish(Err(Error::RunAborted)));
        completed.send(result).unwrap();
    }));
    wait_until(|| global.pending.load(Ordering::Acquire));
    assert_eq!(global.failures.load(Ordering::Acquire), 0);
    cleanup.release.take().unwrap().send(()).unwrap();
    let result = result_receiver.recv_timeout(Duration::from_secs(2));
    let completed = result.is_ok();
    if !completed {
        cleanup.rescue();
    }
    cleanup.owner.take().unwrap().join().unwrap();
    assert!(
        completed,
        "host error did not release the actual root driver and owned join"
    );
    let error = result.unwrap().unwrap_err();
    assert!(
        matches!(error.primary(), Error::GuestClock(message) if message == "host returned cause")
    );
    assert_eq!(
        *global.failure_events.lock().unwrap(),
        vec![reverie::BackendFailure {
            pid: Pid::from_raw(1),
            tid: Pid::from_raw(3),
            phase: "host-owned worker",
        }]
    );
    assert_eq!(
        *global.events.lock().unwrap(),
        vec![(1, 1, 255), (2, 1, 255)]
    );
}

#[derive(Clone, Copy)]
enum PostWorkerCase {
    MissingStatus,
    MissingStatusPending,
    CachedError,
    LateFailure,
    Normal,
}

fn post_worker_control(case: PostWorkerCase) {
    use native_test_support::NativeChildCommand;
    use native_test_support::NativeToolOwner;
    let started = matches!(
        case,
        PostWorkerCase::MissingStatus | PostWorkerCase::CachedError
    );
    let global = Arc::new(RpcGlobal::default());
    let (response, receiver) = oneshot::channel();
    *global.response.lock().unwrap() = Some(receiver);
    global
        .failure_required
        .store(!matches!(case, PostWorkerCase::Normal), Ordering::Release);
    let (release, release_receiver) = std::sync::mpsc::channel();
    let (ready, ready_receiver) = std::sync::mpsc::channel();
    let (completed, result_receiver) = std::sync::mpsc::channel();
    let mut cleanup = NativeControlCleanup {
        response: Some(response),
        release: Some(release),
        owner: None,
    };
    let worker_global = global.clone();
    cleanup.owner = Some(std::thread::spawn(move || {
        let mut owner = NativeToolOwner::new(
            Pid::from_raw(1),
            Arc::new(RpcTool),
            1,
            worker_global.clone(),
            false,
        )
        .unwrap();
        let preparation = matches!(
            case,
            PostWorkerCase::MissingStatus | PostWorkerCase::MissingStatusPending
        )
        .then(|| owner.prepare_task(Pid::from_raw(2)).unwrap());
        if matches!(case, PostWorkerCase::CachedError) {
            owner.unreported_worker_for_test(
                Pid::from_raw(2),
                Error::GuestClock("cached worker cause".to_owned()),
            );
        }
        if matches!(case, PostWorkerCase::LateFailure) {
            *worker_global.late_failure.lock().unwrap() = Some(owner.failure_context_for_test());
        }
        let child = owner
            .fork_child(Pid::from_raw(3), Arc::new(RpcTool), 3)
            .unwrap();
        let (gate, commands) = if started {
            owner.spawn_child(child, NativeRpcCall).unwrap()
        } else {
            owner.spawn_child(child, NativeStatusCall).unwrap()
        };
        if started {
            assert!(gate.start().unwrap());
        }
        ready.send((gate, commands)).unwrap();
        release_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("controller did not release owner completion");
        let result = futures::executor::block_on(owner.finish(Ok(ExitStatus::Exited(37))));
        drop(preparation);
        completed.send(result).unwrap();
    }));
    let (gate, commands) = ready_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("owner did not construct descendant");
    if started {
        assert_eq!(
            commands.recv_timeout(Duration::from_secs(2)).unwrap(),
            NativeChildCommand::Start
        );
        wait_until(|| global.pending.load(Ordering::Acquire));
    } else {
        assert!(gate.is_pending());
    }
    assert_eq!(global.failures.load(Ordering::Acquire), 0);
    cleanup.release.take().unwrap().send(()).unwrap();
    let result = result_receiver.recv_timeout(Duration::from_secs(2));
    let completed = result.is_ok();
    if !completed {
        cleanup.rescue();
    }
    cleanup.owner.take().unwrap().join().unwrap();
    assert!(
        completed,
        "post-worker failure joined a descendant before supplying its terminal wake"
    );
    let result = result.unwrap();
    if started {
        assert!(
            cleanup.response.as_ref().unwrap().is_canceled(),
            "the ordinary RPC future must drop before the owned child join returns"
        );
    }
    match case {
        PostWorkerCase::MissingStatus | PostWorkerCase::MissingStatusPending => {
            assert!(
                matches!(result.unwrap_err().primary(), Error::UnexpectedVcpuExit(message) if message == "KVM process has no final task exit status after joining workers")
            );
            assert_eq!(
                global.failure_events.lock().unwrap()[0].phase,
                "process exit status"
            );
            if !started {
                assert_eq!(
                    commands.recv_timeout(Duration::from_secs(2)).unwrap(),
                    NativeChildCommand::Cancel
                );
            }
        }
        PostWorkerCase::CachedError => {
            assert!(
                matches!(result.unwrap_err().primary(), Error::GuestClock(message) if message == "cached worker cause")
            );
            assert_eq!(
                global.failure_events.lock().unwrap().len(),
                1,
                "cached cause was published twice"
            );
            assert_eq!(
                global.failure_events.lock().unwrap()[0],
                reverie::BackendFailure {
                    pid: Pid::from_raw(1),
                    tid: Pid::from_raw(2),
                    phase: "worker teardown",
                }
            );
        }
        PostWorkerCase::LateFailure => {
            assert_eq!(
                commands.recv_timeout(Duration::from_secs(2)).unwrap(),
                NativeChildCommand::Cancel
            );
            assert!(
                matches!(result.unwrap_err().primary(), Error::GuestClock(message) if message == "late independent worker")
            );
        }
        PostWorkerCase::Normal => {
            assert_eq!(
                commands.recv_timeout(Duration::from_secs(2)).unwrap(),
                NativeChildCommand::Start
            );
            assert_eq!(result.unwrap().0, ExitStatus::Exited(37));
            assert_eq!(global.failures.load(Ordering::Acquire), 0);
            assert_eq!(
                *global.events.lock().unwrap(),
                vec![(1, 1, 37), (2, 1, 37), (1, 3, 73), (2, 3, 73)]
            );
        }
    }
}

#[test]
fn missing_final_status_publishes_before_owner_hooks_and_started_descendant_join() {
    post_worker_control(PostWorkerCase::MissingStatus);
}

#[test]
fn missing_final_status_cancels_pending_descendant_gate() {
    post_worker_control(PostWorkerCase::MissingStatusPending);
}

#[test]
fn cached_worker_error_publishes_once_before_started_descendant_join() {
    post_worker_control(PostWorkerCase::CachedError);
}

#[test]
fn terminal_after_local_success_cancels_pending_descendant_gate() {
    post_worker_control(PostWorkerCase::LateFailure);
}

#[test]
fn normal_post_worker_completion_preserves_start_status_and_owner_before_child_hooks() {
    post_worker_control(PostWorkerCase::Normal);
}

type NativeTaskRetirement = (
    Arc<Mutex<crate::elf::TaskLifecycleTable>>,
    reverie::SignalTaskIdentity,
);

#[derive(Default)]
struct NativeSignalGlobal {
    rpc: RpcGlobal,
    control: Mutex<Option<reverie::BackendSignalControl>>,
    installs: AtomicUsize,
    reject: AtomicBool,
    unchanged: AtomicBool,
    retirement: Mutex<Option<NativeTaskRetirement>>,
}

#[reverie::global_tool]
impl GlobalTool for NativeSignalGlobal {
    type Request = (u8, i32);
    type Response = i64;
    type Config = bool;

    fn install_backend_signal_control(
        &self,
        control: Option<reverie::BackendSignalControl>,
    ) -> std::result::Result<reverie::BackendSignalControlMode, reverie::Error> {
        assert_eq!(self.installs.fetch_add(1, Ordering::SeqCst), 0);
        *self.control.lock().unwrap() = Some(control.expect("real root capability required"));
        if let Some((lifecycle, task)) = self.retirement.lock().unwrap().as_ref() {
            assert_eq!(
                lifecycle
                    .lock()
                    .unwrap()
                    .get(task.tid.as_raw())
                    .unwrap()
                    .generation,
                task.task_generation,
                "setup must see the actual live executor"
            );
        }
        if self.reject.load(Ordering::Acquire) {
            Err(Errno::EACCES.into())
        } else if self.unchanged.load(Ordering::Acquire) {
            Ok(reverie::BackendSignalControlMode::Unchanged)
        } else {
            Ok(reverie::BackendSignalControlMode::ToolControlled)
        }
    }

    async fn receive_rpc(&self, from: Pid, request: (u8, i32)) -> i64 {
        if let Some((lifecycle, task)) = self.retirement.lock().unwrap().as_ref() {
            assert!(
                lifecycle.lock().unwrap().get(task.tid.as_raw()).is_none(),
                "rejected setup must retire before either consuming hook"
            );
        }
        self.rpc.receive_rpc(from, request).await
    }

    fn report_backend_failure(&self, event: reverie::BackendFailure) {
        self.rpc.report_backend_failure(event);
    }
}

#[derive(Default)]
struct NativeSignalTool {
    drops: Arc<AtomicUsize>,
}

impl Drop for NativeSignalTool {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[reverie::tool]
impl Tool for NativeSignalTool {
    type GlobalState = NativeSignalGlobal;
    type ThreadState = Box<i32>;

    async fn on_exit_thread<G: GlobalRPC<NativeSignalGlobal>>(
        &self,
        tid: Pid,
        global: &G,
        state: Box<i32>,
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        assert_eq!(*state, tid.as_raw());
        global.send_rpc((1, conventional_exit_code(status))).await;
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<NativeSignalGlobal>>(
        self,
        _: Pid,
        global: &G,
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        global.send_rpc((2, conventional_exit_code(status))).await;
        Ok(())
    }
}

struct NativeSignalCall {
    global: Arc<NativeSignalGlobal>,
    observations: Mutex<Vec<reverie::SignalTaskIdentity>>,
}

impl native_test_support::NativeToolCallback<NativeSignalTool> for NativeSignalCall {
    fn run<'a, G: Guest<NativeSignalTool>>(
        &'a self,
        _: &'a NativeSignalTool,
        guest: &'a mut G,
    ) -> futures::future::BoxFuture<'a, std::result::Result<i64, reverie::Error>> {
        Box::pin(async move {
            assert_eq!(self.global.installs.load(Ordering::Acquire), 1);
            let task = guest
                .signal_task_identity()
                .expect("real executor identity required");
            assert_eq!(task.tid, guest.tid());
            assert_eq!(task.process.tgid, guest.pid());
            let control = self
                .global
                .control
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .clone();
            let mut observations = self.observations.lock().unwrap();
            let permit = reverie::SignalDeliveryPermit {
                task,
                sequence: observations.len() as u64 + 1,
                site: None,
            };
            // The root-installed facade must recognize the actual generation,
            // including the subsequently constructed fork's registry entry.
            control.process.reserve_delivery(permit).unwrap();
            control.process.release_delivery(permit).unwrap();
            observations.push(task);
            Ok(37)
        })
    }
}

#[test]
fn native_signal_identity_and_root_installation_follow_owned_executor_and_fork() {
    use native_test_support::NativeCallbackOutcome;
    use native_test_support::NativeToolOwner;

    for unchanged in [false, true] {
        let global = Arc::new(NativeSignalGlobal::default());
        global.unchanged.store(unchanged, Ordering::Release);
        let drops = Arc::new(AtomicUsize::new(0));
        let tool = || {
            Arc::new(NativeSignalTool {
                drops: drops.clone(),
            })
        };
        let mut parent = NativeToolOwner::new(
            Pid::from_raw(71),
            tool(),
            Box::new(71),
            global.clone(),
            false,
        )
        .unwrap();
        let (root_identity, controlled) = parent.signal_state_for_test();
        assert_eq!(controlled, !unchanged);
        let callback = NativeSignalCall {
            global: global.clone(),
            observations: Mutex::new(Vec::new()),
        };
        for _ in 0..2 {
            assert!(matches!(
                futures::executor::block_on(parent.run_callback(&callback)).unwrap(),
                NativeCallbackOutcome::Returned(Ok(37))
            ));
        }
        let mut child = parent
            .fork_child(Pid::from_raw(72), tool(), Box::new(72))
            .unwrap();
        let (child_identity, child_controlled) = child.signal_state_for_test();
        assert_eq!(child_controlled, !unchanged);
        assert!(matches!(
            futures::executor::block_on(child.run_callback(&callback)).unwrap(),
            NativeCallbackOutcome::Returned(Ok(37))
        ));
        let root_identity = root_identity.unwrap();
        let child_identity = child_identity.unwrap();
        assert_ne!(
            root_identity.process.generation,
            child_identity.process.generation
        );
        assert_ne!(
            root_identity.task_generation,
            child_identity.task_generation
        );
        assert_eq!(
            *callback.observations.lock().unwrap(),
            vec![root_identity, root_identity, child_identity]
        );
        assert_eq!(global.installs.load(Ordering::Acquire), 1);
        for owner in [child, parent] {
            assert_eq!(
                futures::executor::block_on(owner.finish(Ok(ExitStatus::Exited(37))))
                    .unwrap()
                    .0,
                ExitStatus::Exited(37)
            );
        }
        assert_eq!(drops.load(Ordering::Acquire), 2);
        assert_eq!(
            *global.rpc.events.lock().unwrap(),
            vec![(1, 72, 37), (2, 72, 37), (1, 71, 37), (2, 71, 37)]
        );
        assert_eq!(global.rpc.failures.load(Ordering::Acquire), 0);
    }
}

#[test]
fn native_signal_setup_refusal_retires_before_hooks_and_preserves_original_cause() {
    use native_test_support::NativeToolOwner;

    // Exercise the public constructor as well as its identical post-allocation
    // path with an independently retained actual lifecycle table.
    for (observe_lifecycle, nested) in [(false, false), (true, false), (false, true), (true, true)]
    {
        let global = Arc::new(NativeSignalGlobal::default());
        global.reject.store(true, Ordering::Release);
        global.rpc.failure_required.store(true, Ordering::Release);
        let drops = Arc::new(AtomicUsize::new(0));
        let tool = Arc::new(NativeSignalTool {
            drops: drops.clone(),
        });
        let pid = Pid::from_raw(1);
        let construct = || {
            if observe_lifecycle {
                let state = crate::executor::native_loaded_state(&std::env::current_dir().unwrap());
                let lifecycle = state.task_lifecycle.clone();
                let executor = ElfExecutor::with_output(state, None);
                let identity = executor.signal_task_identity().unwrap();
                *global.retirement.lock().unwrap() = Some((lifecycle, identity));
                let failure = FailureContext::new(RunFailure::new(&global), pid, pid);
                NativeToolOwner::from_executor(
                    executor,
                    pid,
                    tool,
                    Box::new(1),
                    global.clone(),
                    false,
                    failure,
                )
            } else {
                NativeToolOwner::new(pid, tool, Box::new(1), global.clone(), false)
            }
        };
        let result = if nested {
            futures::executor::block_on(async move { construct() })
        } else {
            construct()
        };
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("rejected installation returned a callback-capable owner"),
        };
        assert!(
            matches!(error.primary(), Error::Reverie(reverie::Error::Errno(errno)) if *errno == Errno::EACCES)
        );
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(global.installs.load(Ordering::Acquire), 1);
        assert_eq!(
            *global.rpc.events.lock().unwrap(),
            vec![(1, 1, 255), (2, 1, 255)]
        );
        assert_eq!(
            *global.rpc.failure_events.lock().unwrap(),
            vec![reverie::BackendFailure {
                pid,
                tid: pid,
                phase: "process signal control installation",
            }]
        );
        if let Some((lifecycle, identity)) = global.retirement.lock().unwrap().as_ref() {
            assert!(
                lifecycle
                    .lock()
                    .unwrap()
                    .get(identity.tid.as_raw())
                    .is_none()
            );
            let control = global.control.lock().unwrap().as_ref().unwrap().clone();
            assert_eq!(
                control.process.alarm_recipients(identity.process),
                Err(Errno::ESRCH),
                "no executor registry remains after refusal"
            );
        }
    }
}

#[test]
fn native_signal_cleanup_completion_preserves_inline_wake_and_nested_entry() {
    let polls = AtomicUsize::new(0);
    let mut retained_waker = None;
    let result = futures::executor::block_on(async {
        native_test_support::complete_native_cleanup(poll_fn(|context| {
            match polls.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    retained_waker = Some(context.waker().clone());
                    // Wake during poll, before the helper can wait. Duplicate
                    // wakeups may coalesce, but must not lose the pending wake.
                    context.waker().wake_by_ref();
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
                1 => Poll::Ready(37),
                _ => panic!("completed native cleanup was polled again"),
            }
        }))
    });
    assert_eq!(result, 37);
    assert_eq!(polls.load(Ordering::Acquire), 2);
    // The Arc-owned wake state remains valid after the future has completed.
    retained_waker.unwrap().wake_by_ref();
    assert_eq!(polls.load(Ordering::Acquire), 2);

    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_ready = ready.clone();
    let (send_waker, receive_waker) = std::sync::mpsc::channel::<std::task::Waker>();
    let worker = std::thread::spawn(move || {
        let waker = receive_waker.recv().unwrap();
        worker_ready.store(true, Ordering::Release);
        // Exercise owned Wake from another thread, without relying on where
        // the polling thread is scheduled relative to its condvar wait.
        waker.wake();
    });
    let mut sent = false;
    let result = futures::executor::block_on(async {
        native_test_support::complete_native_cleanup(poll_fn(|context| {
            if !sent {
                sent = true;
                send_waker.send(context.waker().clone()).unwrap();
                return Poll::Pending;
            }
            if ready.load(Ordering::Acquire) {
                Poll::Ready(37)
            } else {
                Poll::Pending
            }
        }))
    });
    worker.join().unwrap();
    assert_eq!(result, 37);
    assert!(ready.load(Ordering::Acquire));
}
