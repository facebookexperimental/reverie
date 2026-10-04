/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Native controls for the real Tool callback driver and post-worker finisher.
//!
//! No VM or guest instruction is created. Executor task retirement precedes
//! the shared production finisher; this does not qualify initialized-VM setup,
//! backend transport release, or guest execution.

use futures::future::BoxFuture;

use super::*;
use crate::executor::ChildCompletionSlot;
use crate::executor::ChildStartCommand;
use crate::executor::ChildThread;
use crate::vm::GuestThreadGroup;

/// Install and validate the process-wide KVM entry signal handler once.
///
/// The reservation remains installed for this process. This control exists so
/// integration tests can exercise the production, non-`cfg(test)` handler.
#[cfg(feature = "native-test-support")]
pub fn check_reserved_entry_signal_handler() -> Result<()> {
    crate::entry::check_reserved_signal_handler()
}

/// A callback expressed against the abstract Guest interface, including Tools
/// whose concrete global request type is private to another crate.
pub trait NativeToolCallback<T: Tool>: Send + Sync {
    /// Run one actual Tool operation against the production KvmGuest.
    fn run<'a, G: Guest<T>>(
        &'a self,
        tool: &'a T,
        guest: &'a mut G,
    ) -> BoxFuture<'a, std::result::Result<i64, reverie::Error>>;
}

/// Observation from the production callback driver.
pub enum NativeCallbackOutcome {
    /// The Tool callback returned its original result.
    Returned(std::result::Result<i64, reverie::Error>),
    /// The driver's failure subscription won before accepting the callback.
    RunFailed,
}

/// The command received from an actual production child gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeChildCommand {
    /// Normal admission permits the child callback.
    Start,
    /// Cancellation consumes the constructed child without starting it.
    Cancel,
}

/// A clone of a production child gate retained for ordering assertions.
#[derive(Clone)]
pub struct NativeChildGate(ChildStartGate);

impl NativeChildGate {
    /// Resolve the gate normally, using the production one-shot Start operation.
    pub fn start(&self) -> Result<bool> {
        self.0
            .start()
            .map_err(|_| Error::UnexpectedVcpuExit("native child lost its start gate".to_owned()))
    }

    /// Whether neither Start nor Cancel has committed.
    pub fn is_pending(&self) -> bool {
        self.0.is_pending()
    }
}

struct NoInstructions<'a> {
    executor: &'a ElfExecutor,
    failure: FailureContext,
}
impl<T: Tool> GuestSyscallExecutor<T> for NoInstructions<'_> {
    fn parent_pid(&self) -> Option<Pid> {
        self.executor.parent_pid()
    }
    fn signal_task_identity(&self) -> Option<reverie::SignalTaskIdentity> {
        self.executor.signal_task_identity()
    }
    fn failure_subscription(&self) -> Option<crate::failure::FailureSubscription> {
        Some(self.failure.run.subscribe())
    }
    fn read_clock(&self) -> Result<u64> {
        panic!("native Tool control must disable guest clock operations")
    }
    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("native Tool control must not inject a guest instruction")
    }
}

// Complete this synchronous preparation cleanup without entering LocalPool:
// the caller may already be polling on one. This polls only the supplied
// future; tasks that need the suspended caller's executor cannot make progress.
pub(super) fn complete_native_cleanup<F: Future>(future: F) -> F::Output {
    struct Notify {
        notified: Mutex<bool>,
        changed: std::sync::Condvar,
    }

    impl std::task::Wake for Notify {
        fn wake(self: Arc<Self>) {
            std::task::Wake::wake_by_ref(&self);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            *self.notified.lock().unwrap() = true;
            self.changed.notify_one();
        }
    }

    let notify = Arc::new(Notify {
        notified: Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let waker = std::task::Waker::from(notify.clone());
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        // Poll without the wake lock: a future may wake inline before Pending.
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
        let mut notified = notify.notified.lock().unwrap();
        while !*notified {
            notified = notify.changed.wait(notified).unwrap();
        }
        *notified = false;
    }
}

/// An actual executor lifecycle preparation kept alive by a native control.
/// Dropping it uses ElfExecutor's ordinary exact-generation retirement.
pub struct NativeTaskPreparation {
    _executor: ElfExecutor,
}

/// Owns real Tool state, executor lifecycle, OS child handles and start gates.
pub struct NativeToolOwner<T: Tool> {
    executor: Option<ElfExecutor>,
    tool: Option<Arc<T>>,
    thread: Option<T::ThreadState>,
    identity: (Pid, Pid),
    global: Arc<T::GlobalState>,
    config: <T::GlobalState as GlobalTool>::Config,
    failure: FailureContext,
    workers: Arc<GuestThreadGroup>,
    starts: SharedChildStarts,
}

impl<T> NativeToolOwner<T>
where
    T: Tool + 'static,
    T::GlobalState: 'static,
    T::ThreadState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    /// Construct an executor fixture around caller-owned real Tool state.
    pub fn new(
        pid: Pid,
        tool: Arc<T>,
        thread: T::ThreadState,
        global: Arc<T::GlobalState>,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<Self> {
        let failure = FailureContext::new(RunFailure::new(&global), pid, pid);
        let cwd = match std::env::current_dir() {
            Ok(cwd) => cwd,
            Err(error) => {
                return Err(consume_failed_preparation(
                    tool,
                    thread,
                    pid,
                    global.as_ref(),
                    &config,
                    &failure,
                    Error::HostIo(error),
                ));
            }
        };
        let mut state = crate::executor::native_loaded_state(&cwd);
        state.pid = pid.as_raw();
        state.tid = pid.as_raw();
        state.pgid = pid.as_raw();
        state.task_lifecycle = Arc::new(Mutex::new(crate::elf::TaskLifecycleTable::with_root(
            pid.as_raw(),
            pid.as_raw(),
            pid.as_raw(),
            true,
        )));
        Self::from_executor(
            ElfExecutor::with_output(state, None),
            pid,
            tool,
            thread,
            global,
            config,
            failure,
        )
    }

    // Keep the post-allocation path shared with controls that retain the actual
    // lifecycle table to observe retirement during a rejected installation.
    pub(super) fn from_executor(
        executor: ElfExecutor,
        pid: Pid,
        tool: Arc<T>,
        thread: T::ThreadState,
        global: Arc<T::GlobalState>,
        config: <T::GlobalState as GlobalTool>::Config,
        failure: FailureContext,
    ) -> Result<Self> {
        let owner = Self {
            executor: Some(executor),
            tool: Some(tool),
            thread: Some(thread),
            identity: (pid, pid),
            global,
            config,
            failure,
            workers: Arc::new(GuestThreadGroup::default()),
            starts: Arc::new(Mutex::new(Vec::new())),
        };
        // Like the installed-ELF path, install once for the run before its
        // first callback. fork_child shares this registry and does not reinstall.
        // The caller has already constructed Tool/thread state in this native API.
        let mode = match owner.global.install_backend_signal_control(Some(
            owner.executor.as_ref().unwrap().backend_signal_control(),
        )) {
            Ok(mode) => mode,
            Err(error) => {
                let error = owner
                    .failure
                    .publish("process signal control installation", Error::Reverie(error));
                // This path owns an executor, unlike the earlier cwd refusal.
                // Retire it before consuming hooks, retaining the setup cause.
                return match complete_native_cleanup(owner.finish(Err(error))) {
                    Err(error) => Err(error),
                    Ok(_) => unreachable!("a refused signal installation cannot succeed"),
                };
            }
        };
        owner
            .executor
            .as_ref()
            .unwrap()
            .install_signal_control(mode, &owner.failure.run);
        Ok(owner)
    }

    /// Borrow the actual owned thread state when constructing a child's state.
    #[cfg(feature = "native-test-support")]
    pub fn thread_state(&self) -> &T::ThreadState {
        self.thread
            .as_ref()
            .expect("native thread already consumed")
    }

    /// Update the owned parent state before the Tool constructs a clone child.
    #[cfg(feature = "native-test-support")]
    pub fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.thread
            .as_mut()
            .expect("native thread already consumed")
    }

    /// Create a real fork lifecycle sharing this run's failure subscription.
    pub fn fork_child(&self, pid: Pid, tool: Arc<T>, thread: T::ThreadState) -> Result<Self> {
        let failure = self.failure.for_process(pid);
        let executor = match self
            .executor
            .as_ref()
            .unwrap()
            .fork_child(pid.as_raw(), false, false)
        {
            Ok(executor) => executor,
            Err(error) => {
                return Err(consume_failed_preparation(
                    tool,
                    thread,
                    pid,
                    self.global.as_ref(),
                    &self.config,
                    &failure,
                    error,
                ));
            }
        };
        Ok(Self {
            executor: Some(executor),
            tool: Some(tool),
            thread: Some(thread),
            identity: (pid, pid),
            global: self.global.clone(),
            config: self.config.clone(),
            failure,
            workers: Arc::new(GuestThreadGroup::default()),
            starts: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Keep an actual task preparation live to exercise missing final status.
    pub fn prepare_task(&self, tid: Pid) -> Result<NativeTaskPreparation> {
        Ok(NativeTaskPreparation {
            _executor: self.executor.as_ref().unwrap().thread_child(tid.as_raw())?,
        })
    }

    /// Poll an actual KvmGuest callback through the production failure-aware driver.
    pub async fn run_callback<C: NativeToolCallback<T>>(
        &mut self,
        callback: &C,
    ) -> Result<NativeCallbackOutcome> {
        let signal = Arc::new(Mutex::new(None));
        let memory = GuestMemory::new(0, STACK_CAPACITY)?;
        let subscriptions = Subscription::none();
        let mut executor = NoInstructions {
            executor: self.executor.as_ref().unwrap(),
            failure: self.failure.clone(),
        };
        let failure_subscription = self
            .failure
            .driver_subscription(self.executor.as_ref().unwrap().is_traced_tree_root());
        let mut guest = KvmGuest::new(
            self.identity.0,
            self.identity.1,
            self.tool.as_ref().unwrap().clone(),
            memory,
            &[],
            // No instruction executes; operations requiring real registers are outside this seam.
            unsafe { std::mem::zeroed() },
            self.thread.as_mut().unwrap(),
            &mut executor,
            self.global.as_ref(),
            Some(self.global.clone()),
            &self.config,
            &subscriptions,
            signal.clone(),
            self.starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        match drive_handler(
            callback.run(self.tool.as_ref().unwrap().as_ref(), &mut guest),
            signal,
            self.starts.clone(),
            wait_for_failure(self.global.as_ref(), Some(failure_subscription)),
        )
        .await
        {
            HandlerOutcome::Returned(result) => Ok(NativeCallbackOutcome::Returned(result)),
            HandlerOutcome::RunFailed => Ok(NativeCallbackOutcome::RunFailed),
            HandlerOutcome::RuntimeError(error) => Err(error),
            _ => Err(Error::UnexpectedVcpuExit(
                "native callback requested guest execution or signal delivery".to_owned(),
            )),
        }
    }

    /// Attach an OS fork child at the same gate and owned join used in production.
    /// The Cancel arm never invokes the supplied child callback.
    pub fn spawn_child<C: NativeToolCallback<T> + 'static>(
        &mut self,
        child: Self,
        callback: C,
    ) -> Result<(
        NativeChildGate,
        std::sync::mpsc::Receiver<NativeChildCommand>,
    )> {
        let pid = child.identity.0.as_raw();
        let (sender, receiver) = std::sync::mpsc::channel();
        let gate = ChildStartGate::new(sender);
        let completion = Arc::new(ChildCompletionSlot::default());
        let child_completion = completion.clone();
        let (observed, observations) = std::sync::mpsc::channel();
        let handle =
            ChildThread::spawn_owned(std::thread::Builder::new(), child, move |mut child| {
                let outcome = match receiver.recv() {
                    Ok(
                        command @ (ChildStartCommand::Cancel
                        | ChildStartCommand::CancelAfterFailure),
                    ) => {
                        let _ = observed.send(NativeChildCommand::Cancel);
                        if let Some(failure) = command.failure() {
                            child.retire(Err(failure))
                        } else {
                            Ok(ToolProcessExit {
                                exit: child.executor.as_mut().unwrap().cancel_current_thread(),
                                disposition: ToolExitDisposition::ExplicitCancellation,
                            })
                        }
                    }
                    Ok(ChildStartCommand::Start) => {
                        let _ = observed.send(NativeChildCommand::Start);
                        let result =
                            match futures::executor::block_on(child.run_callback(&callback)) {
                                Ok(NativeCallbackOutcome::Returned(result)) => result
                                    .map(|code| ExitStatus::Exited(code as i32))
                                    .map_err(Error::Reverie),
                                Ok(NativeCallbackOutcome::RunFailed) => Err(Error::RunAborted),
                                Err(error) => Err(error),
                            };
                        child.retire(result)
                    }
                    Err(_) => child.retire(Err(Error::UnexpectedVcpuExit(
                        "native child lost parent".to_owned(),
                    ))),
                };
                let wait_context = child
                    .executor
                    .as_ref()
                    .unwrap()
                    .fixture_child_wait_context();
                let result = futures::executor::block_on(child.finish_retired(outcome, Ok(())));
                if let Ok((status, _, _)) = &result {
                    // No output is captured by this native fixture.
                    wait_context.publish_fixture_owner(*status, &child_completion)?;
                }
                result.map(|_| ())
            });
        let handle = match handle {
            Ok(handle) => handle,
            Err((error, mut child)) => {
                let outcome = child.retire(Err(Error::HostIo(error)));
                return match futures::executor::block_on(child.finish_retired(outcome, Ok(()))) {
                    Err(error) => Err(error),
                    Ok(_) => unreachable!("a refused spawn cannot complete successfully"),
                };
            }
        };
        self.executor
            .as_mut()
            .unwrap()
            .register_child_process_with_gate(pid, gate.clone(), completion, handle);
        self.starts
            .lock()
            .unwrap()
            .push(PendingChildStart::fork_process(pid, gate.clone()));
        Ok((NativeChildGate(gate), observations))
    }

    /// Attach a host worker whose returned result crosses the actual publication-before-retirement boundary.
    pub fn spawn_host_worker(
        &mut self,
        tid: Pid,
        work: impl FnOnce() -> Result<()> + Send + 'static,
    ) {
        let failure = self.failure.clone();
        let group = self.workers.clone();
        let handle = std::thread::spawn(move || {
            crate::vm::finish_host_worker_outcome(Some(&failure), tid, work(), |failed| {
                if failed {
                    group.record_worker_failure(tid.as_raw());
                }
            })
            .map(|()| (ExitStatus::Exited(0), Vec::new(), Vec::new()))
        });
        self.workers.add_worker_handle(tid.as_raw(), handle);
    }

    #[cfg(test)]
    pub(super) fn unreported_worker_for_test(&mut self, tid: Pid, error: Error) {
        self.workers
            .add_worker_handle(tid.as_raw(), std::thread::spawn(move || Err(error)));
    }

    #[cfg(test)]
    pub(super) fn failure_context_for_test(&self) -> FailureContext {
        self.failure.clone()
    }

    #[cfg(test)]
    pub(super) fn signal_state_for_test(&self) -> (Option<reverie::SignalTaskIdentity>, bool) {
        let executor = self.executor.as_ref().unwrap();
        (
            executor.signal_task_identity(),
            executor.signal_controlled(),
        )
    }

    fn retire(&mut self, result: Result<ExitStatus>) -> Result<ToolProcessExit> {
        match result {
            Ok(status) => Ok(self
                .executor
                .as_mut()
                .unwrap()
                .retire_current_thread(status, false)
                .into()),
            Err(error) => {
                let error = self.failure.publish("execution", error);
                self.executor.as_mut().unwrap().retire_failed_thread();
                Err(error)
            }
        }
    }

    /// Retire the native task, join its owned host workers, then call the shared production finisher.
    pub async fn finish(
        mut self,
        result: Result<ExitStatus>,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let outcome = self.retire(result);
        self.workers.join_workers();
        let workers = self.workers.teardown_result();
        let failure = self.failure.run.clone();
        let result = self.finish_retired(outcome, workers).await;
        failure.complete(result)
    }

    async fn finish_retired(
        mut self,
        outcome: Result<ToolProcessExit>,
        workers: Result<()>,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let mut executor = self.executor.take().unwrap();
        let tool = self.tool.take().unwrap();
        let thread = self.thread.take().unwrap();
        finish_tool_process_after_workers(
            &mut executor,
            tool,
            self.identity,
            self.global.as_ref(),
            &self.config,
            thread,
            outcome,
            None,
            workers,
            Some(&self.failure),
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
fn consume_failed_preparation<T: Tool>(
    tool: Arc<T>,
    thread: T::ThreadState,
    pid: Pid,
    global: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    failure: &FailureContext,
    error: Error,
) -> Error {
    let error = failure.publish("native owner preparation", error);
    let cleanup = futures::executor::block_on(notify_tool_exit(
        tool,
        pid,
        pid,
        global,
        config,
        thread,
        ToolExit {
            status: ExitStatus::Exited(255),
            process_exited: true,
        },
        Some(failure),
    ));
    error.with_cleanup(cleanup.err().into_iter().collect())
}

impl<T: Tool> Drop for NativeToolOwner<T> {
    fn drop(&mut self) {
        let (Some(mut executor), Some(tool), Some(thread)) =
            (self.executor.take(), self.tool.take(), self.thread.take())
        else {
            return;
        };
        // A failed test precondition must not detach a live gated/RPC child.
        // This rescue is fatal and cannot supply the requested success result.
        let error = self.failure.publish(
            "native control abandoned owner",
            Error::UnexpectedVcpuExit(
                "native control abandoned an unconsumed Tool owner".to_owned(),
            ),
        );
        executor.retire_failed_thread();
        for start in self.starts.lock().unwrap().drain(..) {
            start.cancel_after_failure();
        }
        self.workers.join_workers();
        let workers = self.workers.teardown_result();
        let _ = futures::executor::block_on(finish_tool_process_after_workers(
            &mut executor,
            tool,
            self.identity,
            self.global.as_ref(),
            &self.config,
            thread,
            Err(error),
            None,
            workers,
            Some(&self.failure),
        ));
    }
}
