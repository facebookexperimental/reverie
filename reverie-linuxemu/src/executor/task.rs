/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Task and process lifecycle: clone, fork, exec, exit, child processes and run reaping (gVisor: pkg/sentry/kernel/task_clone.go, task_exec.go, task_exit.go, thread_group.go).

use super::*;

/// Private authority staged by the first original-call preflight. The guest
/// pathname may change afterward, but this exact callback never resolves it
/// again. Retain the consumed tombstone until the next callback so neither
/// repeated preflight nor a second injection can resurrect it.
pub(super) struct ParentDeathExecSnapshot {
    pub(super) site: reverie::CallbackSignalSite,
    pub(super) original: SyscallRequest,
    pub(super) alias: Vec<u8>,
    pub(super) file: Arc<std::fs::File>,
    pub(super) image: Arc<[u8]>,
    pub(super) consumed: bool,
}

/// Keeps one exact process-generation registry binding alive without exposing
/// its backend-private representation.
pub struct ProcessSignalBindingGuard {
    pub(super) _binding: Arc<ProcessBinding>,
}

pub(crate) type UnstartedToolCleanup =
    Pin<Box<dyn Future<Output = crate::Result<()>> + Send + 'static>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildStartCommand {
    Start,
    Cancel,
    /// Consuming cleanup after the run's terminal transition, not an ordinary
    /// successful cancellation or permission to execute the child.
    CancelAfterFailure,
}

impl ChildStartCommand {
    pub fn failure(self) -> Option<crate::Error> {
        matches!(self, Self::CancelAfterFailure).then_some(crate::Error::RunAborted)
    }
}

#[derive(Clone)]
pub struct ChildStartGate {
    pub(super) state: Arc<Mutex<ChildStartGateState>>,
}

pub(super) enum ChildStartGateState {
    Pending(std::sync::mpsc::Sender<ChildStartCommand>),
    Started,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildStartCancellation {
    NewlyCancelled { delivery_failed: bool },
    AlreadyStarted,
    AlreadyCancelled,
}

impl ChildStartGate {
    pub fn new(start: std::sync::mpsc::Sender<ChildStartCommand>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ChildStartGateState::Pending(start))),
        }
    }

    /// Starts the child exactly once. `Ok(false)` means the gate was already
    /// resolved as Started or Cancelled; a started child may since have been
    /// completed and collected.
    pub fn start(&self) -> std::result::Result<bool, std::sync::mpsc::SendError<()>> {
        let mut state = self.state.lock().expect("KVM child-start gate poisoned");
        match &*state {
            ChildStartGateState::Pending(start) => {
                start
                    .send(ChildStartCommand::Start)
                    .map_err(|_| std::sync::mpsc::SendError(()))?;
                *state = ChildStartGateState::Started;
                Ok(true)
            }
            ChildStartGateState::Started => Ok(false),
            ChildStartGateState::Cancelled => Ok(false),
        }
    }

    /// Cancels the child exactly once. A failed send is retained in the
    /// result while the Cancelled state still lets cleanup remove and join the
    /// exact registered child.
    pub fn cancel(&self) -> ChildStartCancellation {
        self.cancel_with_command(ChildStartCommand::Cancel)
    }

    pub fn cancel_after_failure(&self) -> ChildStartCancellation {
        self.cancel_with_command(ChildStartCommand::CancelAfterFailure)
    }

    fn cancel_with_command(&self, command: ChildStartCommand) -> ChildStartCancellation {
        let mut state = self.state.lock().expect("KVM child-start gate poisoned");
        match &*state {
            ChildStartGateState::Pending(start) => {
                let delivery_failed = start.send(command).is_err();
                *state = ChildStartGateState::Cancelled;
                ChildStartCancellation::NewlyCancelled { delivery_failed }
            }
            ChildStartGateState::Started => ChildStartCancellation::AlreadyStarted,
            ChildStartGateState::Cancelled => ChildStartCancellation::AlreadyCancelled,
        }
    }

    pub fn same_gate(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    pub fn is_pending(&self) -> bool {
        matches!(
            *self.state.lock().expect("KVM child-start gate poisoned"),
            ChildStartGateState::Pending(_)
        )
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(
            *self.state.lock().expect("KVM child-start gate poisoned"),
            ChildStartGateState::Cancelled
        )
    }
}

#[derive(Default)]
pub(super) struct OwnedChildProcesses {
    pub(super) pending: std::collections::BTreeMap<i32, PendingProcess>,
    pub(super) completed: Vec<ChildProcessHandle>,
}

pub(super) struct PendingProcess {
    pub(super) child: Option<reverie::SignalProcessId>,
    pub(super) start: ChildStartGate,
    pub(super) completion: Arc<ChildCompletionSlot>,
    pub(super) handle: ChildProcessHandle,
}

/// Shared only by one concrete fork owner and its physical join handle.
/// A nonblocking wait or transfer to the leader keeps the same owner intact.
pub struct ChildProcessPanicOwner {
    pub(super) run: Arc<crate::failure::RunFailure>,
    pub(super) error: Mutex<Option<Arc<crate::Error>>>,
}

impl ChildProcessPanicOwner {
    pub fn new(run: Arc<crate::failure::RunFailure>) -> Arc<Self> {
        Arc::new(Self {
            run,
            error: Mutex::new(None),
        })
    }

    pub fn record(&self, error: Arc<crate::Error>) {
        let previous = {
            self.error
                .lock()
                .expect("KVM child panic owner lock poisoned")
                .replace(error)
        };
        assert!(previous.is_none(), "KVM child panic cause recorded twice");
    }

    fn retain_joined(&self, payload: crate::failure::owned_future::PanicPayload) -> crate::Error {
        let error = {
            self.error
                .lock()
                .expect("KVM child panic owner lock poisoned")
                .clone()
        }
        .unwrap_or_else(|| Arc::new(crate::Error::GuestWorkerPanic));
        // The exact joined allocation is transferred after releasing the
        // per-child guard. Completion deduplicates this same diagnostic Arc.
        self.run
            .retain_panic_cleanup(crate::Error::SharedFailure(error.clone()), vec![payload]);
        crate::Error::SharedFailure(error)
    }
}

/// How an exiting owner waits for its children's host threads.
#[derive(Clone, Copy)]
pub(super) enum ChildJoin {
    Blocking,
    Suspending,
}

impl ChildJoin {
    /// Reaps `thread` in place, so an owner whose future is dropped while this
    /// waits still holds the unreaped handle, as at any other await point.
    async fn reap(self, thread: &mut ChildThread) -> std::thread::Result<crate::Result<()>> {
        match self {
            Self::Blocking => thread.join_blocking(),
            Self::Suspending => std::future::poll_fn(|cx| thread.poll_reap(cx)).await,
        }
    }
}

/// What a child's closure leaves for its joiner when it returns or unwinds.
#[derive(Default)]
pub(super) struct ChildThreadExit {
    pub(super) result: Mutex<Option<std::thread::Result<crate::Result<()>>>>,
    pub(super) waker: futures::task::AtomicWaker,
}

/// A child process's host thread. Its closure publishes its result and wakes
/// the joiner, but thread-local destructors and pthread teardown still follow,
/// and embedder code may run in them. So the joiner reaps the pthread only
/// once it has terminated, without ever blocking the joining executor.
pub struct ChildThread {
    // The unique owner of a joinable pthread until it is joined or detached.
    pub(super) pthread: Option<libc::pthread_t>,
    pub(super) exit: Arc<ChildThreadExit>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) id: std::thread::ThreadId,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) join_observed: bool,
    // Blocking joins that report a broken join, as `joined` would for an
    // impossible status, before one is attempted.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) failed_joins: usize,
}

impl ChildThread {
    /// Spawns like [`crate::failure::spawn_owned`], returning the child state
    /// if the OS refuses the thread.
    pub fn spawn_owned<S, F>(
        builder: std::thread::Builder,
        state: S,
        run: F,
    ) -> std::result::Result<Self, (std::io::Error, S)>
    where
        S: Send + 'static,
        F: FnOnce(S) -> crate::Result<()> + Send + 'static,
    {
        let exit = Arc::new(ChildThreadExit::default());
        match crate::failure::spawn_owned(builder, (state, exit.clone()), |(state, exit)| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(state)));
            *exit
                .result
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
            exit.waker.wake();
        }) {
            Ok(handle) => {
                #[cfg(any(test, feature = "test-support"))]
                let id = handle.thread().id();
                Ok(Self {
                    pthread: Some(std::os::unix::thread::JoinHandleExt::into_pthread_t(handle)),
                    exit,
                    #[cfg(any(test, feature = "test-support"))]
                    id,
                    #[cfg(any(test, feature = "test-support"))]
                    join_observed: false,
                    #[cfg(any(test, feature = "test-support"))]
                    failed_joins: 0,
                })
            }
            Err((error, (state, _))) => Err((error, state)),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn spawn(run: impl FnOnce() -> crate::Result<()> + Send + 'static) -> Self {
        match Self::spawn_owned(std::thread::Builder::new(), (), move |()| run()) {
            Ok(thread) => thread,
            Err((error, ())) => panic!("failed to spawn KVM child test thread: {error}"),
        }
    }

    fn observe_join(&mut self, returned: bool) {
        #[cfg(any(test, feature = "test-support"))]
        if returned || !std::mem::replace(&mut self.join_observed, true) {
            crate::entry::driver::test_observation::join(self.id, true, returned);
        }
        #[cfg(not(any(test, feature = "test-support")))]
        let _ = returned;
    }

    /// Accounts for one join attempt that did not report EBUSY. Only status 0
    /// proves the thread terminated and released its pthread. Every other
    /// status is impossible for this handle: it was created joinable, only
    /// Drop detaches it, `&mut self` excludes a concurrent join, the pthread is
    /// released only after status 0 (so never joined twice, ESRCH), and no
    /// child's host thread joins itself or an ancestor's joiner (EDEADLK;
    /// joins follow the acyclic process tree toward the traced root, which
    /// runs on the embedder's thread). So, as std's JoinHandle::join does, a
    /// failed join is a broken invariant: panic, still owning the pthread.
    pub(super) fn joined(&mut self, status: libc::c_int) -> std::thread::Result<crate::Result<()>> {
        assert_eq!(
            status,
            0,
            "KVM child process thread join failed: {}",
            std::io::Error::from_raw_os_error(status)
        );
        self.pthread = None;
        self.observe_join(true);
        self.exit
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .unwrap_or_else(|| {
                Ok(Err(crate::Error::UnexpectedVcpuExit(
                    "KVM child process thread ended without a result".to_owned(),
                )))
            })
    }

    /// Waits for full thread termination. Only owners that no embedder
    /// scheduler depends on may block here.
    pub(crate) fn join_blocking(&mut self) -> std::thread::Result<crate::Result<()>> {
        let pthread = self.pthread.expect("KVM child process thread joined twice");
        self.observe_join(false);
        #[cfg(any(test, feature = "test-support"))]
        if self.failed_joins > 0 {
            self.failed_joins -= 1;
            return self.joined(libc::EINVAL);
        }
        // SAFETY: this handle uniquely owns the joinable pthread, and releases
        // it only once a join reports that the thread terminated.
        let status = unsafe { libc::pthread_join(pthread, std::ptr::null_mut()) };
        self.joined(status)
    }

    /// Ready once the thread has terminated and been reaped. The closure's
    /// wake covers the wait for its return; teardown after that is polled,
    /// yielding to the executor between attempts, because a thread-local
    /// destructor may itself need a turn from a scheduler this executor runs.
    pub(crate) fn poll_reap(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::thread::Result<crate::Result<()>>> {
        let pthread = self.pthread.expect("KVM child process thread joined twice");
        self.exit.waker.register(cx.waker());
        if self
            .exit
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none()
        {
            return std::task::Poll::Pending;
        }
        self.observe_join(false);
        // SAFETY: as in join_blocking. The kernel clears the thread's TID only
        // after every thread-local and pthread-key destructor has run; until
        // then this returns EBUSY and leaves the pthread joinable.
        match unsafe { libc::pthread_tryjoin_np(pthread, std::ptr::null_mut()) } {
            libc::EBUSY => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            status => std::task::Poll::Ready(self.joined(status)),
        }
    }
}

impl Drop for ChildThread {
    fn drop(&mut self) {
        if let Some(pthread) = self.pthread {
            // As dropping a std JoinHandle does.
            // SAFETY: this handle uniquely owns the joinable pthread.
            unsafe { libc::pthread_detach(pthread) };
        }
    }
}

pub(super) struct ChildProcessHandle {
    pub(super) thread: ChildThread,
    pub(super) panic_owner: Option<Arc<ChildProcessPanicOwner>>,
}

impl From<ChildThread> for ChildProcessHandle {
    fn from(thread: ChildThread) -> Self {
        Self {
            thread,
            panic_owner: None,
        }
    }
}

impl ChildProcessHandle {
    fn join(mut self, unowned_panic: impl FnOnce() -> crate::Error) -> crate::Result<()> {
        let joined = self.thread.join_blocking();
        Self::resolve(joined, self.panic_owner, unowned_panic)
    }

    fn resolve(
        joined: std::thread::Result<crate::Result<()>>,
        panic_owner: Option<Arc<ChildProcessPanicOwner>>,
        unowned_panic: impl FnOnce() -> crate::Error,
    ) -> crate::Result<()> {
        match joined {
            Ok(result) => result,
            Err(payload) => Err(match panic_owner {
                Some(owner) => owner.retain_joined(payload),
                None => unowned_panic(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildCompletion {
    Waitable(ExitStatus),
    AutoReaped(ExitStatus),
}

impl ChildCompletion {
    pub fn from_waitability(status: ExitStatus, waitable: bool) -> Self {
        if waitable {
            Self::Waitable(status)
        } else {
            Self::AutoReaped(status)
        }
    }
}

#[derive(Debug, Default)]
pub struct ChildCompletionSlot {
    pub(super) state: Mutex<ChildCompletionState>,
    pub(super) changed: Condvar,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) publication_waiters: std::sync::atomic::AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) publication_waiter_changed: Condvar,
}

#[derive(Debug, Default)]
pub(super) enum ChildCompletionState {
    #[default]
    Pending,
    PublicationFenced,
    Ready(ChildCompletion),
    Failed,
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChildCompletionSlotError {
    Failed,
    PublicationFenced,
    Poisoned,
}

impl ChildCompletionSlot {
    /// Fence a callback-announced transition before polling arbitrary Tool
    /// code. A concurrent nonblocking parent wait may still poll a genuinely
    /// running `Pending` child, but it must wait through this bounded state so
    /// the callback prefix cannot make the parent runnable before waitability.
    pub(crate) fn begin_publication(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("KVM child completion lock poisoned");
        if matches!(*state, ChildCompletionState::Pending) {
            *state = ChildCompletionState::PublicationFenced;
            true
        } else {
            false
        }
    }

    /// Complete a transition previously armed by [`Self::begin_publication`].
    /// The mutex is never held while Tool code runs.
    pub(crate) fn publish_after_fence(&self, completion: ChildCompletion) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("KVM child completion lock poisoned");
        let published = if matches!(*state, ChildCompletionState::PublicationFenced) {
            *state = ChildCompletionState::Ready(completion);
            true
        } else {
            false
        };
        drop(state);
        if published {
            self.changed.notify_all();
        }
        published
    }

    /// Publish a direct logical wait result exactly once. Callback-driven
    /// publication uses the explicit fenced pair above. A consumed result
    /// remains terminal, so later physical-cleanup failure cannot resurrect or
    /// replace it.
    pub fn publish(&self, completion: ChildCompletion) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("KVM child completion lock poisoned");
        if matches!(*state, ChildCompletionState::Pending) {
            *state = ChildCompletionState::Ready(completion);
            true
        } else {
            false
        }
    }

    pub fn fail_if_pending(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("KVM child completion lock poisoned");
        let failed = if matches!(
            *state,
            ChildCompletionState::Pending | ChildCompletionState::PublicationFenced
        ) {
            *state = ChildCompletionState::Failed;
            true
        } else {
            false
        };
        drop(state);
        if failed {
            self.changed.notify_all();
        }
        failed
    }

    /// Return immediately for a genuinely running child, but wait through the
    /// bounded callback-to-publication interval once the child has announced
    /// its terminal transition.
    pub(super) fn waitability_pending(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("KVM child completion lock poisoned");
        #[cfg(any(test, feature = "test-support"))]
        let mut registered_waiter = false;
        loop {
            match *state {
                ChildCompletionState::Pending => return true,
                ChildCompletionState::PublicationFenced => {
                    #[cfg(any(test, feature = "test-support"))]
                    if !registered_waiter {
                        self.publication_waiters.fetch_add(1, Ordering::SeqCst);
                        self.publication_waiter_changed.notify_all();
                        registered_waiter = true;
                    }
                    state = self
                        .changed
                        .wait(state)
                        .expect("KVM child completion lock poisoned");
                }
                ChildCompletionState::Ready(_)
                | ChildCompletionState::Failed
                | ChildCompletionState::Consumed => {
                    #[cfg(any(test, feature = "test-support"))]
                    if registered_waiter {
                        self.publication_waiters.fetch_sub(1, Ordering::SeqCst);
                    }
                    return false;
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn wait_for_publication_waiter(&self) -> bool {
        let state = self
            .state
            .lock()
            .expect("KVM child completion lock poisoned");
        let (_state, timeout) = self
            .publication_waiter_changed
            .wait_timeout_while(state, std::time::Duration::from_secs(5), |_| {
                self.publication_waiters.load(Ordering::SeqCst) == 0
            })
            .expect("KVM child completion lock poisoned");
        !timeout.timed_out() && self.publication_waiters.load(Ordering::SeqCst) != 0
    }

    pub(super) fn take(&self) -> Result<Option<ChildCompletion>, ChildCompletionSlotError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ChildCompletionSlotError::Poisoned)?;
        if matches!(*state, ChildCompletionState::PublicationFenced) {
            return Err(ChildCompletionSlotError::PublicationFenced);
        }
        match std::mem::replace(&mut *state, ChildCompletionState::Consumed) {
            ChildCompletionState::Ready(completion) => Ok(Some(completion)),
            ChildCompletionState::Failed => Err(ChildCompletionSlotError::Failed),
            ChildCompletionState::Pending => Ok(None),
            ChildCompletionState::PublicationFenced => unreachable!("checked above"),
            ChildCompletionState::Consumed => Ok(None),
        }
    }
}

impl ElfExecutor {
    /// Retain an unpolled child consumer. The outer owner must publish the
    /// parent failure before taking and polling these futures outside callbacks.
    pub fn retain_unstarted_tool_cleanup(&mut self, cleanup: UnstartedToolCleanup) {
        self.unstarted_tool_cleanup
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(cleanup);
    }

    /// Transfer every retained consumer exactly once; no future is polled or
    /// dropped while a registry guard is held. Each result remains typed.
    pub fn take_unstarted_tool_cleanup(&mut self) -> Vec<UnstartedToolCleanup> {
        std::mem::take(
            self.unstarted_tool_cleanup
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Leaves `address_space` equal to `Some(memory.clone())`; see
    /// [`GuestMemory::rebind_from`] for why reusing unchanged parts is that.
    pub fn bind_address_space(&mut self, memory: &GuestMemory) {
        match &mut self.address_space {
            Some(bound) => bound.rebind_from(memory),
            None => self.address_space = Some(memory.clone()),
        }
    }

    /// The brk-managed heap region `[heap_base, program_break)` of the loaded
    /// guest. `heap_base` is the initial program break (`align_up(main_end)`),
    /// so the returned range covers exactly the pages `brk()` has mapped; it is
    /// empty when the guest has never grown its break.
    pub fn heap_region(&self) -> (u64, u64) {
        let program_break = self
            .address_space
            .as_ref()
            .and_then(GuestMemory::allocation_cursors)
            .map_or(self.state.program_break, |cursors| cursors.program_break);
        (self.state.heap_base, program_break)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new(state: LoadedStaticElf, capture_output: bool) -> Self {
        let output = capture_output.then(CapturedOutput::default);
        Self::with_output(state, output)
    }

    pub fn with_output(mut state: LoadedStaticElf, output: Option<CapturedOutput>) -> Self {
        let file_table;
        let _retirement = state.file_retirement.hold();
        let transaction = state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let task_generation = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ensure_registered_with_signals(
                state.tid,
                state.pid,
                state.pgid,
                state.dumpable,
                &state.thread_signals,
            );
        let process_generation = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(state.tid)
            .expect("registered KVM task exists")
            .process_generation;
        let next_pid =
            reverie::task_ids::next_task_id(state.pid, state.ids_per_task).unwrap_or(i32::MAX);
        let sigchld_auto_reap = Arc::new(AtomicBool::new(sigchld_auto_reaps(&state)));
        let address_space = None;
        file_table = Arc::new(std::sync::Mutex::new(
            FileTableState::try_from_elf(&state).expect("clone initial KVM file table"),
        ));
        state.fdinfo_table = Arc::downgrade(&file_table);
        let signal_registry = state.children.registry().unwrap_or_default();
        let signal_binding = signal_registry
            .register(&state, &file_table, process_generation, None)
            .expect("a traced root has no parent registration to reject");
        signal_registry.install_namespace_reaper(&state);
        state.children = ChildWaitContext::bind(
            signal_registry.clone(),
            reverie::SignalTaskIdentity {
                process: reverie::SignalProcessId {
                    tgid: reverie::Pid::from_raw(state.pid),
                    generation: process_generation,
                },
                tid: reverie::Pid::from_raw(state.tid),
                task_generation,
            },
        );
        Self {
            state,
            task_generation,
            process_generation,
            signal_registry,
            signal_binding,
            signal_callback_nonce: 0,
            parent_death_exec: Mutex::new(None),
            terminal_factory: None,
            terminal_cleanup: None,
            terminal_backend_stdin: None,
            parked_signals: None,
            completed_signal_effects: Vec::new(),
            signal_effect_raw_result: None,
            unsupported_refusal: None,
            address_space,
            file_table,
            file_table_task_owner: Some(Arc::new(())),
            output,
            owns_output: true,
            next_pid: Arc::new(AtomicI32::new(next_pid)),
            sigchld_auto_reap,
            pending_processes: std::collections::BTreeMap::new(),
            completed_processes: Vec::new(),
            unstarted_tool_cleanup: Mutex::new(Vec::new()),
            transferred_processes: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            namespace_orphanage: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            process_action: None,
            pending_segment: None,
            current_user_stack_pointer: None,
            exit_status: None,
            exit_group: false,
            clear_child_tid: None,
        }
    }

    pub(super) fn execute_accept(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Option<i64> {
        let _retirement = self.state.file_retirement.hold();
        let raw_flags = accept_flags(request)?;
        let flags = match raw_flags {
            Ok(flags) => flags,
            Err(error) => return Some(error),
        };
        let file_table = self.file_table.clone();
        {
            let shared_files = file_table.lock().expect("KVM file-table lock poisoned");
            if let Err(error) = shared_files.install(&mut self.state) {
                return Some(io_error(error));
            }
        }
        self.state.file_retirement.drain_unlocked();

        let mut memory = memory.clone();
        let accepted = match accept_socket(&mut memory, &self.state, request.args(), flags) {
            Ok(file) => self.state.file_retirement.stage(file),
            Err(error) => return Some(error),
        };

        let mut shared_files = file_table.lock().expect("KVM file-table lock poisoned");
        if let Err(error) = shared_files.install(&mut self.state) {
            return Some(io_error(error));
        }
        let result = insert_file_with_flags(
            &mut self.state,
            accepted.into_file(),
            flags & libc::SOCK_CLOEXEC != 0,
            None,
        );
        if result >= 0 {
            shared_files
                .update_from_elf(&self.state)
                .expect("clone updated KVM file table");
        }
        Some(result)
    }

    pub(super) fn execute_process_action(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Option<i64> {
        let number = request.number();
        let args = request.args();
        if number == libc::SYS_set_tid_address as u64 {
            self.clear_child_tid = (args[0] != 0).then_some(args[0]);
            return Some(i64::from(self.state.tid));
        }
        if number == libc::SYS_fork as u64 || number == libc::SYS_vfork as u64 {
            let share_address_space = number == libc::SYS_vfork as u64;
            return Some(self.prepare_fork(None, None, None, None, false, share_address_space));
        }
        if number == libc::SYS_clone as u64 {
            return Some(self.prepare_clone(
                args[0],
                (args[1] != 0).then_some(args[1]),
                args[2],
                args[3],
                args[4],
            ));
        }
        if number == libc::SYS_clone3 as u64 {
            return Some(
                match read_clone3(&ProviderMemory(memory), args[0], args[1]) {
                    Ok(request) if request.flags & libc::CLONE_THREAD as u64 != 0 => self
                        .prepare_thread(
                            request.flags,
                            request.child_stack,
                            request.parent_tid,
                            request.child_tid,
                            request.tls,
                        ),
                    Ok(request) => match validate_process_clone_flags(request.flags) {
                        Err(error) => error,
                        Ok(())
                            if request.flags & PROCESS_CLONE_TID_FLAGS != 0
                                || request.parent_tid.is_some()
                                || request.child_tid.is_some() =>
                        {
                            negative_errno(libc::ENOTSUP)
                        }
                        Ok(()) => self.prepare_fork(
                            request.child_stack,
                            None,
                            None,
                            None,
                            request.flags & CLONE_CLEAR_SIGHAND != 0,
                            request.flags & libc::CLONE_VM as u64 != 0,
                        ),
                    },
                    Err(error) => error,
                },
            );
        }
        if number == libc::SYS_execve as u64 || number == libc::SYS_execveat as u64 {
            return Some(self.prepare_exec(memory, request, None));
        }
        None
    }

    fn prepare_clone(
        &mut self,
        flags: u64,
        child_stack: Option<u64>,
        parent_tid_address: u64,
        child_tid_address: u64,
        tls: u64,
    ) -> i64 {
        if flags & libc::CLONE_THREAD as u64 != 0 {
            return self.prepare_thread(
                flags,
                child_stack,
                (flags & libc::CLONE_PARENT_SETTID as u64 != 0).then_some(parent_tid_address),
                (flags & (libc::CLONE_CHILD_SETTID as u64 | libc::CLONE_CHILD_CLEARTID as u64)
                    != 0)
                    .then_some(child_tid_address),
                (flags & libc::CLONE_SETTLS as u64 != 0).then_some(tls),
            );
        }
        if let Err(error) = validate_process_clone_flags(flags) {
            return error;
        }
        let parent_tid =
            (flags & libc::CLONE_PARENT_SETTID as u64 != 0).then_some(parent_tid_address);
        let child_tid = (flags & libc::CLONE_CHILD_SETTID as u64 != 0).then_some(child_tid_address);
        let clear_child_tid = (flags & libc::CLONE_CHILD_CLEARTID as u64 != 0
            && child_tid_address != 0)
            .then_some(child_tid_address);
        self.prepare_fork(
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            flags & CLONE_CLEAR_SIGHAND != 0,
            flags & libc::CLONE_VM as u64 != 0,
        )
    }

    /// Reserve the next run-wide task ID without wrapping, spending the run's
    /// IDs per task (`reverie::task_ids`). Once the space is exhausted every
    /// later clone fails with EAGAIN, as Linux does when no PID is free, and
    /// the counter no longer moves.
    pub(super) fn allocate_task_id(&self) -> Option<i32> {
        let ids_per_task = self.state.ids_per_task;
        // The counter holds the next ID to hand out; i32::MAX marks the space
        // as exhausted, so the last valid ID is handed out once whatever the
        // step, and the counter then stays at i32::MAX.
        self.next_pid
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |next| {
                (next > 0 && next < i32::MAX).then(|| {
                    reverie::task_ids::next_task_id(next, ids_per_task).unwrap_or(i32::MAX)
                })
            })
            .ok()
            .filter(|id| *id > 0)
    }

    pub(super) fn prepare_thread(
        &mut self,
        flags: u64,
        child_stack: Option<u64>,
        parent_tid: Option<u64>,
        child_tid_address: Option<u64>,
        tls: Option<u64>,
    ) -> i64 {
        if let Err(error) = validate_thread_clone_flags(flags) {
            return error;
        }
        let Some(child_stack) = child_stack else {
            return negative_errno(libc::EINVAL);
        };
        if self.process_action.is_some() {
            return negative_errno(libc::EBUSY);
        }
        // A process-directed signal queued while this process had one thread
        // has no selected recipient. Creating a sibling would let host vCPU
        // timing choose which thread dequeues it. Refuse before allocating a
        // tid or publishing any child state; Hermit's later scheduler
        // integration will own deterministic process-signal target selection.
        // An open signalfd is no obstacle: each thread's probe reads its own
        // queue (`signalfd_readable`).
        if self.parent_death_enrolled() || self.has_shared_pending_signal() {
            return negative_errno(libc::ENOSYS);
        }
        let Some(child_tid) = self.allocate_task_id() else {
            return negative_errno(libc::EAGAIN);
        };
        self.process_action = Some(ProcessAction::Thread {
            child_tid,
            child_stack,
            parent_tid,
            child_tid_address: (flags & libc::CLONE_CHILD_SETTID as u64 != 0)
                .then_some(child_tid_address)
                .flatten(),
            clear_child_tid: (flags & libc::CLONE_CHILD_CLEARTID as u64 != 0)
                .then_some(child_tid_address)
                .flatten(),
            tls,
        });
        i64::from(child_tid)
    }

    pub(super) fn prepare_fork(
        &mut self,
        child_stack: Option<u64>,
        parent_tid: Option<u64>,
        child_tid: Option<u64>,
        clear_child_tid: Option<u64>,
        clear_sighand: bool,
        share_address_space: bool,
    ) -> i64 {
        if self.process_action.is_some() {
            return negative_errno(libc::EBUSY);
        }
        // The host eventfd backing a virtual signalfd is shared by File::try_clone,
        // but Linux evaluates inherited signalfd readiness against each process's
        // own pending set. Refuse process creation while one is open rather than
        // allowing parent-only readiness to wake the child (or vice versa).
        if !self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .signalfd_masks
            .is_empty()
        {
            self.unsupported_refusal = Some(reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::Signalfd,
                reverie::Errno::ENOSYS,
                SIGNALFD_FORK_REFUSAL,
            ));
            return negative_errno(libc::ENOSYS);
        }
        let Some(child_pid) = self.allocate_task_id() else {
            return negative_errno(libc::EAGAIN);
        };
        self.process_action = Some(ProcessAction::Fork {
            child_pid,
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            clear_sighand,
            share_address_space,
        });
        i64::from(child_pid)
    }

    pub(super) fn prepare_exec(
        &mut self,
        memory: &GuestMemory,
        request: &SyscallRequest,
        retained: Option<ResolvedExecutable>,
    ) -> i64 {
        let result = self.prepare_exec_image(memory, request, retained);
        self.unsupported_refusal = nonleader_exec_refusal(result, self.state.tid, self.state.pid);
        result
    }

    fn prepare_exec_image(
        &mut self,
        memory: &GuestMemory,
        request: &SyscallRequest,
        retained: Option<ResolvedExecutable>,
    ) -> i64 {
        let args = request.args();
        let (path_address, argv_address, envp_address, dirfd, flags) =
            if request.number() == libc::SYS_execve as u64 {
                (args[0], args[1], args[2], libc::AT_FDCWD, 0)
            } else {
                (args[1], args[2], args[3], args[0] as i32, args[4])
            };
        if self.process_action.is_some() {
            return negative_errno(libc::EBUSY);
        }
        if flags != 0 || dirfd != libc::AT_FDCWD {
            return negative_errno(libc::ENOTSUP);
        }
        let retained_static_image = retained.is_some();
        let path = if retained_static_image {
            // The admitted pathname bytes and target are already retained;
            // reading the guest pointer again would reopen a TOCTOU window.
            Vec::new()
        } else {
            match read_c_string(&ProviderMemory(memory), path_address, 4096) {
                Ok(path) if !path.is_empty() => path,
                Ok(_) => return negative_errno(libc::ENOENT),
                Err(error) => return read_c_string_errno(error),
            }
        };
        let argv = match read_string_array(&ProviderMemory(memory), argv_address) {
            Ok(argv) => argv,
            Err(error) => return error,
        };
        let envp = match read_string_array(&ProviderMemory(memory), envp_address) {
            Ok(envp) => envp,
            Err(error) => return error,
        };
        let executable = match retained {
            Some(executable) => {
                // Admission proves a supported target, not guaranteed exec
                // success. Preserve the normal permission errno at preparation
                // without reopening or re-resolving the captured pathname.
                let file = executable
                    .file
                    .as_ref()
                    .expect("retained exec owns its image file");
                let access = unsafe {
                    libc::syscall(
                        libc::SYS_faccessat2,
                        file.as_raw_fd(),
                        c"".as_ptr(),
                        libc::X_OK,
                        libc::AT_EMPTY_PATH | libc::AT_EACCESS,
                    )
                };
                if access != 0 {
                    return io_error(std::io::Error::last_os_error());
                }
                executable
            }
            None => match resolve_guest_exec_image(&self.state, path.clone(), &envp) {
                Ok(executable) => executable,
                Err(error) => return error,
            },
        };
        // The filename execve was given (bprm->filename), byte for byte as
        // the guest wrote it: Linux names it in AT_EXECFN and passes it as a
        // `#!` script's own argument. The retained parent-death exec gives
        // the alias it admitted.
        let execfn = if retained_static_image {
            executable.path.as_os_str().as_bytes().to_vec()
        } else {
            path
        };
        let path = executable.path;
        let image = executable.image;
        let mut executable_file = executable.file;
        // Linux runs an empty argv as one empty argument (fs/exec.c).
        let argv = if argv.is_empty() {
            vec![String::new()]
        } else {
            argv
        };
        // TODO-HUMAN-REVIEW(reverie-kvm): in-guest execve `#!` interpreter
        // resolution. The KVM ELF loader only maps ELF images, so a guest that
        // execs a `#!`-script must have its interpreter resolved here, as the
        // kernel's binfmt_script loader does.
        let executable_path = path.clone();
        let (image, argv) = if retained_static_image {
            // Parsed static ELF was part of admission. No shebang or external
            // PT_INTERP lookup can be reached through this retained authority.
            (image, argv)
        } else {
            let script_name = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&execfn));
            match resolve_exec_shebang(script_name, image, argv, |interpreter| {
                let resolved = read_executable_file(&self.state, interpreter)?;
                executable_file = resolved.file;
                Ok(resolved.image)
            }) {
                Ok((_interpreter, image, argv)) => (image, argv),
                Err(errno) => return errno,
            }
        };
        // TODO-HUMAN-REVIEW(PR-156): Review preflight validation before exec image replacement.
        // Loading the live image clears guest memory, so validate against an
        // isolated mapping before reporting exec success to the Reverie tool.
        let mut validation_memory = match GuestMemory::new(memory.guest_base(), memory.len()) {
            Ok(memory) => memory,
            Err(_) => return negative_errno(libc::ENOMEM),
        };
        let argv_refs = argv.iter().map(String::as_str).collect::<Vec<_>>();
        let envp_refs = envp.iter().map(String::as_str).collect::<Vec<_>>();
        if load_static_elf_with_execfn(
            &mut validation_memory,
            &image,
            Some(&execfn),
            &argv_refs,
            &envp_refs,
            &self.state.cwd,
        )
        .is_err()
        {
            return negative_errno(libc::ENOEXEC);
        }
        // Linux makes a non-leader caller the new thread-group leader while it
        // tears down every sibling. The KVM backend does not yet implement that
        // promotion. Refuse after safe preflight but before publishing a
        // ProcessAction, so a worker cannot clear the shared address space.
        // prepare_exec records the typed refusal for this ENOSYS.
        if self.state.tid != self.state.pid {
            return negative_errno(libc::ENOSYS);
        }
        self.process_action = Some(ProcessAction::Exec {
            executable_path,
            executable_file,
            execfn: Some(execfn),
            image,
            argv,
            envp,
        });
        0
    }

    pub fn fork_child(
        &self,
        child_pid: i32,
        clear_sighand: bool,
        share_address_space: bool,
    ) -> crate::Result<Self> {
        let terminal_cleanup = self
            .terminal_factory
            .as_ref()
            .map(crate::terminal_cleanup::CleanupFactory::spawn)
            .transpose()?;
        // Declare owned child state and its cleanup scope before either guard.
        let mut state;
        let file_table;
        let _child_retirement;
        let _retirement = self.state.file_retirement.hold();
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        if !self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .signalfd_masks
            .is_empty()
        {
            return Err(crate::Error::UnexpectedVcpuExit(
                "cannot fork a KVM process while a virtual signalfd is open".to_owned(),
            ));
        }
        state = self.state.try_clone_for_fork_locked(child_pid)?;
        _child_retirement = state.file_retirement.hold();
        if share_address_space {
            state.thp_disabled = self.state.thp_disabled.clone();
        }
        state.dumpable = self.current_dumpable();
        if clear_sighand {
            state
                .process_signals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .dispositions
                .retain(|_, action| action.is_ignored());
        }
        let address_space = None;
        file_table = Arc::new(std::sync::Mutex::new(FileTableState::try_from_elf(&state)?));
        state.fdinfo_table = Arc::downgrade(&file_table);
        let task_generation = {
            let mut lifecycle = state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let generation = lifecycle.register_with_signals(
                state.tid,
                state.pid,
                state.pgid,
                state.dumpable,
                &state.thread_signals,
            );
            if let Err(errno) = lifecycle.inherit_real_parent(
                state.tid,
                generation,
                self.admitted_signal_identity(),
                false,
            ) {
                lifecycle.remove(state.tid, generation);
                return Err(crate::Error::Reverie(errno.into()));
            }
            generation
        };
        let process_generation = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(state.tid)
            .expect("registered KVM task exists")
            .process_generation;
        let sigchld_auto_reap = sigchld_auto_reaps(&state);
        let signal_binding = match self.signal_registry.register(
            &state,
            &file_table,
            process_generation,
            Some(reverie::SignalProcessId {
                tgid: reverie::Pid::from_raw(self.state.pid),
                generation: self.process_generation,
            }),
        ) {
            Ok(binding) => binding,
            Err(parent) => {
                state
                    .task_lifecycle
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(state.tid, task_generation);
                return Err(crate::Error::UnexpectedVcpuExit(format!(
                    "KVM process {} registered a child after parent generation {}:{} became terminal",
                    state.pid,
                    parent.tgid.as_raw(),
                    parent.generation,
                )));
            }
        };
        state.children = ChildWaitContext::bind(
            self.signal_registry.clone(),
            reverie::SignalTaskIdentity {
                process: reverie::SignalProcessId {
                    tgid: reverie::Pid::from_raw(state.pid),
                    generation: process_generation,
                },
                tid: reverie::Pid::from_raw(state.tid),
                task_generation,
            },
        );
        let child = Self {
            state,
            task_generation,
            process_generation,
            signal_registry: self.signal_registry.clone(),
            signal_binding,
            signal_callback_nonce: 0,
            parent_death_exec: Mutex::new(None),
            terminal_factory: self.terminal_factory.clone(),
            terminal_cleanup,
            terminal_backend_stdin: None,
            parked_signals: None,
            completed_signal_effects: Vec::new(),
            signal_effect_raw_result: None,
            unsupported_refusal: None,
            address_space,
            file_table,
            file_table_task_owner: Some(Arc::new(())),
            output: self.output.clone(),
            owns_output: false,
            next_pid: self.next_pid.clone(),
            sigchld_auto_reap: Arc::new(AtomicBool::new(sigchld_auto_reap)),
            pending_processes: std::collections::BTreeMap::new(),
            completed_processes: Vec::new(),
            unstarted_tool_cleanup: Mutex::new(Vec::new()),
            transferred_processes: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            namespace_orphanage: self.namespace_orphanage.clone(),
            process_action: None,
            pending_segment: None,
            current_user_stack_pointer: None,
            exit_status: None,
            exit_group: false,
            clear_child_tid: None,
        };
        Ok(child)
    }

    // TODO-HUMAN-REVIEW(PR-172): Review shared address-space and output ownership.
    pub fn thread_child(&self, child_tid: i32) -> crate::Result<Self> {
        let observe_ignored = self.state.thread_signals.lock().observe_ignored;
        self.thread_child_with_signal_observation(child_tid, observe_ignored)
    }

    pub fn thread_child_with_signal_observation(
        &self,
        child_tid: i32,
        observe_ignored: bool,
    ) -> crate::Result<Self> {
        let terminal_cleanup = self
            .terminal_factory
            .as_ref()
            .map(crate::terminal_cleanup::CleanupFactory::spawn)
            .transpose()?;
        // Declare owned child state and its cleanup scope before either guard.
        let mut state;
        let _child_retirement;
        let _retirement = self.state.file_retirement.hold();
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        // Controlled mode admits new task generations through the Tool before
        // any delivery permit. A pending process signal no longer makes physical
        // thread creation race a backend-selected recipient. An open signalfd
        // is no obstacle: each thread's probe reads its own queue.
        if self.parent_death_enrolled()
            || (!self.signal_controlled() && self.has_shared_pending_signal())
        {
            return Err(crate::Error::UnexpectedVcpuExit(
                "cannot create a KVM guest thread while a process-directed signal lacks a selected recipient"
                    .to_owned(),
            ));
        }
        state = self.state.try_clone_for_fork_locked(child_tid)?;
        _child_retirement = state.file_retirement.hold();
        state.pid = self.state.pid;
        state.ppid = self.state.ppid;
        state.orphan_reaper_pid = self.state.orphan_reaper_pid.clone();
        // A CLONE_THREAD worker stays inside the same process, so it inherits the
        // thread group leader's position in the traced process tree.
        state.is_traced_tree_root = self.state.is_traced_tree_root;
        state.dumpable = self.current_dumpable();
        state.thread_group_leader_name = self.state.thread_group_leader_name.clone();
        state.thp_disabled = self.state.thp_disabled.clone();
        state.process_signals = self.state.process_signals.clone();
        state.pipe_owner_process = self.state.pipe_owner_process.clone();
        // The fork helper made private-table bindings. CLONE_FILES instead
        // shares logical entry lifetime with the authoritative parent table.
        state.poll_table_id = self.state.poll_table_id.clone();
        state.native_poll_fds = self.state.native_poll_fds.clone();
        state.signal_transaction = self.state.signal_transaction.clone();
        state.thread_signals = self.state.thread_signals.for_clone_thread();
        state.thread_signals.lock().observe_ignored = observe_ignored;
        let task_generation = {
            let mut lifecycle = state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let generation = lifecycle.register_with_signals(
                state.tid,
                state.pid,
                state.pgid,
                state.dumpable,
                &state.thread_signals,
            );
            if let Err(errno) = lifecycle.inherit_real_parent(
                state.tid,
                generation,
                self.admitted_signal_identity(),
                true,
            ) {
                lifecycle.remove(state.tid, generation);
                return Err(crate::Error::Reverie(errno.into()));
            }
            generation
        };
        let process_generation = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(state.tid)
            .expect("registered KVM task exists")
            .process_generation;
        state.children = ChildWaitContext::bind(
            self.signal_registry.clone(),
            reverie::SignalTaskIdentity {
                process: reverie::SignalProcessId {
                    tgid: reverie::Pid::from_raw(state.pid),
                    generation: process_generation,
                },
                tid: reverie::Pid::from_raw(state.tid),
                task_generation,
            },
        );
        let child = Self {
            state,
            task_generation,
            process_generation,
            signal_registry: self.signal_registry.clone(),
            signal_binding: self.signal_binding.clone(),
            signal_callback_nonce: 0,
            parent_death_exec: Mutex::new(None),
            terminal_factory: self.terminal_factory.clone(),
            terminal_cleanup,
            terminal_backend_stdin: None,
            parked_signals: None,
            completed_signal_effects: Vec::new(),
            signal_effect_raw_result: None,
            unsupported_refusal: None,
            address_space: self.address_space.clone(),
            file_table: self.file_table.clone(),
            file_table_task_owner: self.file_table_task_owner.clone(),
            output: self.output.clone(),
            owns_output: false,
            next_pid: self.next_pid.clone(),
            sigchld_auto_reap: self.sigchld_auto_reap.clone(),
            pending_processes: std::collections::BTreeMap::new(),
            completed_processes: Vec::new(),
            unstarted_tool_cleanup: Mutex::new(Vec::new()),
            transferred_processes: self.transferred_processes.clone(),
            namespace_orphanage: self.namespace_orphanage.clone(),
            process_action: None,
            pending_segment: None,
            current_user_stack_pointer: None,
            exit_status: None,
            exit_group: false,
            clear_child_tid: None,
        };
        Ok(child)
    }

    pub(super) fn current_dumpable(&self) -> bool {
        process_dumpable(&self.state)
    }

    pub fn set_clear_child_tid(&mut self, address: Option<u64>) {
        self.clear_child_tid = address;
    }

    #[cfg(test)]
    pub(crate) fn child_completion(&self, status: ExitStatus) -> ChildCompletion {
        ChildCompletion::from_waitability(status, !self.sigchld_auto_reap.load(Ordering::SeqCst))
    }

    #[cfg(any(test, feature = "test-support", feature = "native-test-support"))]
    pub fn fixture_child_wait_context(&self) -> ChildWaitContext {
        self.state.children.clone()
    }

    pub fn record_child_completion(
        &mut self,
        child: reverie::SignalProcessId,
        completion: ChildCompletion,
    ) -> crate::Result<()> {
        self.signal_registry
            .publish_direct_child_wait(child, completion)
    }

    fn validate_owned_child_completion(
        &self,
        pid: i32,
        child: Option<reverie::SignalProcessId>,
        completion: ChildCompletion,
    ) -> crate::Result<()> {
        let parent = self.admitted_signal_identity().process;
        let child = child.ok_or(crate::Error::FamilyWaitLedgerMismatch {
            parent,
            child_pid: pid,
        })?;
        self.signal_registry
            .validate_owned_child_wait(parent, child, completion)
    }

    pub fn begin_child_wait_publication(
        &self,
        child: reverie::SignalProcessId,
        completion: &ChildCompletionSlot,
    ) -> crate::Result<()> {
        self.signal_registry.begin_wait_boundary(child, completion)
    }

    pub fn publish_child_wait(
        &self,
        child: reverie::SignalProcessId,
        status: ChildCompletion,
        completion: &ChildCompletionSlot,
        fenced: bool,
    ) -> crate::Result<()> {
        self.signal_registry
            .publish_wait_boundary(child, status, completion, fenced)
    }

    pub fn fail_child_wait_publication(&self, child: reverie::SignalProcessId) {
        self.signal_registry.fail_child_wait(child);
    }

    // TODO-HUMAN-REVIEW(PR-235): Review KVM child registration and join semantics.
    #[cfg(test)]
    pub(super) fn register_mock_child_process(
        &mut self,
        pid: i32,
        start: std::sync::mpsc::Sender<ChildStartCommand>,
        completion: Arc<process_signal_publication::TestChildCompletion>,
        handle: ChildThread,
    ) {
        self.register_child_process(pid, start, completion.slot.clone(), handle);
    }

    #[cfg(test)]
    pub(super) fn mock_child_completion(
        &self,
        pid: i32,
    ) -> Arc<process_signal_publication::TestChildCompletion> {
        Arc::new(process_signal_publication::TestChildCompletion::new(
            &self.state.children,
            pid,
        ))
    }

    #[cfg(test)]
    pub(crate) fn register_child_process(
        &mut self,
        pid: i32,
        start: std::sync::mpsc::Sender<ChildStartCommand>,
        completion: Arc<ChildCompletionSlot>,
        handle: ChildThread,
    ) {
        self.register_child_process_with_gate(pid, ChildStartGate::new(start), completion, handle);
    }

    #[cfg(any(test, feature = "test-support", feature = "native-test-support"))]
    pub fn register_child_process_with_gate(
        &mut self,
        pid: i32,
        start: ChildStartGate,
        completion: Arc<ChildCompletionSlot>,
        handle: ChildThread,
    ) {
        self.register_child_process_with_panic_owner(pid, start, completion, handle, None);
    }

    pub fn register_child_process_with_panic_owner(
        &mut self,
        pid: i32,
        start: ChildStartGate,
        completion: Arc<ChildCompletionSlot>,
        handle: ChildThread,
        panic_owner: Option<Arc<ChildProcessPanicOwner>>,
    ) {
        let previous = self.pending_processes.insert(
            pid,
            PendingProcess {
                child: self
                    .signal_registry
                    .registered_child_wait(self.admitted_signal_identity().process, pid),
                start,
                completion,
                handle: ChildProcessHandle {
                    thread: handle,
                    panic_owner,
                },
            },
        );
        debug_assert!(previous.is_none(), "duplicate KVM child pid {pid}");
    }

    // TODO-HUMAN-REVIEW(PR-235): Review parent-registration ordering for KVM children.
    #[cfg(test)]
    pub(crate) fn start_pending_child_processes(&mut self) -> crate::Result<()> {
        for process in self.pending_processes.values_mut() {
            process.start.start().map_err(|_| {
                crate::Error::UnexpectedVcpuExit(
                    "KVM child exited before its parent released the start gate".to_owned(),
                )
            })?;
        }
        Ok(())
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn has_pending_child_process(&self, pid: i32) -> bool {
        self.pending_processes.contains_key(&pid)
    }

    /// Drops the start gate and joins one child that has not begun guest
    /// execution. Used when parent boundary restoration fails after the child
    /// was constructed but before the Tool can register it.
    pub fn discard_unstarted_child_process(&mut self, pid: i32) -> crate::Result<bool> {
        let Some(process) = self.pending_processes.get(&pid) else {
            return Ok(false);
        };
        let delivery_failed = match process.start.cancel() {
            ChildStartCancellation::NewlyCancelled { delivery_failed } => delivery_failed,
            ChildStartCancellation::AlreadyCancelled => false,
            ChildStartCancellation::AlreadyStarted => return Ok(false),
        };
        let process = self
            .pending_processes
            .remove(&pid)
            .expect("checked unstarted KVM child disappeared");
        process.handle.join(|| {
            crate::Error::UnexpectedVcpuExit(format!("unstarted KVM child process {pid} panicked"))
        })?;
        if delivery_failed {
            return Err(crate::Error::UnexpectedVcpuExit(format!(
                "unstarted KVM child process {pid} lost its parent start gate"
            )));
        }
        Ok(true)
    }

    pub(super) fn collect_child_process(&mut self, pid: i32, block: bool) -> crate::Result<bool> {
        let Some(process) = self.pending_processes.get_mut(&pid) else {
            return Ok(true);
        };
        process.start.start().map_err(|_| {
            crate::Error::UnexpectedVcpuExit(format!(
                "KVM child process {pid} lost its parent start gate"
            ))
        })?;

        if !block && process.completion.waitability_pending() {
            return Ok(false);
        }

        let PendingProcess {
            child,
            completion,
            handle,
            ..
        } = self
            .pending_processes
            .remove(&pid)
            .expect("KVM child disappeared during collection");
        if block {
            handle.join(|| {
                crate::Error::UnexpectedVcpuExit(format!("KVM child process {pid} panicked"))
            })?;
        } else {
            self.completed_processes.push(handle);
        }
        let completion = completion.take().map_err(|reason| {
            crate::Error::UnexpectedVcpuExit(match reason {
                ChildCompletionSlotError::Failed => {
                    format!("KVM child process {pid} failed before publishing its status")
                }
                ChildCompletionSlotError::PublicationFenced => {
                    format!("KVM child process {pid} exited while its wait publication was fenced")
                }
                ChildCompletionSlotError::Poisoned => {
                    format!("KVM child process {pid} completion lock poisoned")
                }
            })
        })?;
        let completion = completion.ok_or_else(|| {
            crate::Error::UnexpectedVcpuExit(format!(
                "KVM child process {pid} exited without publishing its status"
            ))
        })?;
        self.validate_owned_child_completion(pid, child, completion)?;
        Ok(true)
    }

    pub fn configure_terminal_cleanup(
        &mut self,
        factory: crate::terminal_cleanup::CleanupFactory,
        stdin: Arc<Mutex<Option<std::fs::File>>>,
    ) -> crate::Result<()> {
        let cleanup = factory.spawn()?;
        self.terminal_factory = Some(factory);
        self.terminal_cleanup = Some(cleanup);
        self.terminal_backend_stdin = Some(stdin);
        Ok(())
    }

    pub fn bind_terminal_stdin(&mut self, stdin: Arc<Mutex<Option<std::fs::File>>>) {
        if self.terminal_cleanup.is_some() {
            assert!(
                self.terminal_backend_stdin.is_none(),
                "task stdin bound twice"
            );
            self.terminal_backend_stdin = Some(stdin);
        }
    }

    pub async fn ready_terminal_cleanup(&mut self) -> crate::Result<()> {
        if let Some(cleanup) = self.terminal_cleanup.as_mut() {
            cleanup.ready().await?;
        }
        Ok(())
    }

    pub async fn finish_terminal_cleanup(&mut self) -> crate::Result<()> {
        self.release_files_on_exit();
        if let Some(cleanup) = self.terminal_cleanup.as_mut() {
            cleanup.finish().await?;
        }
        Ok(())
    }

    /// The task owns a prestarted service before its first guest callback.
    /// This begins cleanup immediately, including on a dropped run, and never
    /// blocks the caller or destroys its terminal sockets on this host thread.
    pub fn release_files_on_exit(&mut self) {
        let Some(cleanup) = self.terminal_cleanup.as_ref() else {
            return self.release_files_on_exit_ordinary();
        };
        if cleanup.is_submitted() {
            return;
        }
        use crate::native_exit_broker::SocketReference::Owned;
        use crate::native_exit_broker::SocketReference::Shared;
        // Prior explicit closes are ordinary operations. They must settle with
        // their original semantics, never be reclassified as task-exit closes.
        self.state.file_retirement.drain_unlocked();
        let stdin = self.state.take_stdin();
        let retired = std::mem::take(&mut self.state.files);
        self.state.fd_entry_ids.clear();
        self.state.native_poll_fds.clear();
        self.state.pipe_owners.clear();
        self.state.poll_table_id = Default::default();
        self.state.epoll_domain = Default::default();
        let table = std::mem::replace(
            &mut self.file_table,
            Arc::new(Mutex::new(FileTableState::default())),
        );
        let mut files = Vec::new();
        // Elect the last task independently of transient observer Arcs. A
        // genuine CLONE_FILES sibling still owns the table, so its exit must
        // neither acquire this lock nor remove any of its descriptors.
        let last_task = self
            .file_table_task_owner
            .take()
            .is_some_and(|owner| Arc::into_inner(owner).is_some());
        if last_task {
            let mut table = table.lock().unwrap_or_else(|p| p.into_inner());
            files.extend(table.stdin.take().map(Owned));
            files.extend(std::mem::take(&mut table.files).into_values().map(Owned));
        }
        // No table guard crosses service submission or descriptor destruction.
        // A separately selected/duplicated File remains a genuine foreign OFD
        // owner; an observer's table Arc alone no longer owns these files.
        drop(table);
        files.extend(retired.into_values().map(Owned));
        files.extend(stdin.map(Owned));
        if let Some(ProcessAction::Exec {
            executable_file, ..
        }) = self.process_action.take()
        {
            files.extend(executable_file.map(Shared));
        }
        files.extend(self.state.executable_file.take().map(Shared));
        if let Some(snapshot) = self
            .parent_death_exec
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            files.push(Shared(snapshot.file));
        }
        if let Some(input) = self.terminal_backend_stdin.take() {
            files.extend(
                input
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .map(Owned),
            );
        }
        self.terminal_cleanup.as_mut().unwrap().submit(files);
    }

    /// Release only this executor's descriptor references. A live CLONE_FILES
    /// sibling retains the old shared table; clearing its contents would close
    /// that sibling's descriptors too.
    fn release_files_on_exit_ordinary(&mut self) {
        let _retirement = self.state.file_retirement.hold();
        // Only task-private fields and our Arc owner change. A surviving shared
        // table is untouched, so waiting on its locks would add a dependency on
        // a peer's host syscall (and its interrupt) during terminal cleanup.
        let stdin = self.state.take_stdin();
        let retired = std::mem::take(&mut self.state.files);
        self.state.fd_entry_ids.clear();
        // Snapshot retirement is not a logical close in a surviving table.
        self.state.native_poll_fds.clear();
        self.state.pipe_owners.clear();
        self.state.poll_table_id = Default::default();
        self.state.epoll_domain = Default::default();
        self.file_table = Arc::new(Mutex::new(FileTableState::default()));
        drop(self.file_table_task_owner.take());
        let action = self.process_action.take();
        self.state
            .file_retirement
            .retire(retired.into_values().chain(stdin));
        if let Some(ProcessAction::Exec {
            executable_file, ..
        }) = action
        {
            self.state.file_retirement.retire_shared(executable_file);
        }
    }

    /// A worker cannot wait for a fork that needs the leader's exit hooks.
    /// Keep the handles in process-owned storage until all worker hooks finish.
    pub fn transfer_child_processes_to_owner(&mut self) {
        debug_assert!(!self.is_thread_group_leader());
        let children = OwnedChildProcesses {
            pending: std::mem::take(&mut self.pending_processes),
            completed: std::mem::take(&mut self.completed_processes),
        };
        if !children.pending.is_empty() || !children.completed.is_empty() {
            self.transferred_processes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(self.state.tid)
                .or_default()
                .push(children);
        }
    }

    // TODO-HUMAN-REVIEW(PR-235): Review KVM root-exit child synchronization.
    /// Blocking form for owners that no embedder scheduler depends on: native
    /// host threads and tests. A Tool process exit uses the async form.
    #[cfg(any(test, feature = "test-support"))]
    pub fn join_all_child_processes(&mut self) -> crate::Result<()> {
        self.finish_child_processes(false, ChildJoin::Blocking)
            .now_or_never()
            .expect("a blocking KVM child join never suspends")
    }

    /// Blocking form, for a child process's own host thread, the dropped-run
    /// reaper, and tests. On the embedder's executor, use the async form.
    pub fn join_child_processes_after_failure(&mut self) -> crate::Result<()> {
        self.finish_child_processes(true, ChildJoin::Blocking)
            .now_or_never()
            .expect("a blocking KVM child join never suspends")
    }

    /// Suspends, rather than blocks, while a child still runs, so an embedder
    /// scheduler polled on the same executor can grant that child its turns.
    pub async fn join_all_child_processes_async(&mut self) -> crate::Result<()> {
        self.finish_child_processes(false, ChildJoin::Suspending)
            .await
    }

    pub async fn join_child_processes_after_failure_async(&mut self) -> crate::Result<()> {
        self.finish_child_processes(true, ChildJoin::Suspending)
            .await
    }

    /// Takes a pending child a thread of this process handed over as it
    /// exited. No two live processes share a pid; if two did, the second is
    /// cancelled and still joined, as a collected child is, rather than
    /// displacing, and so detaching, either handle.
    fn adopt_pending_process(
        &mut self,
        pid: i32,
        process: PendingProcess,
        errors: &mut Vec<crate::Error>,
    ) {
        match self.pending_processes.entry(pid) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(process);
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                let _ = process.start.cancel_after_failure();
                errors.push(crate::Error::UnexpectedVcpuExit(format!(
                    "KVM child pid {pid} transferred twice"
                )));
                self.completed_processes.push(process.handle);
            }
        }
    }

    async fn finish_child_processes(&mut self, failed: bool, how: ChildJoin) -> crate::Result<()> {
        let mut errors = Vec::new();
        // Every handle stays in this executor's own maps until it is reaped,
        // so dropping this future while it waits leaves each unreaped child
        // with the executor, as at any other await point. The public run's
        // RunningRoot keeps that executor, and so those children, past the
        // drop of the run's own future, and hands it to the dropped-run
        // reaper, which finishes this join, retrying it if it panics. Joining
        // the whole map also joins a child that lost its start gate or
        // returned an error, where collect_child_process would leave a failed
        // start in the map. A lock poisoned by an earlier panic still guards
        // whole maps of handles, which this join must not abandon.
        if self.is_thread_group_leader() {
            let transferred = std::mem::take(
                &mut *self
                    .transferred_processes
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            );
            // BTreeMap gives virtual TID order, independent of host completion.
            for (_, transfers) in transferred {
                for children in transfers {
                    for (pid, process) in children.pending {
                        self.adopt_pending_process(pid, process, &mut errors);
                    }
                    self.completed_processes.extend(children.completed);
                }
            }
        }
        if !failed
            && self.is_thread_group_leader()
            && !self.is_traced_tree_root()
            && self
                .signal_registry
                .transferred_children_to_namespace_init(self.admitted_signal_identity().process)
        {
            // Linux reparents in the exiting process's own exit; it never waits
            // for an adopted child. Release each gate as an ordinary successful
            // exit would, then hand the host handle to the traced root.
            let mut orphanage = self
                .namespace_orphanage
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (pid, process) in std::mem::take(&mut self.pending_processes) {
                if process.start.start().is_err() {
                    errors.push(crate::Error::UnexpectedVcpuExit(format!(
                        "KVM child process {pid} lost its parent start gate"
                    )));
                }
                match orphanage.entry(pid) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(process);
                    }
                    // No two live processes share a pid. If they did, the
                    // second is still joined, as a collected child is.
                    std::collections::btree_map::Entry::Occupied(_) => {
                        errors.push(crate::Error::UnexpectedVcpuExit(format!(
                            "KVM orphan pid {pid} transferred twice"
                        )));
                        self.completed_processes.push(process.handle);
                    }
                }
            }
        }
        if failed {
            // Resolve all pending gates before joining the first child: an
            // earlier child may need a later child's consuming cleanup.
            for (pid, process) in &self.pending_processes {
                if matches!(
                    process.start.cancel_after_failure(),
                    ChildStartCancellation::NewlyCancelled {
                        delivery_failed: true
                    }
                ) {
                    errors.push(crate::Error::UnexpectedVcpuExit(format!(
                        "KVM child process {pid} lost its parent cancellation gate"
                    )));
                }
            }
        }
        while let Some(pid) = self.pending_processes.keys().next().copied() {
            let process = self
                .pending_processes
                .get_mut(&pid)
                .expect("KVM pending child vanished");
            if !failed && process.start.start().is_err() {
                errors.push(crate::Error::UnexpectedVcpuExit(format!(
                    "KVM child process {pid} lost its parent start gate"
                )));
            }
            let joined = how.reap(&mut process.handle.thread).await;
            let process = self
                .pending_processes
                .remove(&pid)
                .expect("KVM pending child vanished");
            let result = ChildProcessHandle::resolve(joined, process.handle.panic_owner, || {
                crate::Error::UnexpectedVcpuExit(format!("KVM child process {pid} panicked"))
            });
            match result {
                Err(error) => errors.push(error),
                Ok(()) => {
                    let completion = process.completion.take().map_err(|reason| {
                        crate::Error::UnexpectedVcpuExit(match reason {
                            ChildCompletionSlotError::Failed => format!(
                                "KVM child process {pid} failed before publishing its status"
                            ),
                            ChildCompletionSlotError::PublicationFenced => format!(
                                "KVM child process {pid} exited while its wait publication was fenced"
                            ),
                            ChildCompletionSlotError::Poisoned => {
                                format!("KVM child process {pid} completion lock poisoned")
                            }
                        })
                    });
                    let completion = completion.and_then(|completion| {
                        completion.ok_or_else(|| {
                            crate::Error::UnexpectedVcpuExit(format!(
                                "KVM child process {pid} exited without publishing its status"
                            ))
                        })
                    });
                    if let Err(error) = completion.and_then(|completion| {
                        self.validate_owned_child_completion(pid, process.child, completion)
                    }) {
                        errors.push(error);
                    }
                }
            }
        }
        while let Some(handle) = self.completed_processes.first_mut() {
            let joined = how.reap(&mut handle.thread).await;
            let handle = self.completed_processes.remove(0);
            let result = ChildProcessHandle::resolve(joined, handle.panic_owner, || {
                crate::Error::UnexpectedVcpuExit("completed KVM child process panicked".to_owned())
            });
            if let Err(error) = result {
                errors.push(error);
            }
        }
        if self.is_thread_group_leader() && self.is_traced_tree_root() {
            self.join_namespace_orphans(failed, how, &mut errors).await;
        }
        crate::Error::combine(errors)
    }

    /// The traced root stands in for the outside namespace init that adopted
    /// these processes: it joins each one and discards its status, which no
    /// traced process can observe. Every process that can add an orphan is
    /// itself joined, directly or through this loop, before the loop ends.
    async fn join_namespace_orphans(
        &self,
        failed: bool,
        how: ChildJoin,
        errors: &mut Vec<crate::Error>,
    ) {
        let orphanage = || {
            self.namespace_orphanage
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        loop {
            // Each batch is the orphans present when it starts; any adopted
            // while it is joined form the next. Only this loop removes one.
            let batch: Vec<i32> = orphanage().keys().copied().collect();
            if batch.is_empty() {
                return;
            }
            if failed {
                for (pid, process) in orphanage().iter().filter(|(pid, _)| batch.contains(pid)) {
                    if matches!(
                        process.start.cancel_after_failure(),
                        ChildStartCancellation::NewlyCancelled {
                            delivery_failed: true
                        }
                    ) {
                        errors.push(crate::Error::UnexpectedVcpuExit(format!(
                            "KVM orphan process {pid} lost its cancellation gate"
                        )));
                    }
                }
            }
            for pid in batch {
                let orphan = |orphans: &mut std::collections::BTreeMap<i32, PendingProcess>| {
                    orphans.remove(&pid).expect("KVM orphan vanished")
                };
                let (joined, process) = match how {
                    // Never block while holding the orphanage: an exiting
                    // descendant adds its own orphans to it.
                    ChildJoin::Blocking => {
                        let mut process = orphan(&mut orphanage());
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            process.handle.thread.join_blocking()
                        })) {
                            Ok(joined) => (joined, process),
                            // A failed join still owns the pthread. Return it
                            // to the orphanage, where a retry finds it, rather
                            // than detach it.
                            Err(payload) => {
                                orphanage().insert(pid, process);
                                std::panic::resume_unwind(payload);
                            }
                        }
                    }
                    ChildJoin::Suspending => {
                        let joined = std::future::poll_fn(|cx| {
                            orphanage()
                                .get_mut(&pid)
                                .expect("KVM orphan vanished")
                                .handle
                                .thread
                                .poll_reap(cx)
                        })
                        .await;
                        (joined, orphan(&mut orphanage()))
                    }
                };
                let result =
                    ChildProcessHandle::resolve(joined, process.handle.panic_owner, || {
                        crate::Error::UnexpectedVcpuExit(format!(
                            "KVM orphan process {pid} panicked"
                        ))
                    });
                if let Err(error) = result {
                    errors.push(error);
                    continue;
                }
                match process.completion.take() {
                    Ok(Some(_)) => {}
                    Ok(None) => errors.push(crate::Error::UnexpectedVcpuExit(format!(
                        "KVM orphan process {pid} exited without publishing its status"
                    ))),
                    Err(ChildCompletionSlotError::Failed) => {
                        errors.push(crate::Error::UnexpectedVcpuExit(format!(
                            "KVM orphan process {pid} failed before publishing its status"
                        )))
                    }
                    Err(ChildCompletionSlotError::PublicationFenced) => {
                        errors.push(crate::Error::UnexpectedVcpuExit(format!(
                            "KVM orphan process {pid} exited while its wait publication was fenced"
                        )))
                    }
                    Err(ChildCompletionSlotError::Poisoned) => {
                        errors.push(crate::Error::UnexpectedVcpuExit(format!(
                            "KVM orphan process {pid} completion lock poisoned"
                        )))
                    }
                }
            }
        }
    }

    pub(super) fn execute_child_wait(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Option<crate::Result<i64>> {
        let args = request.args();
        let waitid_call = request.number() == libc::SYS_waitid as u64;
        if !waitid_call && request.number() != libc::SYS_wait4 as u64 {
            return None;
        }
        let valid = if waitid_call {
            waitid_options_supported(args[3])
        } else {
            wait4_options_supported(args[2])
        };
        if valid {
            let requested = if waitid_call {
                match args[0] as libc::idtype_t {
                    libc::P_PID => match i32::try_from(args[1]) {
                        Ok(pid) => Some(pid),
                        Err(_) => {
                            return Some(Ok(finish_waitid(
                                &ProviderMemory(memory),
                                args,
                                None,
                                negative_errno(libc::ECHILD),
                            )));
                        }
                    },
                    libc::P_ALL | libc::P_PGID => None,
                    _ => {
                        return Some(Ok(finish_waitid(
                            &ProviderMemory(memory),
                            args,
                            None,
                            negative_errno(libc::EINVAL),
                        )));
                    }
                }
            } else {
                let pid = args[0] as i32;
                (pid > 0).then_some(pid)
            };
            // An already ready sibling result need not join or wait through a
            // different creator-owned child's physical completion fence.
            let ready = match self.state.children.has_ready(requested) {
                Ok(ready) => ready,
                Err(error) => return Some(Err(error)),
            };
            // wait4 without a result never accesses status. Leave its ordinary
            // child collection intact and let the raw path distinguish ECHILD
            // and WNOHANG before checking a prospective scalar store. waitid's
            // existing no-result path writes its zero-valued fields instead.
            if (waitid_call || ready)
                && let Err(error) = preflight_wait_shared_outputs(memory, args, waitid_call)
            {
                return Some(Err(error));
            }
            let own_children: Vec<_> = self
                .pending_processes
                .keys()
                .copied()
                .filter(|pid| !ready && requested.is_none_or(|requested| requested == *pid))
                .collect();
            for pid in own_children {
                if self.pending_processes[&pid].child.is_none() {
                    return Some(Err(crate::Error::FamilyWaitLedgerMismatch {
                        parent: self.admitted_signal_identity().process,
                        child_pid: pid,
                    }));
                }
                if let Err(error) = self.collect_child_process(pid, false) {
                    return Some(Err(error));
                }
            }
        }
        let result = if waitid_call {
            waitid_result(memory, &mut self.state, args)
        } else {
            wait4_result(memory, &mut self.state, args)
        };
        let acknowledged = self
            .state
            .consumed_child_wait
            .take()
            .map(|receipt| self.state.children.acknowledge(receipt))
            .transpose();
        Some(match (result, acknowledged) {
            (Ok(value), Ok(_)) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        })
    }

    pub fn take_clear_child_tid(&mut self) -> Option<u64> {
        self.clear_child_tid.take()
    }

    pub fn take_process_action(&mut self) -> Option<ProcessAction> {
        self.process_action.take()
    }

    /// Whether a process action is staged, without taking it.
    pub fn has_process_action(&self) -> bool {
        self.process_action.is_some()
    }

    // TODO-HUMAN-REVIEW(PR-156): Review non-returning exit injection state.
    pub fn has_pending_exit(&self) -> bool {
        self.exit_status.is_some()
    }

    /// The status of a pending exit that ends the whole thread group.
    pub fn pending_group_exit_status(&self) -> Option<ExitStatus> {
        self.exit_status.filter(|_| self.exit_group)
    }

    pub(crate) fn is_thread_group_leader(&self) -> bool {
        self.state.tid == self.state.pid
    }

    /// The tid of the task this executor runs, as the Tool sees it.
    pub fn task_tid(&self) -> i32 {
        self.state.tid
    }

    pub fn replace_after_exec(&mut self, state: LoadedStaticElf) {
        let _retirement = self.state.file_retirement.hold();
        let file_table = self.file_table.clone();
        let mut files = file_table.lock().expect("KVM file-table lock poisoned");
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let previous = std::mem::replace(&mut self.state, state);
        let retired = self.state.inherit_process_state_locked(previous);
        self.state.file_retirement.retire(retired);
        let identity = self
            .state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(self.state.tid)
            .expect("execing KVM task is absent from its lifecycle table");
        self.task_generation = identity.generation;
        self.process_generation = identity.process_generation;
        if let Some(memory) = &self.address_space {
            memory.set_allocation_cursors(AllocationCursors::from_elf(&self.state));
        }
        files
            .update_from_elf(&self.state)
            .expect("clone post-exec KVM file table");
        self.signal_binding.rebind(&self.state, &file_table);
        self.state.children = ChildWaitContext::bind(
            self.signal_registry.clone(),
            self.admitted_signal_identity(),
        );
        self.sigchld_auto_reap
            .store(sigchld_auto_reaps(&self.state), Ordering::SeqCst);
        self.pending_segment = None;
        self.exit_status = None;
        self.exit_group = false;
        self.clear_child_tid = None;
        drop(_transaction);
        drop(files);
    }

    pub fn append_output(&mut self, stdout: Vec<u8>, stderr: Vec<u8>) {
        if let Some(output) = self.output.as_mut() {
            let _ = output.append(false, &stdout);
            let _ = output.append(true, &stderr);
        }
    }

    pub fn cwd(&self) -> &std::path::Path {
        &self.state.cwd
    }

    pub fn auxv(&self) -> &[(libc::c_ulong, libc::c_ulong)] {
        &self.state.auxv
    }

    // TODO-HUMAN-REVIEW(PR-233): Review exposing the initial stack for synthetic exec delivery.
    pub fn initial_stack_pointer(&self) -> u64 {
        self.state.stack_pointer
    }

    pub fn segment_bases(&self) -> (u64, u64) {
        (self.state.fs_base, self.state.gs_base)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED: Route ordinary reads to the Tool for accounting parity.
    // TODO-HUMAN-REVIEW(PR-266): Review tool-visible vs backend-owned read classification.
    //
    // `read`/`readv` are otherwise backend-owned (see
    // `runtime::is_backend_owned_syscall`) so the backend's own event loop can
    // drain worker-created eventfds/pipes through the shared descriptor table
    // without going through Detcore's scheduler (which would deadlock). That
    // ownership, however, also hides ordinary guest file and stream reads from
    // the Tool, breaking faithful syscall accounting (e.g. the dynamic linker's
    // ELF-header `read` on a shared library) and cross-backend parity with
    // ptrace. This narrows the hiding to exactly the worker-shared case:
    // reads on regular files and on the standard streams are ordinary guest I/O
    // and must reach `Tool::handle_syscall_event`; only non-regular,
    // non-standard descriptors (eventfd/pipe/socket) stay backend-owned.
    // Reads of a random device reach the Tool as well: the Tool (Detcore)
    // answers them itself, and executing them here would hand the guest host
    // entropy behind its back.
    pub fn is_tool_visible_read(&self, request: &SyscallRequest) -> bool {
        let number = request.number();
        if number != libc::SYS_read as u64 && number != libc::SYS_readv as u64 {
            return false;
        }
        let fd = request.args()[0] as libc::c_int;
        if is_open_standard(&self.state, fd) {
            return true;
        }
        self.state
            .files
            .get(&fd)
            .and_then(|file| file.metadata().ok())
            .is_some_and(|metadata| {
                metadata.file_type().is_file() || is_random_character_device(&metadata)
            })
    }

    // TODO-HUMAN-REVIEW(PR-235): Review virtual parent identity for KVM Tool callbacks.
    /// The parent inside the *traced* process tree, backing `Guest::ppid`.
    ///
    /// This is deliberately not `state.ppid`, which is the guest-visible
    /// `getppid(2)` value. The root guest synthesizes a container-init parent
    /// (PID 1) so `getppid()` matches the ptrace backend's PID namespace, but it
    /// has no traced parent. Reverie derives `Guest::is_root_process` from this
    /// returning `None`, and Detcore only registers the root thread with its
    /// scheduler when `Guest::is_root_thread()` is true, so reporting the
    /// synthetic parent here makes the root guest permanently unschedulable.
    /// Like the ptrace backend's `Guest::ppid`, it also keeps the fork-time
    /// parent after an orphan is reparented; only `getppid(2)` reports the
    /// namespace reaper.
    pub fn parent_pid(&self) -> Option<reverie::Pid> {
        if self.is_traced_tree_root() {
            return None;
        }
        (self.state.ppid != 0).then(|| reverie::Pid::from_raw(self.state.ppid))
    }

    pub fn is_traced_tree_root(&self) -> bool {
        self.state.is_traced_tree_root
    }
}

/// Public runs a backend admitted that never returned: a run whose future was
/// dropped, or that unwound, before it finished. Such a run's guest threads
/// are cancelled only when its backend drops, and until then they share its
/// memory and run state, so the backend admits no further run, image, or
/// memory access. Each such root stays here, with every child it owns, until
/// that drop hands it, and the run's guest workers, to the run's reaper.
#[derive(Default)]
pub struct AbandonedRuns {
    pub(super) abandoned: bool,
    pub(super) reaper: Option<DroppedRunReaper>,
    pub(super) roots: Vec<ElfExecutor>,
}

impl AbandonedRuns {
    fn lock(runs: &Mutex<Self>) -> std::sync::MutexGuard<'_, Self> {
        runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn admit(runs: &Mutex<Self>) -> crate::Result<()> {
        if Self::lock(runs).abandoned {
            return Err(crate::Error::AbandonedRunNotRetired);
        }
        Ok(())
    }

    pub(crate) fn retain_terminal_service(
        runs: &Mutex<Self>,
        reaper: &DroppedRunReaper,
        thread: ChildThread,
    ) {
        Self::lock(runs).abandon(reaper);
        reaper.adopt(Retirement {
            workers: None,
            roots: Vec::new(),
            terminal: vec![thread],
        });
    }

    fn abandon(&mut self, reaper: &DroppedRunReaper) {
        self.abandoned = true;
        // A backend runs one run at a time, so after its first abandoned run
        // it admits none; that run's reaper retires everything left here.
        self.reaper.get_or_insert_with(|| reaper.clone());
    }

    /// For the backend's drop, once it has cancelled its guest threads. This
    /// never waits: an abandoned run's workers, like its children, may need
    /// turns from the embedder's scheduler to exit, so its reaper joins them,
    /// before its roots, to which exiting workers hand their forks. Returns
    /// whether a run was abandoned.
    pub fn retire<W: GuestWorkers + 'static>(runs: &Mutex<Self>, workers: &Arc<W>) -> bool {
        let (reaper, roots) = {
            let mut runs = Self::lock(runs);
            (runs.reaper.take(), std::mem::take(&mut runs.roots))
        };
        let Some(reaper) = reaper else {
            // Only an abandoned run parks a root, and abandoning establishes
            // a reaper.
            debug_assert!(roots.is_empty());
            return false;
        };
        reaper.adopt(Retirement {
            workers: Some(workers.clone() as Arc<dyn GuestWorkers>),
            roots,
            terminal: Vec::new(),
        });
        true
    }
}

/// The guest worker threads of a run, as its reaper and its admission see
/// them. The backend's thread group implements this.
pub trait GuestWorkers: Send + Sync {
    /// Whether a worker thread of the run has not been joined yet.
    fn has_unjoined_workers(&self) -> bool;
    /// Joins every worker thread of the run.
    fn join_workers(&self);
}

/// The backend's thread group with no worker thread, for this crate's tests:
/// it has no unjoined worker and nothing to join.
#[cfg(any(test, feature = "test-support"))]
pub struct EmptyWorkers;

#[cfg(any(test, feature = "test-support"))]
impl GuestWorkers for EmptyWorkers {
    fn has_unjoined_workers(&self) -> bool {
        false
    }

    fn join_workers(&self) {}
}

// Test-only join, compiled for tests where it can inspect the real
// admission/reaper owner. No production readiness or cleanup rule is bypassed.
#[cfg(any(test, feature = "test-support"))]
impl RunAdmission {
    pub fn finish_fixture_cleanup(mut self) {
        let workers = Arc::new(crate::executor::EmptyWorkers);
        AbandonedRuns::retire(&self.runs, &workers);
        let reaper = self
            .reaper
            .take()
            .expect("fixture admission already finished");
        let observed = reaper.shared.clone();
        drop(reaper);
        self.reaping
            .take()
            .expect("fixture lost its real reaper join")
            .join()
            .expect("fixture cleanup reaper panicked");
        let state = observed.lock();
        assert_eq!(state.handles, 0, "fixture leaked a cleanup owner");
        assert!(
            state.adopted.is_empty(),
            "fixture left retirement work pending"
        );
        assert!(
            state.retained_panics.is_empty(),
            "fixture cleanup retained a panic"
        );
    }
}

/// One public run's admission. Unless the run finishes, dropping this marks
/// its backend abandoned and keeps the run's reaper for the backend's drop.
pub struct RunAdmission {
    pub(super) runs: Arc<Mutex<AbandonedRuns>>,
    pub(super) reaper: Option<DroppedRunReaper>,
    pub(super) reaping: Option<std::thread::JoinHandle<()>>,
}

impl RunAdmission {
    /// Precedes every other step of a run, so a refusal, or a failure to
    /// start the reaper, returns before any image, Tool, or guest state is
    /// touched.
    pub fn begin(runs: &Arc<Mutex<AbandonedRuns>>) -> crate::Result<Self> {
        AbandonedRuns::admit(runs)?;
        let (reaper, reaping) = DroppedRunReaper::spawn()?;
        Ok(Self {
            runs: runs.clone(),
            reaper: Some(reaper),
            reaping: Some(reaping),
        })
    }

    pub fn terminal_factory(
        &self,
        client: crate::native_exit_broker::BrokerClient,
    ) -> crate::terminal_cleanup::CleanupFactory {
        crate::terminal_cleanup::CleanupFactory::new(
            client,
            self.runs.clone(),
            self.reaper.clone().expect("KVM run admission finished"),
        )
    }

    pub fn root(&self, executor: ElfExecutor) -> RunningRoot {
        RunningRoot {
            executor: Some(executor),
            runs: self.runs.clone(),
            reaper: self.reaper.clone().expect("KVM run admission finished"),
        }
    }

    /// A run that returned joined its own children, and on every natural
    /// path its workers, so its reaper has nothing to retire and stops at
    /// once; joining it here means no reaper outlives a returned run. An
    /// error can return before the workers were joined; that run is abandoned
    /// instead, so its backend admits nothing more and its drop hands them to
    /// this reaper rather than waiting for them.
    pub fn finish(mut self, workers: &dyn GuestWorkers) {
        if workers.has_unjoined_workers() {
            return;
        }
        let reaper = self.reaper.take().expect("KVM run admission finished");
        let reaping = self.reaping.take().expect("KVM run admission finished");
        if reaper.release() {
            // The reaper runs no embedder code, and this released its last
            // handle with nothing adopted, so this join is bounded.
            let _ = reaping.join();
        }
    }
}

impl Drop for RunAdmission {
    fn drop(&mut self) {
        if let Some(reaper) = self.reaper.take() {
            // The reaper thread outlives this handle: it exits on its own
            // once it has retired whatever the backend's drop hands it.
            AbandonedRuns::lock(&self.runs).abandon(&reaper);
        }
    }
}

/// Owns a public run's root executor while its guest runs. If the run's future
/// is dropped there, dropping the executor would detach every child host
/// thread it has not reaped. Instead this releases the root's descriptors, as
/// its exit would, so no child waits on them, and parks the executor, with
/// every child it owns, in its backend's `AbandonedRuns`.
pub struct RunningRoot {
    pub(super) executor: Option<ElfExecutor>,
    pub(super) runs: Arc<Mutex<AbandonedRuns>>,
    pub(super) reaper: DroppedRunReaper,
}

impl RunningRoot {
    /// The run returned, so its root has already joined its children.
    pub fn returned(mut self) -> ElfExecutor {
        self.executor
            .take()
            .expect("KVM root executor already returned")
    }
}

impl std::ops::Deref for RunningRoot {
    type Target = ElfExecutor;

    fn deref(&self) -> &ElfExecutor {
        self.executor
            .as_ref()
            .expect("KVM root executor already returned")
    }
}

impl std::ops::DerefMut for RunningRoot {
    fn deref_mut(&mut self) -> &mut ElfExecutor {
        self.executor
            .as_mut()
            .expect("KVM root executor already returned")
    }
}

impl Drop for RunningRoot {
    fn drop(&mut self) {
        if let Some(mut executor) = self.executor.take() {
            executor.release_files_on_exit();
            let mut runs = AbandonedRuns::lock(&self.runs);
            runs.abandon(&self.reaper);
            runs.roots.push(executor);
        }
    }
}

/// What a dropped run leaves its reaper: the run's guest workers, then its
/// roots. Each step leaves what it has not finished in place, so a step that
/// panics can be retried without dropping, and so detaching, anything.
pub(crate) struct Retirement {
    pub(super) workers: Option<Arc<dyn GuestWorkers>>,
    pub(super) roots: Vec<ElfExecutor>,
    pub(super) terminal: Vec<ChildThread>,
}

impl Retirement {
    #[cfg_attr(not(any(test, feature = "test-support")), allow(unused_variables))]
    fn advance(&mut self, reaper: &ReaperShared) {
        // Services already run independently; join them before waiting for a
        // guest that may need their descriptor retirement to observe EOF.
        while let Some(thread) = self.terminal.first_mut() {
            let joined = thread.join_blocking();
            self.terminal.remove(0);
            if let Err(payload) = joined {
                reaper.lock().retained_panics.push(payload);
            }
        }
        if let Some(workers) = &self.workers {
            workers.join_workers();
            self.workers = None;
        }
        while let Some(root) = self.roots.first_mut() {
            #[cfg(any(test, feature = "test-support"))]
            reaper.injected_panic();
            // No caller remains to receive a dropped run's result. A child's
            // panic payload is already retained by its run.
            let _ = root.join_child_processes_after_failure();
            drop(self.roots.remove(0));
        }
    }
}

#[derive(Default)]
pub(super) struct ReaperState {
    pub(super) adopted: Vec<Retirement>,
    /// Live `DroppedRunReaper`s. Only they can adopt, so with none left and
    /// nothing adopted, the reaper stops.
    pub(super) handles: usize,
    pub(super) retained_panics: Vec<Box<dyn std::any::Any + Send>>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) inject_panics: usize,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) attempts: usize,
}

#[derive(Default)]
pub(crate) struct ReaperShared {
    pub(super) state: Mutex<ReaperState>,
    pub(super) changed: Condvar,
}

impl ReaperShared {
    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, ReaperState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn injected_panic(&self) {
        let mut state = self.lock();
        if state.inject_panics > 0 {
            state.inject_panics -= 1;
            drop(state);
            panic!("injected dropped-run retirement panic");
        }
    }
}

/// Joins what one dropped public run left running. Such a child, or guest
/// worker, runs to its own exit, as it would had its run returned, and may
/// need turns from the embedder's scheduler to get there, so no thread that
/// may be the embedder's executor can wait for it; a backend's drop is such a
/// thread. So each public run spawns its own reaper before it starts, and a
/// run that never exits delays no other run's retirement. Like the init
/// process that adopts orphans, a reaper holds what it adopted until it has
/// joined every thread that owns, and never drops it earlier.
pub(crate) struct DroppedRunReaper {
    pub(super) shared: Arc<ReaperShared>,
}

impl DroppedRunReaper {
    pub(crate) fn retain_panic(&self, payload: Box<dyn std::any::Any + Send>) {
        self.shared.lock().retained_panics.push(payload);
    }

    pub(super) fn spawn() -> crate::Result<(Self, std::thread::JoinHandle<()>)> {
        let shared = Arc::new(ReaperShared::default());
        shared.lock().handles = 1;
        let reaping = crate::failure::spawn_owned(
            std::thread::Builder::new().name("reverie-kvm-reaper".into()),
            shared.clone(),
            Self::reap,
        )
        .map_err(|(error, _)| crate::Error::from(error).cleanup("dropped-run reaper spawn"))?;
        Ok((Self { shared }, reaping))
    }

    fn reap(shared: Arc<ReaperShared>) {
        // A retirement step's panic breaks an invariant, but the retirement
        // still owns every thread it has not joined, so it is retried, never
        // dropped: a join that cannot finish keeps its threads here rather
        // than detach them. Each payload is kept until the reaper stops.
        let mut panics = Vec::new();
        let mut state = shared.lock();
        loop {
            if !state.adopted.is_empty() {
                let mut retirement = state.adopted.remove(0);
                drop(state);
                let mut backoff = std::time::Duration::from_millis(1);
                loop {
                    #[cfg(any(test, feature = "test-support"))]
                    {
                        shared.lock().attempts += 1;
                    }
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        retirement.advance(&shared)
                    })) {
                        Ok(()) => break,
                        Err(payload) => panics.push(payload),
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(std::time::Duration::from_secs(1));
                }
                state = shared.lock();
            } else if state.handles == 0 {
                return;
            } else {
                state = shared
                    .changed
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
    }

    /// Never blocks and cannot fail: the reaper stops only once no handle, so
    /// no adopter, remains.
    pub(crate) fn adopt(&self, retirement: Retirement) {
        self.shared.lock().adopted.push(retirement);
        self.shared.changed.notify_all();
    }

    /// Drops this handle, reporting whether it was the last and the reaper
    /// had adopted nothing, so that the reaper stops at once.
    fn release(self) -> bool {
        let idle = {
            let state = self.shared.lock();
            state.handles == 1 && state.adopted.is_empty()
        };
        drop(self);
        idle
    }
}

impl Clone for DroppedRunReaper {
    fn clone(&self) -> Self {
        self.shared.lock().handles += 1;
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for DroppedRunReaper {
    fn drop(&mut self) {
        self.shared.lock().handles -= 1;
        self.shared.changed.notify_all();
    }
}

impl Drop for ElfExecutor {
    fn drop(&mut self) {
        if self.terminal_cleanup.is_some() {
            self.release_files_on_exit();
        }
        // Native release already consumed this token before handing off files.
        // Ordinary destruction also relinquishes task ownership before any
        // lifecycle guard or the later implicit file-table field destruction.
        drop(self.file_table_task_owner.take());
        self.signal_registry
            .retire_task(self.admitted_signal_identity());
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let mut lifecycle = self
            .state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lifecycle.remove(self.state.tid, self.task_generation);
        if self.state.tid == self.state.pid {
            lifecycle.forget_process_exit(self.state.pid, self.process_generation);
        }
    }
}

pub(super) fn validate_process_clone_flags(flags: u64) -> Result<(), i64> {
    let signal = flags & 0xff;
    if signal != 0 && signal != libc::SIGCHLD as u64 {
        return Err(negative_errno(libc::EINVAL));
    }
    let allowed = 0xff
        | libc::CLONE_VM as u64
        | libc::CLONE_VFORK as u64
        | libc::CLONE_PARENT_SETTID as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64
        // The fork action clears caught handlers in the child snapshot.
        | CLONE_CLEAR_SIGHAND;
    if flags & !allowed != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    let shared_address_space = flags & (libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64);
    if shared_address_space != 0
        && shared_address_space != (libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64)
    {
        return Err(negative_errno(libc::ENOTSUP));
    }
    if shared_address_space != 0 && flags & PROCESS_CLONE_TID_FLAGS != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    Ok(())
}

// TODO-HUMAN-REVIEW(PR-132): Review the accepted glibc pthread clone flag profile.
fn validate_thread_clone_flags(flags: u64) -> Result<(), i64> {
    if flags & 0xff != 0 {
        return Err(negative_errno(libc::EINVAL));
    }
    if flags & THREAD_CLONE_REQUIRED_FLAGS != THREAD_CLONE_REQUIRED_FLAGS {
        return Err(negative_errno(libc::EINVAL));
    }
    if flags & !THREAD_CLONE_ALLOWED_FLAGS != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    Ok(())
}

pub(super) struct CloneRequest {
    pub(super) flags: u64,
    pub(super) child_stack: Option<u64>,
    pub(super) parent_tid: Option<u64>,
    pub(super) child_tid: Option<u64>,
    pub(super) tls: Option<u64>,
}

pub(super) fn read_clone3<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    address: u64,
    size: u64,
) -> Result<CloneRequest, i64> {
    const REQUIRED_SIZE: usize = 64;
    const MAX_SIZE: usize = 88;

    let Ok(size) = usize::try_from(size) else {
        return Err(negative_errno(libc::E2BIG));
    };
    if size < REQUIRED_SIZE {
        return Err(negative_errno(libc::EINVAL));
    }
    if size > PAGE_SIZE as usize {
        return Err(negative_errno(libc::E2BIG));
    }
    let mut bytes = [0; MAX_SIZE];
    memory
        .read_exact(address, &mut bytes[..size.min(MAX_SIZE)])
        .map_err(|_| negative_errno(libc::EFAULT))?;
    if size > MAX_SIZE {
        let mut extension = vec![0; size - MAX_SIZE];
        memory
            .read_exact(address + MAX_SIZE as u64, &mut extension)
            .map_err(|_| negative_errno(libc::EFAULT))?;
        if extension.iter().any(|byte| *byte != 0) {
            return Err(negative_errno(libc::E2BIG));
        }
    }
    let field = |offset: usize| {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("u64 clone3 field"),
        )
    };
    // clone3 ignores pidfd unless CLONE_PIDFD is set. glibc leaves that union
    // slot nonzero for pthread clones even though the flag is absent.
    if field(64) != 0 || field(72) != 0 || field(80) != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    let flags = field(0) | field(32);
    let stack = field(40);
    let stack_size = field(48);
    if (stack == 0) != (stack_size == 0) {
        return Err(negative_errno(libc::EINVAL));
    }
    let child_stack = if stack == 0 {
        None
    } else {
        stack.checked_add(stack_size)
    };
    if stack != 0 && child_stack.is_none() {
        return Err(negative_errno(libc::EINVAL));
    }
    Ok(CloneRequest {
        flags,
        child_stack,
        parent_tid: (field(24) != 0).then(|| field(24)),
        child_tid: (field(16) != 0).then(|| field(16)),
        tls: (flags & libc::CLONE_SETTLS as u64 != 0).then(|| field(56)),
    })
}
