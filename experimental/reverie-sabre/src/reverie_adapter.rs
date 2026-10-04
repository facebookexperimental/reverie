/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Adapter from SaBRe callbacks to Reverie's shared tool interface.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use parking_lot::Mutex;
use reverie::Backtrace;
use reverie::Error;
use reverie::ExitStatus;
use reverie::Frame;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Rdtsc;
use reverie::Signal;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool as ReverieTool;
use reverie_memory::MemoryAccess;
use reverie_preload::tool_host::DrivenSyscall;
use reverie_preload::tool_host::TailResult;
use reverie_preload::tool_host::drive_tool_syscall;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RpcError;
use reverie_syscalls::Addr;
use reverie_syscalls::AddrMut;
use reverie_syscalls::Errno;
use reverie_syscalls::Syscall;
use reverie_syscalls::SyscallInfo;
use syscalls::SyscallArgs;
use syscalls::Sysno;
use syscalls::syscall;

use crate::SyscallExt;
use crate::protected_files::ProtectedFd;
use crate::protected_files::protect_with;

type ThreadStateCell<T> = Arc<Mutex<LocalThreadState<T>>>;

struct LocalThreadState<T>
where
    T: ReverieTool,
{
    thread_state: Option<T::ThreadState>,
    exit_handled: bool,
}

/// Runs one shared Reverie tool inside a SaBRe plugin process.
///
/// SaBRe callbacks are synchronous. Subscribed syscall handlers use the shared
/// in-guest driver to poll through synchronous RPC progress and
/// [`Guest::tail_inject`]. Lifecycle and instruction handlers retain their
/// one-poll behavior and fail closed when they suspend.
// AUTONOMOUS-BOT-IMPLEMENTED
pub struct ReverieAdapter<T>
where
    T: ReverieTool,
{
    tool: T,
    global_state: T::GlobalState,
    config: <T::GlobalState as GlobalTool>::Config,
    thread_states: Mutex<HashMap<i32, ThreadStateCell<T>>>,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-142): Review local syscall-subscription caching and bypass.
    syscall_subscriptions: BTreeSet<Sysno>,
}

impl<T> ReverieAdapter<T>
where
    T: ReverieTool,
{
    /// Creates an adapter from already-initialized shared tool state.
    pub fn new(
        tool: T,
        global_state: T::GlobalState,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Self {
        let _ = root_process_pid();
        let syscall_subscriptions = T::subscriptions(&config).iter_syscalls().collect();
        Self {
            tool,
            global_state,
            config,
            thread_states: Mutex::new(HashMap::new()),
            syscall_subscriptions,
        }
    }

    /// Forwards an intercepted syscall to [`ReverieTool::handle_syscall_event`].
    pub fn handle_syscall(&self, syscall: Syscall) -> Result<usize, Errno> {
        self.dispatch_syscall(syscall, None)
    }

    /// Forwards a runtime-bookkept syscall through the shared tool.
    pub fn handle_syscall_with_inject<F>(
        &self,
        syscall: Syscall,
        mut inject: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut() -> usize + Send + Sync,
    {
        self.dispatch_syscall(syscall, Some(&mut inject))
    }

    fn dispatch_syscall(
        &self,
        syscall: Syscall,
        special_inject: Option<&mut (dyn FnMut() -> usize + Send + Sync)>,
    ) -> Result<usize, Errno> {
        if !self.syscall_subscriptions.contains(&syscall.number()) {
            return bypass_tool(syscall, special_inject);
        }
        let original = Some(syscall.into_parts());
        let tid = current_tid();
        let pid = current_pid();
        let state = self.thread_state(tid);
        let mut state = state.lock();
        let LocalThreadState {
            thread_state,
            exit_handled,
        } = &mut *state;
        let rpc: SabreRpc<'_, T> = SabreRpc {
            tid,
            global_state: &self.global_state,
            config: &self.config,
        };
        let tail = TailResult::default();
        let mut guest = SabreGuest::new(
            tid,
            pid,
            thread_state,
            &rpc,
            Some((&self.tool, exit_handled, None)),
            original,
            special_inject,
        )
        .with_tail(&tail);

        shared_result(drive_tool_syscall(&self.tool, &mut guest, syscall, &tail))
    }

    /// Allocates the shared tool's state for a newly observed guest thread.
    pub fn handle_thread_start(&self, thread_id: u32) {
        let tid = Pid::from_raw(thread_id as i32);
        let state = self.thread_state(tid);
        let mut state = state.lock();
        let LocalThreadState {
            thread_state,
            exit_handled,
        } = &mut *state;
        let rpc: SabreRpc<'_, T> = SabreRpc {
            tid,
            global_state: &self.global_state,
            config: &self.config,
        };
        let mut guest = SabreGuest::new(
            tid,
            current_pid(),
            thread_state,
            &rpc,
            Some((&self.tool, exit_handled, None)),
            None,
            None,
        );
        match poll_once(self.tool.handle_thread_start(&mut guest)) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: Tool::handle_thread_start failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: Tool::handle_thread_start suspended and was dropped"
                );
            }
        }
    }

    /// Delivers the shared tool's post-exec callback after the loader has
    /// installed the rewritten guest image.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-194): Review local post-exec lifecycle delivery.
    pub fn handle_post_exec(&self) {
        let tid = current_tid();
        let state = self.thread_state(tid);
        let mut state = state.lock();
        let LocalThreadState {
            thread_state,
            exit_handled,
        } = &mut *state;
        let rpc: SabreRpc<'_, T> = SabreRpc {
            tid,
            global_state: &self.global_state,
            config: &self.config,
        };
        let mut guest = SabreGuest::new(
            tid,
            current_pid(),
            thread_state,
            &rpc,
            Some((&self.tool, exit_handled, None)),
            None,
            None,
        );
        match poll_once(self.tool.handle_post_exec(&mut guest)) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: Tool::handle_post_exec failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!("reverie-sabre: Tool::handle_post_exec suspended and was dropped");
            }
        }
    }

    /// Delivers the consuming process-exit callback using a snapshot of the
    /// process-local tool state.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-194): Review local process-exit lifecycle delivery.
    pub fn handle_process_exit(&self, exit_status: ExitStatus)
    where
        T: Clone,
    {
        let tid = current_tid();
        let rpc: SabreRpc<'_, T> = SabreRpc {
            tid,
            global_state: &self.global_state,
            config: &self.config,
        };
        match poll_once(
            self.tool
                .clone()
                .on_exit_process(current_pid(), &rpc, exit_status),
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: Tool::on_exit_process failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!("reverie-sabre: Tool::on_exit_process suspended and was dropped");
            }
        }
    }

    /// Delivers the shared tool's thread-exit callback and releases its state.
    pub fn handle_thread_exit(&self, thread_id: u32) {
        let tid = Pid::from_raw(thread_id as i32);
        let state = self.thread_states.lock().remove(&tid.as_raw());
        let Some(state) = state else {
            return;
        };
        // exit/exit_group can re-enter here from Guest::inject while the
        // handler still owns this state. Blocking would deadlock a terminating
        // thread, so omit its destructor callback in that case.
        let Some(mut state_guard) = state.try_lock() else {
            return;
        };
        if state_guard.exit_handled {
            return;
        }
        state_guard.exit_handled = true;
        let Some(state) = state_guard.thread_state.take() else {
            return;
        };

        let rpc: SabreRpc<'_, T> = SabreRpc {
            tid,
            global_state: &self.global_state,
            config: &self.config,
        };
        match poll_once(
            self.tool
                .on_exit_thread(tid, &rpc, state, ExitStatus::Exited(0)),
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: Tool::on_exit_thread failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!("reverie-sabre: Tool::on_exit_thread suspended and was dropped");
            }
        }
    }

    fn thread_state(&self, tid: Pid) -> ThreadStateCell<T> {
        self.thread_states
            .lock()
            .entry(tid.as_raw())
            .or_insert_with(|| {
                Arc::new(Mutex::new(LocalThreadState {
                    thread_state: Some(self.tool.init_thread_state(tid, None)),
                    exit_handled: false,
                }))
            })
            .clone()
    }
}

/// Runs a shared Reverie tool in a SaBRe plugin while its GlobalTool lives in
/// an external coordinator.
///
/// The adapter opens one blocking RPC connection per guest thread. The socket
/// response is allowed to wait for scheduler progress, but the surrounding
/// SaBRe callback still observes a handler future that completes on its first
/// poll.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-128): Review the remote SaBRe adapter and per-thread RPC lifecycle.
pub struct RemoteReverieAdapter<T>
where
    T: ReverieTool,
{
    tool: T,
    config: <T::GlobalState as GlobalTool>::Config,
    socket_path: std::path::PathBuf,
    thread_states: Mutex<HashMap<i32, Arc<Mutex<RemoteThreadState<T>>>>>,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-209): Review parent-state handoff for SaBRe thread clones.
    thread_clones_pending: Arc<AtomicUsize>,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-142): Review remote syscall-subscription caching and bypass.
    syscall_subscriptions: BTreeSet<Sysno>,
}

struct RemoteThreadState<T>
where
    T: ReverieTool,
{
    thread_state: Option<T::ThreadState>,
    // TODO-HUMAN-REVIEW(PR-212): Review protection of the coordinator socket
    // from fork children that close inherited descriptors before exec.
    rpc: ProtectedFd<BlockingRpcClient<T::GlobalState>>,
    exit_handled: bool,
}

struct PendingThreadClone(Arc<AtomicUsize>);

impl PendingThreadClone {
    fn new(pending: Arc<AtomicUsize>) -> Self {
        pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("too many concurrent SaBRe thread clones");
        Self(pending)
    }
}

impl Drop for PendingThreadClone {
    fn drop(&mut self) {
        let previous = self.0.fetch_sub(1, Ordering::Release);
        debug_assert!(previous > 0, "SaBRe thread-clone count underflow");
    }
}

struct PendingProcessFork {
    parent_pid: Pid,
}

impl Drop for PendingProcessFork {
    fn drop(&mut self) {
        // A fork child resumes directly in guest code without unwinding the
        // plugin callback. Only the returning parent may clear its copy.
        if current_pid() == self.parent_pid {
            PROCESS_FORK_HANDOFF.lock().take();
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-273): Review fork-safe state transfer across ProcessCell reinitialization.
struct ProcessForkHandoff {
    parent_pid: Pid,
    parent_tid: Pid,
    thread_state: Vec<u8>,
}

static PROCESS_FORK_HANDOFF: Mutex<Option<ProcessForkHandoff>> = Mutex::new(None);

struct ChildThreadRegistry<'a, T>
where
    T: ReverieTool,
{
    states: &'a Mutex<HashMap<i32, Arc<Mutex<RemoteThreadState<T>>>>>,
    socket_path: &'a Path,
    thread_clones_pending: Arc<AtomicUsize>,
}

impl<T> RemoteReverieAdapter<T>
where
    T: ReverieTool,
{
    /// Connects the root guest thread and constructs the process-local tool
    /// from the coordinator's config handshake.
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self, RpcError> {
        Self::connect_with_root_initializer(socket_path, |_, _, _| Ok(()))
    }

    /// Applies an explicit state handoff to a normally initialized root before
    /// any thread callback. An inherited fork state keeps its existing path
    /// and does not run this initializer. A loader bootstrap consumer takes
    /// its opaque payload inside this initializer, after that fork decision.
    /// The normal config handshake happens first; no typed tool RPC or thread
    /// callback has run. The initializer receives no RPC client and must not
    /// publish readiness. In particular, bootstrap is not evidence for the
    /// first-request readiness reported by `RpcServer::bind_with_readiness`.
    ///
    /// Consumers own the payload type/config/image checks and must only change
    /// their declared fields (for example PRNG state and an auxv completion
    /// fact), retaining clocks, metadata and other unrelated initialized state.
    pub fn connect_with_root_initializer<F>(
        socket_path: impl AsRef<Path>,
        initialize: F,
    ) -> Result<Self, RpcError>
    where
        F: FnOnce(
            &<T::GlobalState as GlobalTool>::Config,
            Pid,
            &mut T::ThreadState,
        ) -> Result<(), RpcError>,
    {
        let _ = root_process_pid();
        let socket_path = socket_path.as_ref().to_path_buf();
        let tid = current_tid();
        let rpc = protect_with(|| BlockingRpcClient::<T::GlobalState>::connect(&socket_path, tid))?;
        let config = rpc.as_ref().config().clone();
        let tool = T::new(current_pid(), &config);
        let thread_state = match take_process_fork_handoff(&tool, tid)? {
            Some(inherited) => inherited,
            None => {
                let mut state = tool.init_thread_state(tid, None);
                initialize(&config, tid, &mut state)?;
                state
            }
        };
        let syscall_subscriptions = T::subscriptions(&config).iter_syscalls().collect();
        let mut thread_states = HashMap::new();
        thread_states.insert(
            tid.as_raw(),
            Arc::new(Mutex::new(RemoteThreadState {
                thread_state: Some(thread_state),
                rpc,
                exit_handled: false,
            })),
        );
        Ok(Self {
            tool,
            config,
            socket_path,
            thread_states: Mutex::new(thread_states),
            thread_clones_pending: Arc::new(AtomicUsize::new(0)),
            syscall_subscriptions,
        })
    }

    /// Returns the coordinator-provided static tool config.
    pub fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        &self.config
    }

    /// Forwards an intercepted syscall through the shared tool and remote
    /// GlobalTool.
    pub fn handle_syscall(&self, syscall: Syscall) -> Result<usize, Errno> {
        self.dispatch_syscall(syscall, None)
    }

    /// Forwards an intercepted RDTSC instruction through the shared tool and
    /// remote GlobalTool.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-144): Review SaBRe RDTSC forwarding.
    pub fn handle_rdtsc(&self) -> Result<u64, Errno> {
        let tid = current_tid();
        let pid = current_pid();
        let state = self.thread_state(tid).map_err(remote_rpc_error)?;
        let mut state = state.lock();
        let RemoteThreadState {
            thread_state,
            rpc,
            exit_handled,
        } = &mut *state;
        let mut guest = SabreGuest::new(
            tid,
            pid,
            thread_state,
            rpc.as_ref(),
            Some((&self.tool, exit_handled, None)),
            None,
            None,
        );

        match poll_once(self.tool.handle_rdtsc_event(&mut guest, Rdtsc::Tsc)) {
            Poll::Ready(Ok(result)) => Ok(result.tsc),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: remote Tool::handle_rdtsc_event suspended and was dropped"
                );
                Err(Errno::EIO)
            }
        }
    }

    /// Forwards an intercepted signal through the shared tool and remote
    /// GlobalTool, before the guest's handler runs.
    ///
    /// ⚠️ WHY THIS EXISTS: the remote adapter carried syscalls, RDTSC and thread
    /// lifecycle, but NOT signals. `Tool::handle_signal_event` therefore stayed
    /// the default no-op under this backend, so a Detcore-style tool recorded no
    /// signal event and never made the scheduler request it needs -- its model of
    /// the guest simply had no signals in it. The hermit-side half of this
    /// (rrnewton/hermit#2321) has been unbuildable for want of this method.
    ///
    /// Returns what the tool decided: `Some(sig)` to deliver, `None` to suppress.
    /// Suppression is reported rather than silently honoured by the caller,
    /// because SaBRe's central handler has usually already committed to the guest
    /// action by the time this runs.
    pub fn handle_signal(&self, signal: Signal) -> Result<Option<Signal>, Errno> {
        let tid = current_tid();
        let pid = current_pid();
        let state = self.thread_state(tid).map_err(remote_rpc_error)?;
        let mut state = state.lock();
        let RemoteThreadState {
            thread_state,
            rpc,
            exit_handled,
        } = &mut *state;
        let mut guest = SabreGuest::new(
            tid,
            pid,
            thread_state,
            rpc.as_ref(),
            Some((&self.tool, exit_handled, None)),
            None,
            None,
        );

        match poll_once(self.tool.handle_signal_event(&mut guest, signal)) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                // Same failure mode the RDTSC path guards: a tool that suspends
                // here cannot be resumed, so say so rather than dropping the
                // signal decision on the floor.
                crate::eprintln!(
                    "reverie-sabre: remote Tool::handle_signal_event suspended and was dropped"
                );
                Err(Errno::EIO)
            }
        }
    }

    /// Forwards a runtime-bookkept syscall through the shared tool and remote
    /// GlobalTool.
    pub fn handle_syscall_with_inject<F>(
        &self,
        syscall: Syscall,
        mut inject: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut() -> usize + Send + Sync,
    {
        self.dispatch_syscall(syscall, Some(&mut inject))
    }

    fn dispatch_syscall(
        &self,
        syscall: Syscall,
        special_inject: Option<&mut (dyn FnMut() -> usize + Send + Sync)>,
    ) -> Result<usize, Errno> {
        if !self.syscall_subscriptions.contains(&syscall.number()) {
            return bypass_tool(syscall, special_inject);
        }
        let original = Some(syscall.into_parts());
        let tid = current_tid();
        let pid = current_pid();
        let state = self.thread_state(tid).map_err(remote_rpc_error)?;
        let mut state = state.lock();
        let RemoteThreadState {
            thread_state,
            rpc,
            exit_handled,
        } = &mut *state;
        let tail = TailResult::default();
        let mut guest = SabreGuest::new(
            tid,
            pid,
            thread_state,
            rpc.as_ref(),
            Some((
                &self.tool,
                exit_handled,
                Some(ChildThreadRegistry {
                    states: &self.thread_states,
                    socket_path: &self.socket_path,
                    thread_clones_pending: self.thread_clones_pending.clone(),
                }),
            )),
            original,
            special_inject,
        )
        .with_tail(&tail);

        shared_result(drive_tool_syscall(&self.tool, &mut guest, syscall, &tail))
    }

    /// Allocates remote RPC and tool state for a newly observed guest thread.
    pub fn handle_thread_start(&self, thread_id: u32) {
        let tid = Pid::from_raw(thread_id as i32);
        let state = match self.thread_state(tid) {
            Ok(state) => state,
            Err(error) => {
                remote_rpc_error(error);
                return;
            }
        };
        let mut state = state.lock();
        let RemoteThreadState {
            thread_state,
            rpc,
            exit_handled,
        } = &mut *state;
        let mut guest = SabreGuest::new(
            tid,
            current_pid(),
            thread_state,
            rpc.as_ref(),
            Some((&self.tool, exit_handled, None)),
            None,
            None,
        );
        match poll_once(self.tool.handle_thread_start(&mut guest)) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: remote Tool::handle_thread_start failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: remote Tool::handle_thread_start suspended and was dropped"
                );
            }
        }
    }

    /// Delivers the shared tool's post-exec callback through the coordinator.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-194): Review remote post-exec lifecycle delivery.
    pub fn handle_post_exec(&self) {
        let tid = current_tid();
        let state = match self.thread_state(tid) {
            Ok(state) => state,
            Err(error) => {
                remote_rpc_error(error);
                return;
            }
        };
        let mut state = state.lock();
        let RemoteThreadState {
            thread_state,
            rpc,
            exit_handled,
        } = &mut *state;
        let mut guest = SabreGuest::new(
            tid,
            current_pid(),
            thread_state,
            rpc.as_ref(),
            Some((&self.tool, exit_handled, None)),
            None,
            None,
        );
        match poll_once(self.tool.handle_post_exec(&mut guest)) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: remote Tool::handle_post_exec failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: remote Tool::handle_post_exec suspended and was dropped"
                );
            }
        }
    }

    /// Delivers the consuming process-exit callback over a final coordinator
    /// connection after thread-local RPC connections have begun shutting down.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-194): Review remote process-exit lifecycle delivery.
    pub fn handle_process_exit(&self, exit_status: ExitStatus)
    where
        T: Clone,
    {
        let pid = current_pid();
        let rpc = match protect_with(|| {
            BlockingRpcClient::<T::GlobalState>::connect(&self.socket_path, pid)
        }) {
            Ok(rpc) => rpc,
            Err(error) => {
                remote_rpc_error(error);
                return;
            }
        };
        match poll_once(
            self.tool
                .clone()
                .on_exit_process(pid, rpc.as_ref(), exit_status),
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: remote Tool::on_exit_process failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: remote Tool::on_exit_process suspended and was dropped"
                );
            }
        }
    }

    /// Runs the remote tool's thread destructor and closes its RPC connection.
    pub fn handle_thread_exit(&self, thread_id: u32) {
        let tid = Pid::from_raw(thread_id as i32);
        let state = self.thread_states.lock().remove(&tid.as_raw());
        let Some(state) = state else {
            return;
        };
        let Some(mut state) = state.try_lock() else {
            return;
        };
        if state.exit_handled {
            return;
        }
        state.exit_handled = true;
        let Some(thread_state) = state.thread_state.take() else {
            return;
        };
        match poll_once(self.tool.on_exit_thread(
            tid,
            state.rpc.as_ref(),
            thread_state,
            ExitStatus::Exited(0),
        )) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                crate::eprintln!("reverie-sabre: remote Tool::on_exit_thread failed: {error}");
            }
            Poll::Pending => {
                crate::eprintln!(
                    "reverie-sabre: remote Tool::on_exit_thread suspended and was dropped"
                );
            }
        }
    }

    fn thread_state(&self, tid: Pid) -> Result<Arc<Mutex<RemoteThreadState<T>>>, RpcError> {
        if let Some(state) = wait_for_inherited_thread_state(
            &self.thread_states,
            &self.thread_clones_pending,
            tid.as_raw(),
        ) {
            return Ok(state);
        }

        let rpc = protect_with(|| BlockingRpcClient::connect(&self.socket_path, tid))?;
        let state = Arc::new(Mutex::new(RemoteThreadState {
            thread_state: Some(self.tool.init_thread_state(tid, None)),
            rpc,
            exit_handled: false,
        }));
        Ok(self
            .thread_states
            .lock()
            .entry(tid.as_raw())
            .or_insert_with(|| state.clone())
            .clone())
    }
}

fn wait_for_inherited_thread_state<S: Clone>(
    states: &Mutex<HashMap<i32, S>>,
    pending: &AtomicUsize,
    tid: i32,
) -> Option<S> {
    wait_for_inherited_thread_state_after_miss(states, pending, tid, || {})
}

fn wait_for_inherited_thread_state_after_miss<S: Clone, F: FnMut()>(
    states: &Mutex<HashMap<i32, S>>,
    pending: &AtomicUsize,
    tid: i32,
    mut after_miss: F,
) -> Option<S> {
    loop {
        if let Some(state) = states.lock().get(&tid).cloned() {
            return Some(state);
        }
        after_miss();
        if pending.load(Ordering::Acquire) == 0 {
            // A parent publishes the inherited state before its pending guard
            // performs the release decrement. Recheck after observing zero so
            // a child cannot miss an insertion between the first lookup and
            // the counter load.
            return states.lock().get(&tid).cloned();
        }
        std::thread::yield_now();
    }
}

fn take_process_fork_handoff<T>(tool: &T, child: Pid) -> Result<Option<T::ThreadState>, RpcError>
where
    T: ReverieTool,
{
    let mut slot = PROCESS_FORK_HANDOFF.lock();
    let Some(handoff) = slot.as_ref() else {
        return Ok(None);
    };
    if handoff.parent_pid == current_pid() {
        return Ok(None);
    }
    let handoff = slot.take().unwrap();
    drop(slot);
    let parent_state = reverie_rpc_transport::codec::decode(&handoff.thread_state)?;
    Ok(Some(tool.init_thread_state(
        child,
        Some((handoff.parent_tid, &parent_state)),
    )))
}

fn remote_rpc_error(error: RpcError) -> Errno {
    crate::eprintln!("reverie-sabre: coordinator RPC failed: {error}");
    Errno::EIO
}
fn shared_result(result: DrivenSyscall) -> Result<usize, Errno> {
    match result {
        DrivenSyscall::Result(value) => Errno::from_ret(value as usize),
        DrivenSyscall::Fatal(error) => {
            crate::eprintln!("reverie-sabre: shared tool failed: {error}");
            Err(Errno::EIO)
        }
        DrivenSyscall::Exit { .. } | DrivenSyscall::ForkChild { .. } => {
            crate::eprintln!("reverie-sabre: unsupported shared tool transition");
            Err(Errno::EIO)
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-142): Review direct and process-control bypass semantics.
fn bypass_tool(
    syscall: Syscall,
    special_inject: Option<&mut (dyn FnMut() -> usize + Send + Sync)>,
) -> Result<usize, Errno> {
    if let Some(inject) = special_inject {
        // A process-control injector can resume in a child without unwinding.
        // Clear the parent callback frame across that potentially diverging call.
        let _frame_suspended = crate::callbacks::SyscallFrameGuard::suspend();
        return Errno::from_ret(inject());
    }
    unsafe { syscall.call() }
}

fn current_pid() -> Pid {
    let pid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getpid) };
    Pid::from_raw(pid as i32)
}

static ROOT_PROCESS_PID: AtomicI32 = AtomicI32::new(0);

fn root_process_pid() -> Pid {
    let current = current_pid().as_raw();
    let root = ROOT_PROCESS_PID.load(Ordering::Acquire);
    if root != 0 {
        return Pid::from_raw(root);
    }
    let root = ROOT_PROCESS_PID
        .compare_exchange(0, current, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|root| root);
    Pid::from_raw(root)
}

fn current_tid() -> Pid {
    let tid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) };
    Pid::from_raw(tid as i32)
}

/// Kernel-validated access to memory in the SaBRe guest process.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-153): Review SaBRe process memory access semantics.
#[derive(Clone, Copy, Debug)]
pub struct SabreMemory {
    pid: Pid,
}

impl SabreMemory {
    fn new(pid: Pid) -> Self {
        Self { pid }
    }

    fn transfer_result(result: Result<usize, Errno>) -> Result<usize, Errno> {
        result.or_else(|error| {
            if error == Errno::EFAULT {
                // MemoryAccess treats a fault like an EOF so read_exact and
                // write_exact can consistently report EFAULT.
                Ok(0)
            } else {
                Err(error)
            }
        })
    }
}

impl MemoryAccess for SabreMemory {
    fn read_vectored(
        &self,
        remote: &[io::IoSlice],
        local: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        let result = unsafe {
            syscall!(
                Sysno::process_vm_readv,
                self.pid.as_raw() as usize,
                local.as_ptr() as usize,
                local.len(),
                remote.as_ptr() as usize,
                remote.len(),
                0
            )
        };
        Self::transfer_result(result)
    }

    fn write_vectored(
        &mut self,
        local: &[io::IoSlice],
        remote: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        let result = unsafe {
            syscall!(
                Sysno::process_vm_writev,
                self.pid.as_raw() as usize,
                local.as_ptr() as usize,
                local.len(),
                remote.as_ptr() as usize,
                remote.len(),
                0
            )
        };
        Self::transfer_result(result)
    }

    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let remote = libc::iovec {
            iov_base: unsafe { addr.into().as_ptr() as *mut libc::c_void },
            iov_len: buf.len(),
        };
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let result = unsafe {
            syscall!(
                Sysno::process_vm_readv,
                self.pid.as_raw() as usize,
                &local as *const libc::iovec as usize,
                1,
                &remote as *const libc::iovec as usize,
                1,
                0
            )
        };
        Self::transfer_result(result)
    }

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        let local = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: unsafe { addr.as_mut_ptr().cast() },
            iov_len: buf.len(),
        };
        let result = unsafe {
            syscall!(
                Sysno::process_vm_writev,
                self.pid.as_raw() as usize,
                &local as *const libc::iovec as usize,
                1,
                &remote as *const libc::iovec as usize,
                1,
                0
            )
        };
        Self::transfer_result(result)
    }

    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        addr.as_raw().checked_add(buf.len()).ok_or(Errno::EFAULT)?;
        let local = libc::iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr.as_raw() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: the local descriptor borrows buf for this call; the remote
        // descriptor is a numeric address checked by the kernel. Keep the raw
        // syscall convention used by the other SaBRe memory operations.
        let written = unsafe {
            syscall!(
                Sysno::process_vm_writev,
                self.pid.as_raw() as usize,
                &local as *const libc::iovec as usize,
                1,
                &remote as *const libc::iovec as usize,
                1,
                0
            )
        }?;
        // Do not use transfer_result: this operation reports a first-byte
        // fault as EFAULT and preserves every other syscall error unchanged.
        if written == 0 {
            Err(Errno::EFAULT)
        } else {
            Ok(written)
        }
    }
}

fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    pin!(future).as_mut().poll(&mut context)
}

struct SabreRpc<'a, T>
where
    T: ReverieTool,
{
    tid: Pid,
    global_state: &'a T::GlobalState,
    config: &'a <T::GlobalState as GlobalTool>::Config,
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for SabreRpc<'_, T>
where
    T: ReverieTool,
{
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        self.global_state.receive_rpc(self.tid, message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

/// In-process guest view used while a SaBRe syscall callback is active.
pub struct SabreGuest<'state, 'inject, T>
where
    T: ReverieTool,
{
    tid: Pid,
    pid: Pid,
    thread_state: &'state mut Option<T::ThreadState>,
    rpc: &'state dyn GlobalRPC<T::GlobalState>,
    tool: Option<&'state T>,
    exit_handled: Option<&'state mut bool>,
    original: Option<(Sysno, SyscallArgs)>,
    special_inject: Option<&'inject mut (dyn FnMut() -> usize + Send + Sync)>,
    child_threads: Option<ChildThreadRegistry<'state, T>>,
    tail: Option<&'state TailResult>,
}

impl<'state, 'inject, T> SabreGuest<'state, 'inject, T>
where
    T: ReverieTool,
{
    fn new(
        tid: Pid,
        pid: Pid,
        thread_state: &'state mut Option<T::ThreadState>,
        rpc: &'state dyn GlobalRPC<T::GlobalState>,
        remote: Option<(
            &'state T,
            &'state mut bool,
            Option<ChildThreadRegistry<'state, T>>,
        )>,
        original: Option<(Sysno, SyscallArgs)>,
        special_inject: Option<&'inject mut (dyn FnMut() -> usize + Send + Sync)>,
    ) -> Self {
        let (tool, exit_handled, child_threads) = remote
            .map_or((None, None, None), |(tool, handled, child_threads)| {
                (Some(tool), Some(handled), child_threads)
            });

        Self {
            tid,
            pid,
            thread_state,
            rpc,
            tool,
            exit_handled,
            original,
            special_inject,
            child_threads,
            tail: None,
        }
    }

    fn with_tail(mut self, tail: &'state TailResult) -> Self {
        self.tail = Some(tail);
        self
    }

    fn initialize_child_thread(&mut self, child: Pid) -> Result<(), Errno> {
        let Some(registry) = self.child_threads.as_ref() else {
            return Ok(());
        };
        let Some(tool) = self.tool else {
            return Err(Errno::EIO);
        };
        let Some(parent_state) = self.thread_state.as_ref() else {
            return Err(Errno::EIO);
        };

        let mut states = registry.states.lock();
        if states.contains_key(&child.as_raw()) {
            return Ok(());
        }
        let rpc = protect_with(|| BlockingRpcClient::connect(registry.socket_path, child))
            .map_err(remote_rpc_error)?;
        let thread_state = tool.init_thread_state(child, Some((self.tid, parent_state)));
        states.insert(
            child.as_raw(),
            Arc::new(Mutex::new(RemoteThreadState {
                thread_state: Some(thread_state),
                rpc,
                exit_handled: false,
            })),
        );
        Ok(())
    }
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for SabreGuest<'_, '_, T>
where
    T: ReverieTool,
{
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
    }
}

#[reverie::tool]
impl<T> Guest<T> for SabreGuest<'_, '_, T>
where
    T: ReverieTool,
{
    type Memory = SabreMemory;
    type Stack = SabreStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        if self.pid == root_process_pid() {
            None
        } else {
            let ppid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getppid) };
            (ppid != 0).then(|| Pid::from_raw(ppid as i32))
        }
    }

    // This experimental adapter tracks no begin/ready runtime window, so it
    // cannot attribute any delivered syscall to a runtime bootstrap.
    fn is_backend_runtime_bootstrap(&self) -> bool {
        false
    }

    fn memory(&self) -> Self::Memory {
        SabreMemory::new(self.pid)
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.thread_state
            .as_mut()
            .expect("SaBRe thread state already consumed")
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.thread_state
            .as_ref()
            .expect("SaBRe thread state already consumed")
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-140): Review mapping from the SaBRe frame to user_regs_struct.
    // TODO-HUMAN-REVIEW(PR-242): Review the corrected architectural RIP mapping.
    async fn regs(&mut self) -> libc::user_regs_struct {
        let mut regs = unsafe { std::mem::zeroed::<libc::user_regs_struct>() };
        if let Some((number, args)) = self.original {
            regs.rax = number.id() as u64;
            regs.orig_rax = number.id() as u64;
            regs.rdi = args.arg0 as u64;
            regs.rsi = args.arg1 as u64;
            regs.rdx = args.arg2 as u64;
            regs.r10 = args.arg3 as u64;
            regs.r8 = args.arg4 as u64;
            regs.r9 = args.arg5 as u64;
        }

        let Some(frame) = crate::callbacks::current_syscall_frame() else {
            return regs;
        };
        let frame = unsafe { &*frame };
        regs.r15 = frame.r15 as u64;
        regs.r14 = frame.r14 as u64;
        regs.r13 = frame.r13 as u64;
        regs.r12 = frame.r12 as u64;
        regs.rbp = frame.rbp_prologue as u64;
        regs.rbx = frame.rbx as u64;
        regs.r11 = frame.r11 as u64;
        regs.r10 = frame.r10 as u64;
        regs.r9 = frame.r9 as u64;
        regs.r8 = frame.r8 as u64;
        regs.rcx = frame.rcx as u64;
        regs.rdx = frame.rdx as u64;
        regs.rsi = frame.rsi as u64;
        regs.rdi = frame.rdi as u64;
        regs.rip = frame.fake_ret as u64;
        regs.rsp = frame.guest_stack_pointer();
        regs.eflags = frame.rflags;
        regs
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-140): Review writable versus fixed SaBRe trampoline registers.
    // TODO-HUMAN-REVIEW(PR-242): Review rejection of unsupported RIP rewrites.
    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        let current = self.regs().await;
        let Some(frame) = crate::callbacks::current_syscall_frame() else {
            return Err(Errno::ENOSYS.into());
        };
        if regs.rax != current.rax
            || regs.orig_rax != current.orig_rax
            // SaBRe resumes through an internal scratch trampoline. Rewriting
            // RIP without also relocating its displaced instructions would
            // leave the guest stack and instruction stream inconsistent.
            || regs.rip != current.rip
            || regs.rsp != current.rsp
            || regs.eflags != current.eflags
            || regs.cs != current.cs
            || regs.ss != current.ss
            || regs.ds != current.ds
            || regs.es != current.es
            || regs.fs != current.fs
            || regs.gs != current.gs
            || regs.fs_base != current.fs_base
            || regs.gs_base != current.gs_base
        {
            return Err(Errno::EOPNOTSUPP.into());
        }

        let frame = unsafe { &mut *frame };
        frame.r15 = regs.r15 as *mut libc::c_void;
        frame.r14 = regs.r14 as *mut libc::c_void;
        frame.r13 = regs.r13 as *mut libc::c_void;
        frame.r12 = regs.r12 as *mut libc::c_void;
        frame.rbp_prologue = regs.rbp as *mut libc::c_void;
        frame.rbx = regs.rbx as *mut libc::c_void;
        frame.r11 = regs.r11 as *mut libc::c_void;
        frame.r10 = regs.r10 as *mut libc::c_void;
        frame.r9 = regs.r9 as *mut libc::c_void;
        frame.r8 = regs.r8 as *mut libc::c_void;
        frame.rcx = regs.rcx as *mut libc::c_void;
        frame.rdx = regs.rdx as *mut libc::c_void;
        frame.rsi = regs.rsi as *mut libc::c_void;
        frame.rdi = regs.rdi as *mut libc::c_void;
        Ok(())
    }

    async fn stack(&mut self) -> Self::Stack {
        SabreStack::new()
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (number, args) = syscall.into_parts();
        let terminal_original = self.original == Some((number, args))
            && self.special_inject.is_some()
            && matches!(number, Sysno::exit | Sysno::exit_group);
        let rewritten_thread_exit = number == Sysno::exit && self.original != Some((number, args));
        let mut terminal_tool = None;
        if terminal_original || rewritten_thread_exit {
            if let (Some(tool), Some(exit_handled)) = (self.tool, self.exit_handled.as_deref_mut())
            {
                if !*exit_handled {
                    *exit_handled = true;
                    terminal_tool = Some(tool);
                }
            }
        }
        if let Some(tool) = terminal_tool {
            // The runtime's exit callback re-enters while this handler owns the
            // thread-state lock. Run the consuming destructor immediately before
            // the non-returning injection, then mark the callback as handled.
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-128): Review terminal injection destructor ordering.
            let Some(thread_state) = self.thread_state.take() else {
                return Err(Errno::EIO);
            };
            if let Err(error) = tool
                .on_exit_thread(
                    self.tid,
                    self,
                    thread_state,
                    ExitStatus::Exited(args.arg0 as i32),
                )
                .await
            {
                crate::eprintln!("reverie-sabre: remote Tool::on_exit_thread failed: {error}");
            }
        }
        if self.original == Some((number, args)) {
            if let Some(inject) = self.special_inject.take() {
                // The Tool may rewrite clone3's stable argument image before
                // injection. Classify the final image here so a process clone
                // rewritten to CLONE_THREAD cannot race parent-state handoff.
                let final_thread_clone =
                    self.child_threads.is_some() && is_thread_clone(self.pid, number, args);
                let _pending_thread_clone = if final_thread_clone {
                    let pending = self
                        .child_threads
                        .as_ref()
                        .expect("thread-clone classification requires a remote registry")
                        .thread_clones_pending
                        .clone();
                    Some(PendingThreadClone::new(pending))
                } else {
                    None
                };
                let _pending_process_fork =
                    if self.child_threads.is_some() && is_process_fork(self.pid, number, args) {
                        let Some(parent_state) = self.thread_state.as_ref() else {
                            return Err(Errno::EIO);
                        };
                        let snapshot = reverie_rpc_transport::codec::encode(parent_state)
                            .map_err(remote_rpc_error)?;
                        let replaced = PROCESS_FORK_HANDOFF.lock().replace(ProcessForkHandoff {
                            parent_pid: self.pid,
                            parent_tid: self.tid,
                            thread_state: snapshot,
                        });
                        assert!(
                            replaced.is_none(),
                            "nested SaBRe process-fork snapshots are unsupported"
                        );
                        Some(PendingProcessFork {
                            parent_pid: self.pid,
                        })
                    } else {
                        None
                    };
                // Fork/exit injectors may resume the child or terminate without
                // unwinding this callback. Do not carry its parent stack pointer
                // into that execution path.
                // AUTONOMOUS-BOT-IMPLEMENTED
                // TODO-HUMAN-REVIEW(PR-140): Review frame suspension on diverging injectors.
                let _frame_suspended = crate::callbacks::SyscallFrameGuard::suspend();
                let result = Errno::from_ret(inject()).map(|value| value as i64);
                if final_thread_clone {
                    if let Ok(child) = result {
                        self.initialize_child_thread(Pid::from_raw(child as i32))?;
                    }
                }
                return result;
            }
        }
        if rewritten_thread_exit {
            // A Tool can replace an intercepted syscall with a terminal thread exit. Cleanup was
            // completed above. Ask the outer SaBRe callback to publish the runtime thread's
            // Exited state before it performs the non-returning raw exit.
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-265): Review non-original tail-injected thread exit.
            crate::callbacks::request_tail_injected_exit(args.arg0);
            return Ok(0);
        }
        if matches!(
            number,
            Sysno::clone
                | Sysno::clone3
                | Sysno::fork
                | Sysno::vfork
                | Sysno::exit
                | Sysno::exit_group
        ) {
            return Err(Errno::ENOSYS);
        }

        let syscall = Syscall::from_raw(number, args);
        unsafe { syscall.call() }.map(|value| value as i64)
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        let result = match self.inject(syscall).await {
            Ok(value) => value,
            Err(errno) => -(errno.into_raw() as i64),
        };
        // ⚠️ NO DRIVER IS NOT A PANIC, AND MAKING IT ONE WAS A REGRESSION.
        // `tail` is `None` for every guest built outside `dispatch_syscall` --
        // local and remote thread-start and post-exec, and the remote RDTSC and
        // signal callbacks all construct one. Those callbacks have no syscall
        // driver to hand a result back to, and before this driver was shared they
        // simply suspended and were dropped by their caller. An unconditional
        // `expect` here turned that quiet, established path into a crash in
        // lifecycle code. Found by `agent(hermit-123)`, which built a
        // `handle_thread_start` regression that passes on base `559a37a4` and
        // panics here.
        //
        // Recording the result when there IS a driver, and otherwise suspending
        // exactly as before, keeps the syscall path's new behaviour without
        // changing the lifecycle path's old one.
        if let Some(tail) = self.tail {
            tail.set_result(result);
        }
        std::future::pending::<Never>().await
    }

    fn set_timer(&mut self, _schedule: TimerSchedule) -> Result<(), Error> {
        // SaBRe currently has no PMU delivery hook. Accepting the request keeps
        // single-thread syscall-boundary scheduling usable; no timer event will
        // be delivered.
        Ok(())
    }

    fn set_timer_precise(&mut self, _schedule: TimerSchedule) -> Result<(), Error> {
        // See set_timer. Precise preemption remains an explicit backend gap.
        Ok(())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        // No branch clock is exposed by SaBRe yet. Zero is stable and prevents
        // fabricated RCB progress while syscall-boundary bring-up is exercised.
        Ok(0)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-140): Review the intentionally single-frame backtrace contract.
    // TODO-HUMAN-REVIEW(PR-242): Review the corrected architectural frame IP.
    fn backtrace(&mut self) -> Option<Backtrace> {
        let frame = crate::callbacks::current_syscall_frame()?;
        let ip = unsafe { (*frame).fake_ret as u64 };
        Some(Backtrace::new(
            self.tid,
            vec![Frame {
                ip,
                is_signal: false,
            }],
        ))
    }
}

// TODO-HUMAN-REVIEW(PR-212): Review clone3 thread-state detection.
fn clone_flags(pid: Pid, number: Sysno, args: SyscallArgs) -> Option<u64> {
    match number {
        Sysno::clone => Some(args.arg0 as u64),
        // AUTONOMOUS-BOT-IMPLEMENTED
        Sysno::clone3 if args.arg1 >= std::mem::size_of::<u64>() => {
            let address = Addr::<u64>::from_raw(args.arg0)?;
            SabreMemory::new(pid).read_value(address).ok()
        }
        _ => None,
    }
}

fn is_thread_clone(pid: Pid, number: Sysno, args: SyscallArgs) -> bool {
    clone_flags(pid, number, args).is_some_and(|flags| flags & libc::CLONE_THREAD as u64 != 0)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-273): Review process-fork classification for state inheritance.
fn is_process_fork(pid: Pid, number: Sysno, args: SyscallArgs) -> bool {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-285): Review vfork state inheritance after private-fork rewriting.
    // The SaBRe callback rewrites direct vfork to a private fork so its child
    // cannot overwrite the blocked parent's callback frames on the shared
    // guest stack. Preserve the original vfork classification for Detcore,
    // while handing the forked child an inherited thread-state snapshot.
    if matches!(number, Sysno::fork | Sysno::vfork) {
        return true;
    }
    let Some(flags) = clone_flags(pid, number, args) else {
        return false;
    };
    if flags & libc::CLONE_VFORK as u64 != 0 && flags & libc::CLONE_THREAD as u64 == 0 {
        return true;
    }
    let shared_or_vfork =
        libc::CLONE_VM as u64 | libc::CLONE_THREAD as u64 | libc::CLONE_VFORK as u64;
    flags & shared_or_vfork == 0
}

const STACK_CAPACITY: usize = 4096;

/// In-process scratch storage for arguments to injected syscalls.
pub struct SabreStack {
    arena: Box<[u8]>,
    offset: usize,
}

impl SabreStack {
    fn new() -> Self {
        Self {
            arena: vec![0; STACK_CAPACITY].into_boxed_slice(),
            offset: 0,
        }
    }

    fn allocation<T>(&mut self) -> *mut T {
        let base = self.arena.as_ptr() as usize;
        let align = std::mem::align_of::<T>();
        let start = align_up(base + self.offset, align) - base;
        let end = start + std::mem::size_of::<T>();
        assert!(
            end <= self.arena.len(),
            "SaBRe guest scratch stack overflow"
        );
        self.offset = end;
        unsafe { self.arena.as_mut_ptr().add(start) }.cast()
    }
}

/// Guard retaining a committed [`SabreStack`] allocation arena.
pub struct SabreStackGuard {
    _arena: Box<[u8]>,
}

impl Drop for SabreStackGuard {
    fn drop(&mut self) {}
}

impl Stack for SabreStack {
    type StackGuard = SabreStackGuard;

    fn size(&self) -> usize {
        self.offset
    }

    fn capacity(&self) -> usize {
        self.arena.len()
    }

    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T> {
        let pointer = self.allocation::<T>();
        unsafe { pointer.write(value) };
        Addr::from_raw(pointer as usize).expect("scratch pointer must be non-null")
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        let pointer = self.allocation::<T>();
        unsafe {
            pointer
                .cast::<u8>()
                .write_bytes(0, std::mem::size_of::<T>())
        };
        AddrMut::from_raw(pointer as usize).expect("scratch pointer must be non-null")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(SabreStackGuard { _arena: self.arena })
    }
}

fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;

    use reverie_syscalls::SyscallArgs;
    use syscalls::Sysno;

    use super::*;

    static HANDLED: AtomicUsize = AtomicUsize::new(0);
    static POST_EXECS: AtomicUsize = AtomicUsize::new(0);
    static PROCESS_EXITS: AtomicUsize = AtomicUsize::new(0);
    static RPC_SOCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn identifies_only_thread_clones_for_parent_state_handoff() {
        let thread_args = SyscallArgs::new(libc::CLONE_THREAD as usize, 0, 0, 0, 0, 0);
        let process_args = SyscallArgs::new(libc::SIGCHLD as usize, 0, 0, 0, 0, 0);
        let mut clone3_flags = libc::SIGCHLD as u64;
        let clone3_args = SyscallArgs::new(
            &mut clone3_flags as *mut u64 as usize,
            std::mem::size_of_val(&clone3_flags),
            0,
            0,
            0,
            0,
        );

        assert!(is_thread_clone(current_pid(), Sysno::clone, thread_args));
        assert!(!is_thread_clone(current_pid(), Sysno::clone3, clone3_args));
        clone3_flags = libc::CLONE_THREAD as u64;
        assert!(is_thread_clone(current_pid(), Sysno::clone3, clone3_args));
        assert_eq!(clone3_flags, libc::CLONE_THREAD as u64);
        assert!(!is_thread_clone(current_pid(), Sysno::clone, process_args));
        assert!(!is_thread_clone(current_pid(), Sysno::fork, thread_args));
    }

    #[test]
    fn concurrent_thread_clone_guards_keep_handoff_pending() {
        let pending = Arc::new(AtomicUsize::new(0));
        let first = PendingThreadClone::new(pending.clone());
        let second = PendingThreadClone::new(pending.clone());

        assert_eq!(pending.load(Ordering::Acquire), 2);
        drop(first);
        assert_eq!(pending.load(Ordering::Acquire), 1);
        drop(second);
        assert_eq!(pending.load(Ordering::Acquire), 0);
    }

    #[test]
    fn inherited_thread_state_is_visible_after_pending_clone_finishes() {
        let states = Arc::new(Mutex::new(HashMap::new()));
        let pending = Arc::new(AtomicUsize::new(1));
        let missed = Arc::new(Barrier::new(2));
        let published = Arc::new(Barrier::new(2));

        let waiter = {
            let states = states.clone();
            let pending = pending.clone();
            let missed = missed.clone();
            let published = published.clone();
            thread::spawn(move || {
                wait_for_inherited_thread_state_after_miss(&states, &pending, 17, || {
                    missed.wait();
                    published.wait();
                })
            })
        };

        missed.wait();
        states.lock().insert(17, "inherited");
        pending.fetch_sub(1, Ordering::Release);
        published.wait();

        assert_eq!(waiter.join().unwrap(), Some("inherited"));
    }

    #[test]
    fn identifies_only_private_process_forks_for_lazy_state_handoff() {
        let process_args = SyscallArgs::new(libc::SIGCHLD as usize, 0, 0, 0, 0, 0);
        let thread_args = SyscallArgs::new(
            (libc::CLONE_VM | libc::CLONE_THREAD) as usize,
            0,
            0,
            0,
            0,
            0,
        );
        let vfork_args = SyscallArgs::new(
            (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as usize,
            0,
            0,
            0,
            0,
            0,
        );
        let clone3_flags = libc::SIGCHLD as u64;
        let clone3_args = SyscallArgs::new(
            &clone3_flags as *const u64 as usize,
            std::mem::size_of_val(&clone3_flags),
            0,
            0,
            0,
            0,
        );

        assert!(is_process_fork(current_pid(), Sysno::fork, process_args));
        assert!(is_process_fork(current_pid(), Sysno::clone, process_args));
        assert!(is_process_fork(current_pid(), Sysno::clone3, clone3_args));
        assert!(!is_process_fork(current_pid(), Sysno::clone, thread_args));
        assert!(is_process_fork(current_pid(), Sysno::clone, vfork_args));
        assert!(is_process_fork(current_pid(), Sysno::vfork, process_args));
    }

    #[test]
    fn sabre_memory_reads_and_writes_valid_memory() {
        let mut memory = SabreMemory::new(current_pid());
        let source = *b"sabre";
        let source_addr = Addr::from_ptr(source.as_ptr()).unwrap();
        let mut copy = [0; 5];
        memory.read_exact(source_addr, &mut copy).unwrap();
        assert_eq!(copy, source);

        let mut destination = [0; 5];
        let destination_addr = AddrMut::from_ptr(destination.as_mut_ptr()).unwrap();
        memory.write_exact(destination_addr, b"guest").unwrap();
        assert_eq!(&destination, b"guest");
    }

    #[test]
    fn sabre_memory_reports_invalid_addresses_as_efault() {
        let mut memory = SabreMemory::new(current_pid());
        let invalid = Addr::from_raw(1).unwrap();
        let invalid_mut = AddrMut::from_raw(1).unwrap();
        let mut byte = [0];

        assert_eq!(memory.read(invalid, &mut byte), Ok(0));
        assert_eq!(memory.read_exact(invalid, &mut byte), Err(Errno::EFAULT));
        assert_eq!(memory.write(invalid_mut, &byte), Ok(0));
        assert_eq!(memory.write_exact(invalid_mut, &byte), Err(Errno::EFAULT));
    }

    struct UserCopyPages {
        base: *mut u8,
        length: usize,
        page: usize,
    }

    impl UserCopyPages {
        fn new() -> Self {
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            assert!(page > 0);
            let page = page as usize;
            let length = 3 * page;
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(base, libc::MAP_FAILED);
            Self {
                base: base.cast(),
                length,
                page,
            }
        }

        fn protect_middle(&self, protection: libc::c_int) {
            assert_eq!(
                unsafe { libc::mprotect(self.base.add(self.page).cast(), self.page, protection) },
                0
            );
        }
    }

    impl Drop for UserCopyPages {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.base.cast(), self.length) }, 0);
        }
    }

    #[test]
    fn sabre_user_copy_checks_permissions_at_every_size_and_preserves_prefixes() {
        let mut memory = SabreMemory::new(current_pid());
        let pages = UserCopyPages::new();
        for protection in [libc::PROT_READ, libc::PROT_NONE] {
            for offset in [0, pages.page - 3, pages.page] {
                for length in [0, 1, 7, 8, 9, pages.page + 8] {
                    pages.protect_middle(libc::PROT_READ | libc::PROT_WRITE);
                    unsafe { std::ptr::write_bytes(pages.base, 0xa5, pages.length) };
                    pages.protect_middle(protection);
                    let source: Vec<_> = (0..length + 1).map(|i| (19 + i * 37) as u8).collect();
                    let source = &source[1..];
                    let destination = AddrMut::from_raw(pages.base as usize + offset).unwrap();
                    let expected = if offset < pages.page {
                        (pages.page - offset).min(length)
                    } else {
                        0
                    };
                    assert_eq!(
                        memory.write_with_user_access(destination, source),
                        if expected != 0 || length == 0 {
                            Ok(expected)
                        } else {
                            Err(Errno::EFAULT)
                        },
                        "protection={protection} offset={offset} length={length}"
                    );
                    // Restore read access only after the real API call, then
                    // inspect the entire mapping, including protected canaries.
                    pages.protect_middle(libc::PROT_READ | libc::PROT_WRITE);
                    let actual = unsafe { std::slice::from_raw_parts(pages.base, pages.length) };
                    for (index, &byte) in actual.iter().enumerate() {
                        let expected_byte = if index >= offset && index - offset < expected {
                            source[index - offset]
                        } else {
                            0xa5
                        };
                        assert_eq!(byte, expected_byte, "destination byte {index}");
                    }
                }
            }
        }
    }

    #[test]
    fn sabre_user_copy_empty_and_invalid_addresses_preserve_memory() {
        let mut memory = SabreMemory::new(current_pid());
        let pages = UserCopyPages::new();
        unsafe { std::ptr::write_bytes(pages.base, 0xa5, pages.length) };
        for invalid in [1, usize::MAX - 3, usize::MAX] {
            let destination = AddrMut::from_raw(invalid).unwrap();
            assert_eq!(memory.write_with_user_access(destination, &[]), Ok(0));
            for source in [&b"x"[..], &b"rejected"[..]] {
                assert_eq!(
                    memory.write_with_user_access(destination, source),
                    Err(Errno::EFAULT)
                );
                let actual = unsafe { std::slice::from_raw_parts(pages.base, pages.length) };
                assert!(actual.iter().all(|&byte| byte == 0xa5));
            }
        }
    }

    #[test]
    fn sabre_user_copy_preserves_non_fault_errno() {
        // A negative PID is invalid, so this error case has no PID-reuse race.
        let mut memory = SabreMemory::new(Pid::from_raw(-1));
        let mut destination = [0xa5; 8];
        let address = AddrMut::from_ptr(destination.as_mut_ptr()).unwrap();
        assert_eq!(
            memory.write_with_user_access(address, b"rejected"),
            Err(Errno::ESRCH)
        );
        assert_eq!(destination, [0xa5; 8]);
        assert_eq!(
            memory.write_with_user_access(AddrMut::from_raw(usize::MAX).unwrap(), &[]),
            Ok(0)
        );
    }

    #[derive(Default)]
    struct FixedTool;

    #[reverie::tool]
    impl ReverieTool for FixedTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            _guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            HANDLED.fetch_add(1, Ordering::Relaxed);
            Ok(123)
        }

        async fn handle_post_exec<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Errno> {
            POST_EXECS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn forwards_syscalls_to_shared_tool_handler() {
        HANDLED.store(0, Ordering::Relaxed);
        let adapter = ReverieAdapter::new(FixedTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(123));
        assert_eq!(HANDLED.load(Ordering::Relaxed), 1);
    }

    #[derive(Default)]
    struct RestartWait4Tool;

    #[reverie::tool]
    impl ReverieTool for RestartWait4Tool {
        type GlobalState = ();
        type ThreadState = usize;

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            assert_eq!(syscall.number(), Sysno::wait4);
            let calls = guest.thread_state_mut();
            *calls += 1;
            match *calls {
                1 => Err(Errno::ERESTARTSYS.into()),
                2 => Ok(17),
                calls => panic!("wait4 callback invoked {calls} times"),
            }
        }
    }

    /// ⚠️ A NON-WAIT SYSCALL RESTARTS TOO, AND THE ADAPTER MUST BE SEEN TO APPLY THAT.
    /// `d7eb0a1d` made the shared driver restart EVERY private `ERESTARTSYS`, not
    /// only the wait family. An earlier version of this branch deleted the
    /// adapter's non-wait assertion on the grounds that asserting the new
    /// behaviour here would merely duplicate `reverie-preload`'s unit test. That
    /// reasoning was WRONG and `agent(hermit-123)` measured why: the preload test
    /// establishes the shared driver's POLICY, while an adapter test establishes
    /// that a given CALL SITE applies it. Returning `ERESTARTSYS` for `read` in
    /// only the local adapter left all 76 library tests green — the call sites
    /// were unobserved.
    ///
    /// It returns the errno once and succeeds on the second call so the restart
    /// loop TERMINATES. A tool that returned it forever would not fail here, it
    /// would hang, and a hung suite reads as a slow box.
    #[derive(Default)]
    struct RestartReadTool;

    #[reverie::tool]
    impl ReverieTool for RestartReadTool {
        type GlobalState = ();
        type ThreadState = usize;

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            assert_eq!(syscall.number(), Sysno::read);
            let calls = guest.thread_state_mut();
            *calls += 1;
            match *calls {
                1 => Err(Errno::ERESTARTSYS.into()),
                2 => Ok(17),
                calls => panic!("read callback invoked {calls} times"),
            }
        }
    }

    #[test]
    fn local_adapter_restarts_a_non_wait_private_errno() {
        let adapter = ReverieAdapter::new(RestartReadTool, (), ());
        let syscall = Syscall::from_raw(Sysno::read, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(17));
    }

    #[test]
    fn local_adapter_restarts_wait4_private_errno() {
        let adapter = ReverieAdapter::new(RestartWait4Tool, (), ());
        let syscall = Syscall::from_raw(Sysno::wait4, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(17));
    }

    #[derive(Default)]
    struct RestartWaitidTool;

    #[reverie::tool]
    impl ReverieTool for RestartWaitidTool {
        type GlobalState = ();
        type ThreadState = usize;

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            assert_eq!(syscall.number(), Sysno::waitid);
            let calls = guest.thread_state_mut();
            *calls += 1;
            match *calls {
                1 => Err(Errno::ERESTARTSYS.into()),
                2 => Ok(17),
                calls => panic!("waitid callback invoked {calls} times"),
            }
        }
    }

    #[test]
    fn local_adapter_restarts_waitid_private_errno() {
        let adapter = ReverieAdapter::new(RestartWaitidTool, (), ());
        let syscall = Syscall::from_raw(Sysno::waitid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(17));
    }

    // ⚠️ `local_adapter_preserves_private_errno_for_non_wait4` AND ITS TOOL WERE HERE
    // AND ARE DELIBERATELY GONE. The test asserted that a non-`wait4` syscall surfaces
    // `ERESTARTSYS` to the guest. That was true when this branch was written and is
    // false on main: `d7eb0a1d` ("Restart every preload ERESTARTSYS result") removed
    // the syscall condition from `classify_outcome`, so EVERY private `ERESTARTSYS`
    // restarts.
    //
    // ⚠️ KEPT AS WRITTEN IT DOES NOT FAIL, IT HANGS -- the driver re-invokes a callback
    // that returns `ERESTARTSYS` every time. Measured: over 60 seconds before it was
    // killed. A superseded assertion that wedges the suite is worse than one that goes
    // red, because a wedged run reads as a slow box.
    //
    // Removed rather than inverted: asserting the NEW behaviour here would only
    // duplicate `classify_outcome_restarts_on_erestartsys` in reverie-preload, which
    // already owns that policy.

    #[test]
    fn local_adapter_delivers_post_exec() {
        POST_EXECS.store(0, Ordering::Relaxed);
        let adapter = ReverieAdapter::new(FixedTool, (), ());
        adapter.handle_post_exec();
        assert_eq!(POST_EXECS.load(Ordering::Relaxed), 1);
    }

    #[derive(Clone, Default)]
    struct ProcessExitTool;

    #[reverie::tool]
    impl ReverieTool for ProcessExitTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
            self,
            _pid: Pid,
            _global_state: &G,
            _exit_status: ExitStatus,
        ) -> Result<(), Error> {
            PROCESS_EXITS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn local_adapter_delivers_process_exit() {
        PROCESS_EXITS.store(0, Ordering::Relaxed);
        let adapter = ReverieAdapter::new(ProcessExitTool, (), ());
        adapter.handle_process_exit(ExitStatus::Exited(7));
        assert_eq!(PROCESS_EXITS.load(Ordering::Relaxed), 1);
    }

    /// ⚠️ A LIFECYCLE CALLBACK THAT TAIL-INJECTS MUST NOT PANIC, AND IT DID.
    /// `SabreGuest::tail` is `None` for every guest built outside
    /// `dispatch_syscall` — local and remote thread-start and post-exec, and the
    /// remote RDTSC and signal callbacks. When `tail_inject` gained an
    /// unconditional `expect("tail_inject requires an active syscall driver")`,
    /// those callbacks crashed instead of suspending and being dropped, which is
    /// what they did before the shared driver was wired in.
    ///
    /// Found by `agent(hermit-123)`, whose probe passed on base `559a37a4` and
    /// panicked at the `expect` on `a5d02cda`. This is that probe, kept.
    #[test]
    fn a_lifecycle_callback_that_tail_injects_does_not_panic() {
        #[derive(Default)]
        struct TailInjectingThreadStartTool;

        #[reverie::tool]
        impl ReverieTool for TailInjectingThreadStartTool {
            type GlobalState = ();
            type ThreadState = ();

            async fn handle_thread_start<G: Guest<Self>>(
                &self,
                guest: &mut G,
            ) -> Result<(), Error> {
                // No syscall driver is active here. Before the fix this reached an
                // unconditional `expect` and aborted the process.
                guest
                    .tail_inject(Syscall::from_raw(
                        Sysno::getpid,
                        SyscallArgs::new(0, 0, 0, 0, 0, 0),
                    ))
                    .await
            }
        }

        let adapter = ReverieAdapter::new(TailInjectingThreadStartTool, (), ());
        // The assertion is that this RETURNS. A panic here fails the test by
        // aborting it, which is the regression; suspending and being dropped is
        // the established behaviour being preserved.
        adapter.handle_thread_start(4242);
    }

    #[derive(Default)]
    struct UnsubscribedTool;

    #[reverie::tool]
    impl ReverieTool for UnsubscribedTool {
        type GlobalState = ();
        type ThreadState = ();

        fn subscriptions(_config: &()) -> reverie::Subscription {
            reverie::Subscription::none()
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            _guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            panic!("unsubscribed syscall reached the tool")
        }
    }

    #[test]
    fn local_adapter_bypasses_unsubscribed_syscalls() {
        let adapter = ReverieAdapter::new(UnsubscribedTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(
            adapter.handle_syscall(syscall),
            Ok(std::process::id() as usize)
        );
    }

    #[test]
    fn remote_adapter_bypasses_unsubscribed_syscalls() {
        let path = std::path::Path::new("/tmp").join(format!(
            "reverie-sabre-rpc-{}-{}.sock",
            std::process::id(),
            RPC_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let server_path = path.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);

        let server_thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let server =
                        reverie_rpc_transport::RpcServer::bind(&server_path, Arc::new(()), ())
                            .unwrap();
                    ready_tx.send(()).unwrap();
                    server.serve_one().await
                })
        });
        ready_rx.recv().unwrap();

        let adapter = RemoteReverieAdapter::<UnsubscribedTool>::connect(&path).unwrap();
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(
            adapter.handle_syscall(syscall),
            Ok(std::process::id() as usize)
        );
        drop(adapter);

        assert!(server_thread.join().unwrap().is_ok());
    }

    #[derive(Default)]
    struct RegisterTool;

    #[reverie::tool]
    impl ReverieTool for RegisterTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            let mut regs = guest.regs().await;
            assert_eq!(regs.rax, Sysno::getpid.id() as u64);
            assert_eq!(regs.orig_rax, Sysno::getpid.id() as u64);
            assert_eq!(regs.r15, 15);
            assert_eq!(regs.r10, 40);
            assert_eq!(regs.r9, 50);
            assert_eq!(regs.r8, 60);
            assert_eq!(regs.rdi, 10);
            assert_eq!(regs.rsi, 20);
            assert_eq!(regs.rdx, 30);
            assert_eq!(regs.rip, 0xf00d);
            assert_eq!(regs.eflags, 0x647);
            let frame = crate::callbacks::current_syscall_frame().unwrap();
            assert_eq!(regs.rsp, frame as u64 + 0x90 + 0x80);
            assert_eq!(guest.backtrace().unwrap().iter().next().unwrap().ip, 0xf00d);

            let mut unsupported_rsp = regs;
            unsupported_rsp.rsp += 8;
            assert!(guest.set_regs(unsupported_rsp).await.is_err());

            let mut unsupported_rip = regs;
            unsupported_rip.rip = 0xbeef;
            assert!(guest.set_regs(unsupported_rip).await.is_err());

            let mut unsupported_flags = regs;
            unsupported_flags.eflags ^= 1;
            assert!(guest.set_regs(unsupported_flags).await.is_err());

            regs.r15 = 1515;
            regs.rcx = 0xcafe;
            regs.r11 = 0x202;
            guest.set_regs(regs).await?;
            Ok(123)
        }
    }

    #[test]
    fn exposes_and_updates_the_live_sabre_syscall_frame() {
        let mut frame = unsafe { std::mem::zeroed::<crate::ffi::syscall_stackframe>() };
        frame.r15 = 15usize as *mut libc::c_void;
        frame.r10 = 40usize as *mut libc::c_void;
        frame.r9 = 50usize as *mut libc::c_void;
        frame.r8 = 60usize as *mut libc::c_void;
        frame.rdi = 10usize as *mut libc::c_void;
        frame.rsi = 20usize as *mut libc::c_void;
        frame.rdx = 30usize as *mut libc::c_void;
        frame.fake_ret = 0xf00dusize as *mut libc::c_void;
        frame.ret = 0xdeadusize as *mut libc::c_void;
        frame.rflags = 0x647;

        assert!(crate::callbacks::current_syscall_frame().is_none());
        {
            let _frame_guard = crate::callbacks::SyscallFrameGuard::enter(&mut frame);
            let adapter = ReverieAdapter::new(RegisterTool, (), ());
            let syscall =
                Syscall::from_raw(Sysno::getpid, SyscallArgs::new(10, 20, 30, 40, 60, 50));
            assert_eq!(adapter.handle_syscall(syscall), Ok(123));
        }
        assert!(crate::callbacks::current_syscall_frame().is_none());
        assert_eq!(frame.r15 as usize, 1515);
        assert_eq!(frame.rcx as usize, 0xcafe);
        assert_eq!(frame.r11 as usize, 0x202);
        assert_eq!(frame.fake_ret as usize, 0xf00d);
        assert_eq!(frame.ret as usize, 0xdead);
        assert_eq!(frame.rflags, 0x647);
    }

    #[derive(Default)]
    struct RemoteCounter {
        total: AtomicUsize,
    }

    #[reverie::global_tool]
    impl GlobalTool for RemoteCounter {
        type Request = usize;
        type Response = usize;
        type Config = String;

        async fn receive_rpc(&self, _from: reverie::Tid, increment: usize) -> usize {
            self.total.fetch_add(increment, Ordering::SeqCst) + increment
        }
    }

    #[derive(Default)]
    struct RemoteTool;

    #[reverie::tool]
    impl ReverieTool for RemoteTool {
        type GlobalState = RemoteCounter;
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            Ok(guest.send_rpc(1).await as i64)
        }

        async fn handle_rdtsc_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            _request: Rdtsc,
        ) -> Result<reverie::RdtscResult, Errno> {
            let tsc = guest.send_rpc(10).await as u64;
            Ok(reverie::RdtscResult { tsc, aux: None })
        }
    }

    #[derive(Default)]
    struct InitializedRootTool;

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct InitializedRoot {
        random: u64,
        unrelated: (u64, i32),
    }

    impl Default for InitializedRoot {
        fn default() -> Self {
            Self {
                random: 7,
                unrelated: (93, current_pid().as_raw()),
            }
        }
    }

    #[reverie::tool]
    impl ReverieTool for InitializedRootTool {
        type GlobalState = RemoteCounter;
        type ThreadState = InitializedRoot;

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            assert_eq!(guest.thread_state().unrelated, (93, current_pid().as_raw()));
            Ok(guest.thread_state().random as i64)
        }
    }

    #[test]
    fn root_initializer_preserves_normal_state_and_refuses_failed_transfer() {
        for transfer in [false, true] {
            let global = Arc::new(RemoteCounter::default());
            let server_global = global.clone();
            let rpc_ready = Arc::new(AtomicBool::new(false));
            let server_ready = rpc_ready.clone();
            let path = std::path::Path::new("/tmp").join(format!(
                "reverie-sabre-root-{}-{}.sock",
                std::process::id(),
                RPC_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let server_path = path.clone();
            let (ready_tx, ready_rx) = mpsc::sync_channel(0);
            let server_thread = thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let server = reverie_rpc_transport::RpcServer::bind_with_readiness(
                            &server_path,
                            server_global,
                            "image-config".to_string(),
                            server_ready,
                        )
                        .unwrap();
                        ready_tx.send(()).unwrap();
                        server.serve_one().await
                    })
            });
            ready_rx.recv().unwrap();
            let calls = AtomicUsize::new(0);
            let result = RemoteReverieAdapter::<InitializedRootTool>::connect_with_root_initializer(
                &path,
                |config, tid, state| {
                    assert_eq!(config, "image-config");
                    assert_eq!(tid, current_tid());
                    assert_eq!(state.random, 7);
                    assert_eq!(state.unrelated, (93, current_pid().as_raw()));
                    assert!(!rpc_ready.load(Ordering::Acquire));
                    calls.fetch_add(1, Ordering::SeqCst);
                    if !transfer {
                        return Err(io::Error::from_raw_os_error(libc::ESTALE).into());
                    }
                    state.random = 41;
                    Ok(())
                },
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if transfer {
                let adapter = result.unwrap();
                let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                assert_eq!(adapter.handle_syscall(syscall), Ok(41));
                drop(adapter);
            } else {
                assert!(matches!(result, Err(RpcError::Io(error))
                    if error.raw_os_error() == Some(libc::ESTALE)));
            }
            assert!(server_thread.join().unwrap().is_ok());
            assert_eq!(global.total.load(Ordering::SeqCst), 0);
            assert!(!rpc_ready.load(Ordering::Acquire));
        }
    }

    #[test]
    fn remote_adapter_routes_tool_rpc_over_real_uds_on_first_poll() {
        let global = Arc::new(RemoteCounter::default());
        let server_global = global.clone();
        let path = std::path::Path::new("/tmp").join(format!(
            "reverie-sabre-rpc-{}-{}.sock",
            std::process::id(),
            RPC_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let server_path = path.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);

        let server_thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let server = reverie_rpc_transport::RpcServer::bind(
                        &server_path,
                        server_global,
                        "remote-cfg".to_string(),
                    )
                    .unwrap();
                    ready_tx.send(()).unwrap();
                    server.serve_one().await
                })
        });
        ready_rx.recv().unwrap();

        let adapter = RemoteReverieAdapter::<RemoteTool>::connect(&path).unwrap();
        assert_eq!(adapter.config(), "remote-cfg");
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(1));
        assert_eq!(adapter.handle_syscall(syscall), Ok(2));
        assert_eq!(adapter.handle_rdtsc(), Ok(12));
        drop(adapter);

        assert!(server_thread.join().unwrap().is_ok());
        assert_eq!(global.total.load(Ordering::SeqCst), 12);
    }

    #[test]
    fn remote_adapter_restarts_wait4_private_errno() {
        let path = std::path::Path::new("/tmp").join(format!(
            "reverie-sabre-rpc-{}-{}.sock",
            std::process::id(),
            RPC_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let server_path = path.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);

        let server_thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let server =
                        reverie_rpc_transport::RpcServer::bind(&server_path, Arc::new(()), ())
                            .unwrap();
                    ready_tx.send(()).unwrap();
                    server.serve_one().await
                })
        });
        ready_rx.recv().unwrap();

        let adapter = RemoteReverieAdapter::<RestartWait4Tool>::connect(&path).unwrap();
        let syscall = Syscall::from_raw(Sysno::wait4, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(17));
        drop(adapter);

        assert!(server_thread.join().unwrap().is_ok());
    }

    /// The remote call site, for the same reason as the local one above: a
    /// mutation confined to `RemoteReverieAdapter` left all 77 tests green.
    #[test]
    fn remote_adapter_restarts_a_non_wait_private_errno() {
        let path = std::path::Path::new("/tmp").join(format!(
            "reverie-sabre-rpc-{}-{}.sock",
            std::process::id(),
            RPC_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let server_path = path.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);

        let server_thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let server =
                        reverie_rpc_transport::RpcServer::bind(&server_path, Arc::new(()), ())
                            .unwrap();
                    ready_tx.send(()).unwrap();
                    server.serve_one().await
                })
        });
        ready_rx.recv().unwrap();

        let adapter = RemoteReverieAdapter::<RestartReadTool>::connect(&path).unwrap();
        let syscall = Syscall::from_raw(Sysno::read, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Ok(17));
        drop(adapter);

        assert!(server_thread.join().unwrap().is_ok());
    }

    #[test]
    fn default_tail_inject_executes_the_syscall() {
        #[derive(Default)]
        struct TailTool;

        #[reverie::tool]
        impl ReverieTool for TailTool {
            type GlobalState = ();
            type ThreadState = ();
        }

        let adapter = ReverieAdapter::new(TailTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(
            adapter.handle_syscall(syscall),
            Ok(std::process::id() as usize)
        );
    }

    #[test]
    fn rewritten_tail_exit_publishes_runtime_exit_before_sibling_group_exit() {
        static CLEANUPS: AtomicUsize = AtomicUsize::new(0);
        static RUNTIME_EXITS: AtomicBool = AtomicBool::new(false);

        struct ExitEventSink;

        impl crate::thread::EventSink for ExitEventSink {
            fn on_thread_exit(_pid_tid: crate::thread::PidTid) {
                RUNTIME_EXITS.store(true, Ordering::Release);
            }
        }

        #[derive(Default)]
        struct ExitTool;

        #[reverie::tool]
        impl ReverieTool for ExitTool {
            type GlobalState = ();
            type ThreadState = ();

            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                _syscall: Syscall,
            ) -> Result<i64, Error> {
                guest
                    .tail_inject(reverie_syscalls::Exit::new().with_status(23))
                    .await
            }

            async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
                &self,
                _tid: Pid,
                _global_state: &G,
                _thread_state: Self::ThreadState,
                exit_status: ExitStatus,
            ) -> Result<(), Error> {
                assert_eq!(exit_status, ExitStatus::Exited(23));
                CLEANUPS.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }

        let _slot_map_fork_guard = crate::slot_map::lock_for_fork();
        let child = unsafe { libc::fork() };
        drop(_slot_map_fork_guard);
        assert!(child >= 0);
        if child == 0 {
            CLEANUPS.store(0, Ordering::Release);
            RUNTIME_EXITS.store(false, Ordering::Release);
            let worker = thread::spawn(|| {
                let mut runtime_thread = crate::thread::Thread::<ExitEventSink>::current()
                    .expect("worker should acquire a runtime slot");
                runtime_thread
                    .leave_guest_execution()
                    .expect("worker should enter handler state");

                let adapter = ReverieAdapter::new(ExitTool, (), ());
                let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                assert_eq!(adapter.handle_syscall(syscall), Ok(0));
                assert_eq!(CLEANUPS.load(Ordering::Acquire), 1);
                crate::callbacks::terminate_tail_injected_exit_if_requested(&mut runtime_thread);
                unsafe { libc::_exit(99) };
            });
            drop(worker);

            let deadline = Instant::now() + Duration::from_secs(1);
            while !RUNTIME_EXITS.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            if !RUNTIME_EXITS.load(Ordering::Acquire) {
                unsafe { libc::_exit(98) };
            }

            let Some(exiting_pid) = crate::thread::exit_all(|_, _| {}) else {
                unsafe { libc::_exit(97) };
            };
            let group_exit_completed =
                crate::thread::wait_for_all_to_exit(exiting_pid, Some(Duration::from_millis(100)));
            let cleanup_once = CLEANUPS.load(Ordering::Acquire) == 1;
            unsafe {
                libc::_exit(if group_exit_completed && cleanup_once {
                    0
                } else {
                    96
                })
            };
        }

        let started = Instant::now();
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            assert!(waited >= 0);
            if waited == child {
                break;
            }
            if started.elapsed() >= Duration::from_secs(2) {
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                    libc::waitpid(child, &mut status, 0);
                }
                panic!("tail-injected thread exit did not terminate");
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn runtime_special_injector_reaches_guest_inject() {
        #[derive(Default)]
        struct TailTool;

        #[reverie::tool]
        impl ReverieTool for TailTool {
            type GlobalState = ();
            type ThreadState = ();
        }

        let adapter = ReverieAdapter::new(TailTool, (), ());
        let invoked = AtomicBool::new(false);
        let syscall = Syscall::from_raw(Sysno::exit_group, SyscallArgs::new(7, 0, 0, 0, 0, 0));
        let result = adapter.handle_syscall_with_inject(syscall, || {
            invoked.store(true, Ordering::SeqCst);
            456
        });
        assert_eq!(result, Ok(456));
        assert!(invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn runtime_special_injector_cannot_be_reused() {
        #[derive(Default)]
        struct DoubleInjectTool;

        #[reverie::tool]
        impl ReverieTool for DoubleInjectTool {
            type GlobalState = ();
            type ThreadState = ();

            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                syscall: Syscall,
            ) -> Result<i64, Error> {
                let first = guest.inject(syscall).await?;
                assert_eq!(guest.inject(syscall).await, Err(Errno::ENOSYS));
                Ok(first)
            }
        }

        let adapter = ReverieAdapter::new(DoubleInjectTool, (), ());
        let invoked = AtomicBool::new(false);
        let syscall = Syscall::from_raw(Sysno::clone3, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        let result = adapter.handle_syscall_with_inject(syscall, || {
            invoked.store(true, Ordering::SeqCst);
            456
        });

        assert_eq!(result, Ok(456));
        assert!(invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn rewritten_process_control_syscall_is_rejected() {
        #[derive(Default)]
        struct RewriteTool;

        #[reverie::tool]
        impl ReverieTool for RewriteTool {
            type GlobalState = ();
            type ThreadState = ();

            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                _syscall: Syscall,
            ) -> Result<i64, Error> {
                let clone = Syscall::from_raw(Sysno::clone, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                Ok(guest.inject(clone).await?)
            }
        }

        let adapter = ReverieAdapter::new(RewriteTool, (), ());
        let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        assert_eq!(adapter.handle_syscall(syscall), Err(Errno::ENOSYS));
    }

    struct BlockingTool {
        first_entered: Arc<Barrier>,
        release_first: Arc<Barrier>,
        calls: AtomicUsize,
    }

    impl Default for BlockingTool {
        fn default() -> Self {
            Self {
                first_entered: Arc::new(Barrier::new(1)),
                release_first: Arc::new(Barrier::new(1)),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[reverie::tool]
    impl ReverieTool for BlockingTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            _guest: &mut G,
            _syscall: Syscall,
        ) -> Result<i64, Error> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_entered.wait();
                self.release_first.wait();
            }
            Ok(123)
        }
    }

    #[test]
    fn blocked_handler_does_not_serialize_other_threads() {
        let first_entered = Arc::new(Barrier::new(2));
        let release_first = Arc::new(Barrier::new(2));
        let adapter = Arc::new(ReverieAdapter::new(
            BlockingTool {
                first_entered: first_entered.clone(),
                release_first: release_first.clone(),
                calls: AtomicUsize::new(0),
            },
            (),
            (),
        ));

        let first_adapter = adapter.clone();
        let first = thread::spawn(move || {
            let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
            first_adapter.handle_syscall(syscall)
        });
        first_entered.wait();

        let (tx, rx) = mpsc::channel();
        let second = thread::spawn(move || {
            let syscall = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
            tx.send(adapter.handle_syscall(syscall)).unwrap();
        });
        let second_result = rx.recv_timeout(Duration::from_secs(1));
        release_first.wait();

        assert_eq!(first.join().unwrap(), Ok(123));
        second.join().unwrap();
        assert_eq!(second_result.unwrap(), Ok(123));
    }
}
