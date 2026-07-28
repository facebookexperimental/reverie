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
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
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
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool as ReverieTool;
use reverie_memory::MemoryAccess;
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

thread_local! {
    static TAIL_INJECT_RESULT: std::cell::Cell<Option<i64>> =
        const { std::cell::Cell::new(None) };
}

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
/// SaBRe callbacks are synchronous. A handler must complete during its first
/// poll, except for [`Guest::tail_inject`], whose result is recorded before
/// its future intentionally suspends. Other pending futures fail closed with
/// `EIO` instead of blocking the guest in the plugin callback.
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
        let mut guest = SabreGuest::new(
            tid,
            pid,
            thread_state,
            &rpc,
            Some((&self.tool, exit_handled, None)),
            original,
            special_inject,
        );

        TAIL_INJECT_RESULT.with(|slot| slot.set(None));
        match poll_once(self.tool.handle_syscall_event(&mut guest, syscall)) {
            Poll::Ready(result) => shared_result(result),
            Poll::Pending => TAIL_INJECT_RESULT.with(|slot| {
                slot.take().map_or_else(
                    || {
                        crate::eprintln!(
                            "reverie-sabre: Tool::handle_syscall_event suspended; only immediately-ready handlers and tail_inject are supported"
                        );
                        Err(Errno::EIO)
                    },
                    |result| Ok(result as usize),
                )
            }),
        }
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
    thread_clone_pending: AtomicBool,
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

struct PendingThreadClone<'a>(&'a AtomicBool);

impl Drop for PendingThreadClone<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct ChildThreadRegistry<'a, T>
where
    T: ReverieTool,
{
    states: &'a Mutex<HashMap<i32, Arc<Mutex<RemoteThreadState<T>>>>>,
    socket_path: &'a Path,
}

impl<T> RemoteReverieAdapter<T>
where
    T: ReverieTool,
{
    /// Connects the root guest thread and constructs the process-local tool
    /// from the coordinator's config handshake.
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self, RpcError> {
        let _ = root_process_pid();
        let socket_path = socket_path.as_ref().to_path_buf();
        let tid = current_tid();
        let rpc = protect_with(|| BlockingRpcClient::<T::GlobalState>::connect(&socket_path, tid))?;
        let config = rpc.as_ref().config().clone();
        let tool = T::new(current_pid(), &config);
        let thread_state = tool.init_thread_state(tid, None);
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
            thread_clone_pending: AtomicBool::new(false),
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
                }),
            )),
            original,
            special_inject,
        );

        let _pending_thread_clone = original
            .filter(|(number, args)| is_thread_clone(pid, *number, *args))
            .map(|_| {
                assert!(
                    !self.thread_clone_pending.swap(true, Ordering::AcqRel),
                    "nested SaBRe thread clones are unsupported"
                );
                PendingThreadClone(&self.thread_clone_pending)
            });

        TAIL_INJECT_RESULT.with(|slot| slot.set(None));
        match poll_once(self.tool.handle_syscall_event(&mut guest, syscall)) {
            Poll::Ready(result) => shared_result(result),
            Poll::Pending => TAIL_INJECT_RESULT.with(|slot| {
                slot.take().map_or_else(
                    || {
                        crate::eprintln!(
                            "reverie-sabre: remote Tool::handle_syscall_event suspended without tail_inject"
                        );
                        Err(Errno::EIO)
                    },
                    |result| Ok(result as usize),
                )
            }),
        }
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
        loop {
            if let Some(state) = self.thread_states.lock().get(&tid.as_raw()).cloned() {
                return Ok(state);
            }
            if !self.thread_clone_pending.load(Ordering::Acquire) {
                break;
            }
            std::thread::yield_now();
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

fn remote_rpc_error(error: RpcError) -> Errno {
    crate::eprintln!("reverie-sabre: coordinator RPC failed: {error}");
    Errno::EIO
}
fn shared_result(result: Result<i64, Error>) -> Result<usize, Errno> {
    result.map(|value| value as usize).map_err(|error| {
        error.into_errno().unwrap_or_else(|error| {
            crate::eprintln!("reverie-sabre: shared tool failed: {error}");
            Errno::EIO
        })
    })
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
        }
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
        regs.rsp = unsafe { (frame as *const crate::ffi::syscall_stackframe).add(1) as u64 };
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
        let mut terminal_tool = None;
        if terminal_original {
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
                // Fork/exit injectors may resume the child or terminate without
                // unwinding this callback. Do not carry its parent stack pointer
                // into that execution path.
                // AUTONOMOUS-BOT-IMPLEMENTED
                // TODO-HUMAN-REVIEW(PR-140): Review frame suspension on diverging injectors.
                let _frame_suspended = crate::callbacks::SyscallFrameGuard::suspend();
                let result = Errno::from_ret(inject()).map(|value| value as i64);
                if is_thread_clone(self.pid, number, args) {
                    if let Ok(child) = result {
                        self.initialize_child_thread(Pid::from_raw(child as i32))?;
                    }
                }
                return result;
            }
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
        TAIL_INJECT_RESULT.with(|slot| slot.set(Some(result)));
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
fn is_thread_clone(pid: Pid, number: Sysno, args: SyscallArgs) -> bool {
    let flags = match number {
        Sysno::clone => args.arg0 as u64,
        // AUTONOMOUS-BOT-IMPLEMENTED
        Sysno::clone3 if args.arg1 >= std::mem::size_of::<u64>() => {
            let Some(address) = Addr::<u64>::from_raw(args.arg0) else {
                return false;
            };
            let Ok(flags) = SabreMemory::new(pid).read_value(address) else {
                return false;
            };
            flags
        }
        _ => return false,
    };
    flags & libc::CLONE_THREAD as u64 != 0
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
        let clone3_flags = libc::CLONE_THREAD as u64;
        let clone3_args = SyscallArgs::new(
            &clone3_flags as *const u64 as usize,
            std::mem::size_of_val(&clone3_flags),
            0,
            0,
            0,
            0,
        );

        assert!(is_thread_clone(current_pid(), Sysno::clone, thread_args));
        assert!(is_thread_clone(current_pid(), Sysno::clone3, clone3_args));
        assert!(!is_thread_clone(current_pid(), Sysno::clone, process_args));
        assert!(!is_thread_clone(current_pid(), Sysno::fork, thread_args));
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
        let path = std::env::temp_dir().join(format!(
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
            assert_eq!(guest.backtrace().unwrap().iter().next().unwrap().ip, 0xf00d);

            let mut unsupported_rsp = regs;
            unsupported_rsp.rsp += 8;
            assert!(guest.set_regs(unsupported_rsp).await.is_err());

            let mut unsupported_rip = regs;
            unsupported_rip.rip = 0xbeef;
            assert!(guest.set_regs(unsupported_rip).await.is_err());

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

    #[test]
    fn remote_adapter_routes_tool_rpc_over_real_uds_on_first_poll() {
        let global = Arc::new(RemoteCounter::default());
        let server_global = global.clone();
        let path = std::env::temp_dir().join(format!(
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
