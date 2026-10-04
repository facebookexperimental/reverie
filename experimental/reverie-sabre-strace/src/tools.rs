/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared Reverie example tools hosted by the SaBRe plugin.

// The reused production tool sources each declare the same KVM runner helper.
#![allow(clippy::duplicate_mod)]

#[allow(dead_code)]
#[path = "../../../reverie-examples/chaos.rs"]
mod chaos_exact;
#[allow(dead_code)]
#[path = "../../../reverie-examples/chrome-trace/main.rs"]
mod chrome_trace_exact;
#[allow(dead_code)]
#[path = "../../../reverie-examples/chunky_print.rs"]
mod chunky_print_exact;
#[path = "../../../reverie-examples/counter1_tool.rs"]
mod counter1_exact;
#[path = "../../../reverie-examples/counter2_tool.rs"]
mod counter2_exact;
#[allow(dead_code)]
#[path = "../../../reverie-examples/debug.rs"]
mod debug_exact;
#[allow(dead_code)]
#[path = "../../../reverie-examples/strace_minimal.rs"]
mod strace_minimal_exact;

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

pub(super) use chaos_exact::ChaosOpts as ExactChaosConfig;
use chaos_exact::ChaosTool as ExactChaosTool;
pub(super) use chaos_exact::ChaosToolGlobal as ExactChaosGlobal;
pub(super) use chrome_trace_exact::ChromeTrace as ExactChromeTraceTool;
pub(super) type ExactChromeTraceGlobal = <ExactChromeTraceTool as ReverieTool>::GlobalState;
pub(super) use chunky_print_exact::ChunkyPrintGlobal as ExactChunkyPrintGlobal;
use chunky_print_exact::ChunkyPrintLocal as ExactChunkyPrintTool;
pub(super) use counter1_exact::CounterGlobal as ExactCounter1Global;
use counter1_exact::CounterLocal as ExactCounter1Tool;
pub(super) use counter2_exact::CounterGlobal as ExactCounter2Global;
use counter2_exact::CounterLocal as ExactCounter2Tool;
use debug_exact::DebugTool as ExactDebugTool;
use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool as ReverieTool;
use reverie_sabre::RemoteReverieAdapter;
use reverie_sabre::ReverieAdapter;
use reverie_syscalls::Syscall;
use reverie_syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;
use strace_minimal_exact::StraceTool as ExactStraceMinimalTool;
use syscalls::Errno;
use syscalls::Sysno;

use super::COUNTER_RPC_SOCKET_ENV;
use super::StraceTool;

pub(super) fn exact_chaos_config(
    skip: Option<u64>,
    no_read: bool,
    no_recv: bool,
    no_interrupt: bool,
) -> ExactChaosConfig {
    ExactChaosConfig::for_liteinst(skip, no_read, no_recv, no_interrupt)
}

/// Environment variable selecting the shared tool hosted by the plugin.
pub(super) const TOOL_ENV: &str = "REVERIE_SABRE_TOOL";

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-158): Review fork-inherited example-tool selection.
static SELECTED_TOOL: OnceLock<ToolKind> = OnceLock::new();

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-160): Review fork-inherited counter coordinator discovery.
static COUNTER_RPC_SOCKET: OnceLock<Option<PathBuf>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(super) struct CounterConfig {
    print_process_local_summary: bool,
}

impl Default for CounterConfig {
    fn default() -> Self {
        Self::process_local()
    }
}

impl CounterConfig {
    fn process_local() -> Self {
        Self {
            print_process_local_summary: true,
        }
    }

    pub(super) fn coordinated() -> Self {
        Self {
            print_process_local_summary: false,
        }
    }
}

/// Shared Reverie tool implementations available through the SaBRe runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ToolKind {
    /// Introduce short reads and interrupted-read errors.
    Chaos,
    /// Capture syscall and lifecycle events as Chrome trace data.
    ChromeTrace,
    /// Buffer standard output and error writes by logical epochs.
    ChunkyPrint,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-200): Review exact production debug-tool hosting.
    /// Run the production no-subscription debug tool without a GDB server.
    Debug,
    /// Decode and print every intercepted syscall.
    Strace,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-200): Review exact production minimal-strace hosting.
    /// Print every intercepted syscall before injecting it.
    StraceMinimal,
    /// Count intercepted syscalls in the current plugin process.
    Counter1,
    Counter1Exact,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-142): Review the process-local counter2 adaptation.
    /// Count syscalls and unique process/thread identities in this plugin process.
    Counter2,
    /// Run the exact backend-neutral counter2 implementation.
    Counter2Exact,
    /// Forward syscalls without tool-specific work.
    Noop,
}

impl ToolKind {
    pub(crate) fn from_environment() -> Self {
        if let Some(selected) = SELECTED_TOOL.get() {
            return *selected;
        }

        // SAFETY: Plugin construction runs before SaBRe starts guest callbacks.
        let selected = unsafe { reverie_sabre::take_private_env(TOOL_ENV) };

        Self::remember(&SELECTED_TOOL, selected.as_deref())
    }

    fn remember(slot: &OnceLock<Self>, requested: Option<&OsStr>) -> Self {
        if let Some(selected) = slot.get() {
            return *selected;
        }

        let selected = match requested {
            Some(value) if value == "chaos" => Self::Chaos,
            Some(value) if value == "chrome-trace" => Self::ChromeTrace,
            Some(value) if value == "chunky-print" => Self::ChunkyPrint,
            Some(value) if value == "debug" => Self::Debug,
            Some(value) if value == "counter1" => Self::Counter1,
            Some(value) if value == "counter1-exact" => Self::Counter1Exact,
            Some(value) if value == "counter2" => Self::Counter2,
            Some(value) if value == "counter2-exact" => Self::Counter2Exact,
            Some(value) if value == "noop" => Self::Noop,
            Some(value) if value == "strace" => Self::Strace,
            Some(value) if value == "strace-minimal" => Self::StraceMinimal,
            None => Self::Strace,
            Some(other) => {
                nostd_print::eprintln!("reverie-sabre: unknown {TOOL_ENV}={other:?}; using strace");
                Self::Strace
            }
        };

        *slot.get_or_init(|| selected)
    }
}

fn coordinator_socket() -> Option<PathBuf> {
    if let Some(path) = COUNTER_RPC_SOCKET.get() {
        return path.clone();
    }

    // SAFETY: Plugin construction runs before SaBRe starts guest callbacks.
    let requested = unsafe { reverie_sabre::take_private_env(COUNTER_RPC_SOCKET_ENV) };
    remember_coordinator_socket(&COUNTER_RPC_SOCKET, requested.as_deref())
}

fn remember_coordinator_socket(
    slot: &OnceLock<Option<PathBuf>>,
    requested: Option<&OsStr>,
) -> Option<PathBuf> {
    slot.get_or_init(|| requested.map(PathBuf::from)).clone()
}

#[derive(Debug, Default)]
pub(super) struct Counter1Global {
    num_syscalls: AtomicU64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) struct Counter1Request(Sysno);

#[reverie::global_tool]
impl GlobalTool for Counter1Global {
    type Request = Counter1Request;
    type Response = u64;
    type Config = CounterConfig;

    async fn init_global_state(_config: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, Counter1Request(_sysno): Counter1Request) -> u64 {
        self.num_syscalls.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl Counter1Global {
    pub(super) fn total(&self) -> u64 {
        self.num_syscalls.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
pub(super) struct Counter1Tool;

#[reverie::tool]
impl ReverieTool for Counter1Tool {
    type GlobalState = Counter1Global;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let count = guest.send_rpc(Counter1Request(syscall.number())).await;
        if is_terminal(syscall) && guest.config().print_process_local_summary {
            nostd_print::eprintln!(" [counter tool] Total system calls in plugin process: {count}");
        }
        guest.tail_inject(syscall).await
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-142): Review counter2 state, RPC, and scope semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Counter2Summary {
    pub(super) total_syscalls: u64,
    pub(super) processes: u64,
    pub(super) threads: u64,
}

#[derive(Debug, Default)]
struct Counter2State {
    total_syscalls: u64,
    processes: BTreeSet<i32>,
    threads: BTreeSet<i32>,
}

#[derive(Debug, Default)]
pub(super) struct Counter2Global {
    inner: Mutex<Counter2State>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Counter2Request {
    pid: i32,
    tid: i32,
}

#[reverie::global_tool]
impl GlobalTool for Counter2Global {
    type Request = Counter2Request;
    type Response = Counter2Summary;
    type Config = CounterConfig;

    async fn init_global_state(_config: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, request: Counter2Request) -> Counter2Summary {
        let mut state = self.inner.lock().unwrap();
        state.total_syscalls += 1;
        state.processes.insert(request.pid);
        state.threads.insert(request.tid);
        Counter2Summary {
            total_syscalls: state.total_syscalls,
            processes: state.processes.len() as u64,
            threads: state.threads.len() as u64,
        }
    }
}

impl Counter2Global {
    pub(super) fn summary(&self) -> Counter2Summary {
        let state = self.inner.lock().unwrap();
        Counter2Summary {
            total_syscalls: state.total_syscalls,
            processes: state.processes.len() as u64,
            threads: state.threads.len() as u64,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct Counter2Tool;

#[reverie::tool]
impl ReverieTool for Counter2Tool {
    type GlobalState = Counter2Global;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        let summary = guest
            .send_rpc(Counter2Request {
                pid: guest.pid().as_raw(),
                tid: guest.tid().as_raw(),
            })
            .await;
        if is_terminal(syscall) && guest.config().print_process_local_summary {
            nostd_print::eprintln!(
                " [counter2 tool] Total system calls in plugin process: {}, from {} process identity, {} thread(s).",
                summary.total_syscalls,
                summary.processes,
                summary.threads
            );
        }
        guest.tail_inject(syscall).await
    }
}

#[derive(Debug, Default)]
pub(super) struct NoopTool;

#[reverie::tool]
impl ReverieTool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::none()
    }
}

fn is_terminal(syscall: Syscall) -> bool {
    matches!(syscall, Syscall::ExitGroup(_))
}

pub(crate) enum SharedAdapter {
    ChaosLocal(ReverieAdapter<ExactChaosTool>),
    ChaosRemote(RemoteReverieAdapter<ExactChaosTool>),
    ChromeTraceLocal(ReverieAdapter<ExactChromeTraceTool>),
    ChromeTraceRemote(RemoteReverieAdapter<ExactChromeTraceTool>),
    ChunkyPrintLocal(ReverieAdapter<ExactChunkyPrintTool>),
    ChunkyPrintRemote(RemoteReverieAdapter<ExactChunkyPrintTool>),
    Debug(ReverieAdapter<ExactDebugTool>),
    Strace(ReverieAdapter<StraceTool>),
    StraceMinimal(ReverieAdapter<ExactStraceMinimalTool>),
    Counter1Local(ReverieAdapter<Counter1Tool>),
    Counter1Remote(RemoteReverieAdapter<Counter1Tool>),
    Counter1ExactLocal(ReverieAdapter<ExactCounter1Tool>, ExactCounter1Global),
    Counter1ExactRemote(RemoteReverieAdapter<ExactCounter1Tool>),
    Counter2Local(ReverieAdapter<Counter2Tool>),
    Counter2Remote(RemoteReverieAdapter<Counter2Tool>),
    Counter2ExactLocal(ReverieAdapter<ExactCounter2Tool>),
    Counter2ExactRemote(RemoteReverieAdapter<ExactCounter2Tool>),
    Noop(ReverieAdapter<NoopTool>),
}

impl SharedAdapter {
    pub(crate) fn new(kind: ToolKind, quiet: bool) -> Self {
        match kind {
            ToolKind::Chaos => coordinator_socket().map_or_else(
                || Self::ChaosLocal(local_adapter(ExactChaosConfig::default())),
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::ChaosRemote(adapter),
                    Err(error) => {
                        coordinator_fallback("chaos", &path, &error);
                        Self::ChaosLocal(local_adapter(ExactChaosConfig::default()))
                    }
                },
            ),
            ToolKind::ChromeTrace => coordinator_socket().map_or_else(
                || Self::ChromeTraceLocal(local_adapter(())),
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::ChromeTraceRemote(adapter),
                    Err(error) => {
                        coordinator_fallback("chrome-trace", &path, &error);
                        Self::ChromeTraceLocal(local_adapter(()))
                    }
                },
            ),
            ToolKind::ChunkyPrint => coordinator_socket().map_or_else(
                || Self::ChunkyPrintLocal(local_adapter(())),
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::ChunkyPrintRemote(adapter),
                    Err(error) => {
                        coordinator_fallback("chunky-print", &path, &error);
                        Self::ChunkyPrintLocal(local_adapter(()))
                    }
                },
            ),
            ToolKind::Debug => Self::Debug(ReverieAdapter::new(ExactDebugTool, (), ())),
            ToolKind::Strace => Self::Strace(ReverieAdapter::new(StraceTool { quiet }, (), ())),
            ToolKind::StraceMinimal => {
                Self::StraceMinimal(ReverieAdapter::new(ExactStraceMinimalTool::default(), (), ()))
            }
            ToolKind::Counter1 => coordinator_socket().map_or_else(
                Self::counter1_local,
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::Counter1Remote(adapter),
                    Err(error) => {
                        nostd_print::eprintln!(
                            "reverie-sabre: counter1 coordinator {} unavailable ({error}); using process-local state",
                            path.display()
                        );
                        Self::counter1_local()
                    }
                },
            ),
            ToolKind::Counter1Exact => coordinator_socket().map_or_else(
                Self::counter1_exact_local,
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::Counter1ExactRemote(adapter),
                    Err(error) => {
                        nostd_print::eprintln!(
                            "reverie-sabre: counter1-exact coordinator {} unavailable ({error}); using process-local state",
                            path.display()
                        );
                        Self::counter1_exact_local()
                    }
                },
            ),
            ToolKind::Counter2 => coordinator_socket().map_or_else(
                Self::counter2_local,
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::Counter2Remote(adapter),
                    Err(error) => {
                        nostd_print::eprintln!(
                            "reverie-sabre: counter2 coordinator {} unavailable ({error}); using process-local state",
                            path.display()
                        );
                        Self::counter2_local()
                    }
                },
            ),
            ToolKind::Counter2Exact => coordinator_socket().map_or_else(
                || Self::Counter2ExactLocal(local_adapter(())),
                |path| match RemoteReverieAdapter::connect(&path) {
                    Ok(adapter) => Self::Counter2ExactRemote(adapter),
                    Err(error) => {
                        coordinator_fallback("counter2-exact", &path, &error);
                        Self::Counter2ExactLocal(local_adapter(()))
                    }
                },
            ),
            ToolKind::Noop => Self::Noop(ReverieAdapter::new(NoopTool, (), ())),
        }
    }

    fn counter1_local() -> Self {
        Self::Counter1Local(ReverieAdapter::new(
            Counter1Tool,
            Counter1Global::default(),
            CounterConfig::process_local(),
        ))
    }

    fn counter1_exact_local() -> Self {
        let global = ExactCounter1Global::default();
        Self::Counter1ExactLocal(
            ReverieAdapter::new(ExactCounter1Tool::default(), global.clone(), ()),
            global,
        )
    }

    fn counter2_local() -> Self {
        Self::Counter2Local(ReverieAdapter::new(
            Counter2Tool,
            Counter2Global::default(),
            CounterConfig::process_local(),
        ))
    }

    pub(crate) fn handle_syscall(&self, syscall: Syscall) -> Result<usize, Errno> {
        match self {
            Self::ChaosLocal(adapter) => adapter.handle_syscall(syscall),
            Self::ChaosRemote(adapter) => adapter.handle_syscall(syscall),
            Self::ChromeTraceLocal(adapter) => adapter.handle_syscall(syscall),
            Self::ChromeTraceRemote(adapter) => adapter.handle_syscall(syscall),
            Self::ChunkyPrintLocal(adapter) => adapter.handle_syscall(syscall),
            Self::ChunkyPrintRemote(adapter) => adapter.handle_syscall(syscall),
            Self::Debug(adapter) => adapter.handle_syscall(syscall),
            Self::Strace(adapter) => adapter.handle_syscall(syscall),
            Self::StraceMinimal(adapter) => adapter.handle_syscall(syscall),
            Self::Counter1Local(adapter) => adapter.handle_syscall(syscall),
            Self::Counter1Remote(adapter) => adapter.handle_syscall(syscall),
            Self::Counter1ExactLocal(adapter, _) => adapter.handle_syscall(syscall),
            Self::Counter1ExactRemote(adapter) => adapter.handle_syscall(syscall),
            Self::Counter2Local(adapter) => adapter.handle_syscall(syscall),
            Self::Counter2Remote(adapter) => adapter.handle_syscall(syscall),
            Self::Counter2ExactLocal(adapter) => adapter.handle_syscall(syscall),
            Self::Counter2ExactRemote(adapter) => adapter.handle_syscall(syscall),
            Self::Noop(adapter) => adapter.handle_syscall(syscall),
        }
    }

    pub(crate) fn handle_syscall_with_inject<F>(
        &self,
        syscall: Syscall,
        inject: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut() -> usize + Send + Sync,
    {
        match self {
            Self::ChaosLocal(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::ChaosRemote(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::ChromeTraceLocal(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::ChromeTraceRemote(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::ChunkyPrintLocal(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::ChunkyPrintRemote(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Debug(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Strace(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::StraceMinimal(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter1Local(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter1Remote(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter1ExactLocal(adapter, _) => {
                adapter.handle_syscall_with_inject(syscall, inject)
            }
            Self::Counter1ExactRemote(adapter) => {
                adapter.handle_syscall_with_inject(syscall, inject)
            }
            Self::Counter2Local(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter2Remote(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter2ExactLocal(adapter) => {
                adapter.handle_syscall_with_inject(syscall, inject)
            }
            Self::Counter2ExactRemote(adapter) => {
                adapter.handle_syscall_with_inject(syscall, inject)
            }
            Self::Noop(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
        }
    }

    pub(crate) fn handle_thread_start(&self, thread_id: u32) {
        match self {
            Self::ChaosLocal(adapter) => adapter.handle_thread_start(thread_id),
            Self::ChaosRemote(adapter) => adapter.handle_thread_start(thread_id),
            Self::ChromeTraceLocal(adapter) => adapter.handle_thread_start(thread_id),
            Self::ChromeTraceRemote(adapter) => adapter.handle_thread_start(thread_id),
            Self::ChunkyPrintLocal(adapter) => adapter.handle_thread_start(thread_id),
            Self::ChunkyPrintRemote(adapter) => adapter.handle_thread_start(thread_id),
            Self::Debug(adapter) => adapter.handle_thread_start(thread_id),
            Self::Strace(adapter) => adapter.handle_thread_start(thread_id),
            Self::StraceMinimal(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter1Local(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter1Remote(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter1ExactLocal(adapter, _) => adapter.handle_thread_start(thread_id),
            Self::Counter1ExactRemote(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter2Local(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter2Remote(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter2ExactLocal(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter2ExactRemote(adapter) => adapter.handle_thread_start(thread_id),
            Self::Noop(adapter) => adapter.handle_thread_start(thread_id),
        }
    }

    pub(crate) fn handle_thread_exit(&self, thread_id: u32) {
        match self {
            Self::ChaosLocal(adapter) => adapter.handle_thread_exit(thread_id),
            Self::ChaosRemote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::ChromeTraceLocal(adapter) => adapter.handle_thread_exit(thread_id),
            Self::ChromeTraceRemote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::ChunkyPrintLocal(adapter) => adapter.handle_thread_exit(thread_id),
            Self::ChunkyPrintRemote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Debug(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Strace(adapter) => adapter.handle_thread_exit(thread_id),
            Self::StraceMinimal(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter1Local(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter1Remote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter1ExactLocal(adapter, global) => {
                adapter.handle_thread_exit(thread_id);
                nostd_print::eprintln!("counter1-global syscalls={}", global.total());
            }
            Self::Counter1ExactRemote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter2Local(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter2Remote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter2ExactLocal(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter2ExactRemote(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Noop(adapter) => adapter.handle_thread_exit(thread_id),
        }
    }

    pub(crate) fn handle_post_exec(&self) {
        match self {
            Self::ChaosLocal(adapter) => adapter.handle_post_exec(),
            Self::ChaosRemote(adapter) => adapter.handle_post_exec(),
            Self::ChromeTraceLocal(adapter) => adapter.handle_post_exec(),
            Self::ChromeTraceRemote(adapter) => adapter.handle_post_exec(),
            Self::ChunkyPrintLocal(adapter) => adapter.handle_post_exec(),
            Self::ChunkyPrintRemote(adapter) => adapter.handle_post_exec(),
            Self::Debug(adapter) => adapter.handle_post_exec(),
            Self::Strace(adapter) => adapter.handle_post_exec(),
            Self::StraceMinimal(adapter) => adapter.handle_post_exec(),
            Self::Counter1Local(adapter) => adapter.handle_post_exec(),
            Self::Counter1Remote(adapter) => adapter.handle_post_exec(),
            Self::Counter1ExactLocal(adapter, _) => adapter.handle_post_exec(),
            Self::Counter1ExactRemote(adapter) => adapter.handle_post_exec(),
            Self::Counter2Local(adapter) => adapter.handle_post_exec(),
            Self::Counter2Remote(adapter) => adapter.handle_post_exec(),
            Self::Counter2ExactLocal(adapter) => adapter.handle_post_exec(),
            Self::Counter2ExactRemote(adapter) => adapter.handle_post_exec(),
            Self::Noop(adapter) => adapter.handle_post_exec(),
        }
    }

    pub(crate) fn handle_process_exit(&self, exit_status: reverie::ExitStatus) {
        match self {
            Self::Counter2ExactLocal(adapter) => adapter.handle_process_exit(exit_status),
            Self::Counter2ExactRemote(adapter) => adapter.handle_process_exit(exit_status),
            _ => {}
        }
    }
}

fn local_adapter<T>(config: <T::GlobalState as GlobalTool>::Config) -> ReverieAdapter<T>
where
    T: ReverieTool,
{
    let tool = T::new(Pid::from_raw(unsafe { libc::getpid() }), &config);
    ReverieAdapter::new(tool, T::GlobalState::default(), config)
}

fn coordinator_fallback(tool: &str, path: &std::path::Path, error: &impl std::fmt::Display) {
    nostd_print::eprintln!(
        "reverie-sabre: {tool} coordinator {} unavailable ({error}); using process-local state",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_tool_survives_plugin_reinitialization() {
        let selected = OnceLock::new();

        assert_eq!(
            ToolKind::remember(&selected, Some(OsStr::new("noop"))),
            ToolKind::Noop
        );
        assert_eq!(ToolKind::remember(&selected, None), ToolKind::Noop);
        assert_eq!(
            ToolKind::remember(&selected, Some(OsStr::new("counter1"))),
            ToolKind::Noop
        );
    }

    #[test]
    fn all_production_tools_are_selectable() {
        for (name, expected) in [
            ("chaos", ToolKind::Chaos),
            ("chrome-trace", ToolKind::ChromeTrace),
            ("chunky-print", ToolKind::ChunkyPrint),
            ("debug", ToolKind::Debug),
            ("strace", ToolKind::Strace),
            ("strace-minimal", ToolKind::StraceMinimal),
            ("counter1", ToolKind::Counter1),
            ("counter2", ToolKind::Counter2),
            ("noop", ToolKind::Noop),
        ] {
            assert_eq!(
                ToolKind::remember(&OnceLock::new(), Some(OsStr::new(name))),
                expected,
                "selector {name}"
            );
        }
    }

    #[test]
    fn coordinator_socket_survives_plugin_reinitialization() {
        let selected = OnceLock::new();

        assert_eq!(
            remember_coordinator_socket(&selected, Some(OsStr::new("/tmp/coordinator.sock"))),
            Some(PathBuf::from("/tmp/coordinator.sock"))
        );
        assert_eq!(
            remember_coordinator_socket(&selected, None),
            Some(PathBuf::from("/tmp/coordinator.sock"))
        );
    }

    #[tokio::test]
    async fn counter1_returns_the_updated_total() {
        let global = Counter1Global::default();
        let pid = Pid::from_raw(17);
        assert_eq!(
            global
                .receive_rpc(pid, Counter1Request(Sysno::getpid))
                .await,
            1
        );
        assert_eq!(
            global
                .receive_rpc(pid, Counter1Request(Sysno::gettid))
                .await,
            2
        );
        assert_eq!(global.total(), 2);
    }

    #[tokio::test]
    async fn counter2_tracks_unique_processes_and_threads() {
        let global = Counter2Global::default();
        let from = Pid::from_raw(1);
        let first = global
            .receive_rpc(from, Counter2Request { pid: 10, tid: 10 })
            .await;
        let second = global
            .receive_rpc(from, Counter2Request { pid: 10, tid: 11 })
            .await;
        let third = global
            .receive_rpc(from, Counter2Request { pid: 12, tid: 12 })
            .await;

        assert_eq!(
            first,
            Counter2Summary {
                total_syscalls: 1,
                processes: 1,
                threads: 1,
            }
        );
        assert_eq!(second.total_syscalls, 2);
        assert_eq!(second.processes, 1);
        assert_eq!(second.threads, 2);
        assert_eq!(
            third,
            Counter2Summary {
                total_syscalls: 3,
                processes: 2,
                threads: 3,
            }
        );
    }
}
