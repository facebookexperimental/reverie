/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared Reverie example tools hosted by the SaBRe plugin.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool as ReverieTool;
use reverie_sabre::ReverieAdapter;
use reverie_syscalls::Syscall;
use reverie_syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;
use syscalls::Errno;
use syscalls::Sysno;

use super::StraceTool;

/// Environment variable selecting the shared tool hosted by the plugin.
pub(super) const TOOL_ENV: &str = "REVERIE_SABRE_TOOL";

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-158): Review fork-inherited example-tool selection.
static SELECTED_TOOL: OnceLock<ToolKind> = OnceLock::new();

/// Shared Reverie tool implementations available through the SaBRe runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ToolKind {
    /// Decode and print every intercepted syscall.
    Strace,
    /// Count intercepted syscalls in the current plugin process.
    Counter1,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-142): Review the process-local counter2 adaptation.
    /// Count syscalls and unique process/thread identities in this plugin process.
    Counter2,
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
            Some(value) if value == "counter1" => Self::Counter1,
            Some(value) if value == "counter2" => Self::Counter2,
            Some(value) if value == "noop" => Self::Noop,
            Some(value) if value == "strace" => Self::Strace,
            None => Self::Strace,
            Some(other) => {
                nostd_print::eprintln!("reverie-sabre: unknown {TOOL_ENV}={other:?}; using strace");
                Self::Strace
            }
        };

        *slot.get_or_init(|| selected)
    }
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
    type Config = ();

    async fn init_global_state(_config: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, Counter1Request(_sysno): Counter1Request) -> u64 {
        self.num_syscalls.fetch_add(1, Ordering::SeqCst) + 1
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
        if is_terminal(syscall) {
            nostd_print::eprintln!(" [counter tool] Total system calls in plugin process: {count}");
        }
        guest.tail_inject(syscall).await
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-142): Review counter2 state, RPC, and scope semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Counter2Summary {
    total_syscalls: u64,
    processes: u64,
    threads: u64,
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
    type Config = ();

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
        if is_terminal(syscall) {
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
    Strace(ReverieAdapter<StraceTool>),
    Counter1(ReverieAdapter<Counter1Tool>),
    Counter2(ReverieAdapter<Counter2Tool>),
    Noop(ReverieAdapter<NoopTool>),
}

impl SharedAdapter {
    pub(crate) fn new(kind: ToolKind, quiet: bool) -> Self {
        match kind {
            ToolKind::Strace => Self::Strace(ReverieAdapter::new(StraceTool { quiet }, (), ())),
            ToolKind::Counter1 => Self::Counter1(ReverieAdapter::new(
                Counter1Tool,
                Counter1Global::default(),
                (),
            )),
            ToolKind::Counter2 => Self::Counter2(ReverieAdapter::new(
                Counter2Tool,
                Counter2Global::default(),
                (),
            )),
            ToolKind::Noop => Self::Noop(ReverieAdapter::new(NoopTool, (), ())),
        }
    }

    pub(crate) fn handle_syscall(&self, syscall: Syscall) -> Result<usize, Errno> {
        match self {
            Self::Strace(adapter) => adapter.handle_syscall(syscall),
            Self::Counter1(adapter) => adapter.handle_syscall(syscall),
            Self::Counter2(adapter) => adapter.handle_syscall(syscall),
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
            Self::Strace(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter1(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Counter2(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
            Self::Noop(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
        }
    }

    pub(crate) fn handle_thread_start(&self, thread_id: u32) {
        match self {
            Self::Strace(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter1(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter2(adapter) => adapter.handle_thread_start(thread_id),
            Self::Noop(adapter) => adapter.handle_thread_start(thread_id),
        }
    }

    pub(crate) fn handle_thread_exit(&self, thread_id: u32) {
        match self {
            Self::Strace(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter1(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter2(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Noop(adapter) => adapter.handle_thread_exit(thread_id),
        }
    }
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
