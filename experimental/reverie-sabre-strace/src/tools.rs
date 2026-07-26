/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared Reverie example tools hosted by the SaBRe plugin.

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

/// Shared Reverie tool implementations available through the SaBRe runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ToolKind {
    /// Decode and print every intercepted syscall.
    Strace,
    /// Count intercepted syscalls in the current plugin process.
    Counter1,
    /// Forward syscalls without tool-specific work.
    Noop,
}

impl ToolKind {
    pub(crate) fn from_environment() -> Self {
        let selected = std::env::var(TOOL_ENV);
        // SaBRe caches reserved settings before plugin initialization, so the
        // plugin can consume this value without losing it across exec.
        std::env::remove_var(TOOL_ENV);

        match selected.as_deref() {
            Ok("counter1") => Self::Counter1,
            Ok("noop") => Self::Noop,
            Ok("strace") | Err(_) => Self::Strace,
            Ok(other) => {
                nostd_print::eprintln!("reverie-sabre: unknown {TOOL_ENV}={other:?}; using strace");
                Self::Strace
            }
        }
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
            nostd_print::eprintln!(" [counter tool] Total system calls in process tree: {count}");
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
            ToolKind::Noop => Self::Noop(ReverieAdapter::new(NoopTool, (), ())),
        }
    }

    pub(crate) fn handle_syscall(&self, syscall: Syscall) -> Result<usize, Errno> {
        match self {
            Self::Strace(adapter) => adapter.handle_syscall(syscall),
            Self::Counter1(adapter) => adapter.handle_syscall(syscall),
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
            Self::Noop(adapter) => adapter.handle_syscall_with_inject(syscall, inject),
        }
    }

    pub(crate) fn handle_thread_start(&self, thread_id: u32) {
        match self {
            Self::Strace(adapter) => adapter.handle_thread_start(thread_id),
            Self::Counter1(adapter) => adapter.handle_thread_start(thread_id),
            Self::Noop(adapter) => adapter.handle_thread_start(thread_id),
        }
    }

    pub(crate) fn handle_thread_exit(&self, thread_id: u32) {
        match self {
            Self::Strace(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Counter1(adapter) => adapter.handle_thread_exit(thread_id),
            Self::Noop(adapter) => adapter.handle_thread_exit(thread_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
