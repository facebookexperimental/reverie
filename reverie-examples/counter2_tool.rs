/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Backend-neutral implementation of the counter2 Reverie tool.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;

/// Global counter2 totals.
#[derive(Debug, Default)]
pub struct GlobalInner {
    pub total_syscalls: u64,
    pub exited_procs: u64,
    pub exited_threads: u64,
}

#[derive(Debug, Default)]
pub struct CounterGlobal {
    pub inner: Mutex<GlobalInner>,
}

impl CounterGlobal {
    /// Returns process-tree syscall, process, and thread totals.
    #[allow(dead_code)]
    pub fn totals(&self) -> (u64, u64, u64) {
        let state = self.inner.lock().unwrap();
        (
            state.total_syscalls,
            state.exited_procs,
            state.exited_threads,
        )
    }
}

/// Local, per-process state for counter2.
#[derive(Debug, Default)]
pub struct CounterLocal {
    proc_syscalls: AtomicU64,
    exited_threads: AtomicU64,
}

impl CounterLocal {
    /// Returns the process-local syscall and exited-thread totals.
    #[allow(dead_code)]
    pub fn process_totals(&self) -> (u64, u64) {
        (
            self.proc_syscalls.load(Ordering::SeqCst),
            self.exited_threads.load(Ordering::SeqCst),
        )
    }
}

impl Clone for CounterLocal {
    fn clone(&self) -> Self {
        CounterLocal {
            proc_syscalls: AtomicU64::new(self.proc_syscalls.load(Ordering::SeqCst)),
            exited_threads: AtomicU64::new(self.exited_threads.load(Ordering::SeqCst)),
        }
    }
}

/// Process-exit contribution to the global counter2 state.
#[derive(PartialEq, Debug, Eq, Hash, Clone, Serialize, Deserialize, Copy)]
pub struct IncrMsg(pub u64, pub u64);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, IncrMsg(n, t): IncrMsg) -> Self::Response {
        let mut state = self.inner.lock().unwrap();
        state.total_syscalls += n;
        state.exited_threads += t;
        state.exited_procs += 1;
    }
}

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    type ThreadState = u64;

    fn new(pid: Pid, _cfg: &()) -> Self {
        debug!(" [counter] initialize counter for pid {}", pid);
        Self::default()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        debug!(
            "thread count at syscall ({:?}): {}, process count: {}",
            call.number(),
            guest.thread_state(),
            self.proc_syscalls.load(Ordering::SeqCst)
        );
        guest.tail_inject(call).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Tid,
        _global_state: &G,
        thread_syscalls: u64,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        debug!("count at exit thread {} = {}", tid, thread_syscalls);
        self.proc_syscalls
            .fetch_add(thread_syscalls, Ordering::SeqCst);
        self.exited_threads.fetch_add(1, Ordering::SeqCst);
        eprintln!("counter2-local thread={} syscalls={}", tid, thread_syscalls);
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let count = self.proc_syscalls.load(Ordering::SeqCst);
        let threads = self.exited_threads.load(Ordering::SeqCst);
        debug!(
            "At ExitProc (pid {}), contributing {} to global count.",
            pid, count
        );
        let _ = global_state.send_rpc(IncrMsg(count, threads)).await;
        Ok(())
    }
}
