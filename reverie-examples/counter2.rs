/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An example that counts system calls using a simple, global state.

use reverie::{
    syscalls::{Syscall, SyscallInfo},
    Error, ExitStatus, GlobalRPC, GlobalTool, Guest, Pid, Tid, Tool,
};
use reverie_util::CommonToolArguments;
use structopt::StructOpt;

use core::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tracing::debug;

/// Global state for the tool.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GlobalInner {
    pub total_syscalls: u64,
    pub exited_procs: u64,
    pub exited_threads: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CounterGlobal {
    pub inner: Mutex<GlobalInner>,
}

/// Local, per-process state for the tool.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CounterLocal {
    proc_syscalls: AtomicU64,
    exited_threads: AtomicU64,
}

impl Clone for CounterLocal {
    fn clone(&self) -> Self {
        CounterLocal {
            proc_syscalls: AtomicU64::new(self.proc_syscalls.load(Ordering::SeqCst)),
            exited_threads: AtomicU64::new(self.exited_threads.load(Ordering::SeqCst)),
        }
    }
}

/// The message sent to the global state method.
#[derive(PartialEq, Debug, Eq, Hash, Clone, Serialize, Deserialize, Copy)]
pub struct IncrMsg(u64, u64);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    async fn init_global_state(_: &Self::Config) -> Self {
        CounterGlobal {
            inner: Mutex::new(GlobalInner {
                total_syscalls: 0,
                exited_procs: 0,
                exited_threads: 0,
            }),
        }
    }
    async fn receive_rpc(&self, _from: Pid, IncrMsg(n, t): IncrMsg) -> Self::Response {
        let mut mg = self.inner.lock().unwrap();
        mg.total_syscalls += n;
        mg.exited_threads += t;
        mg.exited_procs += 1;
    }
}

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    /// Yet another level of counters per-thread:
    type ThreadState = u64;

    fn new(pid: Pid, _cfg: &()) -> Self {
        debug!(" [counter] initialize counter for pid {}", pid);
        CounterLocal {
            proc_syscalls: AtomicU64::new(0),
            exited_threads: AtomicU64::new(0),
        }
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
        ts: u64,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        debug!("count at exit thread {} = {}", tid, &ts);
        self.proc_syscalls.fetch_add(ts, Ordering::SeqCst);
        self.exited_threads.fetch_add(1, Ordering::SeqCst);
        debug!(
            "  contributed to process-level count: {}",
            self.proc_syscalls.load(Ordering::Relaxed)
        );
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
        drop(self);
        debug!(
            "At ExitProc (pid {}), contributing {} to global count.",
            pid, count
        );
        let _ = global_state.send_rpc(IncrMsg(count, threads)).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::from_args();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<CounterLocal>::new(args.into())
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    let mg = global_state.inner.lock().unwrap();
    eprintln!(
        " [counter tool] Total system calls in process tree: {}, from {} processes, {} thread(s).",
        mg.total_syscalls, mg.exited_procs, mg.exited_threads
    );
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
