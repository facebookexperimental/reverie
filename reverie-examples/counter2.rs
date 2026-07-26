/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An example that counts system calls using a simple, global state.

#[path = "src/kvm_runner.rs"]
mod kvm_runner;

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::sync::Mutex;

use clap::Parser;
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
use reverie_util::CommonToolArguments;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;

/// Global state for the tool.
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

/// Local, per-process state for the tool.
#[derive(Debug, Default)]
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
    type Config = ();

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
        debug!(
            "At ExitProc (pid {}), contributing {} to global count.",
            pid, count
        );
        let _ = global_state.send_rpc(IncrMsg(count, threads)).await;
        Ok(())
    }
}

#[derive(Debug, Parser)]
struct Opts {
    // TODO-HUMAN-REVIEW(PR-151): Review counter2 runner selection.
    /// Execution runner; KVM selects the prototype KvmGuest host.
    #[clap(long, value_enum, default_value = "ptrace")]
    runner: kvm_runner::Runner,

    #[clap(flatten)]
    common: CommonToolArguments,
}

fn main() -> anyhow::Result<()> {
    let args = Opts::parse();
    let stdin = match args.runner {
        kvm_runner::Runner::Ptrace => None,
        kvm_runner::Runner::Kvm => kvm_runner::reserve_stdin()?,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_main(args, stdin))
}

async fn run_main(args: Opts, stdin: Option<std::fs::File>) -> anyhow::Result<()> {
    let log_guard = args.common.init_tracing();
    let (status, global_state) = match args.runner {
        kvm_runner::Runner::Ptrace => {
            let tracer =
                reverie_ptrace::TracerBuilder::<CounterLocal>::new(args.common.clone().into())
                    .spawn()
                    .await?;
            tracer.wait().await?
        }
        kvm_runner::Runner::Kvm => {
            let result = kvm_runner::run::<CounterLocal>(&args.common, (), stdin).await?;
            (ExitStatus::Exited(result.exit_code), result.global_state)
        }
    };
    let (total_syscalls, exited_procs, exited_threads) = {
        let global = global_state.inner.lock().unwrap();
        (
            global.total_syscalls,
            global.exited_procs,
            global.exited_threads,
        )
    };
    match args.runner {
        kvm_runner::Runner::Ptrace => eprintln!(
            " [counter tool] Total system calls in process tree: {total_syscalls}, from {exited_procs} processes, {exited_threads} thread(s)."
        ),
        kvm_runner::Runner::Kvm => eprintln!(
            " [counter tool] Total system calls observed from root process: {total_syscalls}, from {exited_procs} observed process, {exited_threads} observed thread(s)."
        ),
    }
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "kvm_test_support.rs"]
mod kvm_test_support;

#[cfg(all(test, target_arch = "x86_64"))]
mod kvm_tests {
    use reverie::syscalls::Sysno;

    use super::*;

    fn null_executor(
        _request: &reverie_kvm::SyscallRequest,
        _memory: &reverie_kvm::GuestMemory,
    ) -> i64 {
        0
    }

    #[tokio::test]
    async fn exact_counter2_tool_aggregates_kvm_guest_lifecycle() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_counter2_tool_aggregates_kvm_guest_lifecycle",
            Sysno::getpid,
        ) else {
            return;
        };

        let counter = backend
            .run_with_tool::<CounterLocal, _>((), null_executor)
            .await
            .unwrap();
        let totals = counter.inner.lock().unwrap();

        assert_eq!(totals.total_syscalls, 1);
        assert_eq!(totals.exited_procs, 1);
        assert_eq!(totals.exited_threads, 1);
    }

    #[tokio::test]
    async fn exact_counter2_tool_runs_static_kvm_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_static_syscall(
            "exact_counter2_tool_runs_static_kvm_syscall",
        ) else {
            return;
        };

        let (counter, exit_code, stdout, stderr) = backend
            .run_static_elf_with_tool::<CounterLocal>((), true)
            .await
            .unwrap();
        let totals = counter.inner.lock().unwrap();

        assert_eq!(exit_code, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(totals.total_syscalls, 2);
        assert_eq!(totals.exited_procs, 1);
        assert_eq!(totals.exited_threads, 1);
    }
}
