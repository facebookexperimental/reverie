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

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use clap::Parser;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_util::CommonToolArguments;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Default)]
// TODO-HUMAN-REVIEW(PR-139): Review visibility for the shared LiteInst host.
pub(crate) struct CounterGlobal {
    num_syscalls: AtomicU64,
}

#[derive(Debug, Default, Clone)]
// TODO-HUMAN-REVIEW(PR-139): Review visibility for the shared LiteInst host.
pub(crate) struct CounterLocal {}

impl CounterGlobal {
    // Used by the LiteInst host; the standalone ptrace binary does not read it directly.
    #[allow(dead_code)]
    // TODO-HUMAN-REVIEW(PR-139): Review the LiteInst counter result accessor.
    pub(crate) fn total(&self) -> u64 {
        self.num_syscalls.load(Ordering::SeqCst)
    }
}

/// The message sent to the global state method.
/// This contains the syscall number.
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        CounterGlobal {
            num_syscalls: AtomicU64::new(0),
        }
    }
    async fn receive_rpc(&self, _from: Pid, IncrMsg(sysno): IncrMsg) -> Self::Response {
        AtomicU64::fetch_add(&self.num_syscalls, 1, Ordering::SeqCst);
        tracing::info!("count at syscall ({:?}): {:?}", sysno, self.num_syscalls);
    }
}

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let sysno = syscall.number();
        let _ = guest.send_rpc(IncrMsg(sysno)).await;
        guest.tail_inject(syscall).await
    }
}

#[derive(Debug, Parser)]
struct Opts {
    // TODO-HUMAN-REVIEW(PR-151): Review counter1 runner selection.
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
    let total = global_state.total();
    match args.runner {
        kvm_runner::Runner::Ptrace => {
            eprintln!(" [counter tool] Total system calls in process tree: {total}");
        }
        kvm_runner::Runner::Kvm => {
            eprintln!(" [counter tool] Total system calls observed from root process: {total}");
        }
    }
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "kvm_test_support.rs"]
mod kvm_test_support;

#[cfg(all(test, target_arch = "x86_64"))]
mod kvm_tests {
    use super::*;

    fn null_executor(
        _request: &reverie_kvm::SyscallRequest,
        _memory: &reverie_kvm::GuestMemory,
    ) -> i64 {
        0
    }

    #[tokio::test]
    async fn exact_counter1_tool_counts_kvm_guest_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_counter1_tool_counts_kvm_guest_syscall",
            Sysno::getpid,
        ) else {
            return;
        };

        let counter = backend
            .run_with_tool::<CounterLocal, _>((), null_executor)
            .await
            .unwrap();

        assert_eq!(counter.num_syscalls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_counter1_tool_runs_static_kvm_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_static_syscall(
            "exact_counter1_tool_runs_static_kvm_syscall",
        ) else {
            return;
        };

        let (counter, exit_code, stdout, stderr) = backend
            .run_static_elf_with_tool::<CounterLocal>((), true)
            .await
            .unwrap();

        assert_eq!(exit_code, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(counter.num_syscalls.load(Ordering::SeqCst), 2);
    }
}
