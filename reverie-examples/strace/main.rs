/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// TODO-HUMAN-REVIEW(PR-139): Review module visibility for the shared LiteInst host.
pub(crate) mod config;
pub(crate) mod filter;
pub(crate) mod global_state;
pub(crate) mod tool;

#[path = "../src/kvm_runner.rs"]
mod kvm_runner;

use clap::Parser;
// TODO-HUMAN-REVIEW(PR-139): Review type visibility for the shared LiteInst host.
pub(crate) use config::Config;
pub(crate) use filter::Filter;
use reverie::ExitStatus;
use reverie_util::CommonToolArguments;
pub(crate) use tool::Strace;

/// A tool to trace system calls.
#[derive(Parser, Debug)]
struct Opts {
    // TODO-HUMAN-REVIEW(PR-151): Review strace runner selection.
    /// Execution runner; KVM selects the prototype KvmGuest host.
    #[clap(long, value_enum, default_value = "ptrace")]
    runner: kvm_runner::Runner,

    #[clap(flatten)]
    common: CommonToolArguments,

    /// The set of syscalls to trace. By default, all syscalls are traced. If
    /// this is used, then only the specified syscalls are traced. By limiting
    /// the set of traced syscalls, we can reduce the overhead of the tracer.
    #[clap(long)]
    trace: Vec<Filter>,
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
    let config = Config {
        filters: args.trace,
    };
    let log_guard = args.common.init_tracing();
    let (status, _) = match args.runner {
        kvm_runner::Runner::Ptrace => {
            let tracer = reverie_ptrace::TracerBuilder::<Strace>::new(args.common.clone().into())
                .config(config)
                .spawn()
                .await?;
            tracer.wait().await?
        }
        kvm_runner::Runner::Kvm => {
            let result = kvm_runner::run::<Strace>(&args.common, config, stdin).await?;
            (ExitStatus::Exited(result.exit_code), result.global_state)
        }
    };
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "../kvm_test_support.rs"]
mod kvm_test_support;

#[cfg(all(test, target_arch = "x86_64"))]
mod kvm_tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use reverie::syscalls::Sysno;
    use tokio::sync::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    #[tokio::test]
    async fn exact_strace_tool_forwards_kvm_guest_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_strace_tool_forwards_kvm_guest_syscall",
            Sysno::getpid,
        ) else {
            return;
        };
        let _guard = TEST_LOCK.lock().await;
        tool::take_handled_syscalls();
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let config = Config {
            filters: vec![Filter {
                inverse: false,
                syscalls: vec![Sysno::getpid],
            }],
        };

        backend
            .run_with_tool::<Strace, _>(
                config,
                move |_request: &reverie_kvm::SyscallRequest,
                      _memory: &reverie_kvm::GuestMemory| {
                    executor_calls.fetch_add(1, Ordering::SeqCst);
                    1234
                },
            )
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(tool::take_handled_syscalls(), 1);
    }

    #[tokio::test]
    async fn exact_strace_tool_runs_static_kvm_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_static_syscall(
            "exact_strace_tool_runs_static_kvm_syscall",
        ) else {
            return;
        };
        let _guard = TEST_LOCK.lock().await;
        tool::take_handled_syscalls();
        let config = Config {
            filters: vec![Filter {
                inverse: false,
                syscalls: vec![Sysno::getpid],
            }],
        };

        let (_, exit_code, stdout, stderr) = backend
            .run_static_elf_with_tool::<Strace>(config, true)
            .await
            .unwrap();

        assert_eq!(exit_code, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(tool::take_handled_syscalls(), 1);
    }
}
