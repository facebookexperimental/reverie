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

use clap::Parser;
// TODO-HUMAN-REVIEW(PR-139): Review type visibility for the shared LiteInst host.
pub(crate) use config::Config;
pub(crate) use filter::Filter;
use reverie::Error;
use reverie_util::CommonToolArguments;
pub(crate) use tool::Strace;

/// A tool to trace system calls.
#[derive(Parser, Debug)]
struct Opts {
    #[clap(flatten)]
    common: CommonToolArguments,

    /// The set of syscalls to trace. By default, all syscalls are traced. If
    /// this is used, then only the specified syscalls are traced. By limiting
    /// the set of traced syscalls, we can reduce the overhead of the tracer.
    #[clap(long)]
    trace: Vec<Filter>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Opts::parse();

    let config = Config {
        filters: args.trace,
    };

    let log_guard = args.common.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<Strace>::new(args.common.into())
        .config(config)
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;
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

    use super::*;

    #[tokio::test]
    async fn exact_strace_tool_forwards_kvm_guest_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_strace_tool_forwards_kvm_guest_syscall",
            Sysno::getpid,
        ) else {
            return;
        };
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
    }
}
