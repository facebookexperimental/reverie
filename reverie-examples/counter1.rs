/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Launcher for the shared counter1 tool on any Reverie backend (`--backend`).

mod counter1_tool;

#[path = "backend.rs"]
mod backend;

use clap::Parser;
use counter1_tool::CounterLocal;
use reverie_util::CommonToolArguments;

/// Run PROGRAM under the counter1 tool on BACKEND.
#[derive(Debug, Parser)]
struct Args {
    /// The Reverie backend to run the program on.
    #[clap(long, value_enum, default_value = "ptrace", alias = "runner")]
    backend: backend::BackendKind,
    /// The example preload the in-guest backends host the tool in; by
    /// default `libreverie_examples.so` beside this binary.
    #[clap(long)]
    preload: Option<std::path::PathBuf>,
    #[clap(flatten)]
    common: CommonToolArguments,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_guard = args.common.init_tracing();
    let run = backend::run_blocking::<CounterLocal>(
        args.backend,
        &args.common,
        (),
        "counter1",
        args.preload.clone(),
    )?;
    eprintln!("counter1-global syscalls={}", run.global_state.total());
    drop(log_guard);
    run.status.raise_or_exit()
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

        assert_eq!(counter.total(), 1);
    }
}
