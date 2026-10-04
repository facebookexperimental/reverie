/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Ptrace launcher for the shared counter1 tool.

mod counter1_tool;

use clap::Parser;
use counter1_tool::CounterLocal;
use reverie::Error;
use reverie_util::CommonToolArguments;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::parse();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<CounterLocal>::new(args.into())
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    eprintln!("counter1-global syscalls={}", global_state.total());
    drop(log_guard);
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
