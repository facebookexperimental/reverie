/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This instrumentation tool intercepts events but does nothing with them. It is
//! useful for observing the overhead of interception, and as a starting point.

use clap::Parser;
use reverie::Error;
use reverie::Subscription;
use reverie::Tool;
use reverie_util::CommonToolArguments;

#[derive(Debug, Default)]
// TODO-HUMAN-REVIEW(PR-139): Review visibility for the shared LiteInst host.
pub(crate) struct NoopTool;

#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::parse();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<NoopTool>::new(args.into())
        .spawn()
        .await?;
    let (status, _global_state) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "kvm_test_support.rs"]
mod kvm_test_support;

#[cfg(all(test, target_arch = "x86_64"))]
mod kvm_tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use reverie::syscalls::Sysno;

    use super::*;

    #[tokio::test]
    async fn exact_noop_tool_runs_kvm_guest_syscall_without_interception() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_noop_tool_runs_kvm_guest_syscall_without_interception",
            Sysno::getpid,
        ) else {
            return;
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();

        backend
            .run_with_tool::<NoopTool, _>(
                (),
                move |_request: &reverie_kvm::SyscallRequest,
                      _memory: &reverie_kvm::GuestMemory| {
                    executor_calls.fetch_add(1, Ordering::SeqCst);
                    0
                },
            )
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
