/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This instrumentation tool intercepts events but does nothing with them. It is
//! useful for observing the overhead of interception, and as a starting point.

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
use std::sync::atomic::Ordering;

use clap::Parser;
use reverie::Error;
#[cfg(test)]
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
#[cfg(test)]
use reverie::syscalls::Syscall;
use reverie_util::CommonToolArguments;

#[derive(Debug, Default)]
// TODO-HUMAN-REVIEW(PR-139): Review visibility for the shared LiteInst host.
pub(crate) struct NoopTool;

#[cfg(test)]
static SUBSCRIPTION_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
fn take_subscription_calls() -> usize {
    SUBSCRIPTION_CALLS.swap(0, Ordering::SeqCst)
}

#[cfg(test)]
fn take_handler_calls() -> usize {
    HANDLER_CALLS.swap(0, Ordering::SeqCst)
}

#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        #[cfg(test)]
        SUBSCRIPTION_CALLS.fetch_add(1, Ordering::SeqCst);
        Subscription::none()
    }

    #[cfg(test)]
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        guest.tail_inject(syscall).await
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
    use tokio::sync::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    #[tokio::test]
    async fn exact_noop_tool_runs_kvm_guest_syscall_without_interception() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_noop_tool_runs_kvm_guest_syscall_without_interception",
            Sysno::getpid,
        ) else {
            return;
        };
        let _guard = TEST_LOCK.lock().await;
        take_subscription_calls();
        take_handler_calls();
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
        assert_eq!(take_subscription_calls(), 1);
        assert_eq!(take_handler_calls(), 0);
    }

    #[tokio::test]
    async fn exact_noop_tool_runs_static_kvm_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_static_syscall(
            "exact_noop_tool_runs_static_kvm_syscall",
        ) else {
            return;
        };

        let _guard = TEST_LOCK.lock().await;
        take_subscription_calls();
        take_handler_calls();
        let (_, exit_code, stdout, stderr) = backend
            .run_static_elf_with_tool::<NoopTool>((), true)
            .await
            .unwrap();

        assert_eq!(exit_code, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(take_subscription_calls(), 1);
        assert_eq!(take_handler_calls(), 0);
    }
}
