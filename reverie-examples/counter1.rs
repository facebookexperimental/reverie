/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An example that counts system calls using a simple, global state.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use clap::Parser;
use reverie::Error;
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::parse();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<CounterLocal>::new(args.into())
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    eprintln!(
        " [counter tool] Total system calls in process tree: {}",
        AtomicU64::load(&global_state.num_syscalls, Ordering::SeqCst)
    );
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
}
