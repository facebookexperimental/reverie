/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An example that counts system calls using a simple, global state.

use reverie::{
    syscalls::{Syscall, SyscallInfo, Sysno},
    Error, GlobalTool, Guest, Pid, Tool,
};
use reverie_util::CommonToolArguments;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use structopt::StructOpt;

#[derive(Debug, Serialize, Deserialize, Default)]
struct CounterGlobal {
    num_syscalls: AtomicU64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct CounterLocal {}

/// The message sent to the global state method.
/// This contains the syscall number.
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
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

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let sysno = syscall.number();
        let _ = guest.send_rpc(IncrMsg(sysno)).await?;
        guest.tail_inject(syscall).await
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
    eprintln!(
        " [counter tool] Total system calls in process tree: {}",
        AtomicU64::load(&global_state.num_syscalls, Ordering::SeqCst)
    );
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
