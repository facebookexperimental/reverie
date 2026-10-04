/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Backend-neutral implementation of the counter1 Reverie tool.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

/// Process-tree global counter1 state.
#[derive(Debug, Default, Clone)]
pub struct CounterGlobal {
    num_syscalls: Arc<AtomicU64>,
}

impl CounterGlobal {
    /// Returns the number of intercepted syscalls.
    pub fn total(&self) -> u64 {
        self.num_syscalls.load(Ordering::SeqCst)
    }
}

/// Stateless process-local counter1 tool.
#[derive(Debug, Default, Clone)]
pub struct CounterLocal {}

/// One intercepted syscall, including its number for diagnostics.
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(pub Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, IncrMsg(sysno): IncrMsg) {
        self.num_syscalls.fetch_add(1, Ordering::SeqCst);
        tracing::info!("count at syscall ({sysno:?}): {}", self.total());
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
        let _ = guest.send_rpc(IncrMsg(syscall.number())).await;
        guest.tail_inject(syscall).await
    }
}
