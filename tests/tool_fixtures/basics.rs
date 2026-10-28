/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Caller-owned Tools shared by the basic conformance tests.

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

#[derive(Debug, Default)]
pub struct NoopTool;
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();
}

#[derive(Debug, Default)]
pub struct CounterGlobal {
    pub num_syscalls: AtomicU64,
}

#[derive(Debug, Default, Clone)]
pub struct CounterLocal {}

/// The message sent to the global state method.
/// This contains the syscall number.
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, _: IncrMsg) -> Self::Response {
        AtomicU64::fetch_add(&self.num_syscalls, 1, Ordering::SeqCst);
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
