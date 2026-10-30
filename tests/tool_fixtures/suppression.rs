/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Original suppression decisions with an acknowledged per-call RPC witness.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;

#[derive(Debug, Default)]
pub struct SuppressionCount {
    pub count: AtomicUsize,
}

#[reverie::global_tool]
impl GlobalTool for SuppressionCount {
    type Config = ();
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, (): ()) -> Self::Response {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestTool;

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = SuppressionCount;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Tgkill(_) => {
                // Suppress this syscall. This thread shall not be killed.
                guest.send_rpc(()).await;
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}
