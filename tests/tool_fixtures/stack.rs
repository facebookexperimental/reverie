/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared two-guard stack Tool and its post-assertion RPC witness.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Stack;
use reverie::Tool;
use reverie::syscalls::AddrMut;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

#[derive(Debug, Default)]
pub struct StackObserved {
    pub observed: AtomicBool,
}

#[reverie::global_tool]
impl GlobalTool for StackObserved {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, (): ()) -> Self::Response {
        self.observed.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
pub struct LocalState3;

#[reverie::tool]
impl Tool for LocalState3 {
    type GlobalState = StackObserved;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let exit_success = ExitGroup::new().with_status(0);
        match syscall.number() {
            Sysno::exit_group => {
                {
                    let mut stack = guest.stack().await;
                    let ptr1: AddrMut<u64> = stack.reserve();
                    let _guard1 = stack.commit().unwrap();
                    guest.memory().write_value(ptr1, &3333).unwrap();
                    let v1 = guest.memory().read_value(ptr1).unwrap();
                    assert_eq!(v1, 3333);
                }

                {
                    let mut stack = guest.stack().await;
                    let ptr2: AddrMut<u64> = stack.reserve();
                    let _guard2 = stack.commit().unwrap();
                    guest.memory().write_value(ptr2, &4444).unwrap();
                    let v2 = guest.memory().read_value(ptr2).unwrap();
                    assert_eq!(v2, 4444);
                }

                guest.send_rpc(()).await;
                guest.tail_inject(exit_success).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}
