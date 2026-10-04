/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Mutex;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

#[derive(Default)]
pub struct NestedGlobal {
    pub observed: Mutex<Vec<(i64, u32)>>,
}

#[reverie::global_tool]
impl GlobalTool for NestedGlobal {
    type Request = (i64, u32);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: reverie::Tid, value: (i64, u32)) {
        self.observed.lock().unwrap().push(value);
    }
}

#[derive(Default)]
pub struct NestedTool;

#[reverie::tool]
impl Tool for NestedTool {
    type GlobalState = NestedGlobal;
    type ThreadState = ();

    fn subscriptions(_: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (_, args) = syscall.into_parts();
        let pkru: u32;
        unsafe {
            core::arch::asm!("xor ecx, ecx", "rdpkru", out("eax") pkru,
                out("ecx") _, out("edx") _, options(nomem, nostack));
        }
        assert_eq!(pkru as usize, args.arg3);
        // This instruction is in the Tool DSO, outside the rewritten guest.
        // It must enter the real nested SIGSYS path during the AOT callback.
        let result: i64;
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") libc::SYS_write => result,
                in("rdi") args.arg0, in("rsi") args.arg1, in("rdx") 1usize,
                lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        guest.send_rpc((result, pkru)).await;
        Ok(result)
    }
}
