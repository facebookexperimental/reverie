/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests surrounding exit logic.

use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

#[derive(Debug, Default)]
struct GlobalState {
    // FIXME: Can't use (Pid, ExitStatus) types here since they don't implement
    // Serialize/Deserialize.
    exited: Mutex<Vec<(i32, ExitStatus)>>,
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = ExitStatus;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, from: Pid, exit_status: ExitStatus) -> Self::Response {
        self.exited
            .lock()
            .unwrap()
            .push((from.as_raw(), exit_status));
    }
}

#[derive(Debug, Default, Clone)]
struct InjectExitTool {}

#[reverie::tool]
impl Tool for InjectExitTool {
    type GlobalState = GlobalState;
    type ThreadState = ();

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        global_state: &G,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state.send_rpc(exit_status).await;
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            guest
                .tail_inject(syscalls::ExitGroup::new().with_status(42))
                .await
        } else {
            guest.tail_inject(syscall).await
        }
    }
}

#[cfg(not(sanitized))]
#[test]
fn smoke() {
    use reverie_ptrace::testing::test_fn;

    let (output, state) = test_fn::<InjectExitTool, _>(|| unsafe {
        let _ = libc::getpid();
        libc::syscall(libc::SYS_exit_group, 0);
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(42));
    let mut mg = state.exited.lock().unwrap();
    assert_eq!(mg.pop().map(|x| x.1), Some(ExitStatus::Exited(42)));
    assert!(mg.is_empty());
}
