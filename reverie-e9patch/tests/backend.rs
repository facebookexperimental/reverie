/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::OsString;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Stdio;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_e9patch::E9patchBackend;

#[derive(Default)]
struct EventCounter {
    delivered: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for EventCounter {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, increment: u64) {
        self.delivered.fetch_add(increment, Ordering::SeqCst);
    }
}

fn subscriptions() -> Subscription {
    [Sysno::getpid].into_iter().collect()
}

fn direct_syscall_guest() -> OsString {
    std::env::var_os("REVERIE_E9PATCH_REAL_GUEST")
        .expect("set REVERIE_E9PATCH_REAL_GUEST to a direct getpid-syscall ELF")
}

#[derive(Default)]
struct EmulateGetpid;

#[reverie::tool]
impl Tool for EmulateGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        subscriptions()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        assert_eq!(guest.regs().await.rip, 0x401111);
        guest.send_rpc(1).await;
        Ok(1234)
    }
}

#[derive(Default)]
struct InjectGetpid;

#[reverie::tool]
impl Tool for InjectGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        subscriptions()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        let result = guest.inject(syscall).await?;
        assert!(result > 0);
        Ok(result)
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
async fn rewritten_syscall_is_delivered_and_emulated() {
    let mut command = Command::new(direct_syscall_guest());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let (output, global) = E9patchBackend::run_with_output::<EmulateGetpid>(command, ())
        .await
        .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 1);
    assert_eq!(output.status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
async fn rewritten_syscall_supports_guest_injection() {
    let (status, global) =
        E9patchBackend::run::<InjectGetpid>(Command::new(direct_syscall_guest()), ())
            .await
            .unwrap();
    assert_eq!(global.delivered.load(Ordering::SeqCst), 1);
    assert_eq!(status, ExitStatus::Exited(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
async fn unsubscribed_rewritten_syscall_executes_natively() {
    let (status, ()) = E9patchBackend::run::<()>(Command::new(direct_syscall_guest()), ())
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}
