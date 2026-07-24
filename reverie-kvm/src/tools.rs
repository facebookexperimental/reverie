/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Small, ready-to-run Reverie tools for the KVM backend prototype.
//!
//! These are deliberately trivial: they exercise the [`crate::KvmBackend`]
//! `run_with_tool` path end to end without needing a Linux execution runtime.
//! [`StraceTool`] is an strace-style observer that records each intercepted
//! syscall's name and then forwards it (via `tail_inject`) to the backend's
//! `SyscallExecutor`, exactly as the default [`reverie::Tool`] handler would.

use std::sync::Mutex;

use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;

/// Global state for [`StraceTool`]: the ordered list of intercepted syscall
/// names, aggregated from every guest thread through Reverie's global RPC.
#[derive(Default)]
pub struct StraceLog {
    syscalls: Mutex<Vec<String>>,
}

impl StraceLog {
    /// Returns the syscall names recorded so far, in interception order.
    pub fn syscalls(&self) -> Vec<String> {
        self.syscalls
            .lock()
            .expect("strace log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for StraceLog {
    type Request = String;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, name: String) {
        self.syscalls
            .lock()
            .expect("strace log lock poisoned")
            .push(name);
    }
}

/// An strace-like Reverie tool: on every subscribed syscall it prints the
/// syscall (name + decoded arguments) to stderr, records the name in
/// [`StraceLog`], then tail-injects the syscall so the backend executor still
/// performs it. Running this through [`crate::KvmBackend::run_with_tool`] proves
/// the KVM `Guest`/`Tool` interface works: interception, typed decoding, global
/// RPC, and injection all flow through the same Reverie contracts the ptrace
/// backend uses.
#[derive(Clone, Copy, Debug, Default)]
pub struct StraceTool;

#[reverie::tool]
impl Tool for StraceTool {
    type GlobalState = StraceLog;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        // `SyscallInfo::name` is the bare mnemonic recorded for assertions;
        // the Debug form additionally shows the decoded, typed arguments.
        // (`Syscall` has no bare `Display`; its pretty printer needs guest
        // memory to render pointers, which strace-lite does not require.)
        let name = syscall.name();
        eprintln!("[kvm-strace] {name} {syscall:?}");
        guest.send_rpc(name.to_owned()).await;
        // Forward to the backend `SyscallExecutor`, matching the default
        // `Tool::handle_syscall_event` behavior. `tail_inject` returns `Never`,
        // which coerces to the declared return type.
        guest.tail_inject(syscall).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        _global: &G,
        _thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        Ok(())
    }
}
