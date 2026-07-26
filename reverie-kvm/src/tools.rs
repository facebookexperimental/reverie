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
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

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

// ---------------------------------------------------------------------------
// Syscall counters, ported from reverie-examples/counter1.rs and counter2.rs to
// the KVM backend. They exercise the same Reverie contracts StraceTool does
// (interception, global RPC, tail_inject, and — for the hierarchical variant —
// per-thread ThreadState plus on_exit aggregation), proving these standard
// example Tools run unmodified over `KvmGuest`.
// ---------------------------------------------------------------------------

/// Global state for [`CounterTool`]: one running total of intercepted syscalls,
/// aggregated from every guest thread through Reverie's global RPC. This is the
/// KVM port of `reverie-examples/counter1.rs`.
#[derive(Default)]
pub struct SyscallCounter {
    total: AtomicU64,
}

impl SyscallCounter {
    /// Total number of syscalls counted so far.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for SyscallCounter {
    // Each RPC is one intercepted syscall; the unit payload avoids pulling a
    // serde-derive dependency into reverie-kvm (cf. StraceLog's `String`).
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, _msg: ()) {
        self.total.fetch_add(1, Ordering::SeqCst);
    }
}

/// counter1 ported to KVM: on every subscribed syscall, RPC-increment the global
/// total, then tail-inject so the backend executor still performs the syscall.
#[derive(Clone, Copy, Debug, Default)]
pub struct CounterTool;

#[reverie::tool]
impl Tool for CounterTool {
    type GlobalState = SyscallCounter;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        guest.send_rpc(()).await;
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

/// Aggregated global state for [`HierarchicalCounterTool`], the KVM port of
/// `reverie-examples/counter2.rs`: a process-tree total plus process and thread
/// tallies, contributed once per process at exit.
#[derive(Default)]
pub struct HierarchicalCounter {
    inner: Mutex<HierarchicalTotals>,
}

/// The counts exposed by [`HierarchicalCounter`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HierarchicalTotals {
    pub total_syscalls: u64,
    pub exited_procs: u64,
    pub exited_threads: u64,
}

impl HierarchicalCounter {
    /// Snapshot of the aggregated totals.
    pub fn totals(&self) -> HierarchicalTotals {
        *self.inner.lock().expect("counter global lock poisoned")
    }
}

#[reverie::global_tool]
impl GlobalTool for HierarchicalCounter {
    /// One contribution per process at exit: (syscalls, threads). A plain tuple
    /// satisfies the Serialize/DeserializeOwned bound without a serde derive.
    type Request = (u64, u64);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, (n, t): (u64, u64)) {
        let mut g = self.inner.lock().expect("counter global lock poisoned");
        g.total_syscalls += n;
        g.exited_threads += t;
        g.exited_procs += 1;
    }
}

/// counter2 ported to KVM: each thread tallies its own syscalls in per-thread
/// `ThreadState`; on thread exit that tally rolls up to the process; on process
/// exit the process total is RPC'd once to the global aggregator.
#[derive(Debug, Default)]
pub struct HierarchicalCounterTool {
    proc_syscalls: AtomicU64,
    exited_threads: AtomicU64,
}

impl Clone for HierarchicalCounterTool {
    fn clone(&self) -> Self {
        HierarchicalCounterTool {
            proc_syscalls: AtomicU64::new(self.proc_syscalls.load(Ordering::SeqCst)),
            exited_threads: AtomicU64::new(self.exited_threads.load(Ordering::SeqCst)),
        }
    }
}

#[reverie::tool]
impl Tool for HierarchicalCounterTool {
    type GlobalState = HierarchicalCounter;
    /// Per-thread syscall tally.
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        *guest.thread_state_mut() += 1;
        guest.tail_inject(syscall).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        _global: &G,
        thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        self.proc_syscalls.fetch_add(thread_state, Ordering::SeqCst);
        self.exited_threads.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        global: &G,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        let count = self.proc_syscalls.load(Ordering::SeqCst);
        let threads = self.exited_threads.load(Ordering::SeqCst);
        let _ = global.send_rpc((count, threads)).await;
        Ok(())
    }
}
