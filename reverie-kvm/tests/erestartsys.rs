/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Cover the `ERESTARTSYS` restart protocol's *re-invocation*, not just the
//! decision to re-invoke.
//!
//! `runtime::classify_handler_result` is a pure function and is unit-tested
//! directly, but it only answers "should this syscall be re-run?". The loop in
//! `run_with_tool` that acts on that answer had no test: neutralising both
//! restart sites so the handler is never re-invoked left the whole
//! `reverie-kvm` package green at 248 passed / 0 failed. These tests fail in
//! that state, so they cover the mechanism rather than the policy.

#![cfg(target_arch = "x86_64")]

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
use reverie::Errno;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie_kvm::GuestMemory;
use reverie_kvm::KvmBackend;
use reverie_kvm::SyscallRequest;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;

/// Result the tool returns once it stops asking for a restart. Chosen so it
/// cannot be confused with 0 (the executor's reply) or with any negated errno.
const SETTLED_RESULT: i64 = 4242;

fn kvm_is_unavailable(error: &kvm_ioctls::Error) -> bool {
    matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM)
}

fn kvm_available(test: &str) -> bool {
    match Kvm::new() {
        Ok(_) => true,
        Err(error) if kvm_is_unavailable(&error) => {
            if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                panic!("{test} requires usable /dev/kvm: {error}");
            }
            eprintln!("skipping {test}: cannot open /dev/kvm: {error}");
            false
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
}

fn null_executor(_request: &SyscallRequest, _memory: &GuestMemory) -> i64 {
    0
}

/// Counts handler invocations. A process-global rather than a `GlobalState`
/// because the count must survive the tool being re-entered, which is the very
/// thing under test. Each test below owns its own counter.
static RESTART_ONCE_CALLS: AtomicUsize = AtomicUsize::new(0);
static RESTART_TWICE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Asks for exactly one restart, then settles.
#[derive(Default)]
struct RestartOnceTool;

#[reverie::tool]
impl Tool for RestartOnceTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if RESTART_ONCE_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(Errno::ERESTARTSYS.into());
        }
        Ok(SETTLED_RESULT)
    }
}

/// Asks for two restarts, to show the loop repeats rather than retrying once.
#[derive(Default)]
struct RestartTwiceTool;

#[reverie::tool]
impl Tool for RestartTwiceTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if RESTART_TWICE_CALLS.fetch_add(1, Ordering::SeqCst) < 2 {
            return Err(Errno::ERESTARTSYS.into());
        }
        Ok(SETTLED_RESULT)
    }
}

fn run_one_syscall<T: Tool<GlobalState = ()> + 'static>() {
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
        )
        .unwrap();
    futures::executor::block_on(backend.run_with_tool::<T, _>((), null_executor)).unwrap();
}

#[test]
fn erestartsys_reinvokes_the_tool_handler() {
    if !kvm_available("erestartsys_reinvokes_the_tool_handler") {
        return;
    }
    RESTART_ONCE_CALLS.store(0, Ordering::SeqCst);

    run_one_syscall::<RestartOnceTool>();

    // One invocation asked to restart and one settled. A backend that treats
    // ERESTARTSYS as a terminal result calls the handler exactly once, which is
    // the defect this protocol exists to prevent.
    assert_eq!(
        RESTART_ONCE_CALLS.load(Ordering::SeqCst),
        2,
        "the tool handler must be re-invoked after it returns ERESTARTSYS",
    );
}

#[test]
fn erestartsys_restarts_repeatedly_until_the_tool_settles() {
    if !kvm_available("erestartsys_restarts_repeatedly_until_the_tool_settles") {
        return;
    }
    RESTART_TWICE_CALLS.store(0, Ordering::SeqCst);

    run_one_syscall::<RestartTwiceTool>();

    // Two restarts then a settled result. This distinguishes a loop from a
    // single hard-coded retry, which the one-restart case alone cannot.
    assert_eq!(
        RESTART_TWICE_CALLS.load(Ordering::SeqCst),
        3,
        "the restart must repeat while the tool keeps returning ERESTARTSYS",
    );
}
