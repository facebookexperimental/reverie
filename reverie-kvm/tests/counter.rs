/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end exercise of the syscall-counter Reverie tools over the KVM
//! backend, ported from `reverie-examples/counter1.rs` (simple global total,
//! [`CounterTool`]) and `counter2.rs` (per-thread tally rolled up to the
//! process and then the global aggregator, [`HierarchicalCounterTool`]).
//!
//! Each test installs a small real-mode guest that issues a known sequence of
//! syscalls through the `vmcall` transport, runs the tool via `run_with_tool`,
//! and asserts the counted totals. Like `strace.rs`, these require a working
//! `/dev/kvm`; when it is unavailable the test prints a skip notice and returns.
//!
//! Note on the ptrace baseline: `counter1` reports 114 syscalls for
//! `/bin/echo`. That figure comes from running a *dynamically linked* ELF
//! through the full ptrace loader; the KVM unit-test harness here installs an
//! exact, synthetic syscall sequence instead (as `strace.rs` does), so the
//! assertion is against the known installed count. Counting `/bin/echo` under
//! KVM to reproduce 114 exactly requires the hermit-cli static-ELF loader path,
//! not this lightweight backend harness.

#![cfg(target_arch = "x86_64")]

use kvm_ioctls::Kvm;
use reverie_kvm::CounterTool;
use reverie_kvm::GuestMemory;
use reverie_kvm::HierarchicalCounterTool;
use reverie_kvm::HierarchicalTotals;
use reverie_kvm::KvmBackend;
use reverie_kvm::SyscallRequest;
use reverie_kvm::Sysno;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;

fn kvm_is_unavailable(error: &kvm_ioctls::Error) -> bool {
    matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM)
}

/// Returns true when `/dev/kvm` is usable; otherwise prints a skip notice.
fn kvm_available(test: &str) -> bool {
    match Kvm::new() {
        Ok(_) => true,
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping {test}: cannot open /dev/kvm: {error}");
            false
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
}

/// A no-op executor: the counters only care that each syscall is intercepted,
/// not what it returns.
fn null_executor(_request: &SyscallRequest, _memory: &GuestMemory) -> i64 {
    0
}

/// The known syscall sequence installed by the sequence tests.
fn sequence() -> Vec<SyscallRequest> {
    [
        Sysno::read,
        Sysno::write,
        Sysno::open,
        Sysno::close,
        Sysno::mmap,
        Sysno::munmap,
        Sysno::brk,
        Sysno::ioctl,
    ]
    .into_iter()
    .map(|n| SyscallRequest::new(n.id() as u64, [0; 6]))
    .collect()
}

#[test]
fn counter_tool_counts_single_syscall() {
    if !kvm_available("counter_tool_counts_single_syscall") {
        return;
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
        )
        .unwrap();

    let counter =
        futures::executor::block_on(backend.run_with_tool::<CounterTool, _>((), null_executor))
            .unwrap();

    assert_eq!(counter.total(), 1);
}

#[test]
fn counter_tool_counts_syscall_sequence() {
    if !kvm_available("counter_tool_counts_syscall_sequence") {
        return;
    }

    let requests = sequence();
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscalls(ENTRY_POINT, FRAME_ADDRESS, &requests)
        .unwrap();

    let counter =
        futures::executor::block_on(backend.run_with_tool::<CounterTool, _>((), null_executor))
            .unwrap();

    // counter1 semantics: every intercepted syscall contributes exactly one to
    // the single global total.
    assert_eq!(counter.total(), requests.len() as u64);
}

#[test]
fn hierarchical_counter_aggregates_per_process() {
    if !kvm_available("hierarchical_counter_aggregates_per_process") {
        return;
    }

    let requests = sequence();
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscalls(ENTRY_POINT, FRAME_ADDRESS, &requests)
        .unwrap();

    let counter = futures::executor::block_on(
        backend.run_with_tool::<HierarchicalCounterTool, _>((), null_executor),
    )
    .unwrap();

    // counter2 semantics: per-thread tally -> on_exit_thread -> process -> one
    // on_exit_process RPC. A single guest is one process, one thread.
    assert_eq!(
        counter.totals(),
        HierarchicalTotals {
            total_syscalls: requests.len() as u64,
            exited_procs: 1,
            exited_threads: 1,
        }
    );
}
