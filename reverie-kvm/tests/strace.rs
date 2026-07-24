/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end exercise of the strace-style Reverie tool over the KVM backend.
//!
//! Each test installs a small real-mode guest that issues syscalls through the
//! `vmcall` transport, runs [`StraceTool`] via `run_with_tool`, and checks the
//! recorded syscall-name trace. These require a working `/dev/kvm`; when it is
//! unavailable the test prints a skip notice and returns (matching `vmcall.rs`).

#![cfg(target_arch = "x86_64")]

use std::sync::Arc;
use std::sync::Mutex;

use kvm_ioctls::Kvm;
use reverie_kvm::GuestMemory;
use reverie_kvm::KvmBackend;
use reverie_kvm::StraceTool;
use reverie_kvm::SyscallRequest;
use reverie_kvm::Sysno;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;
const MESSAGE_ADDRESS: u64 = 0x3000;

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

#[test]
fn strace_tool_records_write_syscall_name() {
    if !kvm_available("strace_tool_records_write_syscall_name") {
        return;
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
        .write(MESSAGE_ADDRESS, b"hello")
        .unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_write as u64, [1, MESSAGE_ADDRESS, 5, 0, 0, 0]),
        )
        .unwrap();

    // A minimal executor that fulfils the forwarded write by copying the guest
    // buffer to the host fd, so the guest's "hello" actually appears and the
    // syscall returns a realistic byte count.
    let log = futures::executor::block_on(backend.run_with_tool::<StraceTool, _>(
        (),
        |request: &SyscallRequest, memory: &GuestMemory| {
            if request.number() == libc::SYS_write as u64 {
                let len = request.args()[2] as usize;
                let mut buffer = vec![0; len];
                memory.read(request.args()[1], &mut buffer).unwrap();
                // SAFETY: a plain write(2) to the (already open) guest-selected
                // fd with a host-owned buffer; no borrowed guest pointers escape.
                let written = unsafe {
                    libc::write(
                        request.args()[0] as i32,
                        buffer.as_ptr().cast(),
                        buffer.len(),
                    )
                };
                written as i64
            } else {
                0
            }
        },
    ))
    .unwrap();

    assert_eq!(log.syscalls(), vec!["write".to_string()]);
}

#[test]
fn strace_tool_records_multiple_syscall_names_in_order() {
    if !kvm_available("strace_tool_records_multiple_syscall_names_in_order") {
        return;
    }

    let expected = [
        Sysno::read,
        Sysno::write,
        Sysno::open,
        Sysno::close,
        Sysno::mmap,
        Sysno::munmap,
        Sysno::brk,
        Sysno::ioctl,
    ];
    let requests = expected.map(|number| SyscallRequest::new(number.id() as u64, [0; 6]));

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscalls(ENTRY_POINT, FRAME_ADDRESS, &requests)
        .unwrap();

    // Records what the executor saw, proving StraceTool forwards (tail-injects)
    // every syscall after logging it, rather than swallowing them.
    let executed = Arc::new(Mutex::new(Vec::new()));
    let executor_seen = executed.clone();
    let log = futures::executor::block_on(backend.run_with_tool::<StraceTool, _>(
        (),
        move |request: &SyscallRequest, _memory: &GuestMemory| {
            executor_seen.lock().unwrap().push(request.number());
            0
        },
    ))
    .unwrap();

    let expected_names: Vec<String> = expected.iter().map(|n| n.name().to_string()).collect();
    assert_eq!(log.syscalls(), expected_names);
    assert_eq!(
        *executed.lock().unwrap(),
        expected.iter().map(|n| n.id() as u64).collect::<Vec<_>>(),
    );
}
