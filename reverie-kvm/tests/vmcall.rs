/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use kvm_ioctls::Kvm;
use reverie_kvm::KvmBackend;
use reverie_kvm::SyscallRequest;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;
const MESSAGE_ADDRESS: u64 = 0x3000;

fn kvm_is_unavailable(error: &kvm_ioctls::Error) -> bool {
    matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM)
}

#[test]
fn identifies_unavailable_kvm_errors() {
    for errno in [libc::ENOENT, libc::EACCES, libc::EPERM] {
        let error = kvm_ioctls::Error::new(errno);
        assert!(kvm_is_unavailable(&error));
    }

    let error = kvm_ioctls::Error::new(libc::EINVAL);
    assert!(!kvm_is_unavailable(&error));
}

#[test]
fn guest_write_syscall_is_intercepted_via_vmcall() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM vmcall test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
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

    let mut intercepted = None;
    backend
        .run(|request, memory| {
            let mut message = vec![0; request.args()[2] as usize];
            memory.read(request.args()[1], &mut message).unwrap();
            intercepted = Some((request.number(), request.args()[0], message));
            request.args()[2] as i64
        })
        .unwrap();

    assert_eq!(
        intercepted,
        Some((libc::SYS_write as u64, 1, b"hello".to_vec()))
    );
}
