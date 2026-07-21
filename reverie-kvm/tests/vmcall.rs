/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use std::path::Path;

use reverie_kvm::KvmBackend;
use reverie_kvm::SyscallRequest;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;
const MESSAGE_ADDRESS: u64 = 0x3000;

#[test]
fn guest_write_syscall_is_intercepted_via_vmcall() {
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skipping KVM vmcall test: /dev/kvm is unavailable");
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
