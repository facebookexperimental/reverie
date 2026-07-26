/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared support for compiling the exact example `Tool` types with KVM's
//! prototype `Guest` runner.

use reverie::syscalls::Sysno;
use reverie_kvm::KvmBackend;
use reverie_kvm::SyscallRequest;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;

pub fn backend_with_syscall(test: &str, number: Sysno) -> Option<KvmBackend> {
    let mut backend = match KvmBackend::new(MEMORY_SIZE) {
        Ok(backend) => backend,
        Err(reverie_kvm::Error::Kvm(error))
            if matches!(
                std::io::Error::from_raw_os_error(error.errno()).kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            eprintln!("skipping {test}: cannot use /dev/kvm: {error}");
            return None;
        }
        Err(error) => panic!("failed to create KVM example-tool backend: {error}"),
    };
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(number.id() as u64, [0; 6]),
        )
        .unwrap();
    Some(backend)
}
