/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/exit_rust_guest.rs"]
mod guest;

fn refuse(status: libc::c_int) -> ! {
    unsafe {
        libc::syscall(libc::SYS_exit_group, status);
    }
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn main() {
    let written = unsafe {
        libc::syscall(
            libc::SYS_write,
            libc::STDOUT_FILENO,
            guest::PRE_BODY_MARKER.as_ptr(),
            guest::PRE_BODY_MARKER.len(),
        )
    };
    if written != guest::PRE_BODY_MARKER.len() as libc::c_long {
        refuse(97);
    }
    guest::smoke();
    refuse(98);
}
