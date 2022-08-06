/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use nix::sys::uio;
use nix::sys::uio::IoVec;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;

use super::consts::*;

/// generate syscall instructions at injected page
/// the page address should be 0x7000_0000 (PRIVATE_PAGE_OFFSET)
/// the byte code can be confirmed by running objcopy
/// x86_64-linux-gnu-objcopy -I binary /tmp/1.bin -O elf64-x86-64 -B i386:x86-64 /tmp/1.elf
/// then objdump -d 1.elf must match the instructions listed below.
pub fn populate_mmap_page(pid: Pid, page_address: u64) -> nix::Result<()> {
    /* the syscall sequences used here:
     * 0:   0f 05                   syscall                  // untraced syscall
     * 2:   0f 0b                   ud2
     * 4:   0f 05                   syscall                  // traced syscall
     * 6:   0f 0b                   ud2
     */
    let mut syscall_stubs: Vec<u8> = vec![0x0f, 0x05, 0x0f, 0x0b, 0x0f, 0x05, 0x0f, 0x0b];
    syscall_stubs.resize_with(TRAMPOLINE_SIZE, || 0xcc);
    let local_iov = &[IoVec::from_slice(syscall_stubs.as_slice())];
    let remote_iov = &[RemoteIoVec {
        base: page_address as usize,
        len: TRAMPOLINE_SIZE,
    }];

    // initialize the whole page with int3 to prevent unintended
    // execution in our injected page.
    uio::process_vm_writev(pid, local_iov, remote_iov)?;
    Ok(())
}
