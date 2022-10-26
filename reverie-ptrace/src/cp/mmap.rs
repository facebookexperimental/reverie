/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io::IoSlice;

use nix::sys::uio;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;

use super::consts::*;

/// generate syscall instructions at injected page
/// the page address should be 0x7000_0000 (PRIVATE_PAGE_OFFSET)
/// the byte code can be confirmed by running objcopy
/// x86_64-linux-gnu-objcopy -I binary /tmp/1.bin -O elf64-x86-64 -B i386:x86-64 /tmp/1.elf
/// then objdump -d 1.elf must match the instructions listed below.
pub fn populate_mmap_page(pid: Pid, page_address: u64) -> nix::Result<()> {
    /* For x86_64 architecture, we use the following syscall sequences:
     * 0:   0f 05                   syscall                  // untraced syscall
     * 2:   0f 0b                   ud2
     * 4:   0f 05                   syscall                  // traced syscall
     * 6:   0f 0b                   ud2
     */
    #[cfg(target_arch = "x86_64")]
    let mut syscall_stubs: Vec<u8> = vec![0x0f, 0x05, 0x0f, 0x0b, 0x0f, 0x05, 0x0f, 0x0b];
    /* For aarch64 architecture, we use the following syscall sequences:
     * 0:   d4 00 00 01                svc 0                  // Equivalent to the syscall instruction
     * 2:   00 00 de ad                udf #0xdead            // Equivalent to the ud2 instruction
     * 4:   d4 00 00 01                svc 0
     * 6:   00 00 de ad                udf #0xdead
     */
    #[cfg(target_arch = "aarch64")]
    let mut syscall_stubs: Vec<u8> = vec![
        0xd4, 0x00, 0x00, 0x01, 0x00, 0x00, 0xde, 0xad, 0xd4, 0x00, 0x00, 0x01, 0x00, 0x00, 0xde,
        0xad,
    ];
    // Fill syscall_stubs with a software interrupt (or debug breakpoint) instruction until it reaches the trampoline size
    #[cfg(target_arch = "x86_64")]
    const SOFTWARE_INTERUPT: u8 = 0xcc; // int3 instruction opcode for x86_64
    #[cfg(target_arch = "aarch64")]
    const SOFTWARE_INTERUPT: u8 = 0x00; // For aarch64, we should use BRK 1 but as it is not a single-byte instruction, we'll use a sequence of 0x00 (same as a sequence of udf #0x0 instructions)
    syscall_stubs.resize_with(TRAMPOLINE_SIZE, || SOFTWARE_INTERUPT);
    let local_iov = &[IoSlice::new(syscall_stubs.as_slice())];
    let remote_iov = &[RemoteIoVec {
        base: page_address as usize,
        len: TRAMPOLINE_SIZE,
    }];

    // initialize the whole page with int3 to prevent unintended
    // execution in our injected page.
    uio::process_vm_writev(pid, local_iov, remote_iov)?;
    Ok(())
}
