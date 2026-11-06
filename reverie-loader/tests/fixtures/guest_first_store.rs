/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Literal-first store: the very first opcode writes a magic value
//! into a `.data` witness slot, then the program writes the slot's
//! eight bytes to stdout and exits (two syscalls: write, exit). A
//! host that reads the slot while the new image is stopped before
//! release proves zero guest instructions ran if the slot still
//! holds its initial zero; the stdout bytes prove the store is live
//! (they are the stored magic) once the program runs. The magic and
//! the slot address are recoverable from the first instruction
//! itself (`mov dword ptr [rip + disp32], imm32`), so no constant is
//! duplicated between this fixture and its test.
#![no_std]
#![no_main]

// SAFETY: the ELF entry has the kernel's valid user stack. The first
// instruction is the witness store; afterwards only the Linux x86-64
// write/exit ABI is used, with buffers in this image's own `.data`.
core::arch::global_asm!(
    r#"
    .section .text.entry,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    mov dword ptr [rip + .Lwitness], 0x57495431
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + .Lwitness]
    mov edx, 8
    syscall
    mov eax, 60
    xor edi, edi
    syscall
    ud2
    .size _start, .-_start
    .section .data.witness,"aw",@progbits
    .global witness_slot
    .type witness_slot,@object
witness_slot:
.Lwitness:
    .quad 0
    .size witness_slot, .-witness_slot
"#
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
