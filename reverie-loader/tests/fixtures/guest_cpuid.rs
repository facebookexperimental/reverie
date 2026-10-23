/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Literal-first CPUID: no Rust prologue and no leaf-selection instruction.
#![no_std]
#![no_main]

// SAFETY: the ELF entry has the kernel's valid user stack. CPUID is literally
// its first opcode, with the original kernel EAX/ECX. After the runtime handles
// it, the four64-bit reply slots are saved before any syscall clobbers them.
core::arch::global_asm!(
    r#"
    .section .text.entry,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    cpuid
    push rdx
    push rcx
    push rbx
    push rax
    mov eax, 1
    mov edi, 1
    mov rsi, rsp
    mov edx, 32
    syscall
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + .Lmarker]
    mov edx, {message_bytes}
    syscall
    mov eax, 60
    xor edi, edi
    syscall
    ud2
    .size _start, .-_start
    .section .rodata,"a",@progbits
.Lmarker:
    .ascii "FIRST_CPUID_OK\n"
.Lmarker_end:
"#,
    message_bytes = const b"FIRST_CPUID_OK\n".len(),
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
