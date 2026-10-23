/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Already-armed guest: optionally deny one CPUID arch_prctl, then exec argv[1].
//! This image executes no CPUID and writes no guest marker of its own.
#![no_std]
#![no_main]

core::arch::global_asm!(
    r#"
    .section .text.entry,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    mov rax, [rsp]
    cmp rax, 3
    jne .Lfailed
    mov r12, [rsp + 16]
    mov r13, [rsp + 24]
    lea r14, [rsp + rax*8 + 16]
    cmp byte ptr [r13], 'n'
    je .Lexec
    mov eax, 0x1011
    cmp byte ptr [r13], 'g'
    je .Lselected
    cmp byte ptr [r13], 's'
    jne .Lfailed
    mov eax, 0x1012
.Lselected:
    mov [rip + .Lcommand], eax
    mov eax, 157
    mov edi, 38
    mov esi, 1
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    jne .Lfailed
    mov eax, 317
    mov edi, 1
    xor esi, esi
    lea rdx, [rip + .Lprogram]
    syscall
    test rax, rax
    jne .Lfailed
.Lexec:
    push 0
    push r12
    mov rdi, r12
    mov rsi, rsp
    mov rdx, r14
    mov eax, 59
    syscall
.Lfailed:
    mov edi, 102
    mov eax, 60
    syscall
    ud2
    .size _start, .-_start

    .section .data,"aw",@progbits
    .balign 8
.Lprogram:
    .short 8
    .zero 6
    .quad .Lfilter
.Lfilter:
    // seccomp_data.nr == __NR_arch_prctl, else ALLOW.
    .short 0x20
    .byte 0, 0
    .long 0
    .short 0x15
    .byte 0, 5
    .long 158
    // Require the complete 64-bit first argument, not only its low word.
    .short 0x20
    .byte 0, 0
    .long 20
    .short 0x15
    .byte 0, 3
    .long 0
    .short 0x20
    .byte 0, 0
    .long 16
    .short 0x15
    .byte 0, 1
.Lcommand:
    .long 0
    // SECCOMP_RET_ERRNO | EPERM, and SECCOMP_RET_ALLOW.
    .short 0x06
    .byte 0, 0
    .long 0x00050001
    .short 0x06
    .byte 0, 0
    .long 0x7fff0000
"#,
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
