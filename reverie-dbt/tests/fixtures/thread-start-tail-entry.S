/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 *
 * Record every integer register and flags before clobbering any. Each store
 * preserves flags and uses only RIP-relative addressing; RSP is captured before
 * the pushfq. The final word is the actual fixed entry address.
 */
.section .text
.global _start
.type _start,@function
_start:
    mov %rax, frame+0(%rip)
    mov %rbx, frame+8(%rip)
    mov %rcx, frame+16(%rip)
    mov %rdx, frame+24(%rip)
    mov %rsi, frame+32(%rip)
    mov %rdi, frame+40(%rip)
    mov %rbp, frame+48(%rip)
    mov %rsp, frame+56(%rip)
    mov %r8, frame+64(%rip)
    mov %r9, frame+72(%rip)
    mov %r10, frame+80(%rip)
    mov %r11, frame+88(%rip)
    mov %r12, frame+96(%rip)
    mov %r13, frame+104(%rip)
    mov %r14, frame+112(%rip)
    mov %r15, frame+120(%rip)
    pushfq
    popq frame+128(%rip)
    lea _start(%rip), %rax
    mov %rax, frame+136(%rip)
    mov $1, %eax
    mov $1, %edi
    lea frame(%rip), %rsi
    mov $144, %edx
    syscall
    cmp $144, %rax
    jne .Lfailed
    xor %edi, %edi
    jmp .Lexit
.Lfailed:
    mov $91, %edi
.Lexit:
    mov $60, %eax
    syscall
    ud2
.size _start, .-_start

.section .data
.global witness_byte
.type witness_byte,@object
.size witness_byte,1
witness_byte:
    .byte 0
.balign 8
frame:
    .zero 144
.section .note.GNU-stack,"",@progbits
