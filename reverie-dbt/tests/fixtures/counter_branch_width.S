/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style LICENSE in the root directory.
 * Forward-only branches: even zero counters terminate after one instruction.
 */
.text
.global _start
_start:
    lea results(%rip), %rsi

.macro observe instruction, counter, flags
    movabs $\counter, %rcx
    pushq $\flags
    popfq
    \instruction .Ltaken\@
    mov $0, %rax
    jmp .Ldone\@
.Ltaken\@:
    mov $1, %rax
.Ldone\@:
    mov %rax, 0(%rsi)
    mov %rcx, 8(%rsi)
    pushfq
    popq 16(%rsi)
    lea 24(%rsi), %rsi
.endm

    observe jrcxz, 0, 0x202
    observe jrcxz, 0x1122334400000000, 0x202
    observe jrcxz, 1, 0x202
    observe jecxz, 0, 0x202
    observe jecxz, 0x1122334400000000, 0x202
    observe jecxz, 0x1122334400000001, 0x202

    observe loop, 2, 0x202
    observe loop, 1, 0x202
    observe loop, 0, 0x202
    observe "addr32 loop", 0x1122334400000002, 0x202
    observe "addr32 loop", 0x1122334400000001, 0x202
    observe "addr32 loop", 0x1122334400000000, 0x202

    observe loope, 2, 0x242
    observe loope, 1, 0x242
    observe loope, 2, 0x202
    observe "addr32 loope", 0x1122334400000002, 0x242
    observe "addr32 loope", 0x1122334400000001, 0x242
    observe "addr32 loope", 0x1122334400000002, 0x202
    observe loopne, 2, 0x202
    observe loopne, 1, 0x202
    observe loopne, 2, 0x242
    observe "addr32 loopne", 0x1122334400000002, 0x202
    observe "addr32 loopne", 0x1122334400000001, 0x202
    observe "addr32 loopne", 0x1122334400000002, 0x242

    mov $1, %eax
    mov $1, %edi
    lea results(%rip), %rsi
    mov $576, %edx
    syscall
    cmp $576, %rax
    setne %dil
    movzbl %dil, %edi
    mov $60, %eax
    syscall
.bss
.p2align 3
results:
    .zero 576
.section .note.GNU-stack,"",@progbits
