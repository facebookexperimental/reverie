/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

/*
 * argv: MODE(1..8) TERMINAL(60|231) CODE(23|279).
 * No libc or interpreter executes before these application syscalls.
 * The five unused operands are intentional raw-argument witnesses.
 */
.text
.global _start
.type _start,@function
_start:
    cmpq $4, (%rsp)
    jne failed
    mov 16(%rsp), %rdi
    cmpb $0, 1(%rdi)
    jne failed
    movzbl (%rdi), %r12d
    sub $'0', %r12d
    cmp $1, %r12d
    jb failed
    cmp $8, %r12d
    ja failed
    mov 24(%rsp), %rdi
    call decimal
    mov %rax, %r13
    cmp $60, %r13
    je terminal_valid
    cmp $231, %r13
    jne failed
terminal_valid:
    mov 32(%rsp), %rdi
    call decimal
    mov %rax, %r14
    cmp $23, %r14
    je code_valid
    cmp $279, %r14
    jne failed
code_valid:
    mov $186, %eax
    syscall
    test %rax, %rax
    jle failed
    mov %rax, %r15
    mov $1, %eax
    mov $1, %edi
    lea before(%rip), %rsi
    mov $7, %edx
    syscall
    cmp $7, %rax
    jne failed

    /* All disconnect cases close application stderr before their target RPC.
     * The fatal diagnostic must use the protected native diagnostic owner. */
    cmp $6, %r12d
    jb choose_trigger
    mov $3, %eax
    mov $2, %edi
    syscall
    test %rax, %rax
    jne failed
choose_trigger:
    mov %r13, %rax
    cmp $6, %r12d
    je ordinary_disconnect
    cmp $5, %r12d
    jne trigger
ordinary_disconnect:
    mov $39, %eax
trigger:
    mov %r14, %rdi
    mov $17, %esi
    mov $34, %edx
    mov $51, %r10d
    mov $68, %r8d
    mov $85, %r9d
    syscall

    cmp $6, %r12d
    je unexpected_rpc_return
    cmp $3, %r12d
    je suppressed
    cmp $4, %r12d
    jne failed
    cmp %r15, %rax
    jne failed
    jmp continued
suppressed:
    test %rax, %rax
    jne failed
continued:
    mov %rax, %rsi
    mov $110, %eax
    mov $0x43414c4c, %edi
    mov $3, %edx
    mov $4, %r10d
    mov $5, %r8d
    mov $6, %r9d
    syscall
    cmp $73, %rax
    jne failed
    mov $1, %eax
    mov $1, %edi
    lea resumed(%rip), %rsi
    mov $10, %edx
    syscall
    cmp $10, %rax
    jne failed
    mov $231, %eax
    mov $31, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    syscall
    ud2

unexpected_rpc_return:
    cmp $73, %rax
    jne failed
    mov $1, %eax
    mov $1, %edi
    lea unexpected(%rip), %rsi
    mov $25, %edx
    syscall
    jmp failed

decimal:
    xor %eax, %eax
    cmpb $0, (%rdi)
    je failed
decimal_next:
    movzbl (%rdi), %edx
    test %dl, %dl
    je decimal_done
    sub $'0', %edx
    cmp $9, %edx
    ja failed
    imul $10, %rax, %rax
    jo failed
    add %rdx, %rax
    jo failed
    inc %rdi
    jmp decimal_next
decimal_done:
    ret

failed:
    mov $1, %eax
    mov $2, %edi
    lea failure(%rip), %rsi
    mov $15, %edx
    syscall
    mov $231, %eax
    mov $97, %edi
    syscall
    ud2

.section .rodata
before:
    .ascii "before\n"
resumed:
    .ascii "continued\n"
unexpected:
    .ascii "unexpected RPC continued\n"
failure:
    .ascii "fixture failed\n"
.section .note.GNU-stack,"",@progbits
