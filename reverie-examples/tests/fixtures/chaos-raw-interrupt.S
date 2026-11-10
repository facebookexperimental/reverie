/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

/* A separate raw-Linux-ABI witness: no libc/interpreter reads precede the
 * fixed 32 getpid calls. This does not test libc's -1/errno translation. */
.text
.global _start
.type _start,@function
_start:
    mov $32, %r12d
getpid_loop:
    mov $39, %eax
    syscall
    test %rax, %rax
    jle failed
    dec %r12d
    jne getpid_loop

    mov $293, %eax
    lea pipe_fds(%rip), %rdi
    mov $0x80000, %esi
    syscall
    test %rax, %rax
    jne failed
    mov pipe_fds(%rip), %r13d
    mov pipe_fds+4(%rip), %r14d

    mov $1, %eax
    mov %r14d, %edi
    lea data(%rip), %rsi
    mov $4, %edx
    syscall
    cmp $4, %rax
    jne failed

    xor %eax, %eax
    mov %r13d, %edi
    lea buffer(%rip), %rsi
    mov $4, %edx
    syscall
    cmp $-4, %rax
    jne failed

    xor %eax, %eax
    mov %r13d, %edi
    lea buffer(%rip), %rsi
    mov $4, %edx
    syscall
    cmp $1, %rax
    jne failed
    cmpb $100, buffer(%rip)
    jne failed

    mov $3, %eax
    mov %r13d, %edi
    syscall
    test %rax, %rax
    jne failed
    mov $3, %eax
    mov %r14d, %edi
    syscall
    test %rax, %rax
    jne failed

    mov $1, %eax
    mov $1, %edi
    lea marker(%rip), %rsi
    mov $25, %edx
    syscall
    cmp $25, %rax
    jne failed
    xor %edi, %edi
    jmp exit
failed:
    mov $97, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.section .rodata
data:
    .ascii "data"
marker:
    .ascii "chaos-interrupt-then-one\n"
.bss
.align 4
pipe_fds:
    .skip 8
buffer:
    .skip 4
.section .note.GNU-stack,"",@progbits
