/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */
.global _start
.text
_start:
    mov $39, %eax
    syscall
    mov %rax, parent_pid(%rip)
    mov $0x350f00, %edi
    lea stack1_end(%rip), %rsi
    lea tid1(%rip), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    lea second_clone(%rip), %rdx
    lea child1(%rip), %r11
    test %rax, %rax
    cmovz %r11, %rdx
    lea failure(%rip), %r11
    cmovs %r11, %rdx
    jmp *%rdx
second_clone:
    mov $0x350f00, %edi
    lea stack2_end(%rip), %rsi
    lea tid2(%rip), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    lea join_children(%rip), %rdx
    lea child2(%rip), %r11
    test %rax, %rax
    cmovz %r11, %rdx
    lea failure(%rip), %r11
    cmovs %r11, %rdx
    jmp *%rdx
child1:
    mov $3, %ecx
prefix:
    loop prefix
    mov $39, %eax
    syscall
    cmp parent_pid(%rip), %rax
    mov $91, %edi
    mov $0, %edx
    cmove %edx, %edi
    mov %edi, child_status(%rip)
    mov $60, %eax
    syscall
    ud2
child2:
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
join_children:
    lea tid1(%rip), %rdi
    call join
    lea tid2(%rip), %rdi
    call join
    lea success(%rip), %rdx
    lea failure(%rip), %r11
    cmpl $0, child_status(%rip)
    cmovne %r11, %rdx
    jmp *%rdx
join:
    mov (%rdi), %edx
    lea joined(%rip), %r11
    lea wait(%rip), %r10
    test %edx, %edx
    cmovnz %r10, %r11
    jmp *%r11
wait:
    xor %esi, %esi
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    lea failure(%rip), %r11
    lea join(%rip), %r10
    cmp $0, %rax
    cmove %r10, %r11
    cmp $-11, %rax
    cmove %r10, %r11
    cmp $-4, %rax
    cmove %r10, %r11
    jmp *%r11
joined:
    ret
success:
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $19, %edx
    syscall
    xor %edi, %edi
    jmp exit
failure:
    mov $92, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
message: .ascii "owner-admission=ok\n"
.bss
.balign 8
parent_pid: .zero 8
tid1: .zero 4
tid2: .zero 4
child_status: .zero 4
.balign 16
stack1: .zero 65536
stack1_end:
stack2: .zero 65536
stack2_end:
.section .note.GNU-stack,"",@progbits
