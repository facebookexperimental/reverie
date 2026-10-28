/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -nostdlib -nostartfiles -Wl,--no-as-needed -lc %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1
 */

/* The purpose of this test is to ensure that when Varan encounters a non-relocatable instruction
   it inserts an illegal instruction that will trigger a SIGILL */

.global _start
_start:
mov $39, %rax /* __NR_getpid */
jmp 1f	/* source of jump 1 */
nop
nop
nop
1:
not %edi	/* destination of jump 1 => non relocatable*/
syscall	/* syscall instruction cannot be rewritten with jump*/
lea 0(%rip), %rax	/* PC-relative addressing => non relocatable */
jmp 2f	/* source of jump 2 */
nop
nop
nop
2:
nop	/* destination of jump 2 */
rdtsc	/* RDTSC instruction cannot be rewritten with jump*/
lea 0(%rip), %rax	/* PC-relative addressing => non relocatable */

/* Set flags and non-output registers without changing the flags afterwards. */
mov $1, %rax
cmp $2, %rax
std
pushfq
pop %r12
mov $0x77, %r11
jmp 3f
nop
nop
3:
rdtscp	/* Branch target + RIP-relative snapshot force the SIGILL path. */
mov %rax, fallback_rax(%rip)
mov %rdx, fallback_rdx(%rip)
mov %rcx, fallback_rcx(%rip)
mov %r11, fallback_r11(%rip)
pushfq
pop %r13
cld

cmp %r12, %r13
jne fail
cmpq $0, fallback_rcx(%rip)
jne fail
cmpq $0x77, fallback_r11(%rip)
jne fail
mov fallback_rax(%rip), %rax
or fallback_rdx(%rip), %rax
je fail

/* Repeat with a valid operand-size prefix to cover the marker's NOP tail. */
mov $1, %rax
cmp $2, %rax
std
pushfq
pop %r12
mov $0x77, %r11
jmp 4f
nop
nop
4:
.byte 0x66, 0x0f, 0x01, 0xf9
mov %rax, fallback_rax(%rip)
mov %rdx, fallback_rdx(%rip)
mov %rcx, fallback_rcx(%rip)
mov %r11, fallback_r11(%rip)
pushfq
pop %r13
cld

cmp %r12, %r13
jne fail
cmpq $0, fallback_rcx(%rip)
jne fail
cmpq $0x77, fallback_r11(%rip)
jne fail
mov fallback_rax(%rip), %rax
or fallback_rdx(%rip), %rax
je fail

mov $0, %rdi
jmp exit
fail:
mov $1, %rdi
exit:
mov $60, %rax /* __NR_exit */
syscall

.bss
.align 8
fallback_rax: .zero 8
fallback_rdx: .zero 8
fallback_rcx: .zero 8
fallback_r11: .zero 8

.section .note.GNU-stack,"",@progbits
