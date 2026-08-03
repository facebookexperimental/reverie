/*  Copyright © 2026 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * REQUIRES: rdtsc
 * RUN: %{cc} -nostdlib -nostartfiles -Wl,--no-as-needed -lc %s -o %t1
 * RUN: %t1 native-prefix-probe
 * RUN: %{sbr} %{sbr-id} -- %t1
 */

.macro prepare_rdtscp
  /* Establish flags first; every following setup instruction preserves them. */
  mov $1, %rax
  cmp $2, %rax
  std
  pushfq
  pop %rax
  mov %rax, expected_flags(%rip)

  mov $0x11, %rbx
  mov $0x22, %rsi
  mov $0x33, %rdi
  mov $0x44, %r8
  mov $0x55, %r9
  mov $0x66, %r10
  mov $0x77, %r11
  mov $0x88, %r12
  mov $0x99, %r13
  mov $0xaa, %r14
  mov $0xbb, %r15
.endm

.macro snapshot_rdtscp
  /* MOV and PUSH/POP do not disturb the flags produced by the guest context. */
  mov %rax, observed_rax(%rip)
  mov %rdx, observed_rdx(%rip)
  mov %rcx, observed_rcx(%rip)
  mov %rbx, observed_rbx(%rip)
  mov %rsi, observed_rsi(%rip)
  mov %rdi, observed_rdi(%rip)
  mov %r8, observed_r8(%rip)
  mov %r9, observed_r9(%rip)
  mov %r10, observed_r10(%rip)
  mov %r11, observed_r11(%rip)
  mov %r12, observed_r12(%rip)
  mov %r13, observed_r13(%rip)
  mov %r14, observed_r14(%rip)
  mov %r15, observed_r15(%rip)
  pushfq
  pop %rax
  mov %rax, observed_flags(%rip)
  cld /* Keep the test harness itself SysV-compliant after taking the snapshot. */
.endm

.text
.global _start
.type _start, @function
_start:
  cmpq $2, (%rsp)
  je native_prefix_probe

  call test_unprefixed
  test %eax, %eax
  jnz fail_unprefixed
  call test_operand_size_prefix
  test %eax, %eax
  jnz fail_operand_size_prefix
  call test_rex_prefix
  test %eax, %eax
  jnz fail_rex_prefix

  xor %edi, %edi
  jmp exit
fail_unprefixed:
  mov %eax, %edi
  jmp exit
fail_operand_size_prefix:
  add $20, %eax
  mov %eax, %edi
  jmp exit
fail_rex_prefix:
  add $40, %eax
  mov %eax, %edi
  jmp exit
native_prefix_probe:
  /* These ignored prefixes must be accepted by the native CPU too. */
  .byte 0x66, 0x0f, 0x01, 0xf9
  .byte 0x48, 0x0f, 0x01, 0xf9
  xor %edi, %edi
exit:
  mov $60, %eax /* __NR_exit */
  syscall
.size _start, .-_start

.type test_unprefixed, @function
test_unprefixed:
  prepare_rdtscp
  rdtscp
  snapshot_rdtscp
  jmp check_snapshot
.size test_unprefixed, .-test_unprefixed

.type test_operand_size_prefix, @function
test_operand_size_prefix:
  prepare_rdtscp
  .byte 0x66, 0x0f, 0x01, 0xf9
  snapshot_rdtscp
  jmp check_snapshot
.size test_operand_size_prefix, .-test_operand_size_prefix

.type test_rex_prefix, @function
test_rex_prefix:
  prepare_rdtscp
  .byte 0x48, 0x0f, 0x01, 0xf9
  snapshot_rdtscp
  jmp check_snapshot
.size test_rex_prefix, .-test_rex_prefix

.type check_snapshot, @function
check_snapshot:
  mov observed_flags(%rip), %rax
  cmp expected_flags(%rip), %rax
  jne bad_flags

  cmpq $0, observed_rcx(%rip)
  jne bad_aux

  /* EAX and EDX writes zero their upper halves and carry a nonzero TSC. */
  mov observed_rax(%rip), %rax
  mov %rax, %rdx
  shr $32, %rdx
  jne bad_rax_width
  mov observed_rdx(%rip), %rdx
  mov %rdx, %rcx
  shr $32, %rcx
  jne bad_rdx_width
  or %rdx, %rax
  je bad_tsc

  cmpq $0x11, observed_rbx(%rip)
  jne bad_rbx
  cmpq $0x22, observed_rsi(%rip)
  jne bad_rsi
  cmpq $0x33, observed_rdi(%rip)
  jne bad_rdi
  cmpq $0x44, observed_r8(%rip)
  jne bad_r8
  cmpq $0x55, observed_r9(%rip)
  jne bad_r9
  cmpq $0x66, observed_r10(%rip)
  jne bad_r10
  cmpq $0x77, observed_r11(%rip)
  jne bad_r11
  cmpq $0x88, observed_r12(%rip)
  jne bad_r12
  cmpq $0x99, observed_r13(%rip)
  jne bad_r13
  cmpq $0xaa, observed_r14(%rip)
  jne bad_r14
  cmpq $0xbb, observed_r15(%rip)
  jne bad_r15

  xor %eax, %eax
  ret
bad_flags:
  mov observed_flags(%rip), %rax
  xor expected_flags(%rip), %rax
  and $0xff, %eax
  ret
bad_aux: mov $2, %eax; ret
bad_rax_width: mov $3, %eax; ret
bad_rdx_width: mov $4, %eax; ret
bad_tsc: mov $5, %eax; ret
bad_rbx: mov $6, %eax; ret
bad_rsi: mov $7, %eax; ret
bad_rdi: mov $8, %eax; ret
bad_r8: mov $9, %eax; ret
bad_r9: mov $10, %eax; ret
bad_r10: mov $11, %eax; ret
bad_r11: mov $12, %eax; ret
bad_r12: mov $13, %eax; ret
bad_r13: mov $14, %eax; ret
bad_r14: mov $15, %eax; ret
bad_r15: mov $16, %eax; ret
.size check_snapshot, .-check_snapshot

.bss
.align 8
expected_flags: .zero 8
observed_flags: .zero 8
observed_rax: .zero 8
observed_rdx: .zero 8
observed_rcx: .zero 8
observed_rbx: .zero 8
observed_rsi: .zero 8
observed_rdi: .zero 8
observed_r8: .zero 8
observed_r9: .zero 8
observed_r10: .zero 8
observed_r11: .zero 8
observed_r12: .zero 8
observed_r13: .zero 8
observed_r14: .zero 8
observed_r15: .zero 8

.section .note.GNU-stack,"",@progbits
