/*  Copyright © 2026 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -nostdlib -nostartfiles -Wl,--no-as-needed -lc %s -o %t1
 * RUN: %t1
 * RUN: %{sbr} %{sbr-id} -- %t1
 */

.macro prepare_syscall return_label
  mov $1, %rax
  cmp $2, %rax
  std
  pushfq
  pop %r12
  mov %r12, expected_flags(%rip)
  lea \return_label(%rip), %rax
  mov %rax, expected_rcx(%rip)

  /* Guest red-zone contents must survive the rewrite's own stack traffic. */
  movq $0x11223344, -8(%rsp)
  movq $0x55667788, -128(%rsp)
  mov $0x77, %rbx
  mov $39, %rax /* __NR_getpid */
.endm

.macro snapshot_syscall
  /* Snapshot red-zone and architectural outputs before PUSHFQ uses the stack. */
  mov %rax, observed_rax(%rip)
  mov %rcx, observed_rcx(%rip)
  mov %r11, observed_r11(%rip)
  mov %rbx, observed_rbx(%rip)
  mov -8(%rsp), %rax
  mov %rax, observed_redzone_top(%rip)
  mov -128(%rsp), %rax
  mov %rax, observed_redzone_bottom(%rip)
  pushfq
  pop %rax
  mov %rax, observed_flags(%rip)
  cld
.endm

.text
.global _start
.type _start, @function
_start:
  call test_rewritten_syscall
  test %eax, %eax
  jnz fail_rewritten
  call test_sigill_syscall
  test %eax, %eax
  jnz fail_sigill
  call test_sigill_resume_flags
  test %eax, %eax
  jnz fail_sigill_resume_flags

  xor %edi, %edi
  jmp exit
fail_rewritten:
  mov %eax, %edi
  jmp exit
fail_sigill:
  add $32, %eax
  mov %eax, %edi
  jmp exit
fail_sigill_resume_flags:
  add $64, %eax
  mov %eax, %edi
exit:
  mov $60, %eax /* __NR_exit */
  syscall
.size _start, .-_start

.type test_rewritten_syscall, @function
test_rewritten_syscall:
  prepare_syscall .Lrewritten_return
  syscall
.Lrewritten_return:
  snapshot_syscall
  jmp check_snapshot
.size test_rewritten_syscall, .-test_rewritten_syscall

.type test_sigill_syscall, @function
test_sigill_syscall:
  prepare_syscall .Lsigill_return
  jmp .Lsigill_site
  nop
  nop
.Lsigill_site:
  syscall /* Branch target + RIP-relative snapshot force the SIGILL path. */
.Lsigill_return:
  snapshot_syscall
  jmp check_snapshot
.size test_sigill_syscall, .-test_sigill_syscall

.type test_sigill_resume_flags, @function
test_sigill_resume_flags:
  mov $1, %rax
  cmp $2, %rax
  std
  pushfq
  pop %r12
  mov %r12, expected_flags(%rip)
  mov $39, %rax /* __NR_getpid */
  jmp .Lsigill_resume_site
  nop
  nop
.Lsigill_resume_site:
  syscall
.Lsigill_resume_return:
  /* This must be the first resumed instruction so an injected RF is visible. */
  pushfq
  pop observed_resume_flags(%rip)
  cld
  mov observed_resume_flags(%rip), %rax
  cmp expected_flags(%rip), %rax
  jne bad_resume_flags
  xor %eax, %eax
  ret
bad_resume_flags:
  mov $1, %eax
  ret
.size test_sigill_resume_flags, .-test_sigill_resume_flags

.type check_snapshot, @function
check_snapshot:
  mov observed_rcx(%rip), %rax
  cmp expected_rcx(%rip), %rax
  jne bad_rcx
  mov observed_r11(%rip), %rax
  cmp expected_flags(%rip), %rax
  jne bad_r11
  mov observed_flags(%rip), %rax
  cmp expected_flags(%rip), %rax
  jne bad_flags
  cmpq $0x77, observed_rbx(%rip)
  jne bad_rbx
  cmpq $0x11223344, observed_redzone_top(%rip)
  jne bad_redzone_top
  cmpq $0x55667788, observed_redzone_bottom(%rip)
  jne bad_redzone_bottom
  cmpq $0, observed_rax(%rip)
  jle bad_result

  xor %eax, %eax
  ret
bad_rcx: mov $1, %eax; ret
bad_r11: mov $2, %eax; ret
bad_flags: mov $3, %eax; ret
bad_rbx: mov $4, %eax; ret
bad_redzone_top: mov $5, %eax; ret
bad_redzone_bottom: mov $6, %eax; ret
bad_result: mov $7, %eax; ret
.size check_snapshot, .-check_snapshot

.bss
.align 8
expected_flags: .zero 8
expected_rcx: .zero 8
observed_flags: .zero 8
observed_rax: .zero 8
observed_rcx: .zero 8
observed_r11: .zero 8
observed_rbx: .zero 8
observed_redzone_top: .zero 8
observed_redzone_bottom: .zero 8
observed_resume_flags: .zero 8

.section .note.GNU-stack,"",@progbits
