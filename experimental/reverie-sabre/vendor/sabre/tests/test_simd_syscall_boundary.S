/* Copyright © 2026 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -nostdlib -nostartfiles -Wl,--no-as-needed -lc %s -o %t1
 * RUN: %t1
 * RUN: %{sbr} %{sbr-id} -- %t1
 */

.text
.global _start
.type _start, @function
_start:
  sub $0x400, %rsp
  mov %rsp, %rbx
  xor %edi, %edi
  mov $39, %eax /* __NR_getpid */

  /*
   * Preserve the exact glibc 2.39 sequence that exposed decoder drift before
   * a syscall. Every SIMD opcode below carries a ModR/M byte; losing that byte
   * makes the rewriter place its jump in the middle of MOVUPS.
   */
  .byte 0x66, 0x48, 0x0f, 0x6e, 0xc7
  .byte 0x66, 0x0f, 0x6c, 0xc0
  .byte 0x0f, 0x11, 0x83, 0xd8, 0x02, 0x00, 0x00
  syscall

  test %rax, %rax
  jle fail
  xor %edi, %edi
  jmp exit
fail:
  mov $1, %edi
exit:
  mov $60, %eax /* __NR_exit */
  syscall
.size _start, .-_start
