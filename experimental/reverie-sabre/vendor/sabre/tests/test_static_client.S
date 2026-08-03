/* Copyright © 2026 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -nostdlib -nostartfiles -static -no-pie %s -o %t1
 * RUN: %t1 > %t1.expected
 * RUN: %{sbr} %{sbr-id} -- %t1 > %t1.actual
 * RUN: diff %t1.expected %t1.actual
 */

.section .rodata
message:
  .ascii "Hello from a static ELF!\n"
.set message_len, . - message

.text
.global _start
.type _start, @function
_start:
  mov $1, %eax /* __NR_write */
  mov $1, %edi /* STDOUT_FILENO */
  lea message(%rip), %rsi
  mov $message_len, %edx
  syscall

  cmp $message_len, %eax
  jne fail
  xor %edi, %edi
  jmp exit
fail:
  mov $1, %edi
exit:
  mov $60, %eax /* __NR_exit */
  syscall
