/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "real_syscall.s"
  .text
  .globl real_syscall
  .type real_syscall, @function

  # sc_no lives in %rdi
  # arg1 lives in %rsi
  # arg2 lives in %rdx
  # arg3 lives in %rcx
  # arg4 lives in %r8
  # arg5 lives in %r9
  # arg6 lives in 16(%rbp)

real_syscall:
  pushq %rbp

  # Adjust the arguments
  movq %rsp, %rbp
  movq %rdi, %rax    # sc_no
  movq %rsi, %rdi    # arg1
  movq %rdx, %rsi    # arg2
  movq %rcx, %rdx    # arg3
  movq %r8, %r10     # arg4
  movq %r9, %r8      # arg5
  movq 16(%rbp), %r9 # arg6

  syscall            # syscall

  popq %rbp
  ret
  .size real_syscall, .-real_syscall
  .section .note.GNU-stack,"",@progbits
