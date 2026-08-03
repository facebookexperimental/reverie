/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "vfork_return_from_child.s"
  .text
  .globl vfork_return_from_child
  .type vfork_return_from_child, @function

# long vfork_return_from_child(void *wrapper_sp # %rdi
#                              );

vfork_return_from_child:
  pushq %rbp
  movq %rsp, %rbp

  pushq %rdi
  call *exit_plugin@GOTPCREL(%rip)
  popq %rdi

  movq 0x8(%rdi), %r15
  movq 0x10(%rdi), %r14
  movq 0x18(%rdi), %r13
  movq 0x20(%rdi), %r12
  movq 0x28(%rdi), %r11
  movq 0x30(%rdi), %r10
  movq 0x38(%rdi), %r9
  movq 0x40(%rdi), %r8
  # Skip %rdi because we are reading it.
  movq 0x50(%rdi), %rsi
  movq 0x58(%rdi), %rdx
  movq 0x60(%rdi), %rcx
  movq 0x68(%rdi), %rbx
  movq 0x70(%rdi), %rbp

  # It's safe to clobber %r11 to load *ret.
  # *ret will jump back to the trampoline
  # and then in the first instruction after
  # the vfork syscall.
  movq 0x80(%rdi), %r11

  movq 0x48(%rdi), %rdi

  # The child always returns 0.
  movq $0, %rax

  subq $0x80, %rsp
  jmp *%r11 # We are going back to the client.

  .size vfork_return_from_child, .-vfork_return_from_child
  .section .note.GNU-stack,"",@progbits
