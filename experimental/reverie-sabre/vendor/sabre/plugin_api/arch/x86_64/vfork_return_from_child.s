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

  # Resume from the saved registers, then flags and the scratch continuation,
  # matching handle_syscall's epilogue. The first frame word is stack alignment.
  leaq 8(%rdi), %rsp
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rdi
  popq %rsi
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rbp
  movq $0, %rax
  popfq
  leaq 8(%rsp), %rsp
  ret

  .size vfork_return_from_child, .-vfork_return_from_child
  .section .note.GNU-stack,"",@progbits
