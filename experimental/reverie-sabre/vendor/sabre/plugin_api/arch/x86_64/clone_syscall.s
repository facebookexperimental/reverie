/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "clone_syscall.s"
  .text
  .globl clone_syscall
  .type clone_syscall, @function

# long clone (unsigned long flags,  # %rdi
#             void *child_stack,    # %rsi
#             int *ptid,            # %rdx
#             int *ctid,            # %rcx
#             unsigned long newtls, # %r8
#             void* ret_addr        # %r9
#             void* ctx             # +8(%rsp)
#            );

clone_syscall:
  pushq %rbp
  movq %rsp, %rbp

  # Save xmm0
  subq $16, %rsp
  movdqu %xmm0, (%rsp)

  # Copy argument into xmm0
  movq 16(%rbp), %xmm0

  # Adjust the arguments
  movq $56, %rax
  movq %rcx, %r10
  syscall            # syscall

  # Both child and parent return here
  testq  %rax, %rax
  jnz    1f

  # Child

  # TODO: Return to the plugin after a new child and not directly to client.

  pushq %rdi
  pushq %rsi
  pushq %rdx
  pushq %r10 # %rcx
  pushq %r8
  pushq %r9

  # Call post_clone_hook with xmm0 as first argument
  movq %xmm0, %rdi
  call *post_clone_hook@GOTPCREL(%rip)

  call *exit_plugin@GOTPCREL(%rip)

  # Set xmm0 to NaN to catch xmm0 corruptions
  pcmpeqd %xmm0, %xmm0

  popq %r9
  popq %r8
  popq %r10 # %rcx
  popq %rdx
  popq %rsi
  popq %rdi

  # The child always returns 0.
  movq $0, %rax

  subq $0x80, %rsp
  jmp *%r9

1:
  # Parent
  
  # Restore xmm0
  movdqu (%rsp), %xmm0
  addq $16, %rsp

  popq %rbp
  ret

  .size clone_syscall, .-clone_syscall
  .section .note.GNU-stack,"",@progbits
