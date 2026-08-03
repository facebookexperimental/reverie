/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "clone3_syscall.s"
  .text
  .globl clone3_syscall
  .type clone3_syscall, @function

#                                    - userland args: https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/unix/sysv/linux/x86_64/clone3.S#L25
# long clone3 (long arg1,     # %rdi - struct clone_args *cl_args
#              long arg1,     # %rsi - size_t size
#              long arg2,     # %rdx - int (*func)(void *arg)
#              not_used,      # - %rcx - is clobbered by syscall so we don't use it.
#              long arg4,     # %r8  - void *arg
#              void *ret_addr # %r9
#              void *ctx      # +8(%rsp)
#             );

clone3_syscall:
  pushq %rbp
  movq %rsp, %rbp

  # Save xmm0
  subq $16, %rsp
  movdqu %xmm0, (%rsp)

  # Copy argument into xmm0
  movq 16(%rbp), %xmm0

  # Call clone3
  movq $435, %rax
  syscall

  # Both child and parent return here
  testq  %rax, %rax
  jnz    1f

  # Child

  # TODO: Return to the plugin after a new child and not directly to client.

  pushq %rdi
  pushq %rsi
  pushq %rdx
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
  popq %rdx
  popq %rsi
  popq %rdi

  # The child always returns 0.
  movq $0, %rax

  subq $0x80, %rsp # We need the -0x80 as we are jumping back to our trampoline that adds 0x80.

  # From: https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/unix/sysv/linux/x86_64/clone3.S#L52
  # glibc's clone3 expects %rdx to point to the user provide fn and it's arguments in %r8.
  # clone3 is significanlty different than clone where arguments are actually passed in the
  # child's stack. For more look here: https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/unix/sysv/linux/x86_64/clone.S#L98
  # It's safe to keep %rdx and %r8 unsaved as they are not clobbered from the kernel. For
  # more look here: https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/kernel.tex#L35-37

  jmp *%r9 # ret_addr jumps back to our trampoline.

1:
  # Parent
  
  # Restore xmm0 value
  movdqu (%rsp), %xmm0
  addq $16, %rsp

  popq %rbp
  ret

  .size clone3_syscall, .-clone3_syscall
  .section .note.GNU-stack,"",@progbits
