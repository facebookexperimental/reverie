/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <asm/prctl.h>
#include <sys/syscall.h>

  .file "handle_syscall.S"
  .text
  .globl handle_syscall
  .internal handle_syscall
  .type handle_syscall, @function

handle_syscall:
  .cfi_startproc
  .cfi_def_cfa rsp, 0x88
  .cfi_offset rip, -0x88


  # Check for rt_sigreturn(). It needs to be handled specially.
  #
  # When a user registers a signal through rt_sigaction, glibc (or others) add
  # SA_RESTORER and a pointer to inform Linux how to finish a signal execution.
  # SA_RESTORER points to a function that should eventually call the
  # rt_sigreturn syscall (together with whatever teardown stuff). An important
  # point here is that rt_sigreturn doesn't return. SaBRe will replace the
  # syscall with a jump and because our trampoline messes with the stack layout
  # we need to manually handle it. So whenever we are about to call rt_sigreturn
  # we need to revert all custom stack manipulations we did before rt_sigreturn
  # is called.
  #
  # Replacing the SA_RESTORER pointer with a custom handler (e.g. exactly how we
  # do it for SIGSEGV in plugins/varan/signal/proxy.c:overwrite_handler_func) is
  # not an option as the original SA_RESTORER might have some teardown logic
  # that we shouldn't be messing with. On the other hand, we need to replace the
  # SA_RESTORER pointer for signals that SaBRe should be hanlding internally
  # (e.g. SIGSEGV). In this case when a user wants to define a custom SIGSEGV
  # with a custom SA_RESTORER we need to first execute the user's SA_RESTORER
  # and then our own one. In the current version of SaBRe, glibc is used which
  # can simplify various details related to SA_RESTORER.
  #
  # TODO(andronat): Implement SA_RESTORER overwritting. SIGSEGV by default
  # should be pointing to internal's glibc SA_RESTORER. When a user registers
  # a custom one, we need to properly redirect. Assert that our SA_RESTORER will
  # always be a simple one.
  cmp  $15, %rax  # NR_rt_sigreturn
  jnz  1f
  # It's 0x80 + 0x10 for 2 extra PUSH instructions
  add  $0x90, %rsp  # pop return addresses, red zone, and loader arg
  0:syscall         # rt_sigreturn() is unrestricted
  mov  $66, %edi    # rt_sigreturn() should never return
  mov  $231, %eax   # NR_exit_group
  jmp  0b

  1:
  # The rewrite records the guest's pre-SYSCALL RFLAGS in r11. Save those
  # flags for architectural restoration and clear DF across the C/Rust call.
  pushq %r11
  .cfi_adjust_cfa_offset 8
  .cfi_remember_state
  cld

  # Prologue
  push %rbp
  .cfi_adjust_cfa_offset 8
  mov %rsp, %rbp
  .cfi_def_cfa_register rbp
  .cfi_remember_state

  # Save the registers.
  # While the kernel clobbers %rcx and %r11, we play safe and we store them.
  # From: https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/kernel.tex#L35-37
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15

  # Align the stack on a 16-byte boundary before the call
  push %rbp
  mov %rsp, %rbp
  .cfi_adjust_cfa_offset 0x70
  and $0xfffffffffffffff0, %rsp

  # Adjust the arguments
  pushq %rbp         # wrapper_sp
  pushq %r9          # arg6
  movq %r8, %r9      # arg5
  movq %r10, %r8     # arg4
  movq %rdx, %rcx    # arg3
  movq %rsi, %rdx    # arg2
  movq %rdi, %rsi    # arg1
  movq %rax, %rdi    # sc_no

  call *runtime_syscall_router@GOTPCREL(%rip)

  # Pop arguments
  popq %r9
  popq %r15    # skip wrapper_sp

  # Restore the stack
  mov %rbp, %rsp
  pop %rbp
  .cfi_restore_state

  # Reload registers
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

  # Epilogue
  pop %rbp
  .cfi_restore_state
  popfq
  .cfi_adjust_cfa_offset -8
  leaq 8(%rsp), %rsp # drop fake return address without changing RFLAGS
  .cfi_undefined rip
  ret
  .cfi_endproc
  .size handle_syscall, .-handle_syscall
  .section .note.GNU-stack,"",@progbits
