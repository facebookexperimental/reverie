/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

  .file "handle_vdso.s"
  .text
  .globl handle_vdso
  .internal handle_vdso
  .type handle_vdso, @function

handle_vdso:
  .cfi_startproc
  .cfi_def_cfa rsp, 0x90
  .cfi_offset rip, -0x90
  .cfi_remember_state

  # Prologue
  push %rbp
  .cfi_adjust_cfa_offset 8
  mov %rsp, %rbp
  .cfi_def_cfa_register rbp
  .cfi_remember_state

  # Save the registers
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r9          # arg6

  # Align the stack on a 16-byte boundary before the call
  push %rbp
  mov %rsp, %rbp
  .cfi_adjust_cfa_offset 0x68
  and $0xfffffffffffffff0, %rsp

  # Check if vDSO handler is provided
  test %r15, %r15
  jnz handler_provided

  # Adjust the arguments
  movq %r8, %r9      # arg5
  movq %r10, %r8     # arg4
  movq %rdx, %rcx    # arg3
  movq %rsi, %rdx    # arg2
  movq %rdi, %rsi    # arg1
  movq %rax, %rdi    # sc_no

  # Call the actual handler
  call *plugin_sc_handler(%rip)
  jmp end

handler_provided:
  call *%r15

  # Reload the registers
end:
  # Restore the stack
  mov %rbp, %rsp
  pop %rbp
  .cfi_restore_state

  popq %r9
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r8
  popq %rdi
  popq %rsi
  popq %rdx
  popq %rcx
  popq %rbx

  # Epilogue
  pop %rbp
  .cfi_restore_state
  addq $8, %rsp	# drop fake return address
  .cfi_undefined rip
  ret
  .cfi_endproc
  .size handle_vdso, .-handle_vdso
  .section .note.GNU-stack,"",@progbits
