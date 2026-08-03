/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

.file "main.s"

.data
null_entry:
  .string "FATAL: entry point is null\n"
null_new_stack:
  .string "FATAL: new stack top is null\n"

.text
.globl main
.type main, @function

main:
  .cfi_startproc

  # Function prologue
  pushq %rbp
  .cfi_adjust_cfa_offset 8
  movq %rsp, %rbp
  .cfi_def_cfa_register rbp

  # Push two NULL pointers onto stack and pass them to load
  pushq $0 # The entrypoint initialized to 0
  movq %rsp, %rdx
  pushq $0 # The new stack top initialized to 0
  movq %rsp, %rcx

  # Call the main loading function
  callq *load@GOTPCREL(%rip)

  # Sanity checks
  movq -8(%rbp), %rax
  test %rax, %rax
  je error_entrypoint
  movq -16(%rbp), %r15
  test %r15, %r15
  je error_new_stack

  # Everything seems fine - nuke the stack!
  movq %r15, %rsp
  xorq %rbp, %rbp
  .cfi_undefined rip

  # Nothing at_exit()
  xorq %rdx, %rdx

  # Call the entrypoint of the loader/static ELF
  jmpq *%rax

error_entrypoint:
  andq $~0xF, %rsp # Align the stack
  movq $2, %rdi # Write to stderr
  lea null_entry(%rip), %rsi # since this is a PIC
  callq *dprintf@GOTPCREL(%rip) # ditto
  movq $127, %rax # default bad return code
  movq %rbp, %rsp
  popq %rbp
  retq

error_new_stack:
  andq $~0xF, %rsp
  movq $2, %rdi
  lea null_new_stack(%rip), %rsi
  callq *dprintf@GOTPCREL(%rip)
  movq $127, %rax
  movq %rbp, %rsp
  popq %rbp
  retq

  .cfi_endproc
.size main, .-main
.section .note.GNU-stack,"",@progbits
