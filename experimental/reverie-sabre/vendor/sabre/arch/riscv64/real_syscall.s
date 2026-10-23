/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

.file "real_syscall.s"
.text
.globl real_syscall
.type real_syscall, @function

real_syscall:
  addi sp, sp, -16 # function prologue
  sd ra, 8(sp)
  sd s0, 0(sp)
  addi s0, sp, 0 

  addi t0, a0, 0 # store the syscall number
  addi a0, a1, 0
  addi a1, a2, 0
  addi a2, a3, 0
  addi a3, a4, 0
  addi a4, a5, 0
  addi a5, a6, 0
  addi a6, a7, 0
  
  addi a7, t0, 0 # place the syscall

  ecall

  ld s0, 0(sp)
  ld ra, 8(sp)
  addi sp, sp, 16
  
  ret

.size real_syscall, .-real_syscall
.section .note.GNU-stack,"",@progbits
