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
.global main
.type main, @function

main:
  # Function prologue
  addi sp, sp, -8
  sd ra, 0(sp) #store return address

  addi sp, sp, -8
  sd s0, 0(sp) #save frame pointer
  addi s0, sp, 0 


   # Push two NULL pointers onto stack and pass them to load
  addi sp, sp, -8
  sd x0, 0(sp)
  addi a2, sp, 0 # pass the location for new_entry to load
  addi sp, sp, -8
  sd x0, 0(sp)
  addi a3, sp, 0 # pass the location for new_stack_top to load


  # call the main loading function
  call load

  # TODO sanity check

  ld a0, 0(sp) # new_stack_top in a0
  ld a1, 8(sp) # new_entry in a1

  mv sp, a0 # new stack

  # Nothing at_exit()
  mv a0, zero
 
  # Call the entrypoint of the loader/static 
  jr a1

  # if didn't end, force end
  addi x17, x0, 93
  ecall

error_entrypoint:


error_new_stack:


.size main, .-main
.section .note,"",@progbits
