/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Each selected ELF entry executes exactly its literal opcode first.
 * Falling through any trap is a failure: all four suffixes exit 99. */
.text
.macro first_exec_entry name, first, second=-1
.p2align 4
.globl \name
.type \name, @function
\name:
.byte \first
.if \second != -1
.byte \second
.endif
mov $99, %edi
mov $60, %eax
syscall
ud2
.size \name, .-\name
.endm

first_exec_entry first_exec_cc, 0xcc
first_exec_entry first_exec_f1, 0xf1
first_exec_entry first_exec_cd03, 0xcd, 0x03
first_exec_entry first_exec_nop, 0x90

.section .note.GNU-stack,"",@progbits
