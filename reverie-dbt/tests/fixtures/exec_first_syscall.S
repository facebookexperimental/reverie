/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* No loader or libc syscall may start the helper before this exec. */
.text
.global _start
_start:
    mov $59, %eax
    lea executable(%rip), %rdi
    lea arguments(%rip), %rsi
    xor %edx, %edx
    syscall
    mov $60, %eax
    mov $1, %edi
    syscall

.section .rodata
executable:
    .asciz "/bin/true"
.align 8
arguments:
    .quad executable, 0
.section .note.GNU-stack,"",@progbits
