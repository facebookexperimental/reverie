/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in LICENSE.
 */
.text
.global _start
.type _start, @function
_start:
    mov $39, %eax
    syscall
    xor %edi, %edi
    mov $231, %eax
    syscall
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
