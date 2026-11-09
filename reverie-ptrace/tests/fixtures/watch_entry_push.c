/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A static program without a C library whose first instruction pushes, so a
 * write watch on the 8 bytes below its initial stack pointer catches the
 * image's very first instruction, which Reverie single-steps after the
 * post-exec callback. With an argument, the program then executes itself
 * once more without one; without one, it exits 0.
 *
 * Build: cc -static -nostdlib -no-pie. The label after the push is a global
 * symbol whose value is its run-time address.
 */

__asm__(
    ".globl _start\n"
    "_start:\n"
    "  push %rax\n"
    ".globl reverie_after_push\n"
    "reverie_after_push:\n"
    /* argc, above the pushed word */
    "  cmpq $1, 8(%rsp)\n"
    "  jbe 1f\n"
    /* execve(argv[0], {argv[0], NULL}, NULL) */
    "  mov 16(%rsp), %rdi\n"
    "  movq $0, 24(%rsp)\n"
    "  lea 16(%rsp), %rsi\n"
    "  xor %edx, %edx\n"
    "  mov $59, %eax\n"
    "  syscall\n"
    "  mov $1, %edi\n"
    "  jmp 2f\n"
    "1:\n"
    "  xor %edi, %edi\n"
    "2:\n"
    /* exit_group */
    "  mov $231, %eax\n"
    "  syscall\n");
