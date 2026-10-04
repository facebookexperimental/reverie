/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A shared object for hybrid_truncated_object.c: one getpid site, no other
 * code that makes a system call, and three pages of initialized data that
 * nothing touches, so they stay pages of the object's file.
 */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_library_getpid\n"
    ".type reverie_liteinst_library_getpid,@function\n"
    "reverie_liteinst_library_getpid:\n"
    ".cfi_startproc\n"
    "mov $39, %eax\n"
    ".global reverie_liteinst_library_site\n"
    "reverie_liteinst_library_site:\n"
    "syscall\n"
    ".rept 6\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_library_getpid, "
    ".-reverie_liteinst_library_getpid\n");

unsigned char reverie_liteinst_untouched[3 * 4096]
    __attribute__((aligned(4096))) = {1};
