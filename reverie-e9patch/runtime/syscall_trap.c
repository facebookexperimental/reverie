/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * E9tool's clean call trampoline passes a writable STATE pointer in RDI. The
 * ptrace lifecycle controller recognizes the magic RAX value at this int3 and
 * handles the original syscall using that frame.
 */
__attribute__((naked)) void
reverie_e9patch_syscall(void *state __attribute__((unused))) {
  __asm__ volatile("movabs $0x7265766539653970, %rax\n\t"
                   "int3\n\t"
                   "ret\n\t");
}
