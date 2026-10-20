/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Two places to set software breakpoints 6 bytes apart, close enough that the
 * 8-byte word Reverie's GDB server reads and writes at the first covers the
 * second. Between them are two 3-byte nops, so a single step from the first
 * stops after one nop, short of the second, as GDB's step over a breakpoint
 * would. The program then exits 0.
 *
 * Reverie neither delivers nor reports a SIGTRAP that no breakpoint accounts
 * for, so a stray int3 left at a site makes the guest run on from the byte
 * after it, inside the site's instruction. That byte is an invalid opcode at
 * each site, so the guest dies of SIGILL rather than exiting 0: 0x1f at the
 * first, and 0x0f 0x0b (ud2) at the second, whose instruction is a mov.
 *
 * The labels are global symbols. The test builds this file with -no-pie, so
 * their symbol values are their run-time addresses.
 */

int main(void) {
  __asm__ volatile(
      ".globl reverie_bkpt_a\n"
      "reverie_bkpt_a:\n"
      "  .byte 0x0f, 0x1f, 0x00\n" /* nopl (%rax) */
      "  .byte 0x0f, 0x1f, 0x00\n" /* nopl (%rax) */
      ".globl reverie_bkpt_b\n"
      "reverie_bkpt_b:\n"
      "  .byte 0xb8, 0x0f, 0x0b, 0x90, 0x90\n" /* mov $0x90900b0f, %eax */
      "  .byte 0x90\n" /* nop */
      :
      :
      : "eax");
  return 0;
}
