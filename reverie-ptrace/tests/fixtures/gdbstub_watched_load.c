/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * One load from a global word, between two labelled nops, for the GDB
 * tests that set a hardware read or access watchpoint on the word. The
 * word is initialized in the image, so nothing in the program writes it.
 * The labels and the word are global symbols; the test builds this file
 * with -no-pie, so their symbol values are their run-time addresses.
 */

#include <stdint.h>

volatile uint64_t reverie_watched = 7;

int main(void) {
  __asm__ volatile(
      ".globl reverie_before_load\n"
      "reverie_before_load:\n"
      "  nop\n"
      ".globl reverie_load\n"
      "reverie_load:\n"
      "  movq reverie_watched(%%rip), %%rax\n"
      ".globl reverie_after_load\n"
      "reverie_after_load:\n"
      "  nop\n"
      :
      :
      : "rax", "memory");
  return 0;
}
