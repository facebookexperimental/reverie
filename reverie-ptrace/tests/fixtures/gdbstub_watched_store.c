/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * One store to a global word, between two labelled nops, for the GDB tests
 * that step over the store with a hardware watchpoint on the word. The
 * labels and the word are global symbols; the test builds this file with
 * -no-pie, so their symbol values are their run-time addresses.
 */

#include <stdint.h>

volatile uint64_t reverie_watched;

int main(void) {
  __asm__ volatile(
      ".globl reverie_before_store\n"
      "reverie_before_store:\n"
      "  nop\n"
      ".globl reverie_store\n"
      "reverie_store:\n"
      "  movq $1, reverie_watched(%%rip)\n"
      ".globl reverie_after_store\n"
      "reverie_after_store:\n"
      "  nop\n"
      :
      :
      : "memory");
  return 0;
}
