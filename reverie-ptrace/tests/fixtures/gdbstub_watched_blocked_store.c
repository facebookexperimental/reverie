/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Blocks SIGTRAP, then makes one store to a global word between two
 * labelled nops, for the GDB test that single-steps over the store
 * with a hardware watchpoint on the word under a record-keeping Tool:
 * the step's hit forces a SIGTRAP, which unblocks the signal; the
 * guest checks that SIGTRAP is blocked again afterwards. Exit 5:
 * SIGTRAP left unblocked after the store. Exit 2: fixture error.
 * The labels and the word are global symbols; the test builds this
 * file with -no-pie, so their symbol values are their run-time
 * addresses.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>

volatile uint64_t reverie_watched;

int main(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  if (sigprocmask(SIG_BLOCK, &set, 0) != 0) {
    return 2;
  }
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
  sigset_t now;
  sigemptyset(&now);
  if (sigprocmask(SIG_BLOCK, 0, &now) != 0) {
    return 2;
  }
  if (!sigismember(&now, SIGTRAP)) {
    return 5;
  }
  return 0;
}
