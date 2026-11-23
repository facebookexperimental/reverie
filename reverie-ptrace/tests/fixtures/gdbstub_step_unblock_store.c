/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Blocks SIGTRAP, unblocks it with a raw rt_sigprocmask between
 * labelled nops, then stores to a global word between labelled nops
 * and checks the mask. Gdb single-steps over both instructions with
 * a watch on the word: the stepped unblock must be what the store's
 * hit repairs from — a mask record from before the stepped call
 * would re-block the bit the guest unblocked. Exit 5: SIGTRAP
 * blocked after the store. Exit 2: fixture error. The labels and
 * the word are global symbols; the test builds this file with
 * -no-pie.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

volatile uint64_t reverie_watched;

int main(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  if (sigprocmask(SIG_BLOCK, &set, 0) != 0) {
    return 2;
  }
  register long r10 __asm__("r10") = 8;
  long ret;
  /* rt_sigprocmask(SIG_UNBLOCK=1, &set, NULL, 8). */
  __asm__ volatile(
      ".globl reverie_before_unblock\n"
      "reverie_before_unblock:\n"
      "  nop\n"
      ".globl reverie_unblock\n"
      "reverie_unblock:\n"
      "  syscall\n"
      ".globl reverie_after_unblock\n"
      "reverie_after_unblock:\n"
      "  nop\n"
      : "=a"(ret)
      : "a"((long)SYS_rt_sigprocmask), "D"((long)SIG_UNBLOCK), "S"((long)&set),
        "d"((long)0), "r"(r10)
      : "rcx", "r11", "memory");
  if (ret != 0) {
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
  if (sigismember(&now, SIGTRAP)) {
    return 5;
  }
  return 0;
}
