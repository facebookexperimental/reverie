/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Each round asks the host for a precise timer at a clock_getres syscall,
 * retires close to the number of conditional branches after which the PMU
 * notification comes, and then makes a getppid syscall. Every syscall
 * instruction here is a separate site that runs once, so each seccomp stop
 * at one runs the LiteInst patch helper before the host Tool sees it. In
 * the rounds that retire fewer branches than NOTIFICATION before getppid,
 * the helper's own branches reach it, and the overflow comes while the
 * helper runs.
 *
 * argv[1] is the skid margin. After each getppid the guest retires twice
 * that, past the target of the round's request, before the next request.
 * The guest installs no SIGSTKFLT handler: a timer signal delivered to it
 * terminates it.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Branches from the request to the PMU notification
 * (HELPER_NOTIFICATION_RCBS in hybrid.rs).
 */
#define NOTIFICATION 9000
#define OFFSETS 16
#define ROUNDS 32

/*
 * clock_getres, then exactly NOTIFICATION - 4 + n % OFFSETS conditional
 * branches, then getppid with the round number in rdi, then exactly `after`
 * conditional branches.
 * Nothing else between the two syscalls retires a conditional branch.
 */
#define ROUND(n)                                                      \
  __asm__ volatile(                                                   \
      "mov $229, %%eax\n"                                             \
      "xor %%edi, %%edi\n"                                            \
      "xor %%esi, %%esi\n"                                            \
      "syscall\n"                                                     \
      "mov %0, %%rcx\n"                                               \
      "1: dec %%rcx\n"                                                \
      "jnz 1b\n"                                                      \
      "mov $110, %%eax\n"                                             \
      "mov $" #n                                                      \
      ", %%edi\n"                                                     \
      "syscall\n"                                                     \
      "mov %1, %%rcx\n"                                               \
      "2: dec %%rcx\n"                                                \
      "jnz 2b\n"                                                      \
      :                                                               \
      : "r"((uint64_t)(NOTIFICATION - 4 + (n) % OFFSETS)), "r"(after) \
      : "rax", "rcx", "rdi", "rsi", "r11", "memory")

int main(int argc, char** argv) {
  if (argc != 2) {
    return 2;
  }
  uint64_t after = 2 * strtoull(argv[1], NULL, 10) + OFFSETS;
  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);
  ROUND(10);
  ROUND(11);
  ROUND(12);
  ROUND(13);
  ROUND(14);
  ROUND(15);
  ROUND(16);
  ROUND(17);
  ROUND(18);
  ROUND(19);
  ROUND(20);
  ROUND(21);
  ROUND(22);
  ROUND(23);
  ROUND(24);
  ROUND(25);
  ROUND(26);
  ROUND(27);
  ROUND(28);
  ROUND(29);
  ROUND(30);
  ROUND(31);
  printf("rounds=%d\n", ROUNDS);
  return 0;
}
