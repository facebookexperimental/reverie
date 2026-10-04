/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One syscall site for any syscall number. Its first use, a getpid, reaches
   the host through seccomp, which patches the site, and every later use
   through the site's LiteInst hook, whose trap is an int3. The test's Tool
   subscribes getpid alone, so a getppid there is a hook trap that makes no
   Tool callback. */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_dynamic_syscall\n"
    ".type reverie_liteinst_dynamic_syscall,@function\n"
    "reverie_liteinst_dynamic_syscall:\n"
    ".cfi_startproc\n"
    "mov %rdi, %rax\n"
    "syscall\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_dynamic_syscall, "
    ".-reverie_liteinst_dynamic_syscall\n");

extern long reverie_liteinst_dynamic_syscall(long);

/* Retires exactly `rounds` conditional branches, for `rounds` > 0. */
static void branches(unsigned long rounds) {
  __asm__ volatile("1: dec %0; jnz 1b" : "+r"(rounds) : : "cc");
}

/* The value that the test's Tool gives every getpid. */
#define ANSWER 0x4242

/* Arguments: the branches from each getpid to the getppid that follows it,
   the number of distances past that to cycle through, the number of rounds
   after the first, and the branches after each getppid. */
int main(int argc, char** argv) {
  if (argc != 5) {
    return 2;
  }
  unsigned long before = strtoul(argv[1], NULL, 0);
  unsigned long leads = strtoul(argv[2], NULL, 0);
  unsigned long rounds = strtoul(argv[3], NULL, 0);
  unsigned long after = strtoul(argv[4], NULL, 0);
  long expected_ppid = syscall(SYS_getppid);
  unsigned long wrong = 0;
  for (unsigned long i = 0; i <= rounds; ++i) {
    unsigned long distance = before + i % leads;
    long pid = reverie_liteinst_dynamic_syscall(SYS_getpid);
    branches(distance);
    long ppid = reverie_liteinst_dynamic_syscall(SYS_getppid);
    branches(after);
    wrong += pid != ANSWER || ppid != expected_ppid;
  }
  printf("rounds=%lu wrong=%lu\n", rounds, wrong);
  return 0;
}
