/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One syscall site for any syscall number, with one argument. Its first use,
   a getpid, reaches the host through seccomp, which patches the site, and
   every later use through the site's LiteInst hook, whose trap is an int3.
   The test's Tool subscribes getpid alone, so a getppid or an exit_group
   there is a hook trap that makes no Tool callback. */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_dynamic_syscall\n"
    ".type reverie_liteinst_dynamic_syscall,@function\n"
    "reverie_liteinst_dynamic_syscall:\n"
    ".cfi_startproc\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "syscall\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_dynamic_syscall, "
    ".-reverie_liteinst_dynamic_syscall\n");

extern long reverie_liteinst_dynamic_syscall(long nr, long arg);

/* Retires exactly `rounds` conditional branches, for `rounds` > 0. */
static void branches(unsigned long rounds) {
  __asm__ volatile("1: dec %0; jnz 1b" : "+r"(rounds) : : "cc");
}

/* The value that the test's Tool gives every getpid. */
#define ANSWER 0x4242

/* Argument: the branches from the timer's request to the getppid. The guest
   blocks the timer's signal, so no notification can deliver the event, and
   exits through the patched site with status 0 if every syscall returned what
   it should. */
int main(int argc, char** argv) {
  if (argc != 2) {
    return 2;
  }
  unsigned long before = strtoul(argv[1], NULL, 0);
  long expected_ppid = syscall(SYS_getppid);
  /* Patches the site, and requests no timer. */
  long wrong = reverie_liteinst_dynamic_syscall(SYS_getpid, 0) != ANSWER;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGSTKFLT);
  if (sigprocmask(SIG_BLOCK, &set, NULL)) {
    return 3;
  }
  wrong += reverie_liteinst_dynamic_syscall(SYS_getpid, 1) != ANSWER;
  branches(before);
  wrong += reverie_liteinst_dynamic_syscall(SYS_getppid, 0) != expected_ppid;
  reverie_liteinst_dynamic_syscall(SYS_exit_group, wrong ? 4 : 0);
  return 5;
}
