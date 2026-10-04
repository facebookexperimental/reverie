/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One syscall site for any syscall number, with up to two arguments. Its
   first use, a getpid, reaches the host through seccomp, which patches the
   site, and every later use through the site's LiteInst hook, whose trap is
   an int3. The test's Tool subscribes getpid alone, so an rt_sigsuspend made
   there is a hook trap that makes no Tool callback. A getpid's first
   argument tells the Tool whether to request a timer, and its second is the
   round the request is for. */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_dynamic_syscall\n"
    ".type reverie_liteinst_dynamic_syscall,@function\n"
    "reverie_liteinst_dynamic_syscall:\n"
    ".cfi_startproc\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "syscall\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_dynamic_syscall, "
    ".-reverie_liteinst_dynamic_syscall\n");

extern long reverie_liteinst_dynamic_syscall(long nr, long a0, long a1);

/* Retires exactly `rounds` conditional branches, for `rounds` > 0. */
static void branches(unsigned long rounds) {
  __asm__ volatile("1: dec %0; jnz 1b" : "+r"(rounds) : : "cc");
}

/* The value that the test's Tool gives every getpid. */
#define ANSWER 0x4242

static volatile unsigned long handled;

/* The branches that `handler` runs before it returns, if nonzero. */
static unsigned long handler_branches;

static void handler(int signal) {
  (void)signal;
  if (handler_branches != 0) {
    branches(handler_branches);
  }
  ++handled;
}

/* Arguments: the branches from each round's request to its rt_sigsuspend,
   the number of rounds, the branches after each, then `observe_at`, nonzero
   for a getpid that the Tool sees but that requests nothing that many
   branches after each request, a flag that, if nonzero, blocks the
   timer's signal, SIGSTKFLT, and optionally the branches that the SIGSYS
   handler runs (0, the default, for none).

   The guest's own seccomp filter traps every rt_sigsuspend
   (`SECCOMP_RET_TRAP`), so the one that Reverie injects for the hook, which
   it single steps, raises a SIGSYS with a positive code. The kernel
   dequeues that ahead of the step's SIGTRAP, so the injection ends at the
   SIGSYS's stop, and Reverie holds the SIGSYS for the guest's resume, where
   its handler runs. A signal of another class, or one with a code of its
   own that the kernel does not give (a SIGBUS that the guest queues itself
   while blocking it, or one from signal-driven I/O, which the kernel sends
   with `SI_SIGIO`), is not held: the kernel reports the first at every
   single step, the timer's included, and the second only after the step's
   SIGTRAP. */
int main(int argc, char** argv) {
  if (argc != 6 && argc != 7) {
    return 2;
  }
  unsigned long before = strtoul(argv[1], NULL, 0);
  unsigned long rounds = strtoul(argv[2], NULL, 0);
  unsigned long after = strtoul(argv[3], NULL, 0);
  unsigned long observe_at = strtoul(argv[4], NULL, 0);
  unsigned long block_timer = strtoul(argv[5], NULL, 0);
  if (argc == 7) {
    handler_branches = strtoul(argv[6], NULL, 0);
  }
  if (before == 0 || after == 0 || (observe_at != 0 && observe_at >= before)) {
    return 2;
  }
  unsigned long wrong =
      reverie_liteinst_dynamic_syscall(SYS_getpid, 0, 0) != ANSWER;
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGSYS, &action, NULL)) {
    return 3;
  }
  sigset_t mask;
  sigemptyset(&mask);
  if (block_timer != 0) {
    sigaddset(&mask, SIGSTKFLT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
      return 3;
    }
  }
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigsuspend, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program)) {
    return 3;
  }
  unsigned long unexpected = 0;
  for (unsigned long i = 0; i < rounds; ++i) {
    unsigned long lead = before;
    wrong += reverie_liteinst_dynamic_syscall(SYS_getpid, 1, (long)i) != ANSWER;
    if (observe_at != 0) {
      branches(observe_at);
      wrong += reverie_liteinst_dynamic_syscall(SYS_getpid, 0, 0) != ANSWER;
      lead -= observe_at;
    }
    branches(lead);
    /* The mask is never installed, since the filter traps the syscall. */
    long suspend =
        reverie_liteinst_dynamic_syscall(SYS_rt_sigsuspend, (long)&mask, 8);
    unexpected += handled != i + 1;
    (void)suspend;
    branches(after);
  }
  printf(
      "rounds=%lu handled=%lu wrong=%lu\n",
      rounds,
      handled,
      wrong + unexpected);
  return 0;
}
