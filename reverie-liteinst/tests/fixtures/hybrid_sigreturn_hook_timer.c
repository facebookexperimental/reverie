/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The syscall number of `reverie_liteinst_restorer`'s site. */
long reverie_liteinst_restorer_nr;

/* Two syscall sites, which the first use of each, a getpid, patches. The
   first makes getpid with its arguments in rdi, which tells the test's Tool
   whether to request a timer, and rsi, the round the request is for. The
   second makes the syscall numbered by
   `reverie_liteinst_restorer_nr`, and becomes the signal handler's
   restorer, whose rt_sigreturn is then a LiteInst hook trap. Each has an
   unwind-table entry so that LiteInst's entry census admits its site; the
   restorer's entry does not describe a signal frame, and nothing unwinds
   through it. */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_getpid\n"
    ".type reverie_liteinst_getpid,@function\n"
    "reverie_liteinst_getpid:\n"
    ".cfi_startproc\n"
    "mov $39, %eax\n"
    "syscall\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_getpid, .-reverie_liteinst_getpid\n"
    ".p2align 4\n"
    ".global reverie_liteinst_restorer\n"
    ".type reverie_liteinst_restorer,@function\n"
    "reverie_liteinst_restorer:\n"
    ".cfi_startproc\n"
    "mov reverie_liteinst_restorer_nr(%rip), %rax\n"
    "syscall\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_restorer, .-reverie_liteinst_restorer\n");

extern long reverie_liteinst_getpid(long request, unsigned long round);
extern long reverie_liteinst_restorer(void);

/* Retires exactly `rounds` conditional branches, for `rounds` > 0. */
static void branches(unsigned long rounds) {
  __asm__ volatile("1: dec %0; jnz 1b" : "+r"(rounds) : : "cc");
}

/* The value that the test's Tool gives every getpid. */
#define ANSWER 0x4242

/* The kernel's flag for a caller-supplied restorer, which glibc does not
   export. */
#define SA_RESTORER 0x04000000

/* The kernel's `struct sigaction` for x86-64 rt_sigaction. */
struct kernel_sigaction {
  void (*handler)(int);
  unsigned long flags;
  void (*restorer)(void);
  unsigned long mask;
};

static unsigned long before;
static unsigned long leads = 1;
static unsigned long stride;
static unsigned long observe_at;
static volatile unsigned long round_index;
static volatile unsigned long wrong;
static volatile unsigned long handled;

/* Requests the timer for the current round `i`, and returns
   `before + (i % leads) * stride` branches later. With `observe_at`
   nonzero, and less than that, it makes a getpid that the Tool sees but
   that requests nothing `observe_at` branches after the request. */
static void handler(int signal) {
  (void)signal;
  unsigned long i = round_index;
  unsigned long lead = before + (i % leads) * stride;
  long pid = reverie_liteinst_getpid(1, i);
  if (observe_at != 0) {
    branches(observe_at);
    wrong += reverie_liteinst_getpid(0, 0) != ANSWER;
    lead -= observe_at;
  }
  branches(lead);
  wrong += pid != ANSWER;
  ++handled;
}

/* Arguments: the branches from the handler's getpid to its return, the
   number of signals, and the branches after each; optionally then `leads`
   and `stride`, to add `(i % leads) * stride` branches before round `i`'s
   return, and then a flag that, if nonzero, blocks the timer's signal,
   SIGSTKFLT, for the whole run, so that no notification delivers an event;
   and optionally then `observe_at` (see `handler`, 0 for none), and a flag
   that, if nonzero, makes a getpid that the Tool sees but that requests
   nothing after each signal's handler has returned. */
int main(int argc, char** argv) {
  if (argc != 4 && argc != 6 && argc != 7 && argc != 9) {
    return 2;
  }
  before = strtoul(argv[1], NULL, 0);
  unsigned long rounds = strtoul(argv[2], NULL, 0);
  unsigned long after = strtoul(argv[3], NULL, 0);
  if (argc >= 6) {
    leads = strtoul(argv[4], NULL, 0);
    stride = strtoul(argv[5], NULL, 0);
    if (leads == 0) {
      return 2;
    }
  }
  unsigned long observe_after = 0;
  if (argc == 9) {
    observe_at = strtoul(argv[7], NULL, 0);
    observe_after = strtoul(argv[8], NULL, 0);
    if (observe_at != 0 && observe_at >= before) {
      return 2;
    }
  }
  wrong += reverie_liteinst_getpid(0, 0) != ANSWER;
  reverie_liteinst_restorer_nr = SYS_getpid;
  wrong += reverie_liteinst_restorer() != ANSWER;
  reverie_liteinst_restorer_nr = SYS_rt_sigreturn;
  struct kernel_sigaction action = {
      .handler = handler,
      .flags = SA_RESTORER,
      .restorer = (void (*)(void))reverie_liteinst_restorer,
      .mask = 0,
  };
  if (syscall(SYS_rt_sigaction, SIGUSR1, &action, NULL, sizeof(action.mask))) {
    return 3;
  }
  if (argc >= 7 && strtoul(argv[6], NULL, 0) != 0) {
    sigset_t timer;
    sigemptyset(&timer);
    sigaddset(&timer, SIGSTKFLT);
    if (sigprocmask(SIG_BLOCK, &timer, NULL)) {
      return 5;
    }
  }
  /* The Tool answers getpid, so address the signal by thread alone. */
  pid_t tid = gettid();
  for (unsigned long i = 0; i < rounds; ++i) {
    round_index = i;
    if (syscall(SYS_tkill, tid, SIGUSR1)) {
      return 4;
    }
    if (observe_after != 0) {
      wrong += reverie_liteinst_getpid(0, 0) != ANSWER;
    }
    branches(after);
  }
  printf("rounds=%lu handled=%lu wrong=%lu\n", rounds, handled, wrong);
  return 0;
}
