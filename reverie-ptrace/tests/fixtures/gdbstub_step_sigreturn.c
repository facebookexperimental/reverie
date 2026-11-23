/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A SIGUSR1 handler sends itself SIGUSR2, whose stop gdb sees inside
 * the handler; gdb then single-steps out of the handler, over its
 * rt_sigreturn, to the labelled instruction after main's raw tgkill.
 * Every step must stop: a step that runs away reaches the exit
 * instead. Exit 7: the handler never ran. Exit 2: fixture error.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile int handler_ran;

static void handler(int sig) {
  (void)sig;
  handler_ran = 1;
  syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGUSR2);
}

int main(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, 0) != 0) {
    return 2;
  }
  long tgid = getpid();
  long tid = syscall(SYS_gettid);
  long ret;
  __asm__ volatile(
      "syscall\n"
      ".globl reverie_after_raise\n"
      "reverie_after_raise:\n"
      "  nop\n"
      : "=a"(ret)
      : "a"((long)SYS_tgkill), "D"(tgid), "S"(tid), "d"((long)SIGUSR1)
      : "rcx", "r11", "memory");
  if (ret != 0) {
    return 2;
  }
  if (!handler_ran) {
    return 7;
  }
  return 0;
}
