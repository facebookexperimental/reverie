/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void marker_handler(int signal) {
  (void)signal;
}

int main(int argc, char** argv) {
  if (argc != 2)
    return 2;
  const int guest_marker = strcmp(argv[1], "kick") != 0;
  struct sigaction action = {.sa_handler = marker_handler};
  if (sigemptyset(&action.sa_mask) || sigaction(SIGSTKFLT, &action, 0))
    return 3;
  sigset_t signals;
  if (sigemptyset(&signals) || sigaddset(&signals, SIGSTKFLT))
    return 4;
  if (guest_marker) {
    if (sigprocmask(SIG_BLOCK, &signals, 0))
      return 5;
    if (!strcmp(argv[1], "zero-active")) {
      siginfo_t info = {0};
      info.si_signo = SIGSTKFLT;
      info.si_code = SI_TKILL;
      info.si_pid = 0;
      info.si_uid = getuid();
      if (syscall(
              SYS_rt_tgsigqueueinfo,
              getpid(),
              syscall(SYS_gettid),
              SIGSTKFLT,
              &info))
        return 6;
    } else if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGSTKFLT)) {
      return 7;
    }
  }
  /* Only this syscall is subscribed. A blocked guest marker precedes any
     controller kick, so standard-signal coalescing preserves its real info. */
  if (syscall(SYS_getpgid, 0) < 0)
    return 8;
  if (sigprocmask(SIG_UNBLOCK, &signals, 0))
    return 9;
  for (volatile uint64_t index = 0; index < 100000; ++index)
    __asm__ volatile("" ::: "memory");
  char output[96];
  const int size = snprintf(
      output,
      sizeof output,
      "guest_pid=%ld\nnamespace-survived",
      (long)getpid());
  return size > 0 && syscall(SYS_write, 1, output, size) == size ? 0 : 10;
}
