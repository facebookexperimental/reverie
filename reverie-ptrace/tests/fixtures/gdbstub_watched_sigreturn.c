/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A SIGUSR1 handler whose sa_mask blocks SIGTRAP makes one traced syscall
 * and returns. Its rt_sigreturn restores main's mask, in which SIGTRAP is
 * not blocked. Main then stores to the watched word once and checks
 * SIGTRAP's mask bit. Exit 5: SIGTRAP is blocked after the store, i.e. the
 * hit's repair blocked a bit the guest had left unblocked. Exit 6: SIGTRAP
 * was already blocked before the signal (fixture error). 0: unchanged.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile uint64_t reverie_watched;

static void handler(int sig) {
  (void)sig;
  syscall(SYS_getppid);
}

int main(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGTRAP);
  if (sigaction(SIGUSR1, &sa, 0) != 0) {
    return 2;
  }
  sigset_t before;
  sigemptyset(&before);
  if (sigprocmask(SIG_BLOCK, 0, &before) != 0) {
    return 2;
  }
  if (sigismember(&before, SIGTRAP)) {
    return 6;
  }
  syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGUSR1);
  reverie_watched = 1;
  if (reverie_watched != 1) {
    return 1;
  }
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
