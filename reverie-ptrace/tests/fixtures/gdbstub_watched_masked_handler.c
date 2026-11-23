/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A SIGUSR1 handler whose sa_mask blocks SIGTRAP stores to the watched
 * word before making any syscall, then reads its mask. The hit inside
 * the handler forces a SIGTRAP, which unblocks the signal; the mask
 * the handler runs under must be put back. Exit 5: SIGTRAP unblocked
 * inside the handler after the store. Exit 6: blocked before it.
 * Exit 2: fixture error. 0: unchanged.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile uint64_t reverie_watched;
static volatile int handler_result = 9;

static int sigtrap_blocked(void) {
  sigset_t now;
  sigemptyset(&now);
  if (sigprocmask(SIG_BLOCK, 0, &now) != 0) {
    return -1;
  }
  return sigismember(&now, SIGTRAP);
}

static void handler(int sig) {
  (void)sig;
  reverie_watched = 1;
  handler_result = sigtrap_blocked() == 1 ? 0 : 5;
}

int main(void) {
  if (sigtrap_blocked() != 0) {
    return 6;
  }
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGTRAP);
  if (sigaction(SIGUSR1, &sa, 0) != 0) {
    return 2;
  }
  /* No syscall between installing the handler and signalling it:
   * the hit inside the handler is the first stop after the install. */
  syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGUSR1);
  return handler_result;
}
