/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * SIGUSR1 is queued while blocked, then ppoll waits under a temporary
 * mask that blocks only SIGTRAP, so the handler runs under that mask.
 * The handler stores to the watched word before making any syscall,
 * then reads its mask: the hit's forced SIGTRAP unblocks the signal,
 * and the temporary mask's bit must be put back. Exit 5: SIGTRAP
 * unblocked inside the handler after the store. Exit 2: fixture
 * error. 0: unchanged.
 */
#define _GNU_SOURCE
#include <poll.h>
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
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, 0) != 0) {
    return 2;
  }
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &block, 0) != 0) {
    return 2;
  }
  syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGUSR1);
  sigset_t wait_mask;
  sigemptyset(&wait_mask);
  sigaddset(&wait_mask, SIGTRAP);
  ppoll(0, 0, 0, &wait_mask);
  return handler_result;
}
