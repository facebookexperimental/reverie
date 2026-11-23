/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Catches SIGTRAP and blocks it, raises SIGUSR1 (whose delivery stop GDB
 * sees, with that state intact), then stores to a global word, then
 * checks its own SIGTRAP mask and action. Arming a gdb watch here must
 * be refused: a hit's forced SIGTRAP would reset the caught action to
 * the default, which no repair writes back. The exit status says which
 * check failed: 3 if SIGTRAP is no longer blocked, 4 if its handler is
 * no longer installed. The word is a global symbol; the test builds
 * this file with -no-pie, so its symbol value is its run-time address.
 */

#include <signal.h>
#include <stdint.h>
#include <string.h>

volatile uint64_t reverie_watched;

static void handler(int sig) {
  (void)sig;
}

int main(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGTRAP, &sa, 0) != 0) {
    return 2;
  }
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  if (sigprocmask(SIG_BLOCK, &set, 0) != 0) {
    return 2;
  }
  raise(SIGUSR1);
  reverie_watched = 1;
  if (reverie_watched != 1) {
    return 1;
  }
  sigset_t now;
  sigemptyset(&now);
  if (sigprocmask(SIG_BLOCK, 0, &now) != 0) {
    return 2;
  }
  if (!sigismember(&now, SIGTRAP)) {
    return 3;
  }
  struct sigaction action;
  if (sigaction(SIGTRAP, 0, &action) != 0) {
    return 2;
  }
  if (action.sa_handler != handler) {
    return 4;
  }
  return 0;
}
