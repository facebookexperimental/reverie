/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Ignores SIGTRAP, raises SIGUSR1 (whose delivery stop GDB sees), then
 * stores to a global word, then checks its own SIGTRAP action and mask.
 * Arming a gdb watch here must be refused: a hit's forced SIGTRAP would
 * reset the ignored action to the default, which no repair writes back.
 * The exit status says which check failed: 3 if SIGTRAP is blocked, 4 if
 * its action is no longer SIG_IGN. The word is a global symbol; the test
 * builds this file with -no-pie, so its symbol value is its run-time
 * address.
 */

#include <signal.h>
#include <stdint.h>

volatile uint64_t reverie_watched;

int main(void) {
  if (signal(SIGTRAP, SIG_IGN) == SIG_ERR) {
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
  if (sigismember(&now, SIGTRAP)) {
    return 3;
  }
  struct sigaction action;
  if (sigaction(SIGTRAP, 0, &action) != 0) {
    return 2;
  }
  if (action.sa_handler != SIG_IGN) {
    return 4;
  }
  return 0;
}
