/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Blocks SIGTRAP, raises SIGUSR1 (whose delivery stop GDB sees, with the
 * SIGTRAP mask intact), then stores to a global word, then checks its own
 * SIGTRAP mask and action. Linux reports a hardware-watchpoint hit by
 * forcing a SIGTRAP, which unblocks it and resets its action to the
 * default; with the default action already in place, a backend that
 * repairs the hit puts the mask back, so the guest must still see
 * SIGTRAP blocked with the default action after the store. The exit
 * status says which check failed: 3 if SIGTRAP is no longer blocked,
 * 4 if its action is no longer the default. The word is a global
 * symbol; the test builds this file with -no-pie, so its symbol value
 * is its run-time address.
 */

#include <signal.h>
#include <stdint.h>

volatile uint64_t reverie_watched;

int main(void) {
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
  if (action.sa_handler != SIG_DFL) {
    return 4;
  }
  return 0;
}
