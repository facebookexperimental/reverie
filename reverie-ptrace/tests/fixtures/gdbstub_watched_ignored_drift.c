/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Ignores SIGTRAP after gdb has armed its watch (the guest drifts to
 * an irreparable state post-arming), then stores once and checks the
 * action. Linux's forced SIGTRAP at the hit resets SIG_IGN to
 * SIG_DFL, which no repair writes back, so the drift is reported, not
 * silently preserved. Exit 4:
 * SIGTRAP's action is no longer SIG_IGN after the store.
 */
#include <signal.h>
#include <stdint.h>

volatile uint64_t reverie_watched;

int main(void) {
  if (signal(SIGTRAP, SIG_IGN) == SIG_ERR) {
    return 2;
  }
  reverie_watched = 1;
  struct sigaction action;
  if (sigaction(SIGTRAP, 0, &action) != 0) {
    return 2;
  }
  if (action.sa_handler != SIG_IGN) {
    return 4;
  }
  return 0;
}
