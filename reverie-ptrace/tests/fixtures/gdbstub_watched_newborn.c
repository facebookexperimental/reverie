/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A pthread worker and then main each check SIGTRAP is unblocked, store
 * to the watched word, and check again. A newborn starts under glibc's
 * clone-time all-blocked mask and main blocks every signal across
 * pthread_create, so a gdb watch hit's repair must not restore either
 * thread's mask from a read taken in either window. Exit is
 * worker_code*10 + main_code (0 ok, 5 SIGTRAP blocked after the own
 * store, 6 blocked before it). The word is a global symbol; the test
 * builds this file with -no-pie.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

volatile uint64_t reverie_watched;
static volatile int worker_result = 9;

static int sigtrap_blocked(void) {
  sigset_t now;
  sigemptyset(&now);
  if (pthread_sigmask(SIG_BLOCK, 0, &now) != 0) {
    return -1;
  }
  return sigismember(&now, SIGTRAP);
}

static void *worker(void *unused) {
  (void)unused;
  if (sigtrap_blocked() != 0) {
    worker_result = 6;
    return 0;
  }
  reverie_watched = 1;
  worker_result = sigtrap_blocked() ? 5 : 0;
  return 0;
}

int main(void) {
  if (sigtrap_blocked() != 0) {
    return 99;
  }
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) {
    return 98;
  }
  if (pthread_join(thread, 0) != 0) {
    return 97;
  }
  int main_result;
  if (sigtrap_blocked() != 0) {
    main_result = 6;
  } else {
    reverie_watched = 2;
    main_result = sigtrap_blocked() ? 5 : 0;
  }
  return worker_result * 10 + main_result;
}
