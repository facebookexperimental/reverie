/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#define NR_THREADS 4L

// NB: this counter is supposed to be set by gdb cli for testing only
static unsigned int bkpt_resumed_count;

static _Atomic unsigned int thread_count;

extern pid_t gettid(void);

__attribute__((noinline)) void bkpt(void) {}

__attribute__((noinline)) void foo(void) {
  atomic_fetch_add(&thread_count, 1);
  bkpt();
}

__attribute__((noinline)) void* threaded(void* param) {
  foo();

  return 0;
}

int main(int argc, char* argv[]) {
  pthread_t threadid[NR_THREADS];

  for (int j = 0; j < 2; j++) {
    for (int i = 0; i < NR_THREADS; i++) {
      assert(pthread_create(&threadid[i], NULL, threaded, NULL) == 0);
    }
    for (int i = 0; i < NR_THREADS; i++) {
      pthread_join(threadid[i], NULL);
    }
  }

  printf("%d %d\n", thread_count, bkpt_resumed_count);

  return 0;
}
