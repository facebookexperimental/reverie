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
#include <time.h>

#define NR_THREADS 8L
#define MAX_THREADS 2048

// NB: this counter is supposed to be set by gdb cli for testing only
static volatile unsigned int bkpt_resumed_count;

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
  foo();

  unsigned nthreads = NR_THREADS;
  if (argc == 2) {
    nthreads = atoi(argv[1]);
  }

  if (nthreads > MAX_THREADS) {
    nthreads = MAX_THREADS;
  }

  pthread_t* threadid = calloc(nthreads, sizeof(pthread_t));

  for (int i = 0; i < nthreads; i++) {
    assert(pthread_create(&threadid[i], NULL, threaded, NULL) == 0);
  }
  for (int i = 0; i < nthreads; i++) {
    pthread_join(threadid[i], NULL);
  }

  struct timespec tp = {
      .tv_sec = 0,
      .tv_nsec = 100000000,
  };
  clock_nanosleep(CLOCK_MONOTONIC, 0, &tp, NULL);

  printf("%d %d\n", thread_count, bkpt_resumed_count);

  return 0;
}
