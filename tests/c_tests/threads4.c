/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

#define THREAD_LOOP_COUNT 1000
#define NR_THREADS 4L
#define TIME_100MS 100000000UL

static void* threaded(void* param) {
  long k = (long)param;
  char buf[32];
  int n;

  n = snprintf(buf, 32, "%lu", k);

  for (int i = 0; i < THREAD_LOOP_COUNT; i++) {
    write(STDERR_FILENO, buf, n);
  }

  return 0;
}

int main(int argc, char* argv[]) {
  pthread_attr_t attr;
  pthread_t threadid[NR_THREADS];

  assert(pthread_attr_init(&attr) == 0);

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_create(&threadid[i], &attr, threaded, (void*)i) == 0);
  }

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_join(threadid[i], NULL) == 0);
  }

  assert(pthread_attr_destroy(&attr) == 0);

  return 0;
}
