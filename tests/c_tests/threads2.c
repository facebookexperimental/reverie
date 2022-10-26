/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

#define NR_THREADS 8L
#define TIME_100MS 100000000UL

#define THREAD_SHARED_HEAP 0x67000000L

static void test_clock_nanosleep(unsigned long ns) {
  struct timespec req = {
      .tv_sec = 0,
      .tv_nsec = ns,
  };
  struct timespec rem;
  int ret;

  do {
    ret = clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);
    memcpy(&req, &rem, sizeof(req));
  } while (ret != 0 && errno == EINTR);
}

static void* threaded_0(void* param) {
  long k = (long)param;
  char buf[128];
  int n;

  n = snprintf(buf, 128, "thread %ld enter.\n", k);
  write(STDOUT_FILENO, buf, n);

  long* p = mmap(
      (void*)THREAD_SHARED_HEAP,
      0x2000,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0);

  assert((void*)p == (void*)THREAD_SHARED_HEAP);

  p[k] = pthread_self();

  test_clock_nanosleep(TIME_100MS);

  n = snprintf(buf, 128, "thread %ld exit.\n", k);
  write(STDOUT_FILENO, buf, n);

  return 0;
}

static void* threaded(void* param) {
  long k = (long)param;
  long* ptr = (long*)THREAD_SHARED_HEAP;
  char buf[128];
  int n;

  n = snprintf(buf, 128, "thread %ld enter.\n", k);
  write(STDOUT_FILENO, buf, n);

  ptr[k] = pthread_self();

  test_clock_nanosleep(TIME_100MS);

  n = snprintf(buf, 128, "thread %ld exit.\n", k);
  write(STDOUT_FILENO, buf, n);

  return 0;
}

int main(int argc, char* argv[]) {
  char buf[128];
  int n;
  // sleep in a non-threpaded context
  test_clock_nanosleep(TIME_100MS);

  pthread_attr_t attr;
  pthread_t threadid[NR_THREADS];
  long* ptr = (long*)THREAD_SHARED_HEAP;

  assert(pthread_attr_init(&attr) == 0);

  long i = 0;
  assert(pthread_create(&threadid[i], &attr, threaded_0, (void*)i) == 0);
  pthread_join(threadid[i], NULL);

  for (i = 1; i < NR_THREADS; i++) {
    assert(pthread_create(&threadid[i], &attr, threaded, (void*)i) == 0);
  }

  for (i = 1; i < NR_THREADS; i++) {
    assert(pthread_join(threadid[i], NULL) == 0);
  }

  assert(pthread_attr_destroy(&attr) == 0);

  for (i = 0; i < NR_THREADS; i++) {
    n = snprintf(buf, 128, "threads data: %lx\n", ptr[i]);
    write(STDOUT_FILENO, buf, n);
  }

  return 0;
}
