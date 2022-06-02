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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

#define NR_THREADS 5L
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

  printf("thread %ld enter. allocating with mmap\n", k);

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

  printf("thread %ld exit.\n", k);

  return 0;
}

static void* threaded(void* param) {
  long k = (long)param;
  long* ptr = (long*)THREAD_SHARED_HEAP;

  pid_t tid = syscall(SYS_gettid);
  pid_t pid = getpid();
  pid_t ppid = getppid();
  pid_t pgid = getpgid(0);

  printf(
      "self: %lx thread %05ld (tid=%u, pid=%u, ppid=%u, pgid=%u) enter.\n",
      pthread_self(),
      k,
      tid,
      pid,
      ppid,
      pgid);

  ptr[k] = pthread_self();

  test_clock_nanosleep(TIME_100MS);

  printf(
      "self: %lx thread %05ld (tid=%u, pid=%u, ppid=%u, pgid=%u) exit.\n",
      pthread_self(),
      k,
      tid,
      pid,
      ppid,
      pgid);

  return 0;
}

static void thread_test_0(void) {
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
    printf("%lu threads data: %lx\n", i, ptr[i]);
  }
  assert(ptr[100] == 0);
}

static void thread_test_1(void) {
  // sleep in a non-threpaded context
  test_clock_nanosleep(TIME_100MS);

  pthread_attr_t attr;
  pthread_t threadid[NR_THREADS];
  long* ptr = (long*)THREAD_SHARED_HEAP;

  assert(pthread_attr_init(&attr) == 0);

  long i = 0;
  assert(
      pthread_create(&threadid[i], &attr, threaded_0, (void*)(100 + i)) == 0);
  pthread_join(threadid[i], NULL);

  for (i = 1; i < NR_THREADS; i++) {
    assert(
        pthread_create(&threadid[i], &attr, threaded, (void*)(100 + i)) == 0);
  }

  for (i = 1; i < NR_THREADS; i++) {
    assert(pthread_join(threadid[i], NULL) == 0);
  }

  assert(pthread_attr_destroy(&attr) == 0);

  for (i = 0; i < NR_THREADS; i++) {
    printf("%lu threads data: %lx\n", 100 + i, ptr[100 + i]);
  }
  assert(ptr[0] == 0);
}

int main(int argc, char* argv[]) {
  pid_t pid;

  pid = fork();

  if (pid < 0) {
    perror("fork");
    exit(1);
  } else if (pid == 0) { /* child */
    printf("child pid: %u, parent: %u\n", getpid(), getppid());
    thread_test_0();
  } else {
    int status;
    printf("parent pid: %u, parent: %u\n", getpid(), getppid());
    thread_test_1();

    // wait for SIGCHLD
    waitpid(pid, &status, 0);
  }

  return 0;
}
