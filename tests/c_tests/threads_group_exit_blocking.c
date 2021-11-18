/*
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 *  All rights reserved.
 */

// create `NTHREADS`, all doing (indefinite) blocking futexes, while the thread
// group leader calling `SYS_exit_group`.
// This is to test all blocking futex syscall can be interrupted, and all
// threads can exit gracefully under `SYS_exit_group`.

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define NTHREADS 8

static _Atomic unsigned long counter;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* thread_pfn(void* param) {
  atomic_fetch_add(&counter, 1);

  // Wait for enough time such that the main thread can kill this thread via
  // `exit_group`.
  pthread_mutex_lock(&mutex);

  return NULL;
}

int main(int argc, char* argv[], char* envp[]) {
  // Lock, but never unlock the mutex to force all threads to wait. All threads
  // will get killed while waiting for for this mutex.
  pthread_mutex_lock(&mutex);

  pthread_t threads[NTHREADS];

  for (int i = 0; i < NTHREADS; i++) {
    if (pthread_create(&threads[i], NULL, thread_pfn, NULL) != 0) {
      fprintf(
          stderr,
          "pthread_create to create thread #%d failed: %s\n",
          i,
          strerror(errno));
      abort();
    }
  }

  // Spin while we wait for the threads to finish initializing.
  while (atomic_load(&counter) != NTHREADS) {
    // Yield so that other threads have a chance to run.
    sched_yield();
  }

  // do SYS_exit_group. All threads should be still blocked by mutex.
  // SYS_exit_group should force all threads begin to exit.
  syscall(SYS_exit_group, 0);

  return 0;
}
