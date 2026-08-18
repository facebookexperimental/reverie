/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Regression fixture: hit a breakpoint while sibling threads are blocked in a
 * syscall, then resume and require the whole program to finish.
 *
 * The gdbserver freezes the other threads around a breakpoint stop so gdb sees
 * a consistent picture. Those threads have to be released when gdb resumes,
 * not after the resumed thread next stops -- here the resumed thread blocks in
 * pthread_join on exactly the threads that are frozen, so releasing them late
 * deadlocks the guest and gdb waits forever for a reply.
 *
 * manyThreads.c does not cover this: its only breakpoint hit on the main
 * thread happens before any thread is created, so there is never a frozen
 * sibling to release.
 *
 * Expected under gdb, with `break bkpt; continue; delete breakpoints;
 * continue`: prints "done 43" and exits 0.
 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define NR_THREADS 2

volatile int global = 42;
static int pipefd[2];

// Blocks until main writes, so the thread is inside a syscall when the
// breakpoint below is hit.
static void* worker(void* arg) {
  char c;
  ssize_t n = read(pipefd[0], &c, 1);
  (void)arg;
  (void)n;
  return 0;
}

__attribute__((noinline)) void bkpt(void) {}

int main(void) {
  pthread_t threads[NR_THREADS];

  setvbuf(stdout, NULL, _IOLBF, 0);
  if (pipe(pipefd) != 0) {
    return 1;
  }
  for (int i = 0; i < NR_THREADS; i++) {
    if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
      return 1;
    }
  }

  // Give both workers time to reach their blocking read.
  sleep(1);

  bkpt();

  global = 43;
  if (write(pipefd[1], "xx", NR_THREADS) != NR_THREADS) {
    return 1;
  }
  for (int i = 0; i < NR_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }

  printf("done %d\n", global);
  return 0;
}
