/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Two threads in the same process both call `SYS_exit` (not group exit) with
// the main thread calling it first.

#include <errno.h>
// #include <limits.h>
#include <pthread.h>
// #include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
// #include <sys/types.h>
#include <unistd.h>

#define NTHREADS 8

// do `exit` syscall directly, avoid libc doing sth smart by replacing
// `_exit` with `exit_group`.
static void sys_exit(int code) {
  (void)syscall(SYS_exit, code);
}

// do futex wait with timeout 600s. 600s is to make sure it can timeout
// on sandcastle default configuration.
void* thread_fn(void* _param) {
  printf("Child thread, sleeping...\n");
  struct timespec tp = {0, 500000000};
  clock_nanosleep(CLOCK_MONOTONIC, 0, &tp, NULL);
  printf("Child thread, exiting...\n");
  sys_exit(0);
  return NULL;
}

int main(int argc, char* argv[], char* envp[]) {
  pthread_t child;
  if (pthread_create(&child, NULL, thread_fn, NULL) != 0) {
    fprintf(stderr, "pthread_create failed: %s\n", strerror(errno));
    abort();
  }
  printf("Parent thread, exiting...\n");
  sys_exit(0);
}
