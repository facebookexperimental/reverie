/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Force blocked background threads to exit via exit_group().

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define NTHREADS 8

struct thread_param {
  int* sem;
  long thread_id;
};

static int futex(
    int* uaddr,
    int futex_op,
    int val,
    const struct timespec* timeout,
    int* uaddr2,
    int val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

// do futex wait with timeout 600s. 600s is to make sure it can timeout
// on sandcastle default configuration.
void* thread_pfn(void* param) {
  struct thread_param* tp = (struct thread_param*)param;
  struct timespec ts = {600, 0};

  futex(tp->sem, FUTEX_PRIVATE_FLAG | FUTEX_WAIT, 0, &ts, NULL, 0);
  _exit(0);
}

int main(int argc, char* argv[]) {
  void* page = mmap(
      NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == (void*)-1) {
    fprintf(stderr, "mmap failed: %s\n", strerror(errno));
    exit(1);
  }
  struct thread_param params[NTHREADS];
  pthread_t threads[NTHREADS];
  for (int i = 0; i < NTHREADS; i++) {
    params[i].sem = (int*)page;
    params[i].thread_id = (long)i;

    if (pthread_create(&threads[i], NULL, thread_pfn, (void*)&params[i]) != 0) {
      fprintf(
          stderr,
          "pthread_create to create thread #%d failed: %s\n",
          i,
          strerror(errno));
      abort();
    }
  }

  struct timespec tp = {1, 0};
  clock_nanosleep(CLOCK_MONOTONIC, 0, &tp, NULL);

  // do SYS_exit_group. All threads should be still blocked by mutex.
  // SYS_exit_group should force all threads begin to exit.
  syscall(SYS_exit_group, 0);
}
