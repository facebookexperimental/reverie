/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A guest that never stops on its own, for GDB's interrupt. A second thread
 * makes system calls until `reverie_stop_worker` is set, which only GDB does.
 * Meanwhile the main thread calls getppid(), which one of the interrupt tests'
 * Tools holds until the test lets it go; it then waits for the second thread
 * and exits 0.
 *
 * The test builds this file with -no-pie, so the symbol value of
 * `reverie_stop_worker` is its run-time address.
 */

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile int reverie_stop_worker;

static void* worker(void* arg) {
  while (!reverie_stop_worker) {
    syscall(SYS_getpid);
  }
  return arg;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) {
    return 2;
  }
  syscall(SYS_getppid);
  if (pthread_join(thread, 0) != 0) {
    return 3;
  }
  return 0;
}
