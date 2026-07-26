/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_barrier_t exit_barrier;

static void *exit_worker(void *argument) {
  (void)argument;
  (void)pthread_barrier_wait(&exit_barrier);
  (void)syscall(SYS_exit_group, 0);
  return NULL;
}

// TODO-HUMAN-REVIEW(PR-154): Review concurrent exit_group lifecycle election.
int main(void) {
  pthread_t worker;

  if (pthread_barrier_init(&exit_barrier, NULL, 2) != 0)
    return 1;
  if (pthread_create(&worker, NULL, exit_worker, NULL) != 0)
    return 2;
  (void)pthread_barrier_wait(&exit_barrier);
  (void)syscall(SYS_exit_group, 0);
  return 3;
}
