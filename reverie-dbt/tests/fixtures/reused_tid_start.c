/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "kernel_task_identity.h"

typedef struct {
  pid_t pid;
  pid_t tid;
  kernel_task_identity_t kernel;
} observed_identity_t;

static void* observe_identity(void* argument) {
  observed_identity_t* observed = argument;
  observed->pid = (pid_t)syscall(SYS_getpid);
  observed->tid = (pid_t)syscall(SYS_gettid);
  observed->kernel = kernel_task_identity();
  return NULL;
}

int main(void) {
  observed_identity_t observed = {0};
  pthread_t thread;

  if (pthread_create(&thread, NULL, observe_identity, &observed) != 0)
    return 1;
  if (pthread_join(thread, NULL) != 0)
    return 2;
  if (observed.pid != (pid_t)syscall(SYS_getpid) ||
      observed.pid != observed.kernel.pid || observed.tid != observed.kernel.tid ||
      observed.tid <= 0 || observed.tid == observed.pid)
    return 3;

  puts("reused-tid-start=ok");
  return 0;
}
