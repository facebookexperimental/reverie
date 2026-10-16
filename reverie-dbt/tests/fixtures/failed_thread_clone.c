/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "kernel_task_identity.h"

static kernel_task_identity_t kernel;

static void* observe_identity(void* argument) {
  pid_t* observed = argument;
  *observed = (pid_t)syscall(SYS_gettid);
  kernel = kernel_task_identity();
  return NULL;
}

int main(void) {
  pid_t observed = 0;
  pthread_t thread;

  /* CLONE_THREAD without CLONE_SIGHAND must fail before creating a child. */
  errno = 0;
  if (syscall(SYS_clone, CLONE_THREAD, NULL, NULL, NULL, 0) != -1 ||
      errno != EINVAL)
    return 1;
  if (pthread_create(&thread, NULL, observe_identity, &observed) != 0)
    return 2;
  if (pthread_join(thread, NULL) != 0)
    return 3;
  if (observed != kernel.tid || kernel.pid != (pid_t)syscall(SYS_getpid) ||
      observed <= 0 || observed == kernel.pid)
    return 4;

  puts("failed-thread-clone=ok");
  return 0;
}
