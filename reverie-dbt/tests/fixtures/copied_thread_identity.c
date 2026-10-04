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
#include <sys/wait.h>
#include <unistd.h>

static long observed;

static void* observe_identity(void* unused) {
  (void)unused;
  observed = syscall(SYS_gettid);
  return NULL;
}

int main(void) {
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (child == 0) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, observe_identity, NULL) != 0)
      return 2;
    if (pthread_join(thread, NULL) != 0)
      return 3;
    if (syscall(SYS_getpid) != 4 || observed != 5)
      return 4;
    puts("copied-thread-identity=ok pid=4 tid=5");
    return 0;
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
    return 5;
  return WEXITSTATUS(status);
}
