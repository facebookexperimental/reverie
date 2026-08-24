/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int invalid_process_clone(void) {
  errno = 0;
  long result = syscall(SYS_clone, CLONE_SIGHAND | SIGCHLD, 0, 0, 0, 0);
  return result == -1 && errno == EINVAL;
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;

  if (strcmp(argv[1], "injected") == 0) {
    (void)syscall(SYS_getuid);
    (void)syscall(SYS_getpid);
    puts("injected-clone-latch-ok");
    return 0;
  }

  if (!invalid_process_clone())
    return 3;

#ifdef SYS_clone3
  if (strcmp(argv[1], "clone3") == 0) {
    (void)syscall(SYS_clone3, NULL, 0);
    __builtin_trap();
  }
#endif

  if (strcmp(argv[1], "suppressed") == 0) {
    (void)syscall(SYS_getpid);
    __builtin_trap();
  }

  if (strcmp(argv[1], "deferred") == 0) {
    (void)syscall(SYS_getuid);
    __builtin_trap();
  }

  return 5;
}
