/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { VIRTUAL_IDENTITY_FD = 197 };

// TODO-HUMAN-REVIEW(PR-154): Review deferred DBT identity and private-fd policy.
int main(void) {
  long pid = syscall(SYS_getpid);
  long ppid = syscall(SYS_getppid);
  long tid = syscall(SYS_gettid);

  if (syscall(SYS_close, VIRTUAL_IDENTITY_FD) != 0)
    return 1;
  errno = 0;
  if (fcntl(VIRTUAL_IDENTITY_FD, F_GETFD) < 0)
    return 2;
  if (pid != 3 || ppid != 1 || tid != 3)
    return 3;

  printf("pid=%ld ppid=%ld tid=%ld identity_fd=open\n", pid, ppid, tid);
  return 0;
}
