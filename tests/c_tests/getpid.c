/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  pid_t pid = getpid();
  printf("    my pid = %d\n", pid);
  printf("    my ppid = %d\n", getppid());
  printf("    my uid = %d\n", getuid());
  printf("    my gid = %d\n", getgid());
  printf("    my sid = %d\n", getsid(pid));

  exit(0); // Since glibc 2.3 this calls SYS_exit_group
}
