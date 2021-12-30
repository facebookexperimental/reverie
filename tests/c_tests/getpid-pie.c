/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* must build with flags -pie -fPIE -O */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * 0000000000000740 <sys_getpid>:
 * 740:   b8 27 00 00 00          mov    $0x27,%eax
 * 745:   0f 05                   syscall
 * 747:   c3                      retq
 * 748:   0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
 * 74f:   00
 */
__attribute__((noinline)) static int sys_getpid(void) {
  int ret;
  asm volatile(
      "mov $0x27, %%eax\n\t"
      "syscall\n\t"
      : "=r"(ret));
  return ret;
}

int main(int argc, char* argv[]) {
  int pid0 = getpid();
  int pid = sys_getpid();
  printf("pid = %d\n", pid);
  if (pid0 != pid)
    abort();

  return 0;
}
