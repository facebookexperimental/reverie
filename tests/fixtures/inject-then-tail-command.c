/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

#include <assert.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  const long tid = syscall(SYS_gettid);
  const long pid = syscall(SYS_getpid);
  const long gid = syscall(SYS_getgid);
  const long ppid = syscall(SYS_getppid);
  const long pgid = syscall(SYS_getpgid, 0);
  const long sid = syscall(SYS_getsid, 0);
  assert(tid > 0);
  assert(pid > 0);
  assert(gid >= 0);
  assert(ppid >= 0);
  assert(pgid > 0);
  assert(sid > 0);

  unsigned char random_bytes[8] = {0};
  assert(syscall(SYS_getrandom, random_bytes, sizeof(random_bytes), 0) ==
         (long)sizeof(random_bytes));
  static const char marker[] = "inject-then-tail=ok\n";
  assert(write(STDOUT_FILENO, marker, sizeof(marker) - 1) ==
         (ssize_t)(sizeof(marker) - 1));
  return 0;
}
