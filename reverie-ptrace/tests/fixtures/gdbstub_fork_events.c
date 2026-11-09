/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A guest that makes two vforks and then a fork. Each child runs in_child(),
 * which the tests can break on, and exits with what it returns; main checks
 * every child's exit status, and then calls in_child() itself. It exits 0
 * only if every child exited as expected.
 */

#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) int in_child(int x) {
  return x * 2 + 1;
}

static int reaped_as(pid_t pid, int expected) {
  int status = 0;
  return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
      WEXITSTATUS(status) == expected;
}

int main(void) {
  int failures = 0;
  for (int i = 0; i < 2; i++) {
    pid_t pid = vfork();
    if (pid == 0) {
      _exit(in_child(i));
    }
    failures += !reaped_as(pid, i * 2 + 1);
  }
  pid_t pid = fork();
  if (pid == 0) {
    _exit(in_child(5));
  }
  failures += !reaped_as(pid, 11);
  return failures == 0 && in_child(100) == 201 ? 0 : 1;
}
