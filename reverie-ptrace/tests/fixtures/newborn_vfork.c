/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A forked child that vforks a grandchild which exits at once.

   The LiteInst vfork refusal therefore runs in a non-root task, where the
   task's recorded failure reason decides at task exit whether it skips the
   tool's exit bookkeeping. The root waits for its child, so it is still
   running when that refusal is recorded. */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  pid_t child = fork();
  if (child < 0) {
    return 2;
  }
  if (child == 0) {
    pid_t grandchild = vfork();
    if (grandchild == 0) {
      _exit(0);
    }
    if (grandchild < 0) {
      _exit(3);
    }
    _exit(waitpid(grandchild, NULL, 0) == grandchild ? 0 : 4);
  }
  return waitpid(child, NULL, 0) == child ? 0 : 5;
}
