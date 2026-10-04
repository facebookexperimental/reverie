/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Two generations of children: the root forks a child, and that child forks a
   grandchild. The grandchild's PTRACE_EVENT_FORK is reported to a NON-ROOT
   parent, which is the case that the LiteInst cleanup guard's newborn
   registration has to cover; registering newborns only for the root leaves the
   grandchild unregistered and `handle_new_task` aborts on it. */
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int reap(pid_t child) {
  int status = 0;
  if (waitpid(child, &status, 0) != child) {
    return 0;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(int argc, char** argv) {
  if (argc != 3 || prctl(PR_SET_NAME, argv[1], 0, 0, 0) != 0) {
    return 9;
  }
  FILE* pid_file = fopen(argv[2], "w");
  if (pid_file == NULL) {
    return 8;
  }
  fprintf(pid_file, "%ld\n", (long)getpid());
  if (fclose(pid_file) != 0) {
    return 7;
  }
  pid_t child = fork();
  if (child < 0) {
    return 10;
  }
  if (child == 0) {
    pid_t grandchild = fork();
    if (grandchild < 0) {
      _exit(11);
    }
    if (grandchild == 0) {
      _exit(0);
    }
    _exit(reap(grandchild) ? 0 : 12);
  }
  if (!reap(child)) {
    return 13;
  }
  puts("fork-tree-followed");
  return 0;
}
