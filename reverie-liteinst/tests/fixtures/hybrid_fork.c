/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
    _exit(0);
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child) {
    return 11;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return 12;
  }
  /* Printed only after the child has been created, run and reaped, so a run
     that never forked cannot satisfy the assertion by exiting zero. */
  puts("fork-followed");
  return 0;
}
