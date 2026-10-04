/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A forked child execs with the inherited preload by default. The explicit
   drop-preload mode preserves the session-failure and pending-exit cleanup
   controls using an image that really cannot activate the required runtime. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if ((argc != 3 && argc != 4) || prctl(PR_SET_NAME, argv[1], 0, 0, 0) != 0) {
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
    if (argc == 4 && strcmp(argv[3], "drop-preload") == 0 &&
        unsetenv("LD_PRELOAD") != 0) {
      _exit(126);
    }
    execl("/bin/true", "true", (char*)NULL);
    _exit(127);
  }
  int status = 0;
  (void)waitpid(child, &status, 0);
  puts("fork-exec-root-finished");
  return 0;
}
