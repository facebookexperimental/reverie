/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A forked child that attempts vfork after the session root has exited.

   The LiteInst hybrid deliberately refuses vfork because the vfork child
   shares its parent's memory until exec/_exit.  This fixture puts that
   refusal in a non-root task and delays it until after the root can reach its
   pre-join failure check.  The backend must still report the session failure
   after joining the child; reporting the root's zero exit would be a silent
   green. */
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
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
    /* Make the root's guest exit precede this task's refusal. */
    usleep(250000);
    pid_t grandchild = vfork();
    if (grandchild == 0) {
      _exit(0);
    }
    _exit(grandchild < 0 ? 11 : 0);
  }

  puts("fork-vfork-root-finished");
  return 0;
}
