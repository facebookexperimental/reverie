/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A second thread via pthread_create (clone3 with CLONE_THREAD). The new task
   resumes at the instruction after the two-byte `syscall`, so this also covers
   the rule that a task-creating syscall site is never patched: a relocating
   jump at that site leaves the address mid-instruction and the new thread
   faults immediately. */
#include <pthread.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

static int ran;

static void* body(void* unused) {
  (void)unused;
  ran = 1;
  return NULL;
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
  pthread_t thread;
  if (pthread_create(&thread, NULL, body, NULL) != 0) {
    return 10;
  }
  if (pthread_join(thread, NULL) != 0) {
    return 11;
  }
  if (ran != 1) {
    return 12;
  }
  puts("thread-followed");
  return 0;
}
