/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static void *stay_alive(void *unused) {
  (void)unused;
  for (;;)
    pause();
  return NULL;
}

int main(int argc, char **argv) {
  assert(argc == 2);
  int log = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0600);
  assert(log >= 0);
  int ready[2];
  assert(pipe(ready) == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    close(ready[0]);
    for (int depth = 0; depth < 3; ++depth) {
      assert(setsid() > 0);
      char pid[32];
      int len = snprintf(pid, sizeof(pid), "%d\n", getpid());
      assert(write(log, pid, len) == len);
      if (depth == 2) {
        // A zombie group leader with a live thread is not yet waitable.
        pthread_t thread;
        assert(pthread_create(&thread, NULL, stay_alive, NULL) == 0);
        assert(write(ready[1], "R", 1) == 1);
        pthread_exit(NULL);
      }
      pid_t next = fork();
      assert(next >= 0);
      if (next != 0)
        break;
    }
    for (;;)
      pause();
  }
  close(ready[1]);
  char byte;
  assert(read(ready[0], &byte, 1) == 1 && byte == 'R');
  // All three generations are live in separate sessions before the root
  // exits. Each later orphan is adopted only after its parent is killed.
  return 37;
}
