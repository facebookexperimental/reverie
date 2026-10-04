/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static char** arguments;
static int blocked[2];
static _Atomic int worker_ready;

static void replace_image(void) {
  char* next[] = {arguments[0], "after", arguments[2], arguments[3], NULL};
  if (strcmp(arguments[1], "worker-execveat") == 0) {
    syscall(SYS_execveat, AT_FDCWD, next[0], next, environ, 0);
    _exit(19);
  }
  execv(next[0], next);
  _exit(20);
}

static void* worker(void* unused) {
  (void)unused;
  FILE* ids = fopen(arguments[2], "w");
  if (ids == NULL ||
      fprintf(ids, "%ld %ld\n", (long)getpid(), syscall(SYS_gettid)) < 0 ||
      fclose(ids) != 0) {
    _exit(21);
  }
  atomic_store_explicit(&worker_ready, 1, memory_order_release);
  if (strcmp(arguments[1], "worker") == 0 ||
      strcmp(arguments[1], "worker-execveat") == 0) {
    replace_image();
  }
  if (strcmp(arguments[1], "failed") == 0) {
    char missing[4096];
    int length = snprintf(missing, sizeof(missing), "%s.absent", arguments[0]);
    char* next[] = {missing, NULL};
    if (length <= 0 || (size_t)length >= sizeof(missing) ||
        syscall(SYS_getpid, 0x6e786578, 4, 0) != 0x4242) {
      _exit(24);
    }
    errno = 0;
    if (execve(missing, next, environ) != -1 || errno != ENOENT) {
      _exit(25);
    }
    errno = 0;
    if (syscall(SYS_execveat, AT_FDCWD, missing, next, environ, 0) != -1 ||
        errno != ENOENT || syscall(SYS_getpid, 0x6e786578, 4, 1) != 0x4242) {
      _exit(26);
    }
    return NULL;
  }
  /* The leader cannot join this thread before exec: nobody writes this pipe. */
  char byte;
  if (read(blocked[0], &byte, 1) != 0) {
    _exit(22);
  }
  _exit(23);
}

int main(int argc, char** argv) {
  if (argc != 4) {
    return 10;
  }
  if (strcmp(argv[1], "after") == 0) {
    int marker = open(argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker < 0 || write(marker, "entered\n", 8) != 8 ||
        close(marker) != 0) {
      return 11;
    }
    /* This must still reach the actual Tool after replacing a threaded image.
     */
    if (syscall(SYS_getpid, 0x6e786578, 4, 0) != 0x4242) {
      return 12;
    }
    puts("threaded-leader-exec-followed");
    return 0;
  }
  arguments = argv;
  if (pipe2(blocked, O_CLOEXEC) != 0) {
    return 13;
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0) {
    return 14;
  }
  if (strcmp(argv[1], "leader") == 0) {
    while (!atomic_load_explicit(&worker_ready, memory_order_acquire)) {
      syscall(SYS_sched_yield);
    }
    replace_image();
  }
  if (strcmp(argv[1], "failed") == 0) {
    if (pthread_join(thread, NULL) != 0) {
      return 18;
    }
    puts("worker-failed-exec-preserved");
    return 0;
  }
  if (strcmp(argv[1], "worker") != 0 &&
      strcmp(argv[1], "worker-execveat") != 0) {
    return 15;
  }
  /* A worker exec destroys this still-live leader. */
  char byte;
  return read(blocked[0], &byte, 1) == 0 ? 16 : 17;
}
