/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A timed wait while single-threaded, then another after pthread_create
   (https://github.com/rrnewton/reverie/issues/812).

   glibc's timed futex wait has two `syscall` instructions. In glibc 2.34's
   __futex_abstimed_wait_common the single-threaded path's `syscall` is at
   libc+0x884c7, and the multithreaded path ends with `jmp 884c9`, to the
   instruction after it. The first wait reaches the single-threaded site. If
   LiteInst patched it, the second wait's jump would land inside the patch and
   the guest would die of SIGSEGV. Nothing posts the semaphore, so both waits
   must time out. */
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static sem_t never_posted;

static int wait_times_out(long milliseconds) {
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
    return 0;
  }
  deadline.tv_nsec += milliseconds * 1000000L;
  deadline.tv_sec += deadline.tv_nsec / 1000000000L;
  deadline.tv_nsec %= 1000000000L;
  int result;
  do {
    result = sem_timedwait(&never_posted, &deadline);
  } while (result != 0 && errno == EINTR);
  return result == -1 && errno == ETIMEDOUT;
}

static void* sleeper(void* unused) {
  (void)unused;
  usleep(50000);
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
  if (sem_init(&never_posted, 0, 0) != 0) {
    return 10;
  }
  if (!wait_times_out(10)) {
    return 11;
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, sleeper, NULL) != 0) {
    return 12;
  }
  if (!wait_times_out(20)) {
    return 13;
  }
  if (pthread_join(thread, NULL) != 0) {
    return 14;
  }
  puts("timed-waits-timed-out");
  return 0;
}
