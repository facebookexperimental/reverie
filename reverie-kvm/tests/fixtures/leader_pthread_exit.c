/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
static _Atomic int leader_tid, first_tid, second_tid;
static int mode;
static void await_exit(_Atomic int* word) {
  for (;;) {
    int tid = atomic_load(word);
    if (!tid) {
      /* Pass on the single clear-TID wake to another waiter. */
      if (syscall(SYS_futex, word, FUTEX_WAKE, 1, 0, 0, 0) < 0)
        syscall(SYS_exit_group, 91);
      return;
    }
    long result = syscall(SYS_futex, word, FUTEX_WAIT, tid, 0, 0, 0);
    if (result && errno != EAGAIN && errno != EINTR)
      syscall(SYS_exit_group, 91);
  }
}
static void set_clear_tid(_Atomic int* word) {
  int tid = syscall(SYS_set_tid_address, word);
  if (tid <= 0)
    syscall(SYS_exit_group, 92);
  atomic_store(word, tid);
}
static void marker(void) {
  static const char message[] = "worker continued after leader exit\n";
  if (write(1, message, sizeof(message) - 1) != sizeof(message) - 1)
    syscall(SYS_exit_group, 93);
}
static void* nested(void* unused) {
  (void)unused;
  await_exit(&first_tid);
  marker();
  syscall(SYS_exit, 73);
  __builtin_unreachable();
}
static void* first(void* unused) {
  (void)unused;
  set_clear_tid(&first_tid);
  if (mode == 3)
    syscall(SYS_exit, 61);
  await_exit(&leader_tid);
  if (mode == 4) {
    syscall(SYS_getpid);
    for (;;)
      syscall(SYS_sched_yield);
  }
  if (mode == 1) {
    pthread_t thread;
    if (pthread_create(&thread, 0, nested, 0))
      syscall(SYS_exit_group, 94);
    syscall(SYS_exit, 61);
  }
  if (mode == 2) {
    await_exit(&second_tid);
    syscall(SYS_getpid); /* The Tool also orders the two exit hooks here. */
  }
  marker();
  syscall(SYS_exit, 73);
  __builtin_unreachable();
}
static void* second(void* unused) {
  (void)unused;
  set_clear_tid(&second_tid);
  await_exit(&leader_tid);
  if (mode == 4)
    syscall(SYS_getppid);
  syscall(SYS_exit, 61);
  __builtin_unreachable();
}
int main(int argc, char** argv) {
  if (argc != 2)
    return 95;
  mode = atoi(argv[1]);
  set_clear_tid(&leader_tid);
  atomic_store(&first_tid, -1);
  atomic_store(&second_tid, -1);
  pthread_t thread;
  if (pthread_create(&thread, 0, first, 0))
    return 96;
  if ((mode == 2 || mode == 4) && pthread_create(&thread, 0, second, 0))
    return 97;
  if (mode == 3) {
    await_exit(&first_tid);
    execl(argv[0], argv[0], "0", (char*)0);
    return 98;
  }
  if (mode == 0)
    pthread_exit(0);
  syscall(SYS_exit, 37);
  __builtin_unreachable();
}
