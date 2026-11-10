/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A precise timer event with gdb breakpoints near it. timed_loop() asks the
 * test's Tool for an event `rcbs` conditional branches ahead with
 * clock_getres(rcbs, 0), then runs a loop of `iterations` iterations whose one
 * conditional branch is the `jnz` at reverie_bkpt_branch. No conditional
 * branch lies between the syscall and the loop, so the event is due right
 * after the loop's `rcbs`-th `jnz`: at reverie_timer_loop, with
 * `iterations - rcbs` in %rcx.
 *
 * reverie_bkpt_scheduled, between the syscall and the loop, is passed once,
 * right after the request. reverie_bkpt_branch is passed on every iteration.
 *
 * A third argument picks where timed_loop() runs:
 * - `pair`: in the main thread, while a second thread first calls getppid,
 *   whose Tool callback waits until the main thread's timer callback has
 *   begun, then passes reverie_bkpt_other, then calls getpid, whose callback
 *   lets the main thread's timer callback return.
 * - `fork` or `vfork`: in a child made by fork or vfork, which then exits 0;
 *   main exits 0 if the child did.
 *
 * The labels are global symbols. The test builds this file with -no-pie, so
 * their symbol values are their run-time addresses.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void* other(void* arg) {
  syscall(SYS_getppid);
  __asm__ volatile(
      ".globl reverie_bkpt_other\n"
      "reverie_bkpt_other:\n"
      "  .byte 0x0f, 0x1f, 0x00\n" /* nopl (%rax) */
  );
  syscall(SYS_getpid);
  return arg;
}

__attribute__((noinline)) static void timed_loop(
    unsigned long rcbs,
    unsigned long iterations) {
  long nr = SYS_clock_getres;
  __asm__ volatile(
      "  syscall\n"
      ".globl reverie_bkpt_scheduled\n"
      "reverie_bkpt_scheduled:\n"
      "  .byte 0x0f, 0x1f, 0x00\n" /* nopl (%rax) */
      "  mov %[iterations], %%rcx\n"
      ".globl reverie_timer_loop\n"
      "reverie_timer_loop:\n"
      "  dec %%rcx\n"
      ".globl reverie_bkpt_branch\n"
      "reverie_bkpt_branch:\n"
      "  jnz reverie_timer_loop\n"
      : "+a"(nr)
      : "D"(rcbs), "S"(0UL), [iterations] "r"(iterations)
      : "rcx", "r11", "cc", "memory");
}

static int child_exited_zero(pid_t pid) {
  int status = 0;
  return pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
      WEXITSTATUS(status) == 0;
}

int main(int argc, char** argv) {
  if (argc != 3 && argc != 4) {
    return 2;
  }
  unsigned long rcbs = strtoul(argv[1], NULL, 0);
  unsigned long iterations = strtoul(argv[2], NULL, 0);
  const char* mode = argc == 4 ? argv[3] : "";
  if (strcmp(mode, "fork") == 0) {
    pid_t pid = fork();
    if (pid == 0) {
      timed_loop(rcbs, iterations);
      _exit(0);
    }
    return child_exited_zero(pid) ? 0 : 1;
  }
  if (strcmp(mode, "vfork") == 0) {
    pid_t pid = vfork();
    if (pid == 0) {
      timed_loop(rcbs, iterations);
      _exit(0);
    }
    return child_exited_zero(pid) ? 0 : 1;
  }
  pthread_t thread;
  int pair = strcmp(mode, "pair") == 0;
  if (!pair && argc == 4) {
    return 2;
  }
  if (pair && pthread_create(&thread, NULL, other, NULL) != 0) {
    return 1;
  }
  timed_loop(rcbs, iterations);
  if (pair && pthread_join(thread, NULL) != 0) {
    return 1;
  }
  return 0;
}
