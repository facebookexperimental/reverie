/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* SetRegTool executes each query once through Guest::inject, comparing it with
 * a raw kernel sample taken on the same application callback thread, and with
 * Guest::pid/tid for those two queries. Guest::ppid has separate root semantics.
 * These
 * requests do not enter the separate completed-Tool sentinel getter branches.
 */
static volatile sig_atomic_t validation_handled;
static void validation_handler(int signal) { (void)signal; ++validation_handled; }

static int validation_control(void) {
  struct sigaction action = {.sa_handler = validation_handler};
  sigemptyset(&action.sa_mask);
  sigset_t block, old, pending, current, temporary;
  sigemptyset(&block); sigaddset(&block, SIGCHLD); sigemptyset(&temporary);
  if (sigaction(SIGCHLD, &action, NULL) || sigprocmask(SIG_BLOCK, &block, &old)) return 2;
  long pid = prctl(0x4b494421, SYS_getpid, 0L, 0L, 0L);
  if (pid <= 0 || kill((pid_t)pid, SIGCHLD)) return 3;
  if (sigpending(&pending) || sigismember(&pending, SIGCHLD) != 1 || validation_handled) return 4;
  const struct { const void *mask; size_t bytes; } wrapper = { &temporary, sizeof(uint64_t) };
  struct timespec malformed = { .tv_sec = 0, .tv_nsec = 1000000000 };
  if (prctl(0x50535631, &wrapper, &malformed, &validation_handled, 0L)) return 5;
  if (sigpending(&pending) || sigprocmask(SIG_SETMASK, NULL, &current) ||
      sigismember(&pending, SIGCHLD) != 0 || sigismember(&current, SIGCHLD) != 1 ||
      validation_handled != 1 || malformed.tv_sec != 0 || malformed.tv_nsec != 1000000000 ||
      wrapper.mask != &temporary || wrapper.bytes != sizeof(uint64_t)) return 6;
  if (sigprocmask(SIG_SETMASK, &old, NULL) || validation_handled != 1) return 7;
  puts("returning-pselect-validation=ok");
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "pselect-validation")) return validation_control();
  if (argc != 1) return 2;
  const long queries[] = {SYS_getpid, SYS_getppid, SYS_gettid};
  int failed = 0;
  for (unsigned int i = 0; i < sizeof(queries) / sizeof(queries[0]); ++i) {
    if (prctl(0x4b494421, queries[i], 0L, 0L, 0L) <= 0)
      failed = 1;
  }
  if (failed) {
    fputs("kernel identity injection mismatch\n", stderr);
    return 1;
  }
  puts("kernel-identity-inject=ok");
  return 0;
}
