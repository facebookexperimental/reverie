/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Regression fixture for native virtual-clock and virtual-resource
 * virtualization in copied (forked) DBT children.
 *
 * The DynamoRIO backend runs the Reverie Tool runtime only in the root of the
 * traced tree; copied/forked children are served entirely by the native-only
 * path. Before this fixture's fix, that path applied only identity
 * virtualization, so a forked child read real host time and real host rlimits
 * while the root process saw the deterministic native virtual clock and virtual
 * limits. This fixture forks a child, has it issue raw clock_gettime and
 * prlimit64 syscalls (raw so no libc/vDSO fast path can hide them), and prints
 * both the child's and the root's observations so the harness can assert the
 * child now matches the root's virtualized view:
 *
 *   - Virtual CLOCK_MONOTONIC starts at a 1-second base and advances a
 *     microsecond per read, so tv_sec stays a small single digit; the real host
 *     monotonic clock (uptime) is orders of magnitude larger.
 *   - Virtual RLIMIT_NOFILE is 1048576, distinct from a typical host soft limit.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// TODO-HUMAN-REVIEW(PR-ratchet12): Review the copied-child clock/resource probe.
static void probe(const char *who) {
  struct timespec ts = {0, 0};
  struct rlimit rl = {0, 0};
  // Raw syscalls: prlimit64(pid=0 -> current, RLIMIT_NOFILE, new=NULL, old=&rl).
  (void)syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
  (void)syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, (void *)0, &rl);
  printf("%s_mono_sec=%lld\n", who, (long long)ts.tv_sec);
  printf("%s_nofile=%llu\n", who, (unsigned long long)rl.rlim_cur);
  fflush(stdout);
}

int main(void) {
  pid_t child = fork();
  if (child < 0)
    return 1;
  if (child == 0) {
    probe("child");
    // _exit so the inherited stdio buffer is not flushed twice.
    syscall(SYS_exit, 0);
  }

  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0)
    return 2;

  probe("parent");
  return 0;
}
