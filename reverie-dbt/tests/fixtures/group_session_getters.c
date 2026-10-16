/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int returning;

static long query(long number, long target) {
  if (returning)
    return prctl(0x4b494421, number, target, 0L, 0L);
  return syscall(number, target);
}

int main(int argc, char** argv) {
  if (argc != 6)
    return 2;
  returning = strcmp(argv[1], "returning") == 0;
  long target = strtol(argv[2], NULL, 10);
  long expected[] = {strtol(argv[3], NULL, 10), strtol(argv[4], NULL, 10),
                     strtol(argv[5], NULL, 10)};
  long me = returning ? prctl(0x4b494421, (long)SYS_getpid, 0L, 0L, 0L) : getpid();
  if (me <= 0 || target <= 0 || target == me)
    return 3;

  const long numbers[] = {SYS_getpgid, SYS_getsid, SYS_sched_getscheduler};
  const char* names[] = {"getpgid", "getsid", "sched_getscheduler"};
  int failed = 0;
  for (unsigned int i = 0; i < 3; ++i) {
    errno = 0;
    long live = query(numbers[i], target);
    int live_errno = errno;
    printf("%s live=%ld errno=%d\n", names[i], live, live_errno);
    failed |= live != expected[i] || live_errno != 0;

    long zero = query(numbers[i], 0);
    long self = query(numbers[i], me);
    int zero_is_self = zero >= 0 && zero == self;
    printf("%s zero-is-self=%d\n", names[i], zero_is_self);
    failed |= !zero_is_self;
    // The held child has a different group, session and scheduling policy.
    // Substituting target 0 must not satisfy the positive-target oracle.
    failed |= zero == expected[i];

    const long invalid[] = {-1, INT_MAX};
    const char* labels[] = {"negative", "absent"};
    for (unsigned int j = 0; j < 2; ++j) {
      errno = 0;
      long rc = query(numbers[i], invalid[j]);
      int error = errno;
      printf("%s %s rc=%ld errno=%d\n", names[i], labels[j], rc, error);
      int expected_error = numbers[i] == SYS_sched_getscheduler && j == 0
                               ? EINVAL
                               : ESRCH;
      failed |= rc != -1 || error != expected_error;
    }
  }
  if (failed)
    return 1;
  puts("group-session-getters=ok");
  return 0;
}
