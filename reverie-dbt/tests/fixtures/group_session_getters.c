/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(struct sched_param) == 4, "x86_64 sched_param oracle");

static int returning;

static long query(long number, long target) {
  if (returning)
    return prctl(0x4b494421, number, target, 0L, 0L);
  return syscall(number, target);
}

static long priority_query(long which, long who) {
  if (returning)
    return prctl(0x4b494421, (long)SYS_getpriority, which, who, 0L);
  return syscall(SYS_getpriority, which, who);
}

static long parameter_query(long target, struct sched_param* parameter) {
  if (returning)
    return prctl(0x4b494421, (long)SYS_sched_getparam, target, (long)parameter, 0L);
  return syscall(SYS_sched_getparam, target, parameter);
}

int main(int argc, char** argv) {
  if (argc != 22)
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
  const long priority_which[] = {
      PRIO_PROCESS, PRIO_PROCESS, PRIO_PROCESS, PRIO_PROCESS,
      PRIO_PROCESS, -1, 3, 999};
  const long priority_who[] = {0, me, target, INT_MAX, -1, 0, target, INT_MAX};
  const char* priority_labels[] = {
      "zero", "self", "live", "absent", "negative",
      "invalid-negative-zero", "invalid-three-live", "invalid-999-absent"};
  long live_priority = strtol(argv[6], NULL, 10);
  long self_priority = strtol(argv[7], NULL, 10);
  const long priority_expected[] = {
      self_priority, self_priority, live_priority, -ESRCH,
      -ESRCH, -EINVAL, -EINVAL, -EINVAL};
  for (unsigned int i = 0; i < 8; ++i) {
    errno = 0;
    long rc = priority_query(priority_which[i], priority_who[i]);
    int error = errno;
    printf("getpriority %s rc=%ld errno=%d\n", priority_labels[i], rc, error);
    long expected_rc = priority_expected[i] < 0 ? -1 : priority_expected[i];
    int expected_error = priority_expected[i] < 0 ? (int)-priority_expected[i] : 0;
    failed |= rc != expected_rc || error != expected_error;
  }
  const long parameter_targets[] = {0, me, target, INT_MAX, -1, 0, 0};
  const char* parameter_labels[] = {"zero", "self", "live", "absent", "negative", "null", "bad"};
  for (unsigned int i = 0; i < 7; ++i) {
    struct {
      uint32_t before;
      struct sched_param parameter;
      uint32_t after;
    } output = {UINT32_C(0x2468ace0), {0x13579bdf}, UINT32_C(0xfdb97531)};
    struct sched_param* address =
        i == 5 ? NULL : i == 6 ? (struct sched_param*)(uintptr_t)1 : &output.parameter;
    errno = 0;
    long rc = parameter_query(parameter_targets[i], address);
    int error = errno;
    uint32_t bytes;
    memcpy(&bytes, &output.parameter, sizeof(bytes));
    int canaries = output.before == UINT32_C(0x2468ace0) &&
        output.after == UINT32_C(0xfdb97531);
    printf("sched_getparam %s rc=%ld errno=%d bytes=%08x canaries=%d\n",
           parameter_labels[i], rc, error, (unsigned int)bytes, canaries);
    // Expected return/bytes come from a separate raw Linux observation. Never
    // run that observation into this buffer before testing the injected call.
    long raw_expected = strtol(argv[8 + 2 * i], NULL, 10);
    uint32_t expected_bytes = (uint32_t)strtoul(argv[9 + 2 * i], NULL, 16);
    long expected_rc = raw_expected < 0 ? -1 : raw_expected;
    int expected_error = raw_expected < 0 ? (int)-raw_expected : 0;
    failed |= rc != expected_rc || error != expected_error ||
        bytes != expected_bytes || !canaries;
  }
  if (failed)
    return 1;
  puts("group-session-getters=ok");
  return 0;
}
