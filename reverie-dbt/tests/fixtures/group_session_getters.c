/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(struct sched_param) == 4, "x86_64 sched_param oracle");
_Static_assert(sizeof(void*) == 8 && sizeof(size_t) == 8, "x86_64 robust outputs");

#define AFFINITY_CAPACITY 128

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

static long affinity_query(long target, size_t length, unsigned char* mask) {
  if (returning)
    return prctl(0x4b494421, (long)SYS_sched_getaffinity, target, (long)length, (long)mask);
  return syscall(SYS_sched_getaffinity, target, length, mask);
}

static long robust_query(long target, void* head, void* length) {
  if (returning)
    return prctl(0x4b494421, (long)SYS_get_robust_list, target, (long)head, (long)length);
  return syscall(SYS_get_robust_list, target, head, length);
}

int main(int argc, char** argv) {
  if (argc != 62)
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
  const long affinity_targets[] = {0, me, target, INT_MAX, -1, 0, 0, 0, 0};
  const size_t affinity_lengths[] = {
      AFFINITY_CAPACITY, AFFINITY_CAPACITY, AFFINITY_CAPACITY,
      AFFINITY_CAPACITY, AFFINITY_CAPACITY, 0, 1, AFFINITY_CAPACITY, AFFINITY_CAPACITY};
  const char* affinity_labels[] = {
      "zero", "self", "live", "absent", "negative", "zero-size", "one-byte", "null", "bad"};
  for (unsigned int i = 0; i < 9; ++i) {
    unsigned char output[AFFINITY_CAPACITY + 16];
    memset(output, 0x7f, sizeof(output));
    memset(output, 0xa5, 8);
    memset(output + AFFINITY_CAPACITY + 8, 0x5a, 8);
    unsigned char* address = i == 7 ? NULL : i == 8 ? (unsigned char*)(uintptr_t)1 : output + 8;
    errno = 0;
    long rc = affinity_query(affinity_targets[i], affinity_lengths[i], address);
    int error = errno;
    int canaries = 1;
    for (unsigned int j = 0; j < 8; ++j)
      canaries &= output[j] == 0xa5 && output[AFFINITY_CAPACITY + 8 + j] == 0x5a;
    const char digits[] = "0123456789abcdef";
    char mask[AFFINITY_CAPACITY * 2 + 1];
    for (unsigned int j = 0; j < AFFINITY_CAPACITY; ++j) {
      mask[2 * j] = digits[output[8 + j] >> 4];
      mask[2 * j + 1] = digits[output[8 + j] & 15];
    }
    mask[AFFINITY_CAPACITY * 2] = '\0';
    printf("sched_getaffinity %s len=%zu rc=%ld errno=%d mask=%s canaries=%d\n",
           affinity_labels[i], affinity_lengths[i], rc, error, mask, canaries);
    // Exact host-measured raw byte count and all capacity bytes, including the
    // untouched suffix. Kernel and guest observations never share this buffer.
    long raw_expected = strtol(argv[22 + 2 * i], NULL, 10);
    const char* expected_mask = argv[23 + 2 * i];
    long expected_rc = raw_expected < 0 ? -1 : raw_expected;
    int expected_error = raw_expected < 0 ? (int)-raw_expected : 0;
    failed |= rc != expected_rc || error != expected_error || !canaries ||
        strlen(expected_mask) != AFFINITY_CAPACITY * 2 || strcmp(mask, expected_mask) != 0;
  }
  // Pointer values for self belong to this image, not to the native fixture
  // in another process. Retain the raw words on stderr and compare the two
  // self queries relationally; a legally NULL robust head is allowed.
  long tid = returning ? prctl(0x4b494421, (long)SYS_gettid, 0L, 0L, 0L)
                       : syscall(SYS_gettid);
  struct stat pid_namespace, user_namespace;
  if (tid != me || stat("/proc/self/ns/pid", &pid_namespace) != 0 ||
      stat("/proc/self/ns/user", &user_namespace) != 0)
    return 4;
  fprintf(stderr,
          "robust-context pid=%ld tid=%ld uid=%lu euid=%lu gid=%lu egid=%lu pidns=%llu:%llu userns=%llu:%llu\n",
          me, tid, (unsigned long)getuid(), (unsigned long)geteuid(),
          (unsigned long)getgid(), (unsigned long)getegid(),
          (unsigned long long)pid_namespace.st_dev, (unsigned long long)pid_namespace.st_ino,
          (unsigned long long)user_namespace.st_dev, (unsigned long long)user_namespace.st_ino);
  long absent = strtol(argv[40], NULL, 10);
  if (absent <= target || absent <= me)
    return 5;
  const long robust_targets[] = {0, me, target, target, target, absent, absent};
  const char* robust_labels[] = {"zero", "self", "live", "live-bad-head", "live-bad-length", "absent", "absent-bad-both"};
  struct robust_observation {
    uint64_t head[3];
    uint64_t length[3];
    long rc;
    int error;
  } robust[7];
  for (unsigned int i = 0; i < 7; ++i) {
    struct robust_observation* row = &robust[i];
    row->head[0] = row->length[0] = UINT64_C(0x2468ace02468ace0);
    row->head[1] = UINT64_C(0x13579bdf13579bdf);
    row->length[1] = UINT64_C(0xfedcba9876543210);
    row->head[2] = row->length[2] = UINT64_C(0xfdb97531fdb97531);
    void* head = i == 3 || i == 6 ? (void*)(uintptr_t)1 : &row->head[1];
    void* length = i == 4 || i == 6 ? (void*)(uintptr_t)1 : &row->length[1];
    errno = 0;
    row->rc = robust_query(robust_targets[i], head, length);
    row->error = errno;
  }
  // All seven calls have completed before checking any outcome. In particular,
  // EFAULT can write one output before failing on the other; retain both words.
  for (unsigned int i = 0; i < 7; ++i) {
    const struct robust_observation* row = &robust[i];
    int canaries = row->head[0] == UINT64_C(0x2468ace02468ace0) &&
        row->length[0] == UINT64_C(0x2468ace02468ace0) &&
        row->head[2] == UINT64_C(0xfdb97531fdb97531) &&
        row->length[2] == UINT64_C(0xfdb97531fdb97531);
    fprintf(stderr,
            "robust-raw index=%u target=%ld rc=%ld errno=%d head=%016llx length=%016llx head_before=%016llx head_after=%016llx length_before=%016llx length_after=%016llx\n",
            i, robust_targets[i], row->rc, row->error,
            (unsigned long long)row->head[1], (unsigned long long)row->length[1],
            (unsigned long long)row->head[0], (unsigned long long)row->head[2],
            (unsigned long long)row->length[0], (unsigned long long)row->length[2]);
    char head_text[32];
    if (i < 2)
      strcpy(head_text, "same-image-self");
    else
      snprintf(head_text, sizeof(head_text), "%016llx", (unsigned long long)row->head[1]);
    printf("get_robust_list %s rc=%ld errno=%d head=%s length=%016llx canaries=%d\n",
           robust_labels[i], row->rc, row->error, head_text,
           (unsigned long long)row->length[1], canaries);
    long raw_expected = strtol(argv[41 + 3 * i], NULL, 10);
    uint64_t expected_head = strtoull(argv[42 + 3 * i], NULL, 16);
    uint64_t expected_length = strtoull(argv[43 + 3 * i], NULL, 16);
    long expected_rc = raw_expected < 0 ? -1 : raw_expected;
    int expected_error = raw_expected < 0 ? (int)-raw_expected : 0;
    failed |= row->rc != expected_rc || row->error != expected_error ||
        row->length[1] != expected_length || !canaries;
    if (i < 2)
      failed |= row->rc != 0 || row->error != 0 ||
          row->length[1] != sizeof(struct robust_list_head) ||
          row->head[1] != robust[0].head[1];
    else
      failed |= row->head[1] != expected_head;
  }
  if (failed)
    return 1;
  puts("group-session-getters=ok");
  return 0;
}
