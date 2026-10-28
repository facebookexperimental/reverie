/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef REVERIE_KVM_TERMINAL_READ_H
#define REVERIE_KVM_TERMINAL_READ_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* This operation is for terminal disposal only. CANCELED says nothing about
 * whether the kernel entered/completed the read or produced side effects. */
enum rvk_read_outcome {
  RVK_READ_PENDING = 0,
  RVK_READ_RETURNED = 1,
  RVK_READ_CANCELED = 2,
  RVK_READ_NOT_STARTED = 3,
};

enum rvk_read_state {
  RVK_READ_PREPARED = 0,
  RVK_READ_CREATING = 1,
  RVK_READ_CALLABLE = 2,
  RVK_READ_DISARMED = 3,
  RVK_READ_JOINING = 4,
  RVK_READ_JOINED = 5,
  RVK_READ_JOIN_FAILED = 6,
  RVK_READ_NO_THREAD = 7,
};

enum rvk_read_error_phase {
  RVK_READ_ERROR_NONE = 0,
  RVK_READ_ERROR_CREATE = 1,
  RVK_READ_ERROR_CANCEL = 2,
  RVK_READ_ERROR_JOIN = 3,
  RVK_READ_ERROR_CANCEL_STATE = 4,
  RVK_READ_ERROR_CANCEL_TYPE = 5,
  RVK_READ_ERROR_SYNC = 6,
};

struct rvk_read;

struct rvk_read_snapshot {
  int64_t result;
  uint64_t senders;
  uint32_t outcome;
  uint32_t state;
  uint32_t terminal;
  uint32_t handle_published;
  int32_t read_errno;
  uint32_t error_phase;
  int32_t error_number;
};

/* The fd and the exact numeric staging address remain caller-owned until a
 * successful finish (or no-thread create failure). No fd is duplicated or
 * closed here. count must be zero. All failures are backend control errors. */
struct rvk_read*
rvk_read_new(int fd, uintptr_t address, size_t count, int* error);

/* One owner calls start at most once, then finish. request_cancel, snapshot and
 * wake may run concurrently; no caller may be pthread_cancel'ed. The new C
 * reader is the ONLY cancellation target. */
int rvk_read_start(struct rvk_read* op);
int rvk_read_request_cancel(struct rvk_read* op);
int rvk_read_snapshot(struct rvk_read* op, struct rvk_read_snapshot* snapshot);

/* Arm/recheck wait: read epoch, inspect outcome/terminal futures, then wait on
 * that epoch. Every outcome publication and explicit wake changes the epoch.
 * A wake is not a terminal cause and does not alter the native outcome. */
uint64_t rvk_read_epoch(struct rvk_read* op);
int rvk_read_wake(struct rvk_read* op);
int rvk_read_wait(struct rvk_read* op, uint64_t observed_epoch);

/* Refuses Pending with EBUSY. After outcome: revoke send admission, drain ALL
 * admitted senders through actual pthread_cancel return, then join exactly
 * once outside locks. A join failure is permanent: keep the operation, fd and
 * storage owned, never retry join, detach, or re-enable send admission. The
 * return describes this finish; snapshot retains the first control error. */
int rvk_read_finish(struct rvk_read* op);

/* Only after every concurrent user (including wakers) is gone. Returns EBUSY
 * and retains storage unless no thread was created or finish joined it. */
int rvk_read_destroy(struct rvk_read* op);

#ifdef RVK_READ_TEST
/* State gates are C-only and absent from production. Hooks executed between
 * read return and cancellation disable MUST NOT add a cancellation point. */
enum rvk_read_test_event {
  RVK_READ_TEST_BEFORE_CREATE = 1,
  RVK_READ_TEST_AFTER_CREATE = 2,
  RVK_READ_TEST_BEFORE_ENABLE = 3,
  RVK_READ_TEST_BEFORE_READ = 4,
  RVK_READ_TEST_AFTER_READ = 5,
  RVK_READ_TEST_AFTER_OUTCOME = 6,
  RVK_READ_TEST_BEFORE_CANCEL = 7,
  RVK_READ_TEST_AFTER_CANCEL = 8,
  RVK_READ_TEST_DISARMED = 9,
  RVK_READ_TEST_BEFORE_JOIN = 10,
  RVK_READ_TEST_AFTER_JOIN = 11,
};
void rvk_read_test_hook(struct rvk_read* op, enum rvk_read_test_event event);
void rvk_read_test_fail(
    struct rvk_read* op,
    enum rvk_read_error_phase phase,
    int error);
#endif

#endif
