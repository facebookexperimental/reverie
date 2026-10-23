/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef REVERIE_DBT_MAPPING_CAPTURE_TEST_SIGNALS_H
#define REVERIE_DBT_MAPPING_CAPTURE_TEST_SIGNALS_H

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Explicit native-test support for Linux x86-64. The caller and helper are
 * distinct thread-group leaders. Only the SDK's raw syscall leaf is used:
 * no ordinary DR API, allocation, logging, handler, or RPC occurs here.
 *
 * Once prepare has installed its baseline, any failure must use the parent's
 * terminal test-refusal path. Do not unmask partially consumed test signals.
 * All state lives in the parent's certified private slot, never a global. */
_Static_assert(SIGUSR1 == 10 && SIGPIPE == 13 && SIGKILL == 9 && SIGSTOP == 19,
    "mapping capture signal control requires Linux x86-64 signal numbers");

#define MAPPING_CAPTURE_TEST_SIGNAL_BIT(number) (UINT64_C(1) << ((number) - 1))
#define MAPPING_CAPTURE_TEST_SIGNAL_SET \
  (MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGUSR1) | MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGPIPE) | \
   MAPPING_CAPTURE_TEST_SIGNAL_BIT(34) | MAPPING_CAPTURE_TEST_SIGNAL_BIT(35))

typedef struct {
  uint64_t original_mask;
  uint64_t baseline_mask;
  uint64_t initial_pending;
  uint64_t prepared_pending;
  uint64_t blocked_mask;
  uint64_t restored_mask;
  uint64_t pending_before;
  uint64_t pending_after;
  uint64_t final_mask;
  uint64_t consumed;
  int32_t self_tid;
  int32_t initiator_pid;
  int32_t consumed_signals[4];
  int32_t consumed_senders[4];
  int32_t consumed_codes[4];
  bool prepared;
  bool full;
  bool restored;
  bool pending;
  bool original_restored;
  char failure_record[192];
} mapping_capture_signal_test_t;

/* Test evidence only: one fixed-size raw write to the already reserved native
 * diagnostic file. No formatter, allocation, descriptor creation, or retry.
 * The caller takes the raw terminal path immediately after this observation. */
static void mapping_capture_signal_test_report_mask_mismatch(
    mapping_capture_signal_test_t* state, int diagnostic_fd) {
  const char* fields[2] = {
    "MAPPING_CAPTURE_TEST phase=closed-mask-mismatch executor=helper observed_mask=",
    " expected_mask="
  };
  uint64_t values[2] = { state->blocked_mask, UINT64_MAX &
      ~(MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGKILL) | MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGSTOP)) };
  size_t used = 0;
  for (unsigned int field = 0; field < 2; ++field) {
    for (const char* p = fields[field]; *p != '\0'; ++p) {
      if (used == sizeof(state->failure_record))
        return;
      state->failure_record[used++] = *p;
    }
    uint64_t divisor = 1;
    while (values[field] / divisor >= 10)
      divisor *= 10;
    do {
      if (used == sizeof(state->failure_record))
        return;
      state->failure_record[used++] = '0' + (values[field] / divisor) % 10;
      divisor /= 10;
    } while (divisor != 0);
  }
  if (used == sizeof(state->failure_record))
    return;
  state->failure_record[used++] = '\n';
  dr_mapping_capture_control(DR_MAPPING_CAPTURE_TEST_WRITE, diagnostic_fd,
      (uintptr_t)state->failure_record, used);
}

static bool mapping_capture_signal_test_prepare(
    mapping_capture_signal_test_t* state, int32_t self_tid, int32_t initiator_pid) {
  if (state == NULL || self_tid <= 0 || initiator_pid <= 0)
    return false;
  *state = (mapping_capture_signal_test_t){0};
  state->self_tid = self_tid;
  state->initiator_pid = initiator_pid;
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_QUERY_MASK,
          (uintptr_t)&state->original_mask, 0, 0) != 0 ||
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_PENDING,
          (uintptr_t)&state->initial_pending, 0, 0) != 0 ||
      (state->initial_pending & MAPPING_CAPTURE_TEST_SIGNAL_SET) != 0)
    return false;
  state->baseline_mask = state->original_mask | MAPPING_CAPTURE_TEST_SIGNAL_SET;
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_RESTORE_SIGNALS,
          (uintptr_t)&state->baseline_mask, 0, 0) != 0 ||
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_QUERY_MASK,
          (uintptr_t)&state->restored_mask, 0, 0) != 0 ||
      state->restored_mask != state->baseline_mask)
    return false;
  /* These are test-created standard signals pending before Closed, not
   * arbitrary ambient pending signals. Both are physically blocked first. */
  if (dr_mapping_capture_control(
          DR_MAPPING_CAPTURE_TEST_SIGNAL, self_tid, self_tid, SIGUSR1) != 0 ||
      dr_mapping_capture_control(
          DR_MAPPING_CAPTURE_TEST_SIGNAL, self_tid, self_tid, SIGPIPE) != 0)
    return false;
  uint64_t standard = MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGUSR1) |
      MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGPIPE);
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_PENDING,
          (uintptr_t)&state->prepared_pending, 0, 0) != 0 ||
      (state->prepared_pending & MAPPING_CAPTURE_TEST_SIGNAL_SET) != standard)
    return false;
  state->prepared = true;
  return true;
}

static bool mapping_capture_signal_test_blocked(mapping_capture_signal_test_t* state) {
  if (state == NULL || !state->prepared)
    return false;
  uint64_t full = UINT64_MAX &
      ~(MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGKILL) | MAPPING_CAPTURE_TEST_SIGNAL_BIT(SIGSTOP));
  state->full = dr_mapping_capture_control(DR_MAPPING_CAPTURE_QUERY_MASK,
                    (uintptr_t)&state->blocked_mask, 0, 0) == 0 &&
      state->blocked_mask == full;
  return state->full;
}

/* Called by the initiating caller while the actual target is Parked. */
static bool mapping_capture_signal_test_arrivals(int32_t tid) {
  return tid > 0 &&
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_TEST_SIGNAL, tid, tid, 34) == 0 &&
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_TEST_SIGNAL, tid, tid, 35) == 0;
}

static bool mapping_capture_signal_test_finish(mapping_capture_signal_test_t* state) {
  if (state == NULL || !state->prepared || !state->full)
    return false;
  state->restored = dr_mapping_capture_control(DR_MAPPING_CAPTURE_QUERY_MASK,
                        (uintptr_t)&state->restored_mask, 0, 0) == 0 &&
      state->restored_mask == state->baseline_mask;
  if (!state->restored ||
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_PENDING,
          (uintptr_t)&state->pending_before, 0, 0) != 0 ||
      (state->pending_before & MAPPING_CAPTURE_TEST_SIGNAL_SET) !=
          MAPPING_CAPTURE_TEST_SIGNAL_SET)
    return false;

  uint64_t selected = MAPPING_CAPTURE_TEST_SIGNAL_SET;
  unsigned int taken = 0;
  /* Each raw wait has a zero timeout; the finite attempt bound also limits
   * EINTR retries. Never consume a signal outside the four selected bits. */
  for (unsigned int attempt = 0; attempt < 16 && taken < 4; ++attempt) {
    siginfo_t info = {0};
    ptr_int_t result = dr_mapping_capture_control(DR_MAPPING_CAPTURE_TEST_TAKE_PENDING,
        (uintptr_t)&selected, (uintptr_t)&info, 0);
    if (result == -EINTR)
      continue;
    if (result != SIGUSR1 && result != SIGPIPE && result != 34 && result != 35)
      return false;
    uint64_t bit = MAPPING_CAPTURE_TEST_SIGNAL_BIT(result);
    int32_t sender = result == SIGUSR1 || result == SIGPIPE
        ? state->self_tid : state->initiator_pid;
    if ((state->consumed & bit) != 0 || info.si_signo != result ||
        info.si_code != SI_TKILL || info.si_pid != sender)
      return false;
    state->consumed_signals[taken] = (int32_t)result;
    state->consumed_senders[taken] = info.si_pid;
    state->consumed_codes[taken] = info.si_code;
    state->consumed |= bit;
    ++taken;
  }
  if (taken != 4 || state->consumed != selected ||
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_PENDING,
          (uintptr_t)&state->pending_after, 0, 0) != 0 ||
      (state->pending_after & selected) != 0)
    return false;
  uint64_t unrelated = (state->initial_pending | state->pending_before) & ~selected;
  if ((state->pending_after & unrelated) != unrelated)
    return false;
  state->pending = true;
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_RESTORE_SIGNALS,
          (uintptr_t)&state->original_mask, 0, 0) != 0)
    return false;
  state->original_restored = dr_mapping_capture_control(DR_MAPPING_CAPTURE_QUERY_MASK,
                                (uintptr_t)&state->final_mask, 0, 0) == 0 &&
      state->final_mask == state->original_mask;
  return state->original_restored;
}

#endif /* REVERIE_DBT_MAPPING_CAPTURE_TEST_SIGNALS_H */
