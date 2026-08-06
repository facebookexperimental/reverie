/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum { SPAWNERS = 4, TOTAL_THREADS = SPAWNERS * 2 };

typedef struct {
  int value;
  pid_t spawner_tid;
  pid_t nested_tid;
} worker_state_t;

static pthread_barrier_t start_barrier;

static void *nested_main(void *argument) {
  worker_state_t *state = argument;
  state->nested_tid = (pid_t)syscall(SYS_gettid);
  state->value += 1;
  return NULL;
}

static void *spawner_main(void *argument) {
  worker_state_t *state = argument;
  pthread_t nested;

  state->spawner_tid = (pid_t)syscall(SYS_gettid);
  if (pthread_barrier_wait(&start_barrier) == PTHREAD_BARRIER_SERIAL_THREAD) {
    // The serial participant has no extra work; all spawners continue below.
  }
  if (pthread_create(&nested, NULL, nested_main, state) != 0)
    return (void *)1;
  if (pthread_join(nested, NULL) != 0)
    return (void *)2;
  state->value += 1;
  return NULL;
}

// TODO-HUMAN-REVIEW(PR-154): Review the concurrent native DBT pthread ratchet.
int main(void) {
  pthread_t spawners[SPAWNERS];
  worker_state_t states[SPAWNERS] = {{.value = 0},
                                    {.value = 1},
                                    {.value = 2},
                                    {.value = 3}};
  pid_t tids[TOTAL_THREADS];
  int total = 0;
  int tid_count = 0;

  if (pthread_barrier_init(&start_barrier, NULL, SPAWNERS) != 0)
    return 1;
  for (int index = 0; index < SPAWNERS; ++index) {
    if (pthread_create(&spawners[index], NULL, spawner_main, &states[index]) != 0) {
      return 1;
    }
  }
  for (int index = 0; index < SPAWNERS; ++index) {
    void *result = NULL;
    if (pthread_join(spawners[index], &result) != 0 || result != NULL) {
      return 2;
    }
    total += states[index].value;
    tids[tid_count++] = states[index].spawner_tid;
    tids[tid_count++] = states[index].nested_tid;
  }
  if (pthread_barrier_destroy(&start_barrier) != 0)
    return 3;

  for (int left = 0; left < tid_count; ++left) {
    if (tids[left] <= 0)
      return 4;
    for (int right = left + 1; right < tid_count; ++right)
      if (tids[left] == tids[right])
        return 5;
  }

  printf("threads=%d total=%d unique_tids=%d\n", TOTAL_THREADS, total,
         tid_count);
  return 0;
}
