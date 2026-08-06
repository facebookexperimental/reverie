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
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { ITERATIONS = 64 };

typedef struct {
  pthread_barrier_t start;
  pid_t nested_pid;
  pid_t nested_tid;
} race_state_t;

static void *nested_main(void *argument) {
  race_state_t *state = argument;
  state->nested_pid = (pid_t)syscall(SYS_getpid);
  state->nested_tid = (pid_t)syscall(SYS_gettid);
  return NULL;
}

static void *creator_main(void *argument) {
  race_state_t *state = argument;
  pthread_t nested;

  (void)pthread_barrier_wait(&state->start);
  if (pthread_create(&nested, NULL, nested_main, state) != 0)
    return (void *)1;
  if (pthread_join(nested, NULL) != 0)
    return (void *)2;
  return NULL;
}

static int run_nested_race(pid_t expected_pid) {
  race_state_t state = {.nested_pid = 0, .nested_tid = 0};
  pthread_t creator;
  void *thread_result = NULL;
  int status = 0;

  if (pthread_barrier_init(&state.start, NULL, 2) != 0)
    return 11;
  if (pthread_create(&creator, NULL, creator_main, &state) != 0)
    return 12;
  (void)pthread_barrier_wait(&state.start);

  pid_t child = fork();
  if (child < 0)
    return 13;
  if (child == 0)
    (void)syscall(SYS_exit, 0);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0)
    return 14;
  if (pthread_join(creator, &thread_result) != 0 || thread_result != NULL)
    return 15;
  if (pthread_barrier_destroy(&state.start) != 0)
    return 16;
  if (state.nested_pid != expected_pid || state.nested_tid == expected_pid ||
      state.nested_tid == child)
    return 17;
  return 0;
}

// TODO-HUMAN-REVIEW(PR-154): Review process-clone/pthread identity handoff race.
int main(void) {
  for (int iteration = 0; iteration < ITERATIONS; ++iteration) {
    race_state_t state = {.nested_pid = 0, .nested_tid = 0};
    pthread_t creator;
    void *thread_result = NULL;
    int status = 0;

    if (pthread_barrier_init(&state.start, NULL, 2) != 0)
      return 1;
    if (pthread_create(&creator, NULL, creator_main, &state) != 0)
      return 2;
    (void)pthread_barrier_wait(&state.start);

    pid_t child = fork();
    if (child < 0)
      return 3;
    if (child == 0) {
      int result = run_nested_race((pid_t)syscall(SYS_getpid));
      (void)syscall(SYS_exit, result);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
      return 4;
    if (pthread_join(creator, &thread_result) != 0 || thread_result != NULL)
      return 5;
    if (pthread_barrier_destroy(&state.start) != 0)
      return 6;
    if (state.nested_pid != 3 || state.nested_tid <= 3 ||
        state.nested_tid == child)
      return 7;
  }

  printf("fork-pthread-race=%d\n", ITERATIONS);
  return 0;
}
