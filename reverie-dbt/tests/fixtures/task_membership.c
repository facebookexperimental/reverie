/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE. */
#include "task_membership.h"
#include <assert.h>

static const task_membership_t tasks[] = {{1004, 3}, {1100, 4}};
static const size_t count = sizeof(tasks) / sizeof(tasks[0]);

static void owner(int32_t group, int32_t type, int32_t input,
                  int32_t expected, bool screened) {
  const fcntl_group_view_t groups = {group};
  int32_t value = input;
  assert(screen_owner_entries(tasks, count, &groups, type, &value) == screened);
  assert(value == expected);
}
static void setown(int32_t group, int32_t input,
                   int32_t expected, bool screened) {
  const fcntl_group_view_t groups = {group};
  int32_t value = input;
  assert(screen_setown_entries(tasks, count, &groups, &value) == screened);
  assert(value == expected);
}

int main(void) {
  /* Last identities are usable once; exhaustion cannot wrap into an earlier
   * task's scope, and repeated failures do not rewind the allocator. */
  _Atomic int32_t birth;
  atomic_init(&birth, INT32_MAX - 1);
  assert(task_membership_next_birth(&birth) == INT32_MAX - 1);
  assert(task_membership_next_birth(&birth) == INT32_MAX);
  assert(task_membership_next_birth(&birth) == 0);
  assert(task_membership_next_birth(&birth) == 0);
  assert(atomic_load(&birth) == 0);
  atomic_store(&birth, -1);
  assert(task_membership_next_birth(&birth) == 0);
  assert(atomic_load(&birth) == -1);
  atomic_store(&birth, 1);
  assert(task_membership_next_birth(&birth) == 1);
  assert(atomic_load(&birth) == 2);

  /* Unrecorded getter targets reach Linux regardless of the unused token. */
  assert(task_membership_allows_robust_query(false, 0));
  assert(task_membership_allows_robust_query(false, -1));
  assert(task_membership_allows_robust_query(false, 6));
  assert(!task_membership_allows_robust_query(true, -1));
  task_membership_t task = {37, 6};
  assert(task_membership_allows_robust_query(true, task.birth_token));
  task_membership_publish(&task, 6, false); /* parent after child autoreap */
  assert(task.tid == 37 && task.birth_token == 6);
  task_membership_publish(&task, 7, false); /* late parent cannot replace */
  assert(task.tid == 37 && task.birth_token == 6);
  assert(task_membership_allows_robust_query(true, task.birth_token));
  task_membership_publish(&task, 5, true);  /* later kernel birth, earlier token */
  assert(task.tid == 37 && task.birth_token == 5);
  task_membership_publish(&task, 6, false);
  assert(task.tid == 37 && task.birth_token == 5);
  task.birth_token = 0;                    /* observed helper tombstone */
  task_membership_publish(&task, 6, false);
  assert(task.birth_token == 0);
  assert(!task_membership_contains(&task, 1, 37));
  assert(!task_membership_allows_robust_query(true, task.birth_token));
  task_membership_publish(&task, 4, true);  /* actual later application birth */
  assert(task.tid == 37 && task.birth_token == 4);
  assert(task_membership_contains(&task, 1, 37));
  assert(task_membership_allows_robust_query(true, task.birth_token));
  assert(task_membership_contains(tasks, count, 1004));
  assert(task_membership_contains(tasks, count, 1100));
  assert(!task_membership_contains(tasks, count, 3));
  assert(!task_membership_contains(tasks, count, 4));
  assert(!task_membership_contains(tasks, count, 200));
  assert(!task_membership_contains(tasks, count, 0));
  assert(!task_membership_contains(tasks, count, -1));
  const int32_t impossible = FCNTL_OWNER_IMPOSSIBLE_PID;

  /* Known process/thread/group targets retain raw IDs. Birth tokens never
   * select a task, including collisions with the caller's external group. */
  setown(1004, 1004, 1004, false);
  setown(1004, 1100, 1100, false);
  setown(1004, 3, impossible, true);
  setown(1004, 4, impossible, true);
  setown(1004, 200, impossible, true);
  setown(1004, -1004, -1004, false);
  setown(1004, -1100, -1100, false);
  setown(1004, -200, -impossible, true);
  setown(1004, 0, 0, false);
  setown(1004, INT32_MIN, INT32_MIN, false);
  owner(1004, FCNTL_OWNER_TID, 1100, 1100, false);
  owner(1004, FCNTL_OWNER_PID, 1004, 1004, false);
  owner(1004, FCNTL_OWNER_PGRP, 1004, 1004, false);
  owner(1004, FCNTL_OWNER_PGRP, 1100, 1100, false);
  owner(1004, FCNTL_OWNER_PID, 4, impossible, true);
  owner(1004, FCNTL_OWNER_TID, 200, impossible, true);
  owner(1004, FCNTL_OWNER_PGRP, 200, impossible, true);
  owner(1004, FCNTL_OWNER_PID, 0, 0, false);
  owner(1004, FCNTL_OWNER_PID, -3, -3, false);
  owner(1004, 7, 3, 3, false);
  owner(1004, -1, 3, 3, false);

  /* A caller group led outside the tree is still a real group. Group IDs
   * which equal a birth token are neither hidden nor mapped to another PID. */
  setown(500, -500, -500, false);
  setown(500, -600, -impossible, true);
  setown(500, -1004, -1004, false);
  owner(500, FCNTL_OWNER_PGRP, 500, 500, false);
  setown(3, -3, -3, false);
  owner(3, FCNTL_OWNER_PGRP, 3, 3, false);
  setown(3, 3, impossible, true);

  /* F_GETOWN/F_GETOWN_EX/ioctl results are no longer rewritten. Reading a
   * known owner back and setting that raw value again preserves the target. */
  const int32_t round_trip[] = {1004, 1100, -1004, -1100, 0};
  for (size_t i = 0; i < sizeof(round_trip) / sizeof(round_trip[0]); ++i)
    setown(1004, round_trip[i], round_trip[i], false);
  setown(500, -500, -500, false);
  setown(3, -3, -3, false);
  return 0;
}
