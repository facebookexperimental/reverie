/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
#ifndef REVERIE_DBT_NATIVE_TASK_MEMBERSHIP_H
#define REVERIE_DBT_NATIVE_TASK_MEMBERSHIP_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* A kernel-observed task and its admission transaction. birth_token is opaque:
 * it is never returned to a guest or used as a syscall's PID argument. */
typedef struct {
  int32_t tid;
  int32_t birth_token;
} task_membership_t;

/* A current child (or a parent whose thread child is still gated) owns its
 * birth. A delayed process parent must not replace another existing birth or
 * a helper tombstone. Token values have no chronological ordering meaning. */
static inline void task_membership_publish(
    task_membership_t* task, int32_t birth_token, bool authoritative) {
  if (authoritative)
    task->birth_token = birth_token;
}

/* This getter retains recorded helper/tombstone restrictions, but leaves
 * unrecorded targets to Linux. A missing entry does not prove task ownership. */
static inline bool task_membership_allows_robust_query(
    bool found, int32_t birth_token) {
  return !found || birth_token > 0;
}

typedef struct { int32_t type; int32_t pid; } fcntl_owner_ex_t;
#define FCNTL_OWNER_TID 0
#define FCNTL_OWNER_PID 1
#define FCNTL_OWNER_PGRP 2
#define FCNTL_OWNER_IMPOSSIBLE_PID INT32_MAX
typedef struct { int32_t caller_group; } fcntl_group_view_t;
static inline bool task_membership_contains(
    const task_membership_t* tasks, size_t count, int32_t tid) {
  for (size_t i = 0; i < count; ++i)
    if (tasks[i].tid == tid && tasks[i].birth_token > 0)
      return true;
  return false;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(hermit-3955): retained unknown-owner admission policy.
/* This is the existing helper/foreign-target screen. It does not translate
 * known IDs. Zero, negative IDs and invalid kinds remain for Linux to validate.
 * The caller's group remains admissible even if its leader is outside the tree.
 * Removed numeric-projection policy is not replaced by a new number space. */
static inline bool screen_owner_entries(
    const task_membership_t* tasks, size_t count,
    const fcntl_group_view_t* groups, int32_t type, int32_t* pid) {
  if (type != FCNTL_OWNER_TID && type != FCNTL_OWNER_PID &&
      type != FCNTL_OWNER_PGRP)
    return false;
  if (*pid <= 0)
    return false;
  if (type == FCNTL_OWNER_PGRP && *pid == groups->caller_group)
    return false;
  if (task_membership_contains(tasks, count, *pid))
    return false;
  *pid = FCNTL_OWNER_IMPOSSIBLE_PID;
  return true;
}

static inline bool screen_setown_entries(
    const task_membership_t* tasks, size_t count,
    const fcntl_group_view_t* groups, int32_t* who) {
  if (*who > 0)
    return screen_owner_entries(tasks, count, groups, FCNTL_OWNER_PID, who);
  if (*who == 0 || *who == INT32_MIN)
    return false;
  int32_t pid = -*who;
  if (!screen_owner_entries(tasks, count, groups, FCNTL_OWNER_PGRP, &pid))
    return false;
  *who = -pid;
  return true;
}
#endif
