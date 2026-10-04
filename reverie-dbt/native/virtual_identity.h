/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef REVERIE_DBT_NATIVE_VIRTUAL_IDENTITY_H
#define REVERIE_DBT_NATIVE_VIRTUAL_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  int32_t host;
  int32_t virtual_id;
} virtual_identity_t;

typedef struct {
  bool pending;
  int32_t sysnum;
  int32_t physical_pid;
  int32_t virtual_pid;
} translated_child_wait_t;

static inline void clear_translated_child_wait(translated_child_wait_t* wait) {
  wait->pending = false;
  wait->sysnum = 0;
  wait->physical_pid = 0;
  wait->virtual_pid = 0;
}

static inline bool consume_translated_child_wait(
    translated_child_wait_t* wait,
    int32_t sysnum,
    int32_t physical_pid,
    int32_t* virtual_pid) {
  if (!wait->pending || wait->sysnum != sysnum ||
      wait->physical_pid != physical_pid)
    return false;

  *virtual_pid = wait->virtual_pid;
  clear_translated_child_wait(wait);
  return true;
}

static inline int32_t host_identity_for_guest_entries(
    const virtual_identity_t* identities,
    size_t count,
    int32_t identity) {
  size_t i;

  if (identity <= 0)
    return identity;

  /* A guest virtual ID wins even when an earlier entry has the same numeric
   * host ID. */
  for (i = 0; i < count; ++i) {
    if (identities[i].virtual_id == identity)
      return identities[i].host;
  }

  for (i = 0; i < count; ++i) {
    if (identities[i].host == identity)
      return identities[i].host;
  }

  return -1;
}

#endif
