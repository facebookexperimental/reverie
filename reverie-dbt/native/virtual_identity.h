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

  /* A guest virtual ID wins even when an entry has the same numeric host ID:
   * the guest is never shown a known host ID (see
   * `guest_view_of_host_entries`), so a number it names is virtual first. */
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

/* The host ID of the task whose virtual ID is `identity`, or -1. Unlike
 * `host_identity_for_guest_entries`, a number that is only some task's host ID
 * is not accepted: whether the guest's number happens to equal a host ID
 * depends on host PID allocation, so accepting it would make the outcome
 * follow host state. */
static inline int32_t host_identity_for_virtual_entries(
    const virtual_identity_t* identities,
    size_t count,
    int32_t identity) {
  size_t i;

  if (identity <= 0)
    return identity;
  for (i = 0; i < count; ++i) {
    if (identities[i].virtual_id == identity)
      return identities[i].host;
  }
  return -1;
}

/* How the client's `virtualize_host_identity` shows host ID `host` to the
 * guest, as wait4, waitid, getpgrp, getpgid and getsid report it: a known host
 * ID as its virtual ID, always, and an unknown one unchanged unless that
 * number is also one of the guest's virtual IDs, in which case it is shown as
 * 0, the way Linux shows an ID from outside the caller's PID namespace.
 *
 * The two number spaces overlap whenever the run has its own PID namespace:
 * there, host IDs are small too. So no host ID may be recognised by its value
 * alone, and no host ID may be shown under a number that names another guest
 * task. Applying this to a value that is already virtual is therefore wrong,
 * and callers translate each host result exactly once. */
static inline int32_t guest_view_of_host_entries(
    const virtual_identity_t* identities,
    size_t count,
    int32_t host) {
  size_t i;

  if (host <= 0)
    return host;
  for (i = 0; i < count; ++i) {
    if (identities[i].host == host)
      return identities[i].virtual_id;
  }
  for (i = 0; i < count; ++i) {
    if (identities[i].virtual_id == host)
      return 0;
  }
  return host;
}

/* Linux's `struct f_owner_ex` and its owner kinds, spelled out so this header
 * does not depend on `_GNU_SOURCE`. */
typedef struct {
  int32_t type;
  int32_t pid;
} fcntl_owner_ex_t;

#define FCNTL_OWNER_TID 0
#define FCNTL_OWNER_PID 1
#define FCNTL_OWNER_PGRP 2

/* Outside Linux's PID range (`PID_MAX_LIMIT` is 4194304), so the kernel finds
 * no such task or group. Substituting it for an owner the guest cannot have
 * named lets the kernel validate the descriptor and command in its own order
 * and then fail with ESRCH, rather than resolving the guest's number to
 * whatever host task or group happens to carry it. */
#define FCNTL_OWNER_IMPOSSIBLE_PID INT32_MAX

/* What a process-group owner may name besides the guest's virtual IDs, read
 * from the host by the caller: the calling process's own host process group,
 * or 0 when unknown. */
typedef struct {
  int32_t caller_group;
} fcntl_group_view_t;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(hermit-3955): Review DBT fcntl owner translation.
/* Translate the guest ID an `F_SETOWN_EX` owner of kind `type` names into the
 * host ID the kernel must see. Returns false, leaving `*pid` unchanged, when
 * the kernel must see the guest's value as is: an owner kind Linux rejects
 * (EINVAL), zero, which clears the owner, or a negative ID (ESRCH).
 *
 * A thread or process must be one of the guest's virtual IDs. A process group
 * is named by a number Linux resolves with find_vpid: any ID still in use,
 * including a non-leader's PID (accepted, though no group answers to it) and
 * a group whose leader has exited while members remain. So a group is either
 * the caller's own group, numbered as getpgrp shows it (this includes a group
 * led from outside the guest, such as the launcher's, which the guest sees
 * under its raw host ID unless that number is also a virtual ID, when it sees
 * 0 and cannot name it, as across a PID namespace), or a virtual ID,
 * translated like a task's; the kernel then decides as it does natively. Anything else becomes `FCNTL_OWNER_IMPOSSIBLE_PID`, so the
 * kernel reports ESRCH whatever host tasks and groups exist. */
static inline bool translate_fcntl_owner_entries(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t type,
    int32_t* pid) {
  int32_t host;

  if (type != FCNTL_OWNER_TID && type != FCNTL_OWNER_PID &&
      type != FCNTL_OWNER_PGRP)
    return false;
  if (*pid <= 0)
    return false;
  if (type == FCNTL_OWNER_PGRP && groups->caller_group > 0 &&
      *pid ==
          guest_view_of_host_entries(
              identities, count, groups->caller_group)) {
    *pid = groups->caller_group;
    return true;
  }
  host = host_identity_for_virtual_entries(identities, count, *pid);
  *pid = host > 0 ? host : FCNTL_OWNER_IMPOSSIBLE_PID;
  return true;
}

/* The guest's number for host owner `host` of kind `type`, the inverse of
 * `translate_fcntl_owner_entries` so that an owner read back and set again
 * names the same task or group. That is the getpgrp view whatever the kind:
 * it shows every known task or group by its virtual ID, one-to-one, so the
 * caller's own group reads back under the number that sets it.
 *
 * An owner the guest has no number for, one from outside the guest whose host
 * ID is also a virtual ID, reads back as 0, as Linux's F_GETOWN reports an
 * owner outside the caller's PID namespace; setting 0 clears the owner. */
static inline int32_t guest_owner_for_host_entries(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t type,
    int32_t host) {
  (void)groups;
  (void)type;
  return guest_view_of_host_entries(identities, count, host);
}

/* `F_SETOWN`'s encoding of a host owner, as the guest sees it. */
static inline int32_t guest_setown_for_host_entries(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t who) {
  if (who > 0)
    return guest_owner_for_host_entries(
        identities, count, groups, FCNTL_OWNER_PID, who);
  if (who < 0 && who != INT32_MIN)
    return -guest_owner_for_host_entries(
        identities, count, groups, FCNTL_OWNER_PGRP, -who);
  return who;
}

/* `F_SETOWN` spells the same owner as one integer: a positive process ID or a
 * negated process-group ID. INT32_MIN has no negation; Linux rejects it with
 * EINVAL, so it passes through untouched. */
static inline bool translate_fcntl_setown_entries(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t* who) {
  int32_t pid;

  if (*who > 0) {
    return translate_fcntl_owner_entries(
        identities, count, groups, FCNTL_OWNER_PID, who);
  }
  if (*who == 0 || *who == INT32_MIN)
    return false;
  pid = -*who;
  if (!translate_fcntl_owner_entries(
          identities, count, groups, FCNTL_OWNER_PGRP, &pid))
    return false;
  *who = -pid;
  return true;
}

#endif
