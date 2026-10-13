/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "virtual_identity.h"

static int expect_translation(
    const virtual_identity_t* identities,
    size_t count,
    int32_t guest,
    int32_t expected) {
  int32_t actual = host_identity_for_guest_entries(identities, count, guest);
  if (actual == expected)
    return 0;

  fprintf(
      stderr,
      "guest identity %d resolved to %d, expected %d\n",
      guest,
      actual,
      expected);
  return 1;
}

static int expect_wait_translation(
    translated_child_wait_t* wait,
    int32_t sysnum,
    int32_t physical_pid,
    int32_t expected,
    int should_translate) {
  int32_t actual = physical_pid;
  int32_t translated;
  int did_translate =
      consume_translated_child_wait(wait, sysnum, physical_pid, &translated);
  if (did_translate)
    actual = translated;
  if (did_translate == should_translate && actual == expected)
    return 0;

  fprintf(
      stderr,
      "child wait sysnum %d target %d translated=%d to %d, expected "
      "translated=%d target=%d\n",
      sysnum,
      physical_pid,
      did_translate,
      actual,
      should_translate,
      expected);
  return 1;
}

static int expect_setown(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t guest,
    int32_t expected,
    bool should_translate) {
  int32_t actual = guest;
  bool did_translate =
      translate_fcntl_setown_entries(identities, count, groups, &actual);
  if (did_translate == should_translate && actual == expected)
    return 0;

  fprintf(
      stderr,
      "F_SETOWN %d (caller group %d) translated=%d to %d, expected "
      "translated=%d to %d\n",
      guest,
      groups->caller_group,
      did_translate,
      actual,
      should_translate,
      expected);
  return 1;
}

static int expect_owner_ex(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t type,
    int32_t guest,
    int32_t expected,
    bool should_translate) {
  int32_t actual = guest;
  bool did_translate =
      translate_fcntl_owner_entries(identities, count, groups, type, &actual);
  if (did_translate == should_translate && actual == expected)
    return 0;

  fprintf(
      stderr,
      "F_SETOWN_EX type %d pid %d (caller group %d) translated=%d to %d, "
      "expected translated=%d to %d\n",
      type,
      guest,
      groups->caller_group,
      did_translate,
      actual,
      should_translate,
      expected);
  return 1;
}

static int expect_readback(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t host_who,
    int32_t expected) {
  int32_t actual =
      guest_setown_for_host_entries(identities, count, groups, host_who);
  if (actual == expected)
    return 0;

  fprintf(
      stderr,
      "F_GETOWN host %d (caller group %d) read back as %d, expected %d\n",
      host_who,
      groups->caller_group,
      actual,
      expected);
  return 1;
}

/* An owner read back and set again must name the same host task or group. */
static int expect_round_trip(
    const virtual_identity_t* identities,
    size_t count,
    const fcntl_group_view_t* groups,
    int32_t host_who) {
  int32_t guest =
      guest_setown_for_host_entries(identities, count, groups, host_who);
  int32_t again = guest;
  translate_fcntl_setown_entries(identities, count, groups, &again);
  if (again == host_who)
    return 0;

  fprintf(
      stderr,
      "host owner %d (caller group %d) read back as %d, which sets %d\n",
      host_who,
      groups->caller_group,
      guest,
      again);
  return 1;
}

int main(void) {
  const virtual_identity_t identities[] = {
      {.host = 4, .virtual_id = 3},
      {.host = 100, .virtual_id = 4},
  };
  const size_t count = sizeof(identities) / sizeof(identities[0]);

  if (expect_translation(identities, count, 3, 4) != 0)
    return 1;
  if (expect_translation(identities, count, 4, 100) != 0)
    return 2;
  if (expect_translation(identities, count, 100, 100) != 0)
    return 3;
  if (expect_translation(identities, count, 200, -1) != 0)
    return 4;
  if (expect_translation(identities, count, 0, 0) != 0)
    return 5;
  if (expect_translation(identities, count, -1, -1) != 0)
    return 6;

  /* A signal before syscall entry has no translated-wait record. Even though
   * guest PID 4 is also the host PID of virtual PID 3 above, it must remain 4.
   */
  translated_child_wait_t wait = {0};
  if (expect_wait_translation(&wait, 61, 4, 4, 0) != 0)
    return 7;

  wait.pending = true;
  wait.sysnum = 61;
  wait.physical_pid = 100;
  wait.virtual_pid = 4;
  if (expect_wait_translation(&wait, 61, 100, 4, 1) != 0)
    return 8;
  if (wait.pending)
    return 9;

  /* A record for another syscall or target cannot translate by numeric
   * coincidence and remains available for the actual interrupted wait. */
  wait.pending = true;
  wait.sysnum = 247;
  wait.physical_pid = 100;
  wait.virtual_pid = 4;
  if (expect_wait_translation(&wait, 61, 100, 100, 0) != 0 ||
      expect_wait_translation(&wait, 247, 4, 4, 0) != 0 || !wait.pending)
    return 10;

  /* fcntl owners, with host IDs that do not collide with virtual IDs. A thread
   * or process must be a virtual ID: anything else, including 1100, which is
   * only some task's host ID, becomes an ID outside Linux's PID range so the
   * kernel reports ESRCH whatever host tasks exist. Zero, INT32_MIN, negative
   * pids and invalid owner kinds reach the kernel unchanged so it rejects or
   * clears them itself. */
  const virtual_identity_t owners[] = {
      {.host = 1004, .virtual_id = 3},
      {.host = 1100, .virtual_id = 4},
  };
  const size_t owner_count = sizeof(owners) / sizeof(owners[0]);
  const int32_t impossible = FCNTL_OWNER_IMPOSSIBLE_PID;
  /* The caller is in the group virtual task 3 (host 1004) leads. */
  fcntl_group_view_t own = {1004};
  if (expect_setown(owners, owner_count, &own, 3, 1004, true) != 0 ||
      expect_setown(owners, owner_count, &own, 4, 1100, true) != 0 ||
      expect_setown(owners, owner_count, &own, 1100, impossible, true) != 0 ||
      expect_setown(owners, owner_count, &own, 200, impossible, true) != 0 ||
      expect_setown(owners, owner_count, &own, -3, -1004, true) != 0 ||
      expect_setown(owners, owner_count, &own, 0, 0, false) != 0 ||
      expect_setown(owners, owner_count, &own, INT32_MIN, INT32_MIN, false) !=
          0)
    return 11;
  if (expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_TID, 4, 1100, true) != 0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_PID, 3, 1004, true) != 0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_PGRP, 3, 1004, true) != 0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_PID, 1100, impossible, true) !=
          0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_TID, 200, impossible, true) !=
          0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_PID, 0, 0, false) != 0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_PID, -3, -3, false) != 0 ||
      expect_owner_ex(owners, owner_count, &own, 7, 3, 3, false) != 0)
    return 12;

  /* A group is named the way Linux's find_vpid resolves it: any ID in use. The
   * PID of virtual task 4 (host 1100) is translated even though task 4 leads
   * no group (Linux accepts it and later reports no owner), as is the ID of a
   * leader that has exited, whose entry stays in the table. 200 is no ID the
   * guest has, so it is ESRCH. */
  if (expect_setown(owners, owner_count, &own, -4, -1100, true) != 0 ||
      expect_setown(owners, owner_count, &own, -200, -impossible, true) != 0 ||
      expect_owner_ex(
          owners, owner_count, &own, FCNTL_OWNER_PGRP, 200, impossible, true) !=
          0)
    return 13;

  /* The caller's group is led from outside the guest (host group 500, not a
   * guest task), so getpgrp shows it raw as 500: naming 500 reaches that
   * group, any other unknown number stays ESRCH, and virtual task 3 is still
   * translated. */
  fcntl_group_view_t inherited = {500};
  if (expect_setown(owners, owner_count, &inherited, -500, -500, true) != 0 ||
      expect_setown(
          owners, owner_count, &inherited, -600, -impossible, true) != 0 ||
      expect_setown(owners, owner_count, &inherited, -3, -1004, true) != 0 ||
      expect_owner_ex(
          owners, owner_count, &inherited, FCNTL_OWNER_PGRP, 500, 500, true) !=
          0)
    return 14;

  /* Collision: the launcher's group is host 3, numerically also the guest's
   * virtual ID 3 (host 1004). getpgrp shows the caller's group as 0, as Linux
   * shows a group from outside the caller's PID namespace, because 3 names
   * task 3: -3 reaches task 3's group, host 1004, and never host group 3. */
  fcntl_group_view_t collision = {3};
  if (guest_view_of_host_entries(owners, owner_count, 3) != 0 ||
      expect_setown(owners, owner_count, &collision, -3, -1004, true) != 0 ||
      expect_owner_ex(
          owners, owner_count, &collision, FCNTL_OWNER_PGRP, 3, 1004, true) !=
          0 ||
      expect_setown(owners, owner_count, &collision, 3, 1004, true) != 0)
    return 15;

  /* A guest-led group whose host ID collides with a virtual ID. In the first
   * table host 4 (virtual task 3) leads a group, and 4 is also virtual task
   * 4's ID. A known host ID is always shown as its virtual ID, so getpgrp
   * shows that group as 3: the caller in it names it -3 and reaches host
   * group 4, while -4 names task 4's host 100. */
  fcntl_group_view_t guest_led = {4};
  if (guest_view_of_host_entries(identities, count, 4) != 3 ||
      guest_view_of_host_entries(identities, count, 100) != 4 ||
      guest_view_of_host_entries(identities, count, 500) != 500 ||
      expect_setown(identities, count, &guest_led, -3, -4, true) != 0 ||
      expect_setown(identities, count, &guest_led, -4, -100, true) != 0)
    return 16;

  /* Read-back inverts the setter. Host and virtual IDs overlap here: virtual
   * 3 is host 4 and virtual 4 is host 5, both leading groups, and the caller
   * is in host group 5, which getpgrp shows as 4. Group host 4 reads back as
   * -3 (not -4, which getpgrp's view would give and which names the caller's
   * group), and every owner survives being read back and set again. */
  const virtual_identity_t overlap[] = {
      {.host = 4, .virtual_id = 3},
      {.host = 5, .virtual_id = 4},
  };
  fcntl_group_view_t in_5 = {5};
  if (expect_setown(overlap, 2, &in_5, -3, -4, true) != 0 ||
      expect_readback(overlap, 2, &in_5, -4, -3) != 0 ||
      expect_readback(overlap, 2, &in_5, -5, -4) != 0 ||
      expect_readback(overlap, 2, &in_5, 4, 3) != 0 ||
      expect_readback(overlap, 2, &in_5, 5, 4) != 0 ||
      expect_round_trip(overlap, 2, &in_5, -4) != 0 ||
      expect_round_trip(overlap, 2, &in_5, -5) != 0 ||
      expect_round_trip(overlap, 2, &in_5, 4) != 0 ||
      expect_round_trip(overlap, 2, &in_5, 5) != 0)
    return 17;

  /* The other tables round-trip too: the caller's own group, other tasks and
   * groups, a group led from outside the guest, task 3 and its group while
   * the launcher's group collides with virtual ID 3, and no owner at all. */
  if (expect_round_trip(owners, owner_count, &own, -1004) != 0 ||
      expect_round_trip(owners, owner_count, &own, -1100) != 0 ||
      expect_round_trip(owners, owner_count, &own, 1100) != 0 ||
      expect_round_trip(owners, owner_count, &inherited, -500) != 0 ||
      expect_round_trip(owners, owner_count, &inherited, -1004) != 0 ||
      expect_round_trip(owners, owner_count, &collision, -1004) != 0 ||
      expect_round_trip(owners, owner_count, &collision, 1004) != 0 ||
      expect_readback(owners, owner_count, &own, 0, 0) != 0)
    return 18;

  /* Every group the guest has a number for has its own number: task 4's group
   * (host 100) reads back as -4 and the caller's group (host 4) as -3, and
   * both survive being set again. The one owner without a number is the
   * launcher's group on a collision, which reads back as 0, as Linux's
   * F_GETOWN reports an owner outside the caller's PID namespace. */
  if (expect_readback(identities, count, &guest_led, -100, -4) != 0 ||
      expect_readback(identities, count, &guest_led, -4, -3) != 0 ||
      expect_round_trip(identities, count, &guest_led, -100) != 0 ||
      expect_round_trip(identities, count, &guest_led, -4) != 0 ||
      expect_readback(owners, owner_count, &collision, -1004, -3) != 0 ||
      expect_readback(owners, owner_count, &collision, -3, 0) != 0)
    return 19;

  /* The run's own PID namespace: host and virtual IDs are both small and
   * overlap. Here virtual task 5 is host 11 and virtual task 11 is host 20,
   * the shape that made wait4 report host 11 as if it were task 11. A known
   * host ID is always its virtual ID; an unknown host ID that is also a
   * virtual ID is 0, never that other task; any other unknown one stays. */
  const virtual_identity_t namespace_ids[] = {
      {.host = 11, .virtual_id = 5},
      {.host = 20, .virtual_id = 11},
  };
  if (guest_view_of_host_entries(namespace_ids, 2, 11) != 5 ||
      guest_view_of_host_entries(namespace_ids, 2, 20) != 11 ||
      guest_view_of_host_entries(namespace_ids, 2, 5) != 0 ||
      guest_view_of_host_entries(namespace_ids, 2, 7) != 7 ||
      expect_translation(namespace_ids, 2, 5, 11) != 0 ||
      expect_translation(namespace_ids, 2, 11, 20) != 0)
    return 20;

  return 0;
}
