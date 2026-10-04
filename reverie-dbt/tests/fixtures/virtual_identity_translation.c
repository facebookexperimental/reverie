/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

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

  return 0;
}
