/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>

/* One getpid site. The first call reaches the host through seccomp and the
   later calls through the site's LiteInst hook, whose trap is an int3. */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_stepped_getpid\n"
    ".type reverie_liteinst_stepped_getpid,@function\n"
    "reverie_liteinst_stepped_getpid:\n"
    ".cfi_startproc\n"
    "mov $39, %eax\n"
    "syscall\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_stepped_getpid, "
    ".-reverie_liteinst_stepped_getpid\n");

extern long reverie_liteinst_stepped_getpid(void);

/* The value that the test's Tool gives every getpid. */
#define ANSWER 0x4242

int main(void) {
  unsigned calls = 64;
  unsigned wrong = 0;
  long last_wrong = 0;
  for (unsigned i = 0; i < calls; ++i) {
    long observed = reverie_liteinst_stepped_getpid();
    if (observed != ANSWER) {
      ++wrong;
      last_wrong = observed;
    }
  }
  printf("calls=%u wrong=%u last_wrong=%ld\n", calls, wrong, last_wrong);
  return 0;
}
