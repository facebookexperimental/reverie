/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Regression fixture for the DBT `Guest::backtrace` path. It issues a getpid
 * syscall from a deliberately nested chain of non-inlined functions
 * (main -> level1 -> level2 -> raw_getpid), so a correct in-process frame-pointer
 * walk recovers several frames rather than only the top one. The
 * HERMIT_DBT_TEST_BACKTRACE tool intercepts the getpid, captures the guest
 * backtrace (seeded from the guest register file and walked over the guest's own
 * stack, since the DBT Tool runs in the guest address space), and emits a line
 * reporting whether a backtrace was produced and its frame count.
 *
 * getpid is issued through an inline `syscall` instruction so the trap's
 * instruction pointer lands inside this fixture's own frame-pointer-having code,
 * keeping the saved-rbp chain fully walkable back through the nested callers.
 * Compile with `-O0 -fno-omit-frame-pointer` (see test-example-tools.sh) so the
 * frame pointers the walk depends on are actually present.
 */

#include <stdio.h>

// TODO-HUMAN-REVIEW(PR-ratchet16): Review the DBT backtrace probe fixture.

// SYS_getpid on x86-64.
#define SYS_GETPID 39

static long __attribute__((noinline)) raw_getpid(void) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(SYS_GETPID)
                   : "rcx", "r11", "memory");
  return ret;
}

static long __attribute__((noinline)) level2(void) {
  return raw_getpid();
}

static long __attribute__((noinline)) level1(void) {
  return level2();
}

int main(void) {
  long pid = level1();
  printf("BACKTRACE-GUEST pid=%ld\n", pid);
  return 0;
}
