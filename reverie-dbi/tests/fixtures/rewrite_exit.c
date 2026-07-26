/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

// TODO-HUMAN-REVIEW(PR-154): Review the deferred lifecycle rewrite ratchet.
int main(void) {
  long result = syscall(SYS_getpid);
  (void)result;

  // The DBI regression tool must replace getpid with exit_group(42).
  return 0;
}
