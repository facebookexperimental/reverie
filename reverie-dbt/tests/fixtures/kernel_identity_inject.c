/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* SetRegTool executes each query once through Guest::inject, comparing it with
 * a raw kernel sample taken on the same application callback thread, and with
 * Guest::pid/tid for those two queries. Guest::ppid has separate root semantics.
 * These
 * requests do not enter the separate completed-Tool sentinel getter branches.
 */
int main(void) {
  const long queries[] = {SYS_getpid, SYS_getppid, SYS_gettid};
  int failed = 0;
  for (unsigned int i = 0; i < sizeof(queries) / sizeof(queries[0]); ++i) {
    if (prctl(0x4b494421, queries[i], 0L, 0L, 0L) <= 0)
      failed = 1;
  }
  if (failed) {
    fputs("kernel identity injection mismatch\n", stderr);
    return 1;
  }
  puts("kernel-identity-inject=ok");
  return 0;
}
