/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Regression fixture for the DBT `Guest::ppid` path (and the `is_root_process`
 * default built on it). It issues a getpid syscall, which the
 * HERMIT_DBT_TEST_PPID tool intercepts to emit a line reporting the tool-observed
 * real pid, the `Guest::ppid` result, and `is_root_process`. Because the
 * DynamoRIO backend runs the Reverie Tool runtime only in the root of the traced
 * tree (copied/forked children are served by the native-only identity/policy
 * path and never dispatch to a Rust Tool), the tool-observable case here is the
 * tree root, which must report no in-tree parent (`ppid == None`, root=1). This
 * exercises the full native->Rust ppid surface end to end: `in_tree_parent_pid`
 * -> `reverie_dbt_runtime_thread_init` -> `PROCESS_PPID` -> `current_ppid` ->
 * `Guest::ppid`. The non-root case (a real in-tree parent) is covered by the
 * `reverie-dbt` unit tests, which drive `current_ppid`/`Guest::ppid` with a
 * positive parent pid directly.
 *
 * getpid is issued through the raw syscall interface so no libc getpid cache can
 * hide it from the tool.
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

// TODO-HUMAN-REVIEW(PR-ratchet11): Review the DBT ppid probe fixture.
int main(void) {
  syscall(SYS_getpid);
  return 0;
}
