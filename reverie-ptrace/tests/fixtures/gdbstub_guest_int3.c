/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A guest that executes its own int3, with SIGTRAP's default disposition,
 * then exits 0. Under a debugger, as natively, the trap stops the guest and is
 * reported to GDB: `continue` drops the signal and the guest exits 0, and
 * `signal SIGTRAP` passes it on, which kills the guest.
 *
 * It first sets its soft RLIMIT_CORE to 1, where the hard limit allows, so the
 * kernel writes no core for that death (see tests/fatal_signal_exit_hook.rs).
 *
 * The labels are global symbols. The test builds this file with -no-pie, so
 * their symbol values are their run-time addresses.
 */

#include <sys/resource.h>

int main(void) {
  struct rlimit limit;
  if (getrlimit(RLIMIT_CORE, &limit) == 0) {
    limit.rlim_cur = limit.rlim_max < 1 ? limit.rlim_max : 1;
    setrlimit(RLIMIT_CORE, &limit);
  }
  __asm__ volatile(
      ".globl reverie_guest_int3\n"
      "reverie_guest_int3:\n"
      "  int3\n"
      ".globl reverie_after_guest_int3\n"
      "reverie_after_guest_int3:\n"
      "  nop\n");
  return 0;
}
