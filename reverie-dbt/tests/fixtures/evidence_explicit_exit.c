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

int main(void) {
  (void)syscall(SYS_exit, 0);
  __builtin_unreachable();
}
