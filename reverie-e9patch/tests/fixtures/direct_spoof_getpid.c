/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sys/syscall.h>

int main(void) {
  register long result __asm__("rax") = SYS_getpid;
  __asm__ volatile("syscall" : "+a"(result) : : "rcx", "r11", "memory");
  return result == 424242 ? 0 : 1;
}
