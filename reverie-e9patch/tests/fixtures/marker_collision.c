/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdint.h>
#include <sys/syscall.h>

struct fake_frame {
  uint64_t words[18];
};

int main(void) {
  struct fake_frame frame = {0};
  frame.words[15] = SYS_read;
  frame.words[17] = 0x401000;
  __asm__ volatile(
      "movabs $0x7265766539653970, %%rax\n\t"
      "mov %0, %%rdi\n\t"
      "int3"
      :
      : "r"(&frame)
      : "rax", "rdi", "memory");
  return 0;
}
