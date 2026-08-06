/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Regression fixture for the DBT `Guest::set_regs` path. It loads a known value
 * into the callee-saved r15 register, issues a getpid syscall (which the
 * HERMIT_DBT_TEST_SET_REG tool intercepts to overwrite r15 via set_regs), then
 * reads r15 back. Because r15 is preserved across the syscall boundary, the
 * value observed afterwards is exactly what the tool wrote, proving set_regs
 * reached the application register file.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>

// TODO-HUMAN-REVIEW(PR-167): Review the DBT set_regs probe fixture.
int main(void) {
  uint64_t observed = 0;
  __asm__ volatile(
      "movq $0x1111111111111111, %%r15\n\t"
      "movq $39, %%rax\n\t" /* SYS_getpid */
      "syscall\n\t"
      "movq %%r15, %0\n\t"
      : "=r"(observed)
      :
      : "rax", "rcx", "r11", "r15", "memory");
  printf("r15=0x%016llx\n", (unsigned long long)observed);
  return 0;
}
