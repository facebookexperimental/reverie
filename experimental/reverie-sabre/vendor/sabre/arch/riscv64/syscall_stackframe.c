/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "syscall_stackframe.h"

#include <stddef.h>

struct syscall_stackframe {
  void *rbp_stackalign;
  void *r15;
  void *r14;
  void *r13;
  void *r12;
  void *r11;
  void *r10;
  void *r8;
  void *rdi;
  void *rsi;
  void *rdx;
  void *rcx;
  void *rbx;
  void *rbp_prologue;
  // trampoline
  void *fake_ret;
  void *ret;
} __packed;

void *get_syscall_return_address(struct syscall_stackframe *stack_frame) {
  return stack_frame->ret;
}

size_t get_offsetof_syscall_return_address(void) {
  return offsetof(struct syscall_stackframe, ret);
}
