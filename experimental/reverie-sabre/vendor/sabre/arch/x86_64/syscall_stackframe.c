/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "syscall_stackframe.h"

#include <stddef.h>
#include <stdint.h>

struct syscall_stackframe {
  void *rbp_stackalign;
  void *r15;
  void *r14;
  void *r13;
  void *r12;
  void *r11;
  void *r10;
  void *r9;
  void *r8;
  void *rdi;
  void *rsi;
  void *rdx;
  void *rcx;
  void *rbx;
  void *rbp_prologue;
  unsigned long rflags;
  // trampoline
  void *fake_ret;
  void *ret;
} __packed;

/* Optional initial-image supervisor ABI. Read-only integer data avoids
 * linking the plugin runtime/allocator into the coordinator. Keep this in the
 * translation unit that defines the actual frame: no duplicated offsets.
 * This describes a full assembly frame, never the SIGILL return-only shim.
 */
__attribute__((used, visibility("default")))
const uint64_t sbr_bootstrap_frame_layout_v1[9] = {
    1,
    sizeof(struct syscall_stackframe),
    offsetof(struct syscall_stackframe, rdi),
    offsetof(struct syscall_stackframe, rsi),
    offsetof(struct syscall_stackframe, rdx),
    offsetof(struct syscall_stackframe, fake_ret),
    offsetof(struct syscall_stackframe, ret),
    sizeof(uintptr_t),
    9,
};

/* Version 2 appends r10, the fourth syscall argument, so the supervisor can
 * authenticate a forwarded prlimit64's output pointer. Version 1 stays for
 * supervisors that predate it.
 */
__attribute__((used, visibility("default")))
const uint64_t sbr_bootstrap_frame_layout_v2[10] = {
    2,
    sizeof(struct syscall_stackframe),
    offsetof(struct syscall_stackframe, rdi),
    offsetof(struct syscall_stackframe, rsi),
    offsetof(struct syscall_stackframe, rdx),
    offsetof(struct syscall_stackframe, fake_ret),
    offsetof(struct syscall_stackframe, ret),
    sizeof(uintptr_t),
    10,
    offsetof(struct syscall_stackframe, r10),
};

void *get_syscall_return_address(struct syscall_stackframe *stack_frame) {
  return stack_frame->ret;
}

size_t get_offsetof_syscall_return_address(void) {
  return offsetof(struct syscall_stackframe, ret);
}
