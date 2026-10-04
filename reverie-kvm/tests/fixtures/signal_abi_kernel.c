/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stddef.h>

#include <asm/sigcontext.h>
#include <asm/signal.h>
#include <asm/ucontext.h>

extern int printf(const char*, ...);

struct kernel_rt_sigframe_probe {
  void* pretcode;
  struct ucontext uc;
  unsigned char info[128];
};

int main(void) {
  printf("kernel_sigset_size=%zu\n", sizeof(sigset_t));
  printf("stack_size=%zu\n", sizeof(stack_t));
  printf("sigcontext_size=%zu\n", sizeof(struct sigcontext));
  printf("sigcontext_r8=%zu\n", offsetof(struct sigcontext, r8));
  printf("sigcontext_rdi=%zu\n", offsetof(struct sigcontext, rdi));
  printf("sigcontext_rsp=%zu\n", offsetof(struct sigcontext, rsp));
  printf("sigcontext_rip=%zu\n", offsetof(struct sigcontext, rip));
  printf("sigcontext_eflags=%zu\n", offsetof(struct sigcontext, eflags));
  printf("sigcontext_cs=%zu\n", offsetof(struct sigcontext, cs));
  printf("sigcontext_ss=%zu\n", offsetof(struct sigcontext, ss));
  printf("sigcontext_fpstate=%zu\n", offsetof(struct sigcontext, fpstate));
  printf("sigcontext_reserved1=%zu\n", offsetof(struct sigcontext, reserved1));
  printf("ucontext_size=%zu\n", sizeof(struct ucontext));
  printf("ucontext_stack=%zu\n", offsetof(struct ucontext, uc_stack));
  printf("ucontext_mcontext=%zu\n", offsetof(struct ucontext, uc_mcontext));
  printf("ucontext_sigmask=%zu\n", offsetof(struct ucontext, uc_sigmask));
  printf("rt_sigframe_size=%zu\n", sizeof(struct kernel_rt_sigframe_probe));
  printf(
      "rt_sigframe_ucontext=%zu\n",
      offsetof(struct kernel_rt_sigframe_probe, uc));
  printf(
      "rt_sigframe_siginfo=%zu\n",
      offsetof(struct kernel_rt_sigframe_probe, info));
  printf("xstate_size=%zu\n", sizeof(struct _xstate));
  printf(
      "xstate_sw_reserved=%zu\n",
      offsetof(struct _xstate, fpstate.sw_reserved));
  printf("xstate_header=%zu\n", offsetof(struct _xstate, xstate_hdr));
  printf("xstate_ymmh=%zu\n", offsetof(struct _xstate, ymmh));
  return 0;
}
