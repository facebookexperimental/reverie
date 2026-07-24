/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

#include <stdbool.h>

// Sanitizers intercept various function calls, look here:
// https://github.com/llvm/llvm-project/blob/b3ca4f34311b87345cf87bfdd0343045eed22f5c/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc#L5185
// In various TLS models _Thread_local variables calls __tls_get_addr to resolve
// its value. Unfortunately these modes crash LLVM sanitizers in the above
// function. The LLVM sanitizers themselves actually use initial-exec to avoid
// this problem. initial-exec doesn't go through __tls_get_addr but rather uses
// the %fs register directly.
// In the current setup, we need "initial-exec" as runtime_syscall_router will
// be called during pthread initialization which will happen before the
// sanitizers initialization phase.
// TODO(andronat): Will the following create any issues with other libraries?
// e.g. overlapping offsets and thus writting/reading from wrong variables?
static _Thread_local bool from_plugin
    __attribute__((tls_model("initial-exec"))) = false;

bool calling_from_plugin() { return from_plugin; }
void enter_plugin() { from_plugin = true; }
void exit_plugin() { from_plugin = false; }

// vDSO cannot be used in preinit: https://reviews.llvm.org/D40679. So when a
// SaBRe plugin makes a vDSO call, it instantly crashes.
//
// vDSO are initialized in __vdso_platform_setup () at
// ../sysdeps/unix/sysv/linux/x86_64/init-first.c:36
//
// Newer glibc 2.31 fixes this issue:
// 1) https://sourceware.org/bugzilla/show_bug.cgi?id=24967
// 2)
// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=1bdda52fe92fd01b424cd6fbb63e3df96a95015c
// 3) https://sourceware.org/pipermail/glibc-cvs/2020q1/068454.html
//
// Unfortunately, we can't rely on sanitizer interceptors either as the above
// patch is not currently introduced in Ubuntu 18.04.
//
// Until them, we used a guard that will change value after glibc is
// initialized.

static _Thread_local bool vdso_ready
    __attribute__((tls_model("initial-exec"))) = false;

void vdso_are_ready() __attribute__((constructor));
void vdso_are_ready() { vdso_ready = true; }

bool is_vdso_ready() { return vdso_ready; }

__attribute__((weak)) void post_clone_hook(void *ctx) {
  (void)ctx; // unused
  return;
}
