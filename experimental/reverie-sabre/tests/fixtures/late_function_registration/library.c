/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
__attribute__((noinline, patchable_function_entry(32, 0))) ssize_t
late_probe(unsigned char* buf, size_t len, unsigned flags) {
  if (len != 4 || flags != 0x1357) {
    errno = EINVAL;
    return -1;
  }
  buf[0] = 0x6a;
  errno = EDOM;
  return 37;
}
__attribute__((noinline, patchable_function_entry(32, 0))) ssize_t
late_probe_two(unsigned char* buf, size_t len, unsigned flags) {
  return late_probe(buf, len, flags);
}
__attribute__((noinline)) long late_raw_getpid(void) {
  long result;
  __asm__ volatile("syscall" : "=a"(result) : "a"(39) : "rcx", "r11", "memory");
  return result;
}

bool late_guest_ran;

extern __typeof(late_probe) late_probe_alias
    __attribute__((alias("late_probe")));

/* These belong to the guest and its ordinary dependency, not the plugin. */
extern bool calling_from_plugin(void) __attribute__((weak));
__attribute__((destructor)) static void guest_finalizer(void) {
  if (!late_guest_ran)
    return;
  assert(calling_from_plugin != NULL);
  assert(!calling_from_plugin());
}
