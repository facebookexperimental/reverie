/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Three raw syscalls in a row between labelled nops, for the tests
 * that single-step over each with gdb: rt_sigprocmask (a query that
 * changes nothing), rt_sigaction (a query that installs nothing),
 * and getppid. The labels and the word are global symbols; the test
 * builds this file with -no-pie, so their symbol values are their
 * run-time addresses. A step over any of the syscalls must stop at
 * the next label, never run on.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

volatile uint64_t reverie_watched;
static struct {
  uint64_t words[4];
} act_buf;

int main(void) {
  long ret;
  register long r10 __asm__("r10") = 8;
  /* rt_sigprocmask(SIG_BLOCK=0, NULL, &old, 8): a pure query. */
  __asm__ volatile(
      ".globl reverie_before_procmask\n"
      "reverie_before_procmask:\n"
      "  nop\n"
      ".globl reverie_procmask\n"
      "reverie_procmask:\n"
      "  syscall\n"
      ".globl reverie_after_procmask\n"
      "reverie_after_procmask:\n"
      "  nop\n"
      : "=a"(ret)
      : "a"((long)SYS_rt_sigprocmask), "D"((long)0), "S"((long)0),
        "d"((long)&act_buf), "r"(r10)
      : "rcx", "r11", "memory");
  if (ret != 0) {
    return 2;
  }
  /* rt_sigaction(SIGUSR1, NULL, &old, 8): a pure query. */
  __asm__ volatile(
      ".globl reverie_before_sigaction\n"
      "reverie_before_sigaction:\n"
      "  nop\n"
      ".globl reverie_sigaction\n"
      "reverie_sigaction:\n"
      "  syscall\n"
      ".globl reverie_after_sigaction\n"
      "reverie_after_sigaction:\n"
      "  nop\n"
      : "=a"(ret)
      : "a"((long)SYS_rt_sigaction), "D"((long)SIGUSR1), "S"((long)0),
        "d"((long)&act_buf), "r"(r10)
      : "rcx", "r11", "memory");
  if (ret != 0) {
    return 3;
  }
  /* getppid. */
  __asm__ volatile(
      ".globl reverie_before_getppid\n"
      "reverie_before_getppid:\n"
      "  nop\n"
      ".globl reverie_getppid\n"
      "reverie_getppid:\n"
      "  syscall\n"
      ".globl reverie_after_getppid\n"
      "reverie_after_getppid:\n"
      "  nop\n"
      : "=a"(ret)
      : "a"((long)SYS_getppid)
      : "rcx", "r11", "memory");
  if (ret <= 0) {
    return 4;
  }
  return 0;
}
