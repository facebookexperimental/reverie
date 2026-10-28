/* Copyright © 2026 Meta Platforms, Inc. and affiliates.
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Success" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#define _GNU_SOURCE

#include <asm/prctl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  unsigned long fs = 0;
  if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fs) != 0 || fs == 0) {
    return 1;
  }
  if (syscall(SYS_arch_prctl, ARCH_SET_FS, fs) != 0) {
    return 2;
  }

  puts("Success");
  return 0;
}
