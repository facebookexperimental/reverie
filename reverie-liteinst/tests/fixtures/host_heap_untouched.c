/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Reports the guest heap state at the first statement of main.
 *
 * Natively nothing in a small dynamically linked program allocates from glibc
 * malloc before main, so the program break is still at its initial value and
 * the main arena is uninitialised.  The LiteInst host runtime's constructor
 * must preserve that: everything below is measured before any stdio or malloc
 * call of the fixture itself.
 *
 * Output: exactly one line "brk_delta=<cur-start_brk> arena=<n> mmapped=<n>".
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Field 47 of /proc/<pid>/stat is start_brk.  Field 2 (comm) may contain
 * spaces and parentheses, so fields are counted after the LAST ')': the first
 * field after it is field 3.  Returns 0 on a parse failure. */
static int
parse_start_brk(const char* buffer, long length, unsigned long* start_brk) {
  long close_paren = -1;
  for (long i = 0; i < length; ++i) {
    if (buffer[i] == ')') {
      close_paren = i;
    }
  }
  if (close_paren < 0) {
    return 0;
  }
  int field = 2;
  long i = close_paren + 1;
  while (i < length) {
    while (i < length && buffer[i] == ' ') {
      ++i;
    }
    if (i >= length || buffer[i] == '\n') {
      return 0;
    }
    ++field;
    if (field == 47) {
      unsigned long value = 0;
      int digits = 0;
      while (i < length && buffer[i] >= '0' && buffer[i] <= '9') {
        value = value * 10 + (unsigned long)(buffer[i] - '0');
        ++digits;
        ++i;
      }
      if (digits == 0) {
        return 0;
      }
      *start_brk = value;
      return 1;
    }
    while (i < length && buffer[i] != ' ' && buffer[i] != '\n') {
      ++i;
    }
  }
  return 0;
}

int main(void) {
  unsigned long current_brk = (unsigned long)syscall(SYS_brk, 0);

  char buffer[4096];
  long fd =
      syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 2;
  }
  long length = 0;
  for (;;) {
    long got = syscall(
        SYS_read, fd, buffer + length, (long)sizeof(buffer) - 1 - length);
    if (got < 0) {
      return 2;
    }
    if (got == 0 || length + got >= (long)sizeof(buffer) - 1) {
      length += got;
      break;
    }
    length += got;
  }
  syscall(SYS_close, fd);
  buffer[length] = '\0';

  unsigned long start_brk = 0;
  if (!parse_start_brk(buffer, length, &start_brk)) {
    return 2;
  }

  struct mallinfo2 info = mallinfo2();

  printf(
      "brk_delta=%ld arena=%zu mmapped=%zu\n",
      (long)(current_brk - start_brk),
      info.arena,
      info.hblkhd);
  return 0;
}
