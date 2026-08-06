/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Plants a marker in dead stack BEFORE issuing any syscall.
 *
 * `stack_scrub_marker.c` is an ordinary libc program, and that is exactly why
 * it cannot reach the case this fixture exists for: libc's startup issues
 * syscalls long before `main` runs, so by the time it plants anything the
 * client's INITIAL scrub has already fired. It can only ever exercise the
 * clone-re-armed scrub.
 *
 * So this one is `-static -nostdlib -nostartfiles`: execution begins at
 * `_start` with the kernel-provided stack, and the FIRST syscall this process
 * ever makes is the one issued below, deliberately after the marker is in
 * place. Any client that scrubs positionally at the first syscall erases the
 * marker; a client that scrubs before the guest's first instruction does not.
 *
 * Freestanding on purpose: no libc, no startup files, no builtins that could
 * lower a loop into a `memset` call that does not exist here.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Exit statuses, kept distinct so a broken environment cannot masquerade as the
 * product bug this fixture exists to catch. */
#define MARKER_OK 0
#define HARNESS_FAILURE 2
#define MARKER_MISMATCH 42

/* Mirrors `stack_scrub_marker.c`. Deep enough to be unambiguously dead, and
 * inside the 64 KiB + 256 B window below the stack pointer that Linux will
 * auto-grow the main stack for. */
#define MARKER_DEPTH_BYTES 32768
#define MARKER_WORDS 90
/* Neutral: not a pointer, not zero, not a value DynamoRIO deals in. */
#define MARKER_BYTE 0x5a

#define SYS_write 1
#define SYS_getpid 39
#define SYS_exit_group 231
#define STDOUT_FD 1

static inline long syscall0(long number) {
  long result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "a"(number)
                   : "rcx", "r11", "memory");
  return result;
}

static void write_all(const char *bytes, unsigned long length) {
  __asm__ volatile("syscall"
                   :
                   : "a"((long)SYS_write), "D"((long)STDOUT_FD), "S"(bytes),
                     "d"(length)
                   : "rcx", "r11", "memory");
}

static void write_str(const char *text) {
  unsigned long length = 0;
  while (text[length] != '\0')
    ++length;
  write_all(text, length);
}

/* Decimal rendering by hand: there is no libc here to borrow one from. The
 * counts matter because they pin WHICH read lost the marker, so a regression
 * report names the path instead of just saying "mismatch". */
static void write_int(int value) {
  char digits[12];
  int at = (int)sizeof(digits);
  if (value == 0)
    digits[--at] = '0';
  while (value > 0 && at > 0) {
    digits[--at] = (char)('0' + value % 10);
    value /= 10;
  }
  write_all(digits + at, (unsigned long)((int)sizeof(digits) - at));
}

__attribute__((noreturn)) static void exit_with(int status) {
  __asm__ volatile("syscall"
                   :
                   : "a"((long)SYS_exit_group), "D"((long)status)
                   : "rcx", "r11", "memory");
  __builtin_unreachable();
}

/* `volatile` throughout so the compiler cannot decide this memory is dead and
 * elide the writes or the reads: that memory is precisely what is under test. */
static int surviving_marker_words(volatile const unsigned char *marker) {
  int intact = 0;
  for (int word = 0; word < MARKER_WORDS; ++word) {
    bool whole = true;
    for (size_t at = 0; at < sizeof(uintptr_t); ++at) {
      if (marker[(size_t)word * sizeof(uintptr_t) + at] != MARKER_BYTE)
        whole = false;
    }
    if (whole)
      ++intact;
  }
  return intact;
}

void _start(void) {
  /* Anchor off this frame so the marker lands below the stack pointer and is
   * dead by the ABI -- inside the range the scrub is allowed to consider. */
  volatile unsigned char here = 0;
  uintptr_t anchor = (uintptr_t)&here;
  if (anchor <= MARKER_DEPTH_BYTES)
    exit_with(HARNESS_FAILURE);

  volatile unsigned char *marker =
      (volatile unsigned char *)(anchor - MARKER_DEPTH_BYTES);

  /* THE POINT OF THIS FIXTURE: planted before any syscall has been issued. */
  for (size_t at = 0; at < (size_t)MARKER_WORDS * sizeof(uintptr_t); ++at)
    marker[at] = MARKER_BYTE;

  int before = surviving_marker_words(marker);
  write_str("first-scrub-marker before=");
  write_int(before);
  if (before != MARKER_WORDS) {
    write_str("\n");
    exit_with(HARNESS_FAILURE); /* the plant itself did not take */
  }

  /* By now the diagnostic `write` above has already been this process's first
   * syscall -- which is fine and is still the case under test: the marker was
   * planted before it. This `getpid` simply gives a second, side-effect-free
   * syscall so the check does not depend on which one the scrub hooks. */
  (void)syscall0(SYS_getpid);

  int after = surviving_marker_words(marker);
  write_str(" after_first_syscall=");
  write_int(after);
  write_str("\n");
  exit_with(after == MARKER_WORDS ? MARKER_OK : MARKER_MISMATCH);
}
