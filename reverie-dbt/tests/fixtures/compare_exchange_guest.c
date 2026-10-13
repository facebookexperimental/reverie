/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Asks the prototype runtime's compare-exchange test tool to exchange guest
 * words through Guest::memory(): `prctl(COMPARE_EXCHANGE_PRCTL, address,
 * expected, desired)` returns the value the word held, or fails with errno.
 *
 * 1. code_page: a word on a writable, executable page whose code the guest has
 *    just run, so DynamoRIO has made the page read-only for its code cache
 *    while the guest still sees it writable. The exchange must succeed.
 * 2. refused: the same word with a stale expected value is left alone.
 * 3. code_ok: the code on that page still runs, before and after.
 * 4. read_only and unmapped: EFAULT, and nothing is stored. past_eof: a word
 *    in a shared file mapping past the end of its file, where the page is
 *    mapped readable and writable but any access raises SIGBUS, is EFAULT
 *    too, as Linux's futex_cmpxchg_value_locked gives.
 * 5. gated: the code-page word exchanged from a DynamoRIO client thread,
 *    outside any system-call event, through
 *    `prctl(COMPARE_EXCHANGE_OUTSIDE_EVENT_PRCTL, ...)`. DynamoRIO recovers a
 *    write to such a page only inside a system-call event, so the runtime
 *    must refuse with EFAULT and leave the word alone. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define COMPARE_EXCHANGE_PRCTL 0x43415321UL
#define COMPARE_EXCHANGE_OUTSIDE_EVENT_PRCTL 0x43415322UL

static long compare_exchange_through(
    unsigned long option,
    uint32_t* word,
    uint32_t expected,
    uint32_t desired) {
  return syscall(
      SYS_prctl,
      option,
      (unsigned long)word,
      (unsigned long)expected,
      (unsigned long)desired,
      0UL);
}

/* A word on the second page of a two-page shared mapping of a one-page file. */
static uint32_t* past_end_of_file(size_t page) {
  int fd = (int)syscall(SYS_memfd_create, "cas-past-eof", 0U);
  if (fd < 0 || ftruncate(fd, (off_t)page) != 0)
    return NULL;
  unsigned char* mapping =
      mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  return mapping == MAP_FAILED ? NULL : (uint32_t*)(mapping + page);
}

static long compare_exchange(uint32_t* word, uint32_t expected, uint32_t desired) {
  return compare_exchange_through(COMPARE_EXCHANGE_PRCTL, word, expected, desired);
}

int main(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char* code = mmap(
      NULL,
      page,
      PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0);
  uint32_t* read_only = mmap(
      NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  uint32_t* unmapped = mmap(
      NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (code == MAP_FAILED || read_only == MAP_FAILED || unmapped == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  static const unsigned char body[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
  memcpy(code, body, sizeof(body)); /* mov eax, 42; ret */
  uint32_t* word = (uint32_t*)(code + 64);
  *word = 7;
  int (*function)(void) = (int (*)(void))(void*)code;
  int before = function();

  errno = 0;
  long outside = compare_exchange_through(
      COMPARE_EXCHANGE_OUTSIDE_EVENT_PRCTL, word, 7, 9);
  int gated = outside == -1 && errno == EFAULT && *word == 7;

  long swapped = compare_exchange(word, 7, 9);
  int code_page = swapped == 7 && *word == 9;
  long stale = compare_exchange(word, 7, 11);
  int refused = stale == 9 && *word == 9;
  int after = function();

  *read_only = 7;
  if (mprotect(read_only, page, PROT_READ) != 0 || munmap(unmapped, page) != 0) {
    perror("mprotect/munmap");
    return 1;
  }
  errno = 0;
  long read_only_result = compare_exchange(read_only, 7, 9);
  int read_only_ok = read_only_result == -1 && errno == EFAULT && *read_only == 7;
  errno = 0;
  long unmapped_result = compare_exchange(unmapped, 0, 1);
  int unmapped_ok = unmapped_result == -1 && errno == EFAULT;
  uint32_t* past_eof = past_end_of_file(page);
  if (past_eof == NULL) {
    perror("memfd mapping");
    return 1;
  }
  errno = 0;
  long past_eof_result = compare_exchange(past_eof, 0, 1);
  int past_eof_ok = past_eof_result == -1 && errno == EFAULT;

  printf(
      "cas_guest gated=%d code_page=%d refused=%d code_ok=%d read_only=%d "
      "unmapped=%d past_eof=%d\n",
      gated,
      code_page,
      refused,
      before == 42 && after == 42,
      read_only_ok,
      unmapped_ok,
      past_eof_ok);
  return gated && code_page && refused && before == 42 && after == 42 && read_only_ok &&
          unmapped_ok && past_eof_ok
      ? 0
      : 1;
}
