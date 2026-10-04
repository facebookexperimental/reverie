/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define ARENA (2 * PAGE)
#define READ_FD 100
#define WRITE_FD 101
#define INVALID_FD 30000
#define REQUIRE(condition)                                                     \
  do {                                                                         \
    if (!(condition)) {                                                        \
      dprintf(2, "poll descriptor ABI: line %d, errno %d\n", __LINE__, errno); \
      return 80;                                                               \
    }                                                                          \
  } while (0)

struct report {
  int64_t result;
  int32_t error;
  uint32_t mode;
  uint64_t raw_nfds;
  uint32_t offset, count;
  int64_t timeout[2];
};
_Static_assert(sizeof(struct pollfd) == 8, "x86_64 pollfd ABI");
_Static_assert(offsetof(struct pollfd, revents) == 6, "revents offset");
_Static_assert(sizeof(struct report) == 48, "complete report layout");

static int write_all(int fd, const void* data, size_t length) {
  const unsigned char* bytes = data;
  while (length) {
    ssize_t n = write(fd, bytes, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    bytes += n;
    length -= (size_t)n;
  }
  return 0;
}

static int fixed_pipe(void) {
  int pair[2];
  REQUIRE(pipe(pair) == 0);
  /* Pin both endpoints before replacing either fixed number. */
  int read_copy = fcntl(pair[0], F_DUPFD_CLOEXEC, 200);
  int write_copy = fcntl(pair[1], F_DUPFD_CLOEXEC, 200);
  REQUIRE(read_copy >= 200 && write_copy >= 200);
  REQUIRE(close(pair[0]) == 0 && close(pair[1]) == 0);
  REQUIRE(dup2(read_copy, READ_FD) == READ_FD);
  REQUIRE(dup2(write_copy, WRITE_FD) == WRITE_FD);
  REQUIRE(close(read_copy) == 0 && close(write_copy) == 0);
  errno = 0;
  REQUIRE(fcntl(INVALID_FD, F_GETFD) == -1 && errno == EBADF);
  return 0;
}

static void
put_descriptor(unsigned char* arena, size_t offset, int fd, short events) {
  struct pollfd descriptor = {.fd = fd, .events = events, .revents = 0x5a5a};
  /* The input-fields-only page case is intentionally unaligned. */
  memcpy(arena + offset, &descriptor, sizeof(descriptor));
}

static void
put_revents(unsigned char* arena, size_t offset, unsigned index, short value) {
  memcpy(
      arena + offset + index * sizeof(struct pollfd) +
          offsetof(struct pollfd, revents),
      &value,
      sizeof(value));
}

int main(int argc, char** argv) {
  REQUIRE(argc == 2);
  int mode = atoi(argv[1]);
  REQUIRE(mode >= 0 && mode <= 15);
  REQUIRE(fixed_pipe() == 0);
  unsigned char* arena = mmap(
      NULL, ARENA, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct timespec* zero = mmap(
      NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(arena != MAP_FAILED && zero != MAP_FAILED);
  memset(arena, 0xa5, ARENA);
  zero->tv_sec = zero->tv_nsec = 0;
  REQUIRE(mprotect(zero, PAGE, PROT_READ) == 0);

  unsigned count = 1;
  size_t offset = 128;
  int ready = 1;
  int use_ppoll = mode == 1 || mode == 3 || mode == 4 || mode == 5 ||
      mode == 6 || mode == 8 || mode == 10 || mode == 12 || mode == 13 ||
      mode == 15;
  if (mode == 2 || mode == 3)
    count = 0;
  if (mode == 4 || mode == 5 || mode == 6 || mode == 11 || mode == 12 ||
      mode == 13)
    count = 2;
  if (mode == 4 || mode == 13)
    ready = 0;
  if (mode == 7 || mode == 8)
    offset = PAGE - 6;
  if (mode == 14 || mode == 15)
    offset = PAGE - 7;
  if (mode == 11 || mode == 12)
    offset = PAGE - sizeof(struct pollfd);

  if (ready)
    REQUIRE(write(WRITE_FD, "r", 1) == 1);
  put_descriptor(arena, offset, READ_FD, POLLIN);
  if (mode == 4 || mode == 5) {
    put_descriptor(arena, offset, INVALID_FD, 0);
    put_descriptor(arena, offset + sizeof(struct pollfd), READ_FD, POLLIN);
  } else if (mode == 6 || mode == 13) {
    put_descriptor(arena, offset, -7, POLLIN);
    put_descriptor(arena, offset + sizeof(struct pollfd), READ_FD, POLLIN);
  } else if (mode == 11 || mode == 12) {
    put_descriptor(arena, offset + sizeof(struct pollfd), READ_FD, POLLIN);
  }

  unsigned char expected[ARENA];
  memcpy(expected, arena, sizeof(expected));
  long expected_result = count ? 1 : 0;
  int expected_error = 0;
  if (mode == 5)
    expected_result = 2;
  if (mode == 13)
    expected_result = 0;
  if ((mode >= 9 && mode <= 12) || mode == 14 || mode == 15) {
    expected_result = -1;
    expected_error = EFAULT;
  }
  if (mode == 4 || mode == 5) {
    put_revents(expected, offset, 0, POLLNVAL);
    put_revents(expected, offset, 1, ready ? POLLIN : 0);
  } else if (mode == 6 || mode == 13) {
    put_revents(expected, offset, 0, 0);
    put_revents(expected, offset, 1, ready ? POLLIN : 0);
  } else if (count && mode != 9 && mode != 10 && mode != 14 && mode != 15) {
    /* On a later field fault, the first completed store survives. */
    put_revents(expected, offset, 0, POLLIN);
  }
  if (mode >= 7 && mode <= 10)
    REQUIRE(mprotect(arena, PAGE, PROT_READ) == 0);
  /* Require EFAULT without a partial store when revents straddles RW -> RO. */
  if (mode == 11 || mode == 12 || mode == 14 || mode == 15)
    REQUIRE(mprotect(arena + PAGE, PAGE, PROT_READ) == 0);

  struct report output = {0};
  output.mode = (uint32_t)mode;
  output.count = count;
  output.offset = (uint32_t)offset;
  output.raw_nfds = count;
  if (mode <= 3)
    output.raw_nfds |= 1ULL << 32;
  void* argument = count ? arena + offset : NULL;
  /* No worker ever writes this pipe: POLLNVAL alone must prevent blocking. */
  const struct timespec* timeout = (mode >= 4 && mode <= 6) ? NULL : zero;
  errno = 0;
  output.result = use_ppoll
      ? syscall(SYS_ppoll, argument, output.raw_nfds, timeout, NULL, 8)
      : syscall(SYS_poll, argument, output.raw_nfds, 0);
  output.error = output.result == -1 ? errno : 0;
  memcpy(output.timeout, zero, sizeof(output.timeout));
  REQUIRE(output.result == expected_result && output.error == expected_error);
  REQUIRE(output.timeout[0] == 0 && output.timeout[1] == 0);
  REQUIRE(memcmp(arena, expected, ARENA) == 0);
  REQUIRE(write_all(1, &output, sizeof(output)) == 0);
  REQUIRE(write_all(1, arena, ARENA) == 0);
  REQUIRE(close(READ_FD) == 0 && close(WRITE_FD) == 0);
  return 0;
}
