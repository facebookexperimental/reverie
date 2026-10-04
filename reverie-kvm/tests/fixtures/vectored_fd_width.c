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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

struct observation {
  long result;
  int error;
  off_t position;
  unsigned char buffer[16];
  unsigned char file[64];
};

static const long operations[] =
    {SYS_readv, SYS_writev, SYS_preadv, SYS_pwritev, SYS_preadv2, SYS_pwritev2};

static void print_bytes(const unsigned char* bytes, size_t length) {
  for (size_t i = 0; i < length; ++i)
    printf("%02x", bytes[i]);
}

static struct observation
exercise(int fd, size_t operation, uint64_t high, uint64_t flags, int invalid) {
  unsigned char initial[64];
  for (size_t i = 0; i < sizeof(initial); ++i)
    initial[i] = (unsigned char)('0' + i);
  assert(pwrite(fd, initial, sizeof(initial), 0) == sizeof(initial));
  assert(ftruncate(fd, sizeof(initial)) == 0);
  assert(lseek(fd, 7, SEEK_SET) == 7);

  struct observation result = {0};
  memset(result.buffer, 0xa5, sizeof(result.buffer));
  if (operation % 2 != 0)
    memcpy(result.buffer + 4, "abcdefgh", 8);
  unsigned char before[16];
  memcpy(before, result.buffer, sizeof(before));
  struct iovec vectors[] = {{result.buffer + 4, 3}, {result.buffer + 7, 5}};
  struct iovec saved_vectors[2];
  memcpy(saved_vectors, vectors, sizeof(vectors));
  const uint64_t raw_fd = high | (invalid ? UINT32_MAX : (uint32_t)fd);
  errno = 0;
  result.result =
      syscall(operations[operation], raw_fd, vectors, 2UL, 4UL, 0UL, flags);
  result.error = errno;
  result.position = lseek(fd, 0, SEEK_CUR);
  assert(pread(fd, result.file, sizeof(result.file), 0) == sizeof(result.file));
  assert(memcmp(vectors, saved_vectors, sizeof(vectors)) == 0);

  const int unsupported_flags = (flags & UINT32_C(0x80000000)) != 0;
  if (invalid || unsupported_flags) {
    assert(result.result == -1);
    assert(result.error == (invalid ? EBADF : EOPNOTSUPP));
    assert(result.position == 7);
    assert(memcmp(result.buffer, before, sizeof(before)) == 0);
    assert(memcmp(result.file, initial, sizeof(initial)) == 0);
  } else {
    const size_t position = operation < 2 ? 7 : 4;
    assert(result.result == 8 && result.error == 0);
    assert(result.position == (operation < 2 ? 15 : 7));
    if (operation % 2 == 0) {
      memcpy(before + 4, initial + position, 8);
    } else {
      memcpy(initial + position, before + 4, 8);
    }
    assert(memcmp(result.buffer, before, sizeof(before)) == 0);
    assert(memcmp(result.file, initial, sizeof(initial)) == 0);
  }

  printf(
      "syscall=%ld high=%016lx flags=%016lx invalid=%d result=%ld/%d "
      "position=%ld buffer=",
      operations[operation],
      (unsigned long)high,
      (unsigned long)flags,
      invalid,
      result.result,
      result.error,
      (long)result.position);
  print_bytes(result.buffer, sizeof(result.buffer));
  printf(" file=");
  print_bytes(result.file, sizeof(result.file));
  puts("");
  return result;
}

static void assert_same(struct observation left, struct observation right) {
  assert(left.result == right.result);
  assert(left.error == right.error);
  assert(left.position == right.position);
  assert(memcmp(left.buffer, right.buffer, sizeof(left.buffer)) == 0);
  assert(memcmp(left.file, right.file, sizeof(left.file)) == 0);
}

int main(int argc, char** argv) {
  assert(argc == 2);
  int fd = open(argv[1], O_CREAT | O_TRUNC | O_RDWR, 0600);
  assert(fd >= 0);
  for (size_t operation = 0; operation < 6; ++operation) {
    struct observation ordinary = exercise(fd, operation, 0, 0, 0);
    assert_same(ordinary, exercise(fd, operation, UINT64_C(1) << 32, 0, 0));
    assert_same(
        ordinary, exercise(fd, operation, UINT64_C(0xffffffff00000000), 0, 0));
    struct observation bad_fd = exercise(fd, operation, 0, 0, 1);
    assert_same(bad_fd, exercise(fd, operation, UINT64_C(1) << 32, 0, 1));
    if (operation >= 4) {
      assert_same(ordinary, exercise(fd, operation, 0, UINT64_C(1) << 32, 0));
      assert_same(
          ordinary,
          exercise(fd, operation, 0, UINT64_C(0xffffffff00000000), 0));
      struct observation bad_flags =
          exercise(fd, operation, 0, UINT64_C(0x80000000), 0);
      assert_same(
          bad_flags, exercise(fd, operation, 0, UINT64_C(0x180000000), 0));
    }
  }
  assert(close(fd) == 0);
  return 0;
}
