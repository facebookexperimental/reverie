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
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(e)                                                      \
  do {                                                                \
    if (!(e)) {                                                       \
      fprintf(stderr, "line %d: %s errno=%d\n", __LINE__, #e, errno); \
      return 1;                                                       \
    }                                                                 \
  } while (0)
#define FAIL(call, err)    \
  do {                     \
    errno = 0;             \
    CHECK((call) == -1);   \
    CHECK(errno == (err)); \
  } while (0)

/* Crossed-error controls use the same native and KVM guest calls. A held
 * anonymous reservation supplies one occupied page and one deliberately free
 * hole; every rejected request must preserve both and the descriptor status. */
static int mapping_errors(long fd, long mode) {
  unsigned char* pages = (void*)syscall(
      SYS_mmap,
      0L,
      12288L,
      (long)(PROT_READ | PROT_WRITE),
      (long)(MAP_PRIVATE | MAP_ANONYMOUS),
      -1L,
      0L);
  CHECK(pages != MAP_FAILED);
  memset(pages, 0xa5, 12288);
  CHECK(syscall(SYS_munmap, (long)(pages + 4096), 4096L) == 0);
  long original = syscall(SYS_fcntl, fd, (long)F_GETFL, 0L);
  const long f = MAP_FIXED, n = MAP_FIXED_NOREPLACE, h = MAP_HUGETLB,
             t = MAP_TYPE;
  struct {
    long address, length, flags, offset, error;
  } cases[] = {
      {(long)pages, 4096, MAP_PRIVATE | h | f, 0, EINVAL},
      {(long)pages, 4096, MAP_PRIVATE | h | n, 0, EINVAL},
      {-4096L, 4096, MAP_PRIVATE | h | f, 0, EINVAL},
      {(long)pages, 4096, MAP_PRIVATE | h | f, -4096L, EINVAL},
      {(long)pages, -1L, MAP_PRIVATE | h | f, 0, EINVAL},
      {(long)pages, 4096, MAP_PRIVATE | h | f, 1, EINVAL},
      {(long)pages, 4096, t | n, 0, EEXIST},
      {-4096L, 4096, t | f, 0, ENOMEM},
      {(long)(pages + 4096), 4096, t | f, -4096L, EOVERFLOW},
      {(long)(pages + 4096), 4096, t | f, 0, EINVAL},
      {(long)(pages + 4096), 4096, MAP_SHARED_VALIDATE | n, 0, EOPNOTSUPP},
      {(long)pages, 4096, MAP_SHARED_VALIDATE | n, 0, EEXIST},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    int error = cases[i].offset == 1
        ? EINVAL
        : (mode == O_PATH ? EBADF : cases[i].error);
    FAIL(
        syscall(
            SYS_mmap,
            cases[i].address,
            cases[i].length,
            (long)PROT_READ,
            cases[i].flags,
            fd,
            cases[i].offset),
        error);
  }
  const long legacy[] = {MAP_GROWSDOWN, 0x04000000, 0x80, 21L << 26, 30L << 26};
  for (unsigned i = 0; i < sizeof(legacy) / sizeof(legacy[0]); ++i) {
    int error = mode == O_PATH
        ? EBADF
        : (mode == O_WRONLY || mode == 3 ? EACCES : ENODEV);
    FAIL(
        syscall(
            SYS_mmap,
            (long)pages,
            4096L,
            (long)PROT_READ,
            MAP_SHARED_VALIDATE | f | legacy[i],
            fd,
            0L),
        error);
  }
  const long extension[] = {MAP_SYNC, 0x80000000L, 0x02000000};
  for (unsigned i = 0; i < sizeof(extension) / sizeof(extension[0]); ++i)
    FAIL(
        syscall(
            SYS_mmap,
            (long)pages,
            4096L,
            (long)PROT_READ,
            MAP_SHARED_VALIDATE | f | extension[i],
            fd,
            0L),
        mode == O_PATH ? EBADF : EOPNOTSUPP);
  /* Raw x86-64 syscall arguments are unsigned long, including flags.
   * These bits must reach SHARED_VALIDATE intact, while ordinary mapping
   * kinds ignore them. Keep every earlier mmap validation ahead of them. */
  _Static_assert(sizeof(unsigned long) == 8, "requires x86-64 syscall word");
  const unsigned long high[] = {0UL, 1UL << 32, 1UL << 63};
  const unsigned long kinds[] = {MAP_SHARED, MAP_PRIVATE, MAP_SHARED_VALIDATE};
  for (unsigned i = 0; i < sizeof(high) / sizeof(high[0]); ++i) {
    for (unsigned k = 0; k < sizeof(kinds) / sizeof(kinds[0]); ++k) {
      int error = mode == O_PATH
          ? EBADF
          : (kinds[k] == MAP_SHARED_VALIDATE && high[i] != 0
                 ? EOPNOTSUPP
                 : (mode == O_WRONLY || mode == 3 ? EACCES : ENODEV));
      FAIL(
          syscall(
              SYS_mmap,
              (long)pages,
              4096L,
              (long)PROT_READ,
              kinds[k] | (unsigned long)f | high[i],
              fd,
              0L),
          error);
    }
    if (high[i] == 0)
      continue;
    struct {
      long address, length, offset, error;
      unsigned long flags;
    } crossed[] = {
        {(long)pages, 4096, 1, EINVAL, MAP_SHARED_VALIDATE | f},
        {(long)pages, 4096, 0, EINVAL, MAP_SHARED_VALIDATE | f | h},
        {(long)pages, 0, 0, EINVAL, MAP_SHARED_VALIDATE | f},
        {(long)pages, -1L, 0, ENOMEM, MAP_SHARED_VALIDATE | f},
        {-4096L, 4096, 0, ENOMEM, MAP_SHARED_VALIDATE | f},
        {(long)pages, 4096, 0, EEXIST, MAP_SHARED_VALIDATE | n},
        {(long)pages, 4096, -4096L, EOVERFLOW, MAP_SHARED_VALIDATE | f},
        {(long)pages, 4096, 0, EINVAL, t | f},
    };
    for (unsigned c = 0; c < sizeof(crossed) / sizeof(crossed[0]); ++c) {
      int error = crossed[c].offset == 1
          ? EINVAL
          : (mode == O_PATH ? EBADF : crossed[c].error);
      FAIL(
          syscall(
              SYS_mmap,
              crossed[c].address,
              crossed[c].length,
              (long)PROT_READ,
              crossed[c].flags | high[i],
              fd,
              crossed[c].offset),
          error);
    }
  }
  const struct {
    unsigned long address, length;
    int error;
  } ranges[] = {
      {0xffffffffffffe001UL, 4096UL, ENOMEM},
      {0x1001UL, 1UL << 63, ENOMEM},
      {(unsigned long)(pages + 1), 4096UL, EINVAL},
      {0x7f0000001001UL, 4096UL, EINVAL},
      {0x1001UL, 4096UL, EINVAL},
  };
  for (unsigned i = 0; i < sizeof(ranges) / sizeof(ranges[0]); ++i)
    FAIL(
        syscall(
            SYS_mmap,
            ranges[i].address,
            ranges[i].length,
            (unsigned long)PROT_READ,
            (unsigned long)(MAP_PRIVATE | MAP_FIXED),
            fd,
            0UL),
        mode == O_PATH ? EBADF : ranges[i].error);
  CHECK(syscall(SYS_fcntl, fd, (long)F_GETFL, 0L) == original);
  for (unsigned i = 0; i < 4096; ++i)
    CHECK(pages[i] == 0xa5 && pages[8192 + i] == 0xa5);
  CHECK(
      syscall(
          SYS_mmap,
          (long)(pages + 4096),
          4096L,
          (long)(PROT_READ | PROT_WRITE),
          (long)(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE),
          -1L,
          0L) == (long)(pages + 4096));
  CHECK(syscall(SYS_munmap, (long)pages, 12288L) == 0);
  return 0;
}

static int one(const char* path, unsigned minor_number, int native) {
  const long modes[] = {O_RDONLY, O_WRONLY, O_RDWR, 3, O_PATH};
  for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
    long mode = modes[m];
    long fd =
        syscall(SYS_openat, (long)AT_FDCWD, (long)path, mode | O_CLOEXEC, 0L);
    CHECK(fd >= 0);
    long alias = syscall(SYS_dup, fd);
    CHECK(alias >= 0);
    struct stat st, at;
    CHECK(syscall(SYS_fstat, fd, (long)&st) == 0);
    CHECK(S_ISCHR(st.st_mode));
    CHECK(major(st.st_rdev) == 1 && minor(st.st_rdev) == minor_number);
    CHECK(st.st_size == 0 && st.st_blocks == 0);
    struct statx sx;
    CHECK(
        syscall(
            SYS_statx,
            alias,
            (long)"",
            (long)AT_EMPTY_PATH,
            (long)STATX_BASIC_STATS,
            (long)&sx) == 0);
    CHECK(
        (sx.stx_mode & S_IFMT) == S_IFCHR && sx.stx_rdev_major == 1 &&
        sx.stx_rdev_minor == minor_number);
    CHECK(sx.stx_size == 0 && sx.stx_blocks == 0 && sx.stx_ino == st.st_ino);
    CHECK(
        syscall(
            SYS_newfstatat, alias, (long)"", (long)&at, (long)AT_EMPTY_PATH) ==
        0);
    CHECK(
        at.st_mode == st.st_mode && at.st_rdev == st.st_rdev &&
        at.st_ino == st.st_ino && at.st_dev == st.st_dev);
    long original = mode == O_PATH ? O_PATH : 0100000 | mode;
    CHECK(syscall(SYS_fcntl, fd, (long)F_GETFL, 0L) == original);
    FAIL(
        syscall(
            SYS_fcntl,
            alias,
            (long)F_SETFL,
            (long)(O_DIRECT | O_ASYNC | O_RDWR | O_APPEND | O_NONBLOCK)),
        mode == O_PATH ? EBADF : EINVAL);
    CHECK(syscall(SYS_fcntl, fd, (long)F_GETFL, 0L) == original);
    CHECK(syscall(SYS_fcntl, alias, (long)F_GETFL, 0L) == original);
    CHECK(mapping_errors(fd, mode) == 0);
    if (mode == O_PATH) {
      FAIL(
          syscall(SYS_fcntl, alias, (long)F_SETFL, (long)(O_RDWR | O_NONBLOCK)),
          EBADF);
      FAIL(syscall(SYS_fcntl, fd, (long)F_SETLK, -1L), EBADF);
      FAIL(syscall(SYS_fgetxattr, fd, (long)"user.test", 0L, 0L), EBADF);
      FAIL(syscall(SYS_fgetxattr, fd, -1L, 0L, 0L), EFAULT);
      FAIL(syscall(SYS_fsetxattr, fd, (long)"user.test", -1L, 1L, 0L), EFAULT);
      FAIL(syscall(SYS_fsetxattr, fd, (long)"user.test", 0L, 0L, 0L), EBADF);
      FAIL(syscall(SYS_fremovexattr, fd, (long)"user.test"), EBADF);
    } else {
      CHECK(
          syscall(
              SYS_fcntl,
              alias,
              (long)F_SETFL,
              (long)(O_RDWR | O_NONBLOCK | O_APPEND)) == 0);
      CHECK(
          syscall(SYS_fcntl, fd, (long)F_GETFL, 0L) ==
          (original | O_NONBLOCK | O_APPEND));
      CHECK(syscall(SYS_fcntl, fd, (long)F_SETFL, (long)O_RDONLY) == 0);
      CHECK(syscall(SYS_fcntl, alias, (long)F_GETFL, 0L) == original);
      CHECK(
          syscall(
              SYS_fcntl, alias, (long)F_SETFL, (long)(O_ASYNC | O_NONBLOCK)) ==
          0);
      CHECK(
          syscall(SYS_fcntl, fd, (long)F_GETFL, 0L) ==
          (original | O_ASYNC | O_NONBLOCK));
      CHECK(syscall(SYS_fcntl, fd, (long)F_SETFL, 0L) == 0);
      CHECK(syscall(SYS_fcntl, alias, (long)F_GETFL, 0L) == original);
    }
    if (mode == O_WRONLY || mode == 3 || mode == O_PATH) {
      FAIL(syscall(SYS_read, fd, -1L, 0L), EBADF);
      FAIL(syscall(SYS_readv, alias, -1L, 1025L), EBADF);
      FAIL(syscall(SYS_pread64, fd, -1L, 1L, 0L), EBADF);
      FAIL(syscall(SYS_preadv2, alias, -1L, 1025L, 0L, 0L, 0L), EBADF);
    }
    if (mode == O_RDONLY || mode == 3 || mode == O_PATH) {
      FAIL(syscall(SYS_write, fd, -1L, 0L), EBADF);
      FAIL(syscall(SYS_writev, alias, -1L, 1025L), EBADF);
      FAIL(syscall(SYS_pwrite64, fd, -1L, 1L, 0L), EBADF);
    }
    FAIL(
        syscall(SYS_mmap, 0L, 0L, (long)PROT_READ, (long)MAP_PRIVATE, fd, 0L),
        mode == O_PATH ? EBADF : EINVAL);
    FAIL(
        syscall(
            SYS_mmap, 0L, 4096L, (long)PROT_READ, (long)MAP_PRIVATE, fd, 0L),
        mode == O_PATH ? EBADF
                       : (mode == O_WRONLY || mode == 3 ? EACCES : ENODEV));
    if (!native && (mode == O_WRONLY || mode == O_RDWR)) {
      unsigned char* pages = (void*)syscall(
          SYS_mmap,
          0L,
          8192L,
          (long)(PROT_READ | PROT_WRITE),
          (long)(MAP_PRIVATE | MAP_ANONYMOUS),
          -1L,
          0L);
      CHECK(pages != MAP_FAILED);
      memset(pages, 0x5a, 8192);
      CHECK(syscall(SYS_mprotect, (long)(pages + 4096), 4096L, 0L) == 0);
      CHECK(syscall(SYS_write, fd, (long)(pages + 4096 - 7), 15L) == 7);
      FAIL(syscall(SYS_write, alias, (long)(pages + 4096), 8L), EFAULT);
      struct iovec iv[] = {{pages, 7}, {pages + 4096, 8}, {pages + 30, 9}};
      CHECK(syscall(SYS_writev, alias, (long)iv, 3L) == 7);
      CHECK(syscall(SYS_pwrite64, fd, (long)pages, 13L, 123L) == 13);
      CHECK(syscall(SYS_pwritev2, fd, (long)iv, 3L, -1L, 0L, 0L) == 7);
      CHECK(syscall(SYS_munmap, (long)pages, 8192L) == 0);
    }
    if (mode == O_RDONLY || mode == O_RDWR) {
      unsigned char bytes[82];
      CHECK(syscall(SYS_read, fd, (long)bytes, 23L) == 23);
      struct iovec iv[] = {{bytes + 23, 7}, {bytes + 30, 19}, {bytes + 49, 33}};
      CHECK(syscall(SYS_readv, alias, (long)iv, 3L) == 59);
      if (!native)
        for (unsigned i = 0; i < sizeof(bytes); ++i)
          CHECK(bytes[i] == (unsigned char)((i * 73 + 41) & 255));
    }
    CHECK(syscall(SYS_close, fd) == 0);
    CHECK(syscall(SYS_close, alias) == 0);
  }
  return 0;
}
int main(int argc, char** argv) {
  int native = argc == 2 && strcmp(argv[1], "native") == 0;
  CHECK(one("/dev/random", 8, native) == 0);
  CHECK(one("/dev/urandom", 9, native) == 0);
  CHECK(one("/dev//random", 8, native) == 0);
  CHECK(one("/dev/./urandom", 9, native) == 0);
  puts("random carrier access, identity, flags, faults and bytes ok");
  return 0;
}
