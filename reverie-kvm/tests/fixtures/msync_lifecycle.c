/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Ordinary-file MAP_SHARED coherence and mapping lifetime. These observations
 * concern the page cache, not persistence across power loss. No observation
 * depends on a concurrent writer, a sleep, or an unmodified MAP_PRIVATE page.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int bytes_equal(const char *step, const volatile unsigned char *actual,
                       const unsigned char *expected, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    unsigned char observed = actual[i];
    if (observed != expected[i]) {
      fprintf(stderr, "%s byte[%zu]=%u expected=%u\n", step, i,
              (unsigned)observed, (unsigned)expected[i]);
      return 0;
    }
  }
  return 1;
}

static int file_equal(const char *step, int fd, unsigned char *scratch,
                      const unsigned char *expected, size_t length) {
  struct stat st;
  errno = 0;
  int rc = fstat(fd, &st);
  if (rc != 0) {
    fprintf(stderr, "%s fstat rc=%d errno=%d expected=0\n", step, rc, errno);
    return 0;
  }
  if (st.st_size != (off_t)length) {
    fprintf(stderr, "%s size=%lld expected=%zu\n", step,
            (long long)st.st_size, length);
    return 0;
  }
  errno = 0;
  ssize_t count = pread(fd, scratch, length, 0);
  if (count != (ssize_t)length) {
    fprintf(stderr, "%s pread rc=%zd errno=%d expected=%zu\n", step, count,
            errno, length);
    return 0;
  }
  return bytes_equal(step, scratch, expected, length);
}

#define REQUIRE(condition, step)                                                \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s failed errno=%d\n", step, errno);                    \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

#define NEW_FD(destination, call, step)                                          \
  do {                                                                         \
    errno = 0;                                                                 \
    (destination) = (call);                                                     \
    if ((destination) < 0) {                                                    \
      fprintf(stderr, "%s rc=%d errno=%d expected nonnegative\n", step,          \
              (destination), errno);                                           \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

#define NEW_MAP(destination, call, step)                                         \
  do {                                                                         \
    errno = 0;                                                                 \
    (destination) = (call);                                                     \
    if ((destination) == MAP_FAILED) {                                          \
      fprintf(stderr, "%s rc=MAP_FAILED errno=%d\n", step, errno);               \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

#define FIXED_MAP(call, expected, step)                                          \
  do {                                                                         \
    errno = 0;                                                                 \
    void *actual_ = (call);                                                     \
    if (actual_ != (expected)) {                                                \
      fprintf(stderr, "%s rc=%p errno=%d expected=%p\n", step, actual_, errno,   \
              (expected));                                                     \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

#define EXACT(call, expected, step)                                             \
  do {                                                                         \
    errno = 0;                                                                 \
    long actual_ = (long)(call);                                                \
    long expected_ = (long)(expected);                                          \
    if (actual_ != expected_) {                                                 \
      fprintf(stderr, "%s rc=%ld errno=%d expected=%ld\n", step, actual_,       \
              errno, expected_);                                               \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

#define FILES(step)                                                             \
  do {                                                                         \
    REQUIRE(file_equal(step " A", observer, scratch, expected_a, length), step); \
    REQUIRE(file_equal(step " B", fd_b, scratch, expected_b, length), step);    \
  } while (0)

#define ALIASES(step)                                                           \
  do {                                                                         \
    REQUIRE(bytes_equal(step " alias1", alias1, expected_a + page, 2 * page),   \
            step);                                                             \
    REQUIRE(bytes_equal(step " alias2", alias2, expected_a + 2 * page, page),   \
            step);                                                             \
  } while (0)

int main(void) {
  int result = 1;
  int fd_a = -1, fd_b = -1, observer = -1, duplicate = -1, reused = -1;
  char path_a[] = "msync_lifecycle_a_XXXXXX";
  char path_b[] = "msync_lifecycle_b_XXXXXX";
  int linked_a = 0, linked_b = 0;
  unsigned char *expected_a = NULL, *expected_b = NULL, *scratch = NULL;
  unsigned char *expected_private = NULL;
  volatile unsigned char *main_map = MAP_FAILED, *alias1 = MAP_FAILED;
  volatile unsigned char *alias2 = MAP_FAILED, *private_map = MAP_FAILED;
  size_t page = 0, length = 0;
  unsigned syncs = 0;
  long page_size = sysconf(_SC_PAGESIZE);
  REQUIRE(page_size > 127 && page_size <= LONG_MAX / 3, "page size");
  page = (size_t)page_size;
  length = 3 * page;
  expected_a = malloc(length);
  expected_b = malloc(length);
  scratch = malloc(length);
  expected_private = malloc(length);
  REQUIRE(expected_a && expected_b && scratch && expected_private, "buffers");
  for (size_t i = 0; i < length; ++i) {
    expected_a[i] = (unsigned char)(17 * i + 31 * (i / page) + 19);
    expected_b[i] = (unsigned char)(23 * i + 47 * (i / page) + 83);
    expected_private[i] = (unsigned char)(7 * i + 61 * (i / page) + 149);
  }
  NEW_FD(fd_a, mkstemp(path_a), "mkstemp A");
  linked_a = 1;
  NEW_FD(fd_b, mkstemp(path_b), "mkstemp B");
  linked_b = 1;
  EXACT(pwrite(fd_a, expected_a, length, 0), length, "initialize A");
  EXACT(pwrite(fd_b, expected_b, length, 0), length, "initialize B");
  NEW_FD(observer, open(path_a, O_RDWR), "independent A observer");
  NEW_FD(duplicate, dup(fd_a), "duplicate A");
  NEW_MAP(main_map,
          mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd_a, 0),
          "shared A");
  NEW_MAP(alias1,
          mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED, duplicate,
               (off_t)page),
          "shared A offset one");
  NEW_MAP(alias2,
          mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, observer,
               (off_t)(2 * page)),
          "shared A offset two");
  FILES("initial");
  ALIASES("initial");
  REQUIRE(bytes_equal("initial main", main_map, expected_a, length), "initial main");

  /* Neither direction gets an msync before its first observation. */
  main_map[page + 7] = 0xe1;
  expected_a[page + 7] = 0xe1;
  FILES("mapped write before sync");
  ALIASES("mapped write before sync");
  const unsigned char from_fd[] = {0x43, 0x91, 0x28, 0xde};
  EXACT(pwrite(observer, from_fd, sizeof(from_fd), (off_t)(2 * page + 17)),
        sizeof(from_fd), "observer write before sync");
  memcpy(expected_a + 2 * page + 17, from_fd, sizeof(from_fd));
  REQUIRE(bytes_equal("fd write main", main_map, expected_a, length), "fd write main");
  ALIASES("fd write before sync");
  FILES("fd write before sync");

  /* Returning a byte to its original value must still overwrite a newer fd
   * write; comparing a guest snapshot only with its initial bytes is wrong. */
  unsigned char original = expected_a[2 * page + 31];
  unsigned char temporary = original ^ 0xff;
  EXACT(pwrite(duplicate, &temporary, 1, (off_t)(2 * page + 31)), 1,
        "duplicate write original-to-temporary");
  expected_a[2 * page + 31] = temporary;
  ALIASES("temporary fd byte visible");
  alias2[31] = original;
  expected_a[2 * page + 31] = original;
  FILES("mapped restore before sync");
  ALIASES("mapped restore before sync");

  for (unsigned cycle = 0; cycle < 3; ++cycle) {
    unsigned char fd_byte = (unsigned char)(0x71 + cycle);
    EXACT(pwrite(observer, &fd_byte, 1, (off_t)(page + 50 + cycle)), 1,
          "cycle independent write");
    expected_a[page + 50 + cycle] = fd_byte;
    alias1[page + 70 + cycle] = (unsigned char)(0xb1 + cycle);
    expected_a[2 * page + 70 + cycle] = (unsigned char)(0xb1 + cycle);
    EXACT(msync((void *)alias1, 2 * page, MS_SYNC), 0, "repeated shared sync");
    ++syncs;
    FILES("repeated shared sync");
    ALIASES("repeated shared sync");
  }

  /* The mappings retain A even after both related descriptors close and the
   * original descriptor number explicitly names unrelated file B. */
  int original_fd = fd_a;
  EXACT(close(fd_a), 0, "close original A");
  fd_a = -1;
  EXACT(close(duplicate), 0, "close duplicate A");
  duplicate = -1;
  EXACT(dup2(fd_b, original_fd), original_fd, "reuse original descriptor for B");
  reused = original_fd;
  main_map[5] = 0x19;
  expected_a[5] = 0x19;
  EXACT(msync((void *)main_map, page, MS_SYNC), 0, "sync after descriptor reuse");
  ++syncs;
  FILES("descriptor reuse");
  REQUIRE(file_equal("reused descriptor is B", reused, scratch, expected_b, length),
          "reused descriptor is B");
  EXACT(unlink(path_a), 0, "unlink mapped A");
  linked_a = 0;
  alias2[93] = 0xf2;
  expected_a[2 * page + 93] = 0xf2;
  EXACT(msync((void *)alias2, page, MS_SYNC), 0, "sync after unlink");
  ++syncs;
  FILES("unlink lifetime");
  ALIASES("unlink lifetime");

  EXACT(munmap((void *)(main_map + page), page), 0, "unmap only middle page");
  FILES("split unmap preserves outgoing bytes");
  main_map[11] = 0x52;
  main_map[2 * page + 13] = 0xc6;
  expected_a[11] = 0x52;
  expected_a[2 * page + 13] = 0xc6;
  EXACT(msync((void *)main_map, page, MS_SYNC), 0, "sync split first page");
  ++syncs;
  EXACT(msync((void *)(main_map + 2 * page), page, MS_SYNC), 0,
        "sync split third page");
  ++syncs;
  FILES("split survivors retain file offsets");
  ALIASES("split survivors retain file offsets");

  void *middle = (void *)(main_map + page);
  FIXED_MAP(mmap(middle, page, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), middle,
            "fixed private into hole");
  memset(scratch, 0, page);
  REQUIRE(bytes_equal("anonymous hole replacement starts zero", main_map + page,
                      scratch, page), "anonymous hole replacement starts zero");
  for (size_t i = 0; i < page; ++i)
    main_map[page + i] = expected_private[i];
  EXACT(msync(middle, page, MS_SYNC), 0, "sync anonymous replacement");
  ++syncs;
  FILES("private replacement leaves files alone");
  REQUIRE(bytes_equal("private replacement", main_map + page, expected_private, page),
          "private replacement");

  FIXED_MAP(mmap(middle, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
                 fd_b, (off_t)page), middle, "fixed private to shared B");
  FILES("private to shared preserves files");
  REQUIRE(bytes_equal("B offset one", main_map + page, expected_b + page, page),
          "B offset one");
  main_map[page + 29] = 0xad;
  expected_b[page + 29] = 0xad;
  EXACT(msync(middle, page, MS_SYNC), 0, "sync B replacement");
  ++syncs;
  FILES("B replacement has its own offset");

  FIXED_MAP(mmap(middle, page, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), middle,
            "fixed shared B to private");
  FILES("shared to private never zeros B");
  memset(scratch, 0, page);
  REQUIRE(bytes_equal("anonymous B replacement starts zero", main_map + page,
                      scratch, page), "anonymous B replacement starts zero");
  for (size_t i = 0; i < page; ++i)
    main_map[page + i] = expected_private[page + i];
  EXACT(msync(middle, page, MS_SYNC), 0, "sync second private replacement");
  ++syncs;
  FILES("second private leaves files alone");
  REQUIRE(bytes_equal("second private", main_map + page, expected_private + page, page),
          "second private");

  FIXED_MAP(mmap(middle, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
                 observer, (off_t)page), middle, "fixed private to shared A");
  REQUIRE(bytes_equal("A offset restored", main_map + page, expected_a + page, page),
          "A offset restored");
  main_map[page + 103] = 0x37;
  expected_a[page + 103] = 0x37;
  EXACT(msync(middle, page, MS_SYNC), 0, "sync restored A");
  ++syncs;
  FILES("restored A");
  ALIASES("restored A");
  FIXED_MAP(mmap(middle, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
                 fd_b, (off_t)(2 * page)), middle, "fixed shared A to shared B");
  FILES("shared to shared never zeros A");
  REQUIRE(bytes_equal("B offset two", main_map + page, expected_b + 2 * page, page),
          "B offset two");
  main_map[page + 107] = 0x64;
  expected_b[2 * page + 107] = 0x64;
  EXACT(msync(middle, page, MS_SYNC), 0, "sync shared-to-shared replacement");
  ++syncs;
  FILES("shared-to-shared correct file and offset");
  ALIASES("shared-to-shared retains A aliases");
  REQUIRE(bytes_equal("first survivor", main_map, expected_a, page), "first survivor");
  REQUIRE(bytes_equal("third survivor", main_map + 2 * page, expected_a + 2 * page, page),
          "third survivor");
  EXACT(munmap((void *)main_map, length), 0, "unmap mixed three-page view");
  main_map = MAP_FAILED;
  FILES("mixed-view retirement preserves both files");
  ALIASES("aliases survive mixed-view retirement");

  NEW_MAP(private_map,
          mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, observer, 0),
          "private A");
  REQUIRE(bytes_equal("initial private file bytes", private_map, expected_a, length),
          "initial private file bytes");
  /* Dirty every private byte before any later file-side change. */
  for (size_t i = 0; i < length; ++i)
    private_map[i] = expected_private[i];
  EXACT(msync((void *)private_map, length, MS_SYNC), 0, "sync dirty private A");
  ++syncs;
  FILES("private writes stay private");
  ALIASES("private writes leave shared aliases unchanged");
  alias1[127] = 0x6e;
  expected_a[page + 127] = 0x6e;
  EXACT(msync((void *)alias1, 2 * page, MS_SYNC), 0, "sync surviving shared alias");
  ++syncs;
  FILES("shared write after private dirtying");
  ALIASES("shared write after private dirtying");
  REQUIRE(bytes_equal("private independence", private_map, expected_private, length),
          "private independence");
  EXACT(munmap((void *)private_map, length), 0, "unmap private A");
  private_map = MAP_FAILED;
  EXACT(munmap((void *)alias1, 2 * page), 0, "unmap alias one");
  alias1 = MAP_FAILED;
  EXACT(munmap((void *)alias2, page), 0, "unmap alias two");
  alias2 = MAP_FAILED;
  FILES("last-view retirement preserves both files");
  EXACT(syncs, 14, "completed sync operations");
  EXACT(close(observer), 0, "close observer");
  observer = -1;
  EXACT(close(reused), 0, "close reused descriptor");
  reused = -1;
  EXACT(close(fd_b), 0, "close B");
  fd_b = -1;
  EXACT(unlink(path_b), 0, "unlink B");
  linked_b = 0;
  puts("msync lifecycle shared=ok replacement=ok private=ok syncs=14");
  result = 0;

cleanup:
  if (main_map != MAP_FAILED) munmap((void *)main_map, length);
  if (alias1 != MAP_FAILED) munmap((void *)alias1, 2 * page);
  if (alias2 != MAP_FAILED) munmap((void *)alias2, page);
  if (private_map != MAP_FAILED) munmap((void *)private_map, length);
  if (fd_a >= 0) close(fd_a);
  if (fd_b >= 0) close(fd_b);
  if (observer >= 0) close(observer);
  if (duplicate >= 0) close(duplicate);
  if (reused >= 0) close(reused);
  if (linked_a) unlink(path_a);
  if (linked_b) unlink(path_b);
  free(expected_a);
  free(expected_b);
  free(scratch);
  free(expected_private);
  return result;
}
