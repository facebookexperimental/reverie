/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Settled fork visibility, independently of scheduling before waitpid. These
 * are ordinary-file and memfd MAP_SHARED mappings, not anonymous MAP_SHARED.
 * Readback observes the page cache; it does not claim power-loss durability.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PAGE = 4096, FILE_BYTES = 3 * PAGE, WORDS = 8 };

#define REQUIRE(condition, step)                                               \
  do {                                                                        \
    if (!(condition)) {                                                       \
      fprintf(stderr, "%s failed errno=%d\n", step, errno);                    \
      _exit(1);                                                               \
    }                                                                         \
  } while (0)

static void bytes_equal(const char *step, const volatile unsigned char *actual,
                        const unsigned char *expected, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    unsigned char observed = actual[i];
    if (observed != expected[i]) {
      fprintf(stderr, "%s byte[%zu]=%u expected=%u\n", step, i,
              (unsigned)observed, (unsigned)expected[i]);
      _exit(1);
    }
  }
}

static void set_word(unsigned char *bytes, size_t index, uint64_t value) {
  memcpy(bytes + index * sizeof(value), &value, sizeof(value));
}

static void initialize_file(int fd, unsigned char byte) {
  unsigned char initial[FILE_BYTES];
  memset(initial, byte, sizeof(initial));
  REQUIRE(ftruncate(fd, FILE_BYTES) == 0, "initial file size");
  REQUIRE(pwrite(fd, initial, sizeof(initial), 0) == (ssize_t)sizeof(initial),
          "initial file contents");
}

static void file_equal(const char *step, int fd,
                       const unsigned char *expected) {
  unsigned char observed[FILE_BYTES];
  REQUIRE(pread(fd, observed, sizeof(observed), 0) == (ssize_t)sizeof(observed),
          "full file readback");
  bytes_equal(step, observed, expected, sizeof(observed));
}

int main(void) {
  REQUIRE(sysconf(_SC_PAGESIZE) == PAGE, "page size");
  int file_fd = open("shared-file.bin", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
                     0600);
  int memfd = (int)syscall(SYS_memfd_create, "shared-fork", MFD_CLOEXEC);
  REQUIRE(file_fd >= 0 && memfd >= 0 && file_fd != memfd, "create backings");
  initialize_file(file_fd, 0xa1);
  initialize_file(memfd, 0xb2);

  unsigned char *file_map = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
                                  file_fd, PAGE);
  unsigned char *memfd_map = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
                                   memfd, PAGE);
  unsigned char *private_map = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(file_map != MAP_FAILED && memfd_map != MAP_FAILED &&
              private_map != MAP_FAILED,
          "map middle pages and private memory");
  memset(private_map, 0xaa, PAGE);

  unsigned char expected_file[FILE_BYTES];
  unsigned char expected_memfd[FILE_BYTES];
  unsigned char expected_replacement[FILE_BYTES];
  unsigned char expected_private[PAGE];
  memset(expected_file, 0xa1, sizeof(expected_file));
  memset(expected_memfd, 0xb2, sizeof(expected_memfd));
  memset(expected_replacement, 0xc3, sizeof(expected_replacement));
  memset(expected_private, 0xaa, sizeof(expected_private));
  bytes_equal("initial file offset", file_map, expected_file + PAGE, PAGE);
  bytes_equal("initial memfd offset", memfd_map, expected_memfd + PAGE, PAGE);

  /* Keep a distinct memfd description reference for independent readback, but
   * close both descriptor numbers used by mmap. Their replacements name an
   * unrelated file before the backend has to construct the child mappings.
   */
  int memfd_reader = fcntl(memfd, F_DUPFD_CLOEXEC, 0);
  int replacement = open("replacement.bin", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
                         0600);
  REQUIRE(memfd_reader >= 0 && replacement >= 0, "create retained and reused fds");
  initialize_file(replacement, 0xc3);
  REQUIRE(close(file_fd) == 0 && close(memfd) == 0, "close mapping descriptors");
  REQUIRE(dup2(replacement, file_fd) == file_fd &&
              dup2(replacement, memfd) == memfd,
          "reuse mapping descriptor numbers");
  REQUIRE(close(replacement) == 0, "close replacement source");

  const uint64_t file_fd_word = UINT64_C(0x5152535455565758);
  const uint64_t memfd_fd_word = UINT64_C(0x6162636465666768);
  const uint64_t replacement_first = UINT64_C(0x7172737475767778);
  const uint64_t replacement_second = UINT64_C(0x8182838485868788);
  for (size_t i = 0; i < WORDS; ++i) {
    set_word(expected_file + PAGE, i, UINT64_C(0x3300000000000000) + i);
    set_word(expected_memfd + PAGE, i, UINT64_C(0x4400000000000000) + i);
  }
  set_word(expected_file + PAGE, WORDS, file_fd_word);
  set_word(expected_memfd + PAGE, WORDS, memfd_fd_word);
  set_word(expected_replacement, 0, replacement_first);
  set_word(expected_replacement, 1, replacement_second);

  pid_t child = (pid_t)syscall(SYS_fork);
  REQUIRE(child >= 0, "fork with retained shared mappings");
  if (child == 0) {
    for (size_t i = 0; i < WORDS; ++i) {
      ((volatile uint64_t *)file_map)[i] = UINT64_C(0x3300000000000000) + i;
      ((volatile uint64_t *)memfd_map)[i] = UINT64_C(0x4400000000000000) + i;
    }
    bytes_equal("child initial private bytes", private_map, expected_private,
                PAGE);
    ((volatile uint64_t *)private_map)[0] = UINT64_C(0xbbbbbbbbbbbbbbbb);
    REQUIRE(((volatile uint64_t *)private_map)[0] == UINT64_C(0xbbbbbbbbbbbbbbbb),
            "child private write");
    int reopened = open("shared-file.bin", O_RDWR | O_CLOEXEC);
    REQUIRE(reopened >= 0, "reopen ordinary backing");
    REQUIRE(pwrite(reopened, &file_fd_word, sizeof(file_fd_word),
                   PAGE + WORDS * sizeof(uint64_t)) == (ssize_t)sizeof(file_fd_word),
            "ordinary fd-to-mapping write");
    REQUIRE(close(reopened) == 0, "close reopened child backing");
    REQUIRE(pwrite(memfd_reader, &memfd_fd_word, sizeof(memfd_fd_word),
                   PAGE + WORDS * sizeof(uint64_t)) == (ssize_t)sizeof(memfd_fd_word),
            "memfd fd-to-mapping write");
    REQUIRE(pwrite(file_fd, &replacement_first, sizeof(replacement_first), 0) ==
                (ssize_t)sizeof(replacement_first),
            "first reused descriptor write");
    REQUIRE(pwrite(memfd, &replacement_second, sizeof(replacement_second),
                   sizeof(uint64_t)) == (ssize_t)sizeof(replacement_second),
            "second reused descriptor write");
    REQUIRE(msync(file_map, PAGE, MS_SYNC) == 0, "child ordinary msync");
    REQUIRE(msync(memfd_map, PAGE, MS_SYNC) == 0, "child memfd msync");
    bytes_equal("child file coherence", file_map, expected_file + PAGE, PAGE);
    bytes_equal("child memfd coherence", memfd_map, expected_memfd + PAGE, PAGE);
    _exit(0);
  }

  int status = 0x5a5a5a5a;
  REQUIRE(waitpid(child, &status, 0) == child, "wait for exact child");
  REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0 && status == 0,
          "exact successful child status");
  bytes_equal("settled ordinary mapping", file_map, expected_file + PAGE, PAGE);
  bytes_equal("settled memfd mapping", memfd_map, expected_memfd + PAGE, PAGE);
  bytes_equal("parent private COW", private_map, expected_private, PAGE);
  int reader = open("shared-file.bin", O_RDONLY | O_CLOEXEC);
  REQUIRE(reader >= 0, "reopen ordinary file for readback");
  file_equal("ordinary readback including guard pages", reader, expected_file);
  file_equal("memfd readback including guard pages", memfd_reader, expected_memfd);
  file_equal("replacement readback", file_fd, expected_replacement);
  REQUIRE(munmap(file_map, PAGE) == 0 && munmap(memfd_map, PAGE) == 0 &&
              munmap(private_map, PAGE) == 0,
          "retire mappings");
  REQUIRE(close(reader) == 0 && close(memfd_reader) == 0 && close(file_fd) == 0 &&
              close(memfd) == 0,
          "close retained and reused descriptors");
  REQUIRE(unlink("shared-file.bin") == 0 && unlink("replacement.bin") == 0,
          "remove fixture files");
  puts("shared fork ordinary=ok memfd=ok offset=ok reuse=ok cow=ok child=0 syncs=2");
  return 0;
}
