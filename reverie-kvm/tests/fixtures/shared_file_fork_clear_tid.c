/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A non-CLONE_VM child has its own mm. Linux mm_release skips the store
 * and wake when mm_users is one, but native procfs inspection can temporarily
 * hold another mm reference: do_task_stat calls get_task_mm before mmput.
 * https://github.com/gregkh/linux/blob/v7.1.3/kernel/fork.c#L1463
 * https://github.com/gregkh/linux/blob/v7.1.3/fs/proc/array.c#L489
 * https://github.com/gregkh/linux/blob/v7.1.3/include/linux/sched/mm.h#L131
 * Therefore only native's registered four-byte word admits original or zero;
 * all other bytes stay exact. KVM's independent address space must preserve
 * the original word exactly. Print actual observations, never normalize one
 * backend's output to make it appear byte-identical to the other.
 * This explains permitted values, not the cause of any historical mismatch.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PAGE = 4096, FILE_BYTES = 2 * PAGE, TID_OFFSET = 64, STAMP_OFFSET = 256 };

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

static void file_equal(int fd, const unsigned char *expected) {
  unsigned char observed[FILE_BYTES];
  REQUIRE(pread(fd, observed, sizeof(observed), 0) == (ssize_t)sizeof(observed),
          "complete backing readback");
  bytes_equal("backing including unmapped guard page", observed, expected,
              sizeof(observed));
}

int main(int argc, char **argv) {
  REQUIRE(argc == 2, "one explicit backend mode");
  int native = strcmp(argv[1], "native") == 0;
  REQUIRE(native || strcmp(argv[1], "kvm") == 0, "known backend mode");
  REQUIRE(sysconf(_SC_PAGESIZE) == PAGE, "page size");
  int fds[2];
  fds[0] = open("clear-tid.bin", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  fds[1] = (int)syscall(SYS_memfd_create, "clear-tid", MFD_CLOEXEC);
  REQUIRE(fds[0] >= 0 && fds[1] >= 0 && fds[0] != fds[1], "create backings");
  unsigned char expected[2][FILE_BYTES];
  volatile unsigned char *maps[2];
  for (size_t backing = 0; backing < 2; ++backing) {
    memset(expected[backing], backing == 0 ? 0x5d : 0x6e, FILE_BYTES);
    REQUIRE(ftruncate(fds[backing], FILE_BYTES) == 0, "size backing");
    REQUIRE(pwrite(fds[backing], expected[backing], FILE_BYTES, 0) == FILE_BYTES,
            "initialize backing");
    maps[backing] = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fds[backing], PAGE);
    REQUIRE(maps[backing] != MAP_FAILED, "map second backing page");
  }

  for (size_t registration = 0; registration < 2; ++registration) {
    for (size_t backing = 0; backing < 2; ++backing) {
      int marker = 0x31526475 + (int)backing * 0x01010101 + (int)registration;
      volatile int *clear_tid = (volatile int *)(maps[backing] + TID_OFFSET);
      memcpy(expected[backing] + PAGE + TID_OFFSET, &marker, sizeof(marker));
      REQUIRE(pwrite(fds[backing], &marker, sizeof(marker), PAGE + TID_OFFSET) ==
                  (ssize_t)sizeof(marker),
              "install nonzero clear-tid marker");
      bytes_equal("pre-fork mapped bytes", maps[backing],
                  expected[backing] + PAGE, PAGE);
      size_t stamp_offset = STAMP_OFFSET + registration;
      unsigned char stamp = (unsigned char)(0xa0 + 2 * registration + backing);
      unsigned char old_stamp = expected[backing][PAGE + stamp_offset];
      long child;
      if (registration == 0) {
        /* x86-64 raw clone arguments: flags, stack, parent_tid, child_tid, tls.
         * There is deliberately no CLONE_VM and no CLONE_CHILD_SETTID store.
         */
        child = syscall(SYS_clone,
                        (unsigned long)(SIGCHLD | CLONE_CHILD_CLEARTID), 0UL,
                        0UL, (unsigned long)clear_tid, 0UL);
      } else {
        child = syscall(SYS_fork);
      }
      REQUIRE(child >= 0, "create independent child address space");
      if (child == 0) {
        REQUIRE(*clear_tid == marker, "child marker before registration");
        if (registration == 1) {
          long tid = syscall(SYS_gettid);
          REQUIRE(tid > 0, "child tid");
          REQUIRE(syscall(SYS_set_tid_address, (int *)clear_tid) == tid,
                  "register inherited shared clear-tid address");
        }
        REQUIRE(*clear_tid == marker, "registration must not clear marker");
        REQUIRE(maps[backing][stamp_offset] == old_stamp, "child initial stamp");
        maps[backing][stamp_offset] = stamp;
        REQUIRE(maps[backing][stamp_offset] == stamp, "child shared stamp");
        syscall(SYS_exit, 0);
        _exit(2);
      }
      int status = 0x5a5a5a5a;
      REQUIRE(waitpid((pid_t)child, &status, 0) == child, "wait exact child");
      REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0 && status == 0,
              "exact normal child status");
      int observed_marker = *clear_tid;
      printf("clear-tid mode=%s registration=%zu backing=%zu expected=%d "
             "actual=%d waitstatus=%d\n",
             native ? "native" : "kvm", registration, backing, marker,
             observed_marker, status);
      REQUIRE(fflush(stdout) == 0, "retain exact clear-tid observation");
      if (observed_marker != marker && (!native || observed_marker != 0)) {
        int saved_errno = errno;
        fprintf(stderr,
                "clear-tid mismatch registration=%zu backing=%zu expected=%d "
                "actual=%d waitstatus=%d\n",
                registration, backing, marker, observed_marker, status);
        errno = saved_errno;
      }
      if (native) {
        REQUIRE(observed_marker == marker || observed_marker == 0,
                "native clear-tid word must be original or exactly zero");
        /* Only the registered field uses the observed permitted value. The
         * complete mapping and backing comparisons below remain unchanged.
         */
        memcpy(expected[backing] + PAGE + TID_OFFSET, &observed_marker,
               sizeof(observed_marker));
      } else {
        REQUIRE(*clear_tid == marker, "single-mm-user exit preserves marker");
      }
      expected[backing][PAGE + stamp_offset] = stamp;
      for (size_t observed = 0; observed < 2; ++observed) {
        bytes_equal("post-exit complete mapped page", maps[observed],
                    expected[observed] + PAGE, PAGE);
        file_equal(fds[observed], expected[observed]);
      }
    }
  }
  for (size_t backing = 0; backing < 2; ++backing) {
    REQUIRE(munmap((void *)maps[backing], PAGE) == 0, "retire shared mapping");
    REQUIRE(close(fds[backing]) == 0, "close backing");
  }
  REQUIRE(unlink("clear-tid.bin") == 0, "remove ordinary backing");
  puts("shared clear-tid clone=2 fork-set=2 ordinary=ok memfd=ok markers=4 children=0");
  return 0;
}
