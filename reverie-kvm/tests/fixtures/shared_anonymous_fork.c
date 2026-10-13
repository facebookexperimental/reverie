/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* MAP_SHARED | MAP_ANONYMOUS memory is one shmem object shared by a parent and
 * every child forked after the mapping. Each check settles through waitpid, so
 * it holds whatever order the processes run in. Private anonymous memory is a
 * copy in each direction. A child that unmaps the object or execs a new image
 * leaves it intact for the others.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PAGE = 4096, PAGES = 3 };

#define REQUIRE(condition, step)                                               \
  do {                                                                        \
    if (!(condition)) {                                                       \
      fprintf(stderr, "%s failed errno=%d\n", step, errno);                    \
      _exit(1);                                                               \
    }                                                                         \
  } while (0)

static volatile uint64_t *word(unsigned char *base, int page) {
  return (volatile uint64_t *)(base + page * PAGE);
}

static void wait_ok(pid_t child, const char *step) {
  int status = 0x5a5a5a5a;
  REQUIRE(waitpid(child, &status, 0) == child, step);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "%s status=%#x\n", step, status);
    _exit(1);
  }
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "exec-child") == 0) {
    return 0;
  }
  REQUIRE(argc == 1, "usage");
  REQUIRE(sysconf(_SC_PAGESIZE) == PAGE, "page size");
  unsigned char *shared = mmap(NULL, PAGES * PAGE, PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  unsigned char *private_map = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(shared != MAP_FAILED && private_map != MAP_FAILED, "map memory");
  *word(shared, 0) = UINT64_C(0x1111111111111111);
  *word(private_map, 0) = UINT64_C(0xaaaaaaaaaaaaaaaa);

  /* The child sees the parent's store before the fork and its own stores
   * reach the parent; its private store does not. */
  pid_t child = (pid_t)syscall(SYS_fork);
  REQUIRE(child >= 0, "first fork");
  if (child == 0) {
    REQUIRE(*word(shared, 0) == UINT64_C(0x1111111111111111),
            "child reads pre-fork store");
    *word(shared, 1) = UINT64_C(0x2222222222222222);
    *word(private_map, 0) = UINT64_C(0xbbbbbbbbbbbbbbbb);
    /* A grandchild joins the same object. */
    pid_t grandchild = (pid_t)syscall(SYS_fork);
    REQUIRE(grandchild >= 0, "nested fork");
    if (grandchild == 0) {
      REQUIRE(*word(shared, 1) == UINT64_C(0x2222222222222222),
              "grandchild reads child store");
      *word(shared, 2) = UINT64_C(0x3333333333333333);
      _exit(0);
    }
    wait_ok(grandchild, "wait for grandchild");
    REQUIRE(*word(shared, 2) == UINT64_C(0x3333333333333333),
            "child reads grandchild store");
    REQUIRE(munmap(shared, PAGES * PAGE) == 0, "child unmaps shared memory");
    _exit(0);
  }
  wait_ok(child, "wait for first child");
  REQUIRE(*word(shared, 1) == UINT64_C(0x2222222222222222),
          "parent reads child store");
  REQUIRE(*word(shared, 2) == UINT64_C(0x3333333333333333),
          "parent reads grandchild store");
  REQUIRE(*word(private_map, 0) == UINT64_C(0xaaaaaaaaaaaaaaaa),
          "parent private memory stays private");

  /* A second child, forked after the object already exists, writes through
   * it and then replaces its image; neither the store nor the exec disturbs
   * the parent's view. */
  child = (pid_t)syscall(SYS_fork);
  REQUIRE(child >= 0, "second fork");
  if (child == 0) {
    *word(shared, 0) = UINT64_C(0x4444444444444444);
    char *const child_argv[] = {argv[0], "exec-child", NULL};
    char *const child_envp[] = {NULL};
    execve(argv[0], child_argv, child_envp);
    fprintf(stderr, "execve failed errno=%d\n", errno);
    _exit(1);
  }
  wait_ok(child, "wait for exec child");
  REQUIRE(*word(shared, 0) == UINT64_C(0x4444444444444444),
          "parent reads store made before the child's exec");
  REQUIRE(*word(shared, 1) == UINT64_C(0x2222222222222222) &&
              *word(shared, 2) == UINT64_C(0x3333333333333333),
          "exec leaves the shared object intact");
  REQUIRE(munmap(shared, PAGES * PAGE) == 0 && munmap(private_map, PAGE) == 0,
          "retire mappings");
  puts("shared anonymous fork child=ok grandchild=ok cow=ok unmap=ok exec=ok");
  return 0;
}
