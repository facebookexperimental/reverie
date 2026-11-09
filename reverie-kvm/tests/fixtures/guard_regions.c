/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* madvise(MADV_GUARD_INSTALL) and madvise(MADV_GUARD_REMOVE), observed only
 * through syscalls: a kernel copy to or from a guard page faults (EFAULT).
 * The program never touches a guard page itself, and each line evaluates one
 * check, in order. Prints one line per check;
 * the output is the same wherever guard regions behave as Linux 6.13+. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#endif
#ifndef MADV_GUARD_REMOVE
#define MADV_GUARD_REMOVE 103
#endif

static int pipe_fds[2];
static long page;

/* "ok" when a kernel copy can read the byte at `address`, else the errno. */
static const char *probe(char *address) {
  static char error[32];
  if (write(pipe_fds[1], address, 1) == 1) {
    char byte;
    if (read(pipe_fds[0], &byte, 1) != 1) {
      abort();
    }
    return "ok";
  }
  snprintf(error, sizeof error, "%s", strerror(errno));
  return error;
}

static const char *result(int rc) {
  static char text[32];
  if (rc == 0) {
    return "0";
  }
  snprintf(text, sizeof text, "%s", strerror(errno));
  return text;
}

static int guard(char *address, long pages, int advice) {
  return madvise(address, pages * page, advice);
}

int main(void) {
  page = sysconf(_SC_PAGESIZE);
  if (pipe(pipe_fds) != 0) {
    return 2;
  }
  char *p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    return 3;
  }
  memset(p, 'a', 4 * page);
  int rc = guard(p + page, 1, MADV_GUARD_INSTALL);
  if (rc != 0 && errno == EINVAL) {
    printf("guard: unsupported\n");
    return 0;
  }
  printf("install: %s\n", result(rc));
  printf("guard page: %s\n", probe(p + page));
  printf("neighbours: %s\n", probe(p));
  printf("            %s\n", probe(p + 2 * page));
  if (write(pipe_fds[1], "x", 1) != 1) {
    return 4;
  }
  printf("read into guard: %s\n",
         read(pipe_fds[0], p + page, 1) < 0 ? strerror(errno) : "copied");
  char drain;
  if (read(pipe_fds[0], &drain, 1) != 1) {
    return 4;
  }
  printf("neighbour kept: %c\n", p[0]);
  printf("again: %s\n", result(guard(p + page, 1, MADV_GUARD_INSTALL)));
  printf("guard page: %s\n", probe(p + page));
  printf("unaligned: %s\n", result(madvise(p + 1, page, MADV_GUARD_INSTALL)));

  printf("dontneed: %s\n", result(madvise(p, 4 * page, MADV_DONTNEED)));
  printf("guard page: %s\n", probe(p + page));
  printf("mprotect: %s\n", result(mprotect(p, 4 * page, PROT_READ)));
  printf("guard page: %s\n", probe(p + page));
  mprotect(p, 4 * page, PROT_READ | PROT_WRITE);

  fflush(stdout);
  pid_t child = fork();
  if (child == 0) {
    printf("child guard page: %s\n", probe(p + page));
    printf("child remove: %s\n", result(guard(p + page, 1, MADV_GUARD_REMOVE)));
    printf("child page: %s\n", probe(p + page));
    fflush(stdout);
    _exit(0);
  }
  int status;
  waitpid(child, &status, 0);
  printf("child exit: %d\n", WEXITSTATUS(status));
  printf("parent guard page: %s\n", probe(p + page));

  printf("remove: %s\n", result(guard(p + page, 1, MADV_GUARD_REMOVE)));
  printf("page: %s\n", probe(p + page));
  printf("contents: %d\n", p[page]);

  /* A hole: the mapped part takes the guard, and the call reports ENOMEM. */
  munmap(p + 3 * page, page);
  printf("install over hole: %s\n",
         result(guard(p + 2 * page, 2, MADV_GUARD_INSTALL)));
  printf("mapped part: %s\n", probe(p + 2 * page));
  printf("remove over hole: %s\n",
         result(guard(p + 2 * page, 2, MADV_GUARD_REMOVE)));
  printf("mapped part: %s\n", probe(p + 2 * page));

  /* munmap and a new mapping end a guard. */
  guard(p + 2 * page, 1, MADV_GUARD_INSTALL);
  munmap(p + 2 * page, page);
  char *again = mmap(p + 2 * page, page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  printf("remapped: %s\n", again == p + 2 * page ? "same" : "moved");
  printf("page: %s\n", probe(again));
  guard(p, 1, MADV_GUARD_INSTALL);
  char *fixed = mmap(p, page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  printf("mapped over guard: %s\n", probe(fixed));

  /* mremap moves a guard with its page; the pages a grow adds have none. */
  char *two = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  guard(two + page, 1, MADV_GUARD_INSTALL);
  char *moved = mremap(two, 2 * page, 3 * page, MREMAP_MAYMOVE);
  printf("moved first: %s\n", probe(moved));
  printf("moved guard: %s\n", probe(moved + page));
  printf("grown: %s\n", probe(moved + 2 * page));
  return 0;
}
