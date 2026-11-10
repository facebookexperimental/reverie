/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Mappings whose flags (smaps' VmFlags) each case sets, for the KVM
 * backend's vm_flags facts to be compared with Linux's. Every case lies in
 * a range of its own, with unmapped pages around it, so that no case's
 * mapping merges with another's:
 * - MAP_STACK, read-write, and as glibc makes a thread's stack (PROT_NONE,
 *   then mprotect read-write);
 * - MAP_GROWSDOWN, MAP_LOCKED, MAP_SYNC (anonymous, and a private mapping of
 *   a file), MAP_NORESERVE and MAP_HUGETLB | MAP_NORESERVE;
 * - a guard installed on the first page of four, then the last made
 *   read-only, which splits it; and a guarded mapping that a plain one
 *   placed right below merges with, then unmapped;
 * - anonymous memory never written made read-only, a private file mapping
 *   made read-only, and guarded anonymous memory made read-only;
 * - shared mappings of a file opened read-only and read-write, shared
 *   anonymous memory, and a memfd mapped shared and read-only;
 * - a thread's stack, as glibc makes it.
 * Then a forked child looks at the locked and the guarded mappings.
 *
 * At each point (1 in the process, 2 in the child), for each case, it
 * prints "case POINT NAME ADDRESS", and natively the VmFlags line of the
 * mapping that holds the address in its own smaps ("flags POINT NAME
 * FLAGS..."); under a Tool (the mode "tool") it asks the Tool, with
 * tuxcall, for its map instead.
 *
 * Usage: vm_flags MODE DIRECTORY   (MODE: native or tool)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ASK 0x6d656d6f72796d61L
#define PAGE 4096UL
#ifndef MAP_SYNC
#define MAP_SYNC 0x80000
#endif
#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#endif

static void fail(int line) {
  char message[64];
  int length = snprintf(message, sizeof(message), "vm_flags.c:%d: errno %d\n",
                        line, errno);
  if (write(2, message, (size_t)length) < 0) {
  }
  _exit(90);
}

#define CHECK(condition)                                                  \
  do {                                                                    \
    if (!(condition)) {                                                   \
      fail(__LINE__);                                                     \
    }                                                                     \
  } while (0)

static int tool;

static void out(const char *text) {
  size_t length = strlen(text);
  while (length > 0) {
    ssize_t written = write(1, text, length);
    CHECK(written > 0);
    text += written;
    length -= (size_t)written;
  }
}

/* The cases, by name, and the address each looks at. */
static struct {
  const char *name;
  uintptr_t address;
} cases[32];
static int count;

static void track(const char *name, uintptr_t address) {
  CHECK(count < 32);
  cases[count].name = name;
  cases[count].address = address;
  count++;
}

/* The smaps text, read whole. */
static char smaps[4 << 20];

/* The VmFlags of the mapping that holds `address`, from `smaps`. */
static const char *flags_of(uintptr_t address, char *flags, size_t size) {
  int inside = 0;
  for (char *line = smaps; *line != '\0';) {
    char *end = strchr(line, '\n');
    CHECK(end != NULL);
    *end = '\0';
    unsigned long start, stop;
    if (sscanf(line, "%lx-%lx ", &start, &stop) == 2) {
      inside = start <= address && address < stop;
    } else if (inside && strncmp(line, "VmFlags:", 8) == 0) {
      snprintf(flags, size, "%s", line + 8);
      *end = '\n';
      return flags;
    }
    *end = '\n';
    line = end + 1;
  }
  return NULL;
}

/* One point: each case's address, and natively its mapping's flags. */
static void point(int at) {
  if (tool) {
    syscall(SYS_tuxcall, ASK, (long)syscall(SYS_gettid), (long)at);
  } else {
    int fd = open("/proc/self/smaps", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    size_t length = 0;
    for (;;) {
      ssize_t got = read(fd, smaps + length, sizeof(smaps) - 1 - length);
      CHECK(got >= 0);
      if (got == 0) {
        break;
      }
      length += (size_t)got;
      CHECK(length < sizeof(smaps) - 1);
    }
    smaps[length] = '\0';
    CHECK(close(fd) == 0);
  }
  for (int i = 0; i < count; i++) {
    char line[512];
    snprintf(line, sizeof(line), "case %d %s %lx\n", at, cases[i].name,
             (unsigned long)cases[i].address);
    out(line);
    if (!tool) {
      char flags[256];
      const char *found = flags_of(cases[i].address, flags, sizeof(flags));
      CHECK(found != NULL);
      snprintf(line, sizeof(line), "flags %d %s%s\n", at, cases[i].name, found);
      out(line);
    }
  }
}

/* Room for `pages` pages with an unmapped page on each side, which no
 * later mapping of fewer than three pages can take: the address of the
 * first. */
static uintptr_t room(unsigned long pages) {
  char *base = mmap(NULL, (pages + 4) * PAGE, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  CHECK(base != MAP_FAILED);
  CHECK(munmap(base, (pages + 4) * PAGE) == 0);
  return (uintptr_t)base + 2 * PAGE;
}

static uintptr_t fixed(uintptr_t at, unsigned long pages, int prot, int flags,
                       int fd) {
  void *mapped = mmap((void *)at, pages * PAGE, prot,
                      flags | MAP_FIXED | (fd < 0 ? MAP_ANONYMOUS : 0), fd, 0);
  CHECK(mapped == (void *)at);
  return at;
}

static int pipe_fds[2];
static uintptr_t volatile thread_stack;

static void *thread_main(void *unused) {
  (void)unused;
  volatile char local = 0;
  thread_stack = (uintptr_t)&local;
  char byte;
  CHECK(read(pipe_fds[0], &byte, 1) == 1);
  return NULL;
}

/* A file of `pages` pages in `directory`, opened with `flags`. */
static int file(const char *directory, const char *name, unsigned long pages,
                int flags) {
  char path[4096];
  snprintf(path, sizeof(path), "%s/%s", directory, name);
  int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  CHECK(fd >= 0);
  CHECK(ftruncate(fd, (off_t)(pages * PAGE)) == 0);
  if ((flags & O_ACCMODE) != O_RDWR) {
    CHECK(close(fd) == 0);
    fd = open(path, flags | O_CLOEXEC);
    CHECK(fd >= 0);
  }
  return fd;
}

int main(int argc, char **argv) {
  CHECK(argc == 3);
  tool = strcmp(argv[1], "tool") == 0;
  const char *directory = argv[2];
  int private = MAP_PRIVATE;
  int rw = PROT_READ | PROT_WRITE;

  track("stack", fixed(room(2), 2, rw, private | MAP_STACK, -1));
  uintptr_t glibc = fixed(room(2), 2, PROT_NONE, private | MAP_STACK, -1);
  CHECK(mprotect((void *)glibc, 2 * PAGE, rw) == 0);
  track("glibc-stack", glibc);
  track("growsdown", fixed(room(2), 2, rw, private | MAP_GROWSDOWN, -1));
  uintptr_t locked = fixed(room(1), 1, rw, private | MAP_LOCKED, -1);
  track("locked", locked);
  track("sync-anonymous", fixed(room(1), 1, rw, private | MAP_SYNC, -1));
  int sync_file = file(directory, "sync", 1, O_RDONLY);
  track("sync-file", fixed(room(1), 1, PROT_READ, private | MAP_SYNC, sync_file));
  track("noreserve", fixed(room(1), 1, rw, private | MAP_NORESERVE, -1));
  void *huge = mmap(NULL, 2UL << 20, rw,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE,
                    -1, 0);
  CHECK(huge != MAP_FAILED);
  track("hugetlb", (uintptr_t)huge);

  uintptr_t split = fixed(room(4), 4, rw, private, -1);
  CHECK(madvise((void *)split, PAGE, MADV_GUARD_INSTALL) == 0);
  CHECK(mprotect((void *)(split + 3 * PAGE), PAGE, PROT_READ) == 0);
  track("guard-split-first", split);
  track("guard-split-last", split + 3 * PAGE);
  uintptr_t merge = room(4);
  fixed(merge + 2 * PAGE, 2, rw, private, -1);
  CHECK(madvise((void *)(merge + 2 * PAGE), PAGE, MADV_GUARD_INSTALL) == 0);
  fixed(merge, 2, rw, private, -1);
  CHECK(munmap((void *)(merge + 2 * PAGE), 2 * PAGE) == 0);
  track("guard-merged-then-unmapped", merge);

  uintptr_t anonymous = fixed(room(2), 2, rw, private, -1);
  CHECK(mprotect((void *)anonymous, 2 * PAGE, PROT_READ) == 0);
  track("anonymous-read-only", anonymous);
  int rw_file = file(directory, "private", 2, O_RDWR);
  uintptr_t private_file = fixed(room(2), 2, rw, private, rw_file);
  CHECK(mprotect((void *)private_file, 2 * PAGE, PROT_READ) == 0);
  track("file-read-only", private_file);
  uintptr_t guarded = fixed(room(3), 3, rw, private, -1);
  CHECK(madvise((void *)guarded, PAGE, MADV_GUARD_INSTALL) == 0);
  CHECK(mprotect((void *)guarded, 3 * PAGE, PROT_READ) == 0);
  track("guarded-read-only", guarded + PAGE);

  int read_only = file(directory, "shared-read", 1, O_RDONLY);
  track("shared-file-read-only",
        fixed(room(1), 1, PROT_READ, MAP_SHARED, read_only));
  int read_write = file(directory, "shared-write", 1, O_RDWR);
  track("shared-file-read-write", fixed(room(1), 1, rw, MAP_SHARED, read_write));
  track("shared-anonymous", fixed(room(1), 1, rw, MAP_SHARED, -1));
  int memfd = (int)syscall(SYS_memfd_create, "vm-flags", 0);
  CHECK(memfd >= 0);
  CHECK(ftruncate(memfd, (off_t)PAGE) == 0);
  track("memfd-shared-read-only",
        fixed(room(1), 1, PROT_READ, MAP_SHARED, memfd));

  CHECK(pipe(pipe_fds) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, thread_main, NULL) == 0);
  while (thread_stack == 0) {
    sched_yield();
  }
  track("thread-stack", thread_stack);

  point(1);
  CHECK(write(pipe_fds[1], "x", 1) == 1);
  CHECK(pthread_join(thread, NULL) == 0);

  count = 0;
  track("locked", locked);
  track("guard-split-first", split);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    point(2);
    _exit(0);
  }
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  return 0;
}
