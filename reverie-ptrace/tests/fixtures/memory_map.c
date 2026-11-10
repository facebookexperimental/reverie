/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Changes its address space one step at a time (the program break grown by
 * three pages, its middle page made read-only, inaccessible, read and
 * execute, write-only and read-write again; a page of the stack made
 * inaccessible and accessible again; the break shrunk back), then makes a
 * sibling thread and a child process, which grows its own break, and at each
 * numbered point reads the maps file of a thread, /proc/<tid>/maps: its
 * text, or the errno of the read. Under a Tool (the mode "tool") it then asks
 * the Tool, with tuxcall, which Linux does not implement, for the map of the
 * same thread; the Tool records what Guest::memory_map answered. A thread of
 * this process asks about itself, a sibling or the child; the child as a
 * zombie and reaped, this process's parent, a number no task has, zero and a
 * negative number name no guest thread.
 *
 * It allocates nothing from the heap before the break is shrunk back, and
 * makes no call between a point's read and its question, so both see the
 * same address space. Standard output lists the program break's first page
 * and the stack page it protects, then every point, in order: the thread it
 * asked about, the text or errno it read, and under a Tool that it asked.
 *
 * Usage: memory_map MODE
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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

enum {
  START = 1,
  HEAP,
  HEAP_READ_ONLY,
  HEAP_NONE,
  HEAP_EXEC,
  HEAP_WRITE_ONLY,
  HEAP_JOINED,
  STACK_GUARD,
  STACK_JOINED,
  BREAK_SHRUNK,
  SIBLING_LEADER,
  SIBLING,
  SIBLING_SELF,
  CHILD,
  ZOMBIE_CHILD,
  REAPED_CHILD,
  HOST_PARENT,
  NO_TASK,
  ZERO,
  NEGATIVE,
  POINTS,
};

static void fail(int line) {
  char message[64];
  int length = snprintf(message, sizeof(message), "memory_map.c:%d: errno %d\n",
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

/* Writes all of `text` to standard output. */
static void out(const char *text, size_t length) {
  while (length > 0) {
    ssize_t written = write(1, text, length);
    CHECK(written > 0);
    text += written;
    length -= (size_t)written;
  }
}

static void line(const char *text) { out(text, strlen(text)); }

/* One read's text, and the same in hexadecimal for standard output. */
static char text[1 << 20];
static char hex[2 << 20];

static pid_t gettid_raw(void) { return (pid_t)syscall(SYS_gettid); }

/* One point: read thread `tid`'s maps, then under a Tool ask about it. */
static void point(int point, long tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%ld/maps", tid);
  ssize_t length = -1;
  int error = 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    error = errno;
  } else {
    length = 0;
    for (;;) {
      ssize_t got = read(fd, text + length, sizeof(text) - (size_t)length);
      if (got < 0) {
        error = errno;
        break;
      }
      if (got == 0) {
        break;
      }
      length += got;
      CHECK((size_t)length < sizeof(text));
    }
    CHECK(close(fd) == 0);
  }
  if (tool) {
    syscall(SYS_tuxcall, ASK, tid, (long)point);
  }
  char header[96];
  snprintf(header, sizeof(header), "tid %d %ld\n", point, tid);
  line(header);
  if (error != 0) {
    snprintf(header, sizeof(header), "point %d errno %d\n", point, error);
    line(header);
  } else {
    snprintf(header, sizeof(header), "point %d text ", point);
    line(header);
    static const char digits[] = "0123456789abcdef";
    for (ssize_t i = 0; i < length; i++) {
      hex[2 * i] = digits[(unsigned char)text[i] >> 4];
      hex[2 * i + 1] = digits[(unsigned char)text[i] & 15];
    }
    out(hex, 2 * (size_t)length);
    line("\n");
  }
  if (tool) {
    snprintf(header, sizeof(header), "point %d asked\n", point);
    line(header);
  }
}

static int sibling_ready[2], sibling_release[2];

/* A sibling thread: it asks about itself, then waits while the leader asks
 * about it. */
static void *sibling(void *argument) {
  (void)argument;
  pid_t tid = gettid_raw();
  point(SIBLING_SELF, tid);
  CHECK(write(sibling_ready[1], &tid, sizeof(tid)) == sizeof(tid));
  char byte;
  CHECK(read(sibling_release[0], &byte, 1) == 1);
  return NULL;
}

int main(int argc, char **argv) {
  CHECK(argc >= 2);
  tool = strcmp(argv[1], "tool") == 0;
  pid_t tid = gettid_raw();
  char header[96];

  /* No heap yet: the break is where the image left it, on a page boundary. */
  uintptr_t base = (uintptr_t)sbrk(0);
  CHECK(base % PAGE == 0);
  point(START, tid);

  /* The break grown by three pages, then its middle page changed. */
  CHECK((uintptr_t)sbrk(3 * PAGE) == base);
  snprintf(header, sizeof(header), "heap %lx\n", (unsigned long)base);
  line(header);
  point(HEAP, tid);
  void *middle = (void *)(base + PAGE);
  CHECK(mprotect(middle, PAGE, PROT_READ) == 0);
  point(HEAP_READ_ONLY, tid);
  CHECK(mprotect(middle, PAGE, PROT_NONE) == 0);
  point(HEAP_NONE, tid);
  CHECK(mprotect(middle, PAGE, PROT_READ | PROT_EXEC) == 0);
  point(HEAP_EXEC, tid);
  CHECK(mprotect(middle, PAGE, PROT_WRITE) == 0);
  point(HEAP_WRITE_ONLY, tid);
  CHECK(mprotect(middle, PAGE, PROT_READ | PROT_WRITE) == 0);
  point(HEAP_JOINED, tid);

  /* A page of the stack, four pages below this frame's, made inaccessible,
   * then accessible again. */
  volatile char local = 0;
  uintptr_t guard = ((uintptr_t)&local & ~(PAGE - 1)) - 4 * PAGE;
  snprintf(header, sizeof(header), "guard %lx\n", (unsigned long)guard);
  line(header);
  CHECK(mprotect((void *)guard, PAGE, PROT_NONE) == 0);
  point(STACK_GUARD, tid);
  CHECK(mprotect((void *)guard, PAGE, PROT_READ | PROT_WRITE) == 0);
  point(STACK_JOINED, tid);
  (void)local;

  /* The break shrunk back. */
  CHECK(sbrk(-3 * (intptr_t)PAGE) != (void *)-1);
  CHECK((uintptr_t)sbrk(0) == base);
  point(BREAK_SHRUNK, tid);

  /* A sibling thread, which asks about itself, then waits while this
   * thread asks about itself and about it. */
  CHECK(pipe2(sibling_ready, O_CLOEXEC) == 0 &&
        pipe2(sibling_release, O_CLOEXEC) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, sibling, NULL) == 0);
  pid_t sibling_tid;
  CHECK(read(sibling_ready[0], &sibling_tid, sizeof(sibling_tid)) ==
        sizeof(sibling_tid));
  point(SIBLING_LEADER, tid);
  point(SIBLING, sibling_tid);
  CHECK(write(sibling_release[1], "r", 1) == 1);
  CHECK(pthread_join(thread, NULL) == 0);

  /* A child process while it waits, its break grown by a page so that its
   * map is its own, then the child as a zombie and reaped. */
  int child_ready[2], child_release[2];
  CHECK(pipe2(child_ready, O_CLOEXEC) == 0 &&
        pipe2(child_release, O_CLOEXEC) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(sbrk(PAGE) != (void *)-1);
    CHECK(write(child_ready[1], "c", 1) == 1);
    char byte;
    CHECK(read(child_release[0], &byte, 1) == 1);
    _exit(0);
  }
  char byte;
  CHECK(read(child_ready[0], &byte, 1) == 1);
  point(CHILD, child);
  CHECK(write(child_release[1], "r", 1) == 1);
  siginfo_t info;
  CHECK(waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT) == 0);
  point(ZOMBIE_CHILD, child);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  point(REAPED_CHILD, child);

  /* Numbers that name no guest thread: this process's parent, one no task
   * has, zero and a negative one. */
  point(HOST_PARENT, getppid());
  point(NO_TASK, 0x7fffffff);
  point(ZERO, 0);
  point(NEGATIVE, -1);
  return 0;
}
