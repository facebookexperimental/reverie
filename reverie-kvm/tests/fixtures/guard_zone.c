/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A guard zone on the main thread's stack, as a JVM keeps one. The program
 * reads its main-thread stack with pthread_getattr_np, as the JVM and Rust's
 * standard library do; protects a zone of four pages 64 KiB below the frame
 * that reads it (PROT_NONE, as the JVM protects its yellow and red zones);
 * reads the stack again, which glibc now ends at the zone; runs down to the
 * page just above the zone through a recursion that writes each page it
 * reaches; then makes the zone accessible again. It then protects the zone
 * again and forks: the child makes its copy of the zone accessible, which
 * on Linux stays a mapping of its own in the child, so glibc still ends the
 * child's stack there; then the parent makes its zone accessible. Last, it
 * sets the stack's soft rlimit to one page, less than its arguments above
 * the stack's first page (the test passes a long one), then to 256 MiB,
 * more than the distance to the mapping below the stack, then to none, and
 * protects the zone once more with no limit. At each step it prints, as
 * fixtures/memory_map.c does, the text of /proc/self/maps, under a Tool (the
 * mode "tool") that it asked for the memory map, and what
 * pthread_getattr_np answered with __libc_stack_end and the stack's rlimit.
 * Under a Tool that does not answer for the rlimit, the program leaves it
 * as it is, and the test applies the native run's limit.
 *
 * Usage: guard_zone MODE [ARGUMENT]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ASK 0x6d656d6f72796d61L
#define PAGE 4096UL

enum {
  BEFORE = 1,
  GUARDED,
  USED,
  UNGUARDED,
  CHILD_UNGUARDED,
  PARENT_UNGUARDED,
  LOWERED,
  RAISED,
  UNLIMITED,
  UNLIMITED_GUARDED
};

extern void *__libc_stack_end;

static int tool;

static void fail(int line) {
  char message[64];
  int length = snprintf(message, sizeof(message), "guard_zone.c:%d: errno %d\n",
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

static void out(const char *text) {
  size_t length = strlen(text);
  while (length > 0) {
    ssize_t written = write(1, text, length);
    CHECK(written > 0);
    text += written;
    length -= (size_t)written;
  }
}

static char text[1 << 20];
static char hex[(2 << 20) + 1];

/* One step: the maps text, the memory map under a Tool, and what
 * pthread_getattr_np answers for this, the main thread. */
static void step(int step) {
  long tid = syscall(SYS_gettid);
  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  CHECK(fd >= 0);
  size_t length = 0;
  for (;;) {
    ssize_t got = read(fd, text + length, sizeof(text) - length);
    CHECK(got >= 0);
    if (got == 0) {
      break;
    }
    length += (size_t)got;
    CHECK(length < sizeof(text));
  }
  CHECK(close(fd) == 0);
  if (tool) {
    syscall(SYS_tuxcall, ASK, tid, (long)step);
  }
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < length; i++) {
    hex[2 * i] = digits[(unsigned char)text[i] >> 4];
    hex[2 * i + 1] = digits[(unsigned char)text[i] & 15];
  }
  hex[2 * length] = 0;
  char line[192];
  snprintf(line, sizeof(line), "tid %d %ld\npoint %d text ", step, tid, step);
  out(line);
  out(hex);
  out("\n");
  if (tool) {
    snprintf(line, sizeof(line), "point %d asked\n", step);
    out(line);
  }
  pthread_attr_t attr;
  void *low = NULL;
  size_t size = 0;
  int ret = pthread_getattr_np(pthread_self(), &attr);
  if (ret == 0) {
    CHECK(pthread_attr_getstack(&attr, &low, &size) == 0);
    CHECK(pthread_attr_destroy(&attr) == 0);
  }
  struct rlimit limit = {0, 0};
  if (getrlimit(RLIMIT_STACK, &limit) != 0) {
    limit.rlim_cur = 0;
  }
  snprintf(line, sizeof(line), "stack %d %d %lx %lx %lx %lx\n", step, ret,
           (unsigned long)((uintptr_t)low + size), (unsigned long)size,
           (unsigned long)(uintptr_t)__libc_stack_end,
           (unsigned long)limit.rlim_cur);
  out(line);
}

/* Sets the stack's soft rlimit to `soft`, no more than its hard limit; under
 * a Tool that does not answer for the rlimit, leaves it as it is. */
static void set_stack_limit(rlim_t soft) {
  struct rlimit limit;
  if (getrlimit(RLIMIT_STACK, &limit) != 0) {
    CHECK(tool);
    return;
  }
  limit.rlim_cur = soft < limit.rlim_max ? soft : limit.rlim_max;
  CHECK(setrlimit(RLIMIT_STACK, &limit) == 0);
}

/* Writes a page of each frame down to `floor`, then returns how many frames
 * it took. */
static int __attribute__((noinline)) run_down(uintptr_t floor) {
  volatile char frame[PAGE];
  frame[0] = 1;
  frame[PAGE - 1] = 1;
  if ((uintptr_t)&frame[0] < floor + 2 * PAGE) {
    return 1;
  }
  return run_down(floor) + frame[0];
}

int main(int argc, char **argv) {
  CHECK(argc >= 2);
  tool = strcmp(argv[1], "tool") == 0;
  step(BEFORE);
  volatile char here = 0;
  uintptr_t zone_top = ((uintptr_t)&here & ~(PAGE - 1)) - 16 * PAGE;
  void *zone = (void *)(zone_top - 4 * PAGE);
  CHECK(mprotect(zone, 4 * PAGE, PROT_NONE) == 0);
  step(GUARDED);
  CHECK(run_down(zone_top) > 1);
  step(USED);
  CHECK(mprotect(zone, 4 * PAGE, PROT_READ | PROT_WRITE) == 0);
  step(UNGUARDED);
  CHECK(mprotect(zone, 4 * PAGE, PROT_NONE) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(mprotect(zone, 4 * PAGE, PROT_READ | PROT_WRITE) == 0);
    step(CHILD_UNGUARDED);
    _exit(0);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(mprotect(zone, 4 * PAGE, PROT_READ | PROT_WRITE) == 0);
  step(PARENT_UNGUARDED);
  set_stack_limit(PAGE);
  step(LOWERED);
  set_stack_limit(256UL << 20);
  step(RAISED);
  set_stack_limit(RLIM_INFINITY);
  step(UNLIMITED);
  CHECK(mprotect(zone, 4 * PAGE, PROT_NONE) == 0);
  step(UNLIMITED_GUARDED);
  return here;
}
