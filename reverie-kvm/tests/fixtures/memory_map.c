/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A process's stack as it changes. At each numbered point a thread reads the
 * maps file of a thread, /proc/<tid>/maps: its text, or the errno of the
 * read. Under a Tool (the mode "tool") it then asks the Tool, with tuxcall,
 * which Linux does not implement, for the map of the same thread; the Tool
 * records what Guest::memory_map answered. Where the main thread of a
 * process asks about itself, it also prints what pthread_getattr_np answers
 * for it, with __libc_stack_end and the stack's rlimit, from which glibc
 * computes that answer ("stack POINT RET TOP SIZE END LIMIT").
 *
 * The process asks first as it started. Then forked children each change
 * their copy of the stack and ask:
 * - madvise advice that keeps the mapping's flags (MADV_WILLNEED and
 *   MADV_DONTNEED);
 * - a page made read-only, and read-write again;
 * - a guard zone of four pages made inaccessible, as the JVM protects its
 *   guard zones, and accessible again;
 * - two pages made executable as well, as for an executable stack;
 * - madvise hints: MADV_RANDOM, and MADV_NORMAL undoing it; MADV_HUGEPAGE,
 *   then MADV_NOHUGEPAGE on the same page; and MADV_DONTFORK, which the
 *   backend refuses;
 * - mlock, then munlock, of a page (natively without the mlock, which the
 *   backend refuses, so that both runs compare the same stack);
 * - a page unmapped, then mapped again with MAP_FIXED, which the backend
 *   refuses;
 * - a child that changes its stack and sets it back, then forks a
 *   grandchild, which asks, then executes this program again, which asks as
 *   the new image starts;
 * - a child that makes a page read-only and forks a grandchild, which asks;
 *   and one that does the same and makes a vfork child, which asks about
 *   itself, then asks once the child exited;
 * - mprotect of the stack's top page and the page past the top of the user
 *   address space, which Linux applies to the top page before it fails;
 * - a child that shares the address space, made with vfork, with clone and
 *   with clone3 (CLONE_VM|CLONE_VFORK), stores into a page of the stack and
 *   exits, and the parent prints whether it sees the store (such a child may
 *   not leave a mapping changed when it exits on KVM, which refuses that by
 *   name; the mode "protect FAMILY" below has it do so);
 * - a vfork child asks about itself once a sibling thread of its parent has
 *   changed the parent's stack;
 * - a child posix_spawn made executes this program again, which asks as the
 *   new image starts, and its parent asks once it exited.
 * The process asks again once its children are done; a sibling thread asks
 * about the leader, then changes the leader's stack and sets it back, and
 * the leader asks again; last, the process asks about a live child and
 * about a number no task has.
 *
 * With "protect FAMILY" (vfork, clone or clone3) as its second and third
 * arguments, the process only makes that child, which protects the page,
 * executable as well, and exits, leaving the change to its parent's stack on
 * Linux, and prints "protected POINT" once the child exited.
 *
 * A call whose result the test checks prints "result POINT RC ERRNO". The
 * page each change touches lies 32 KiB below the frame that computes it,
 * inside the stack Linux maps at exec and below anything these calls use,
 * except the top page. Standard output lists every point, in order: the
 * thread it asked about, the text or errno it read, and under a Tool that it
 * asked.
 *
 * Usage: memory_map MODE [start | exec | spawned]
 *   start:   ask at the first point only, then exit.
 *   exec:    the image a grandchild executed: ask, then exit.
 *   spawned: the image a posix_spawn child executed: ask, then exit.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ASK 0x6d656d6f72796d61L
#define PAGE 4096UL

enum {
  START = 1,
  KEPT,
  PROTECTED,
  PROTECTED_BACK,
  GUARDED,
  GUARDED_BACK,
  EXECUTABLE,
  ADVISED,
  ADVISED_BACK,
  HUGE,
  NOHUGE,
  REFUSED_HINT,
  MLOCKED,
  MUNLOCKED,
  UNMAPPED,
  REMAPPED,
  FORKED,
  EXECUTED,
  FORK_AFTER,
  VFORK_AFTER,
  VFORK_PARENT_AFTER,
  PARTIAL,
  VFORKED,
  CLONED,
  CLONED3,
  VFORK_SEES,
  SPAWNED,
  SPAWN_PARENT,
  PARENT_AGAIN,
  SIBLING,
  SIBLING_CHANGED,
  CHILD,
  NO_TASK,
  POINTS,
};

extern char **environ;
extern void *__libc_stack_end;

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

/* What pthread_getattr_np answers for this thread, the main thread of its
 * process, and what glibc computes it from. */
static void stack(int point) {
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
  char header[160];
  snprintf(header, sizeof(header), "stack %d %d %lx %lx %lx %lx\n", point, ret,
           (unsigned long)((uintptr_t)low + size), (unsigned long)size,
           (unsigned long)(uintptr_t)__libc_stack_end,
           (unsigned long)limit.rlim_cur);
  line(header);
}

/* A point at which this thread, its process's main thread, asks about
 * itself, with what pthread_getattr_np answers. */
static void ask(int at) {
  point(at, gettid_raw());
  stack(at);
}

/* Prints a call's result for the test. */
static void result(int point, long rc, int error) {
  char header[96];
  snprintf(header, sizeof(header), "result %d %ld %d\n", point, rc,
           rc < 0 ? error : 0);
  line(header);
}

/* A page of the stack 32 KiB below this function's frame. */
static uintptr_t __attribute__((noinline)) stack_page(void) {
  volatile char local = 0;
  uintptr_t page = ((uintptr_t)&local & ~(PAGE - 1)) - 8 * PAGE;
  (void)local;
  return page;
}

/* Waits for child `child` to exit with status 0. */
static void reap(pid_t child) {
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* Runs `step` in a forked child, which exits with status 0 after it. */
static void in_child(void (*step)(void)) {
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    step();
    _exit(0);
  }
  reap(child);
}

static void kept(void) {
  void *page = (void *)stack_page();
  CHECK(madvise(page, PAGE, MADV_WILLNEED) == 0);
  CHECK(madvise(page, PAGE, MADV_DONTNEED) == 0);
  ask(KEPT);
}

static void protected(void) {
  void *page = (void *)stack_page();
  CHECK(mprotect(page, PAGE, PROT_READ) == 0);
  ask(PROTECTED);
  CHECK(mprotect(page, PAGE, PROT_READ | PROT_WRITE) == 0);
  ask(PROTECTED_BACK);
}

/* Four pages below the page 32 KiB down made inaccessible, as the JVM makes
 * its guard zones, then accessible again. */
static void guarded(void) {
  void *zone = (void *)(stack_page() - 3 * PAGE);
  CHECK(mprotect(zone, 4 * PAGE, PROT_NONE) == 0);
  ask(GUARDED);
  CHECK(mprotect(zone, 4 * PAGE, PROT_READ | PROT_WRITE) == 0);
  ask(GUARDED_BACK);
}

static void executable(void) {
  void *pages = (void *)(stack_page() - PAGE);
  CHECK(mprotect(pages, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
  ask(EXECUTABLE);
}

static void advised(void) {
  void *page = (void *)stack_page();
  CHECK(madvise(page, PAGE, MADV_RANDOM) == 0);
  ask(ADVISED);
  CHECK(madvise(page, PAGE, MADV_NORMAL) == 0);
  ask(ADVISED_BACK);
}

static void huge(void) {
  void *page = (void *)stack_page();
  CHECK(madvise(page, PAGE, MADV_HUGEPAGE) == 0);
  ask(HUGE);
  CHECK(madvise(page, PAGE, MADV_NOHUGEPAGE) == 0);
  ask(NOHUGE);
}

/* MADV_DONTFORK, which Linux applies and the backend refuses (ENOSYS). */
static void refused_hint(void) {
  long rc = madvise((void *)stack_page(), PAGE, MADV_DONTFORK);
  result(REFUSED_HINT, rc, errno);
  ask(REFUSED_HINT);
}

static void locked(void) {
  void *page = (void *)stack_page();
  if (tool) {
    long rc = mlock(page, PAGE);
    result(MLOCKED, rc, errno);
  }
  ask(MLOCKED);
  CHECK(munlock(page, PAGE) == 0);
  ask(MUNLOCKED);
}

static void remapped(void) {
  void *page = (void *)stack_page();
  CHECK(munmap(page, PAGE) == 0);
  ask(UNMAPPED);
  void *mapped = mmap(page, PAGE, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  result(REMAPPED, mapped == MAP_FAILED ? -1 : 0, errno);
  ask(REMAPPED);
}

static char *program;
static char *mode;

static void forked(void) {
  void *page = (void *)stack_page();
  CHECK(mprotect(page, PAGE, PROT_READ) == 0);
  CHECK(mprotect(page, PAGE, PROT_READ | PROT_WRITE) == 0);
  pid_t grandchild = fork();
  CHECK(grandchild >= 0);
  if (grandchild == 0) {
    ask(FORKED);
    char *args[] = {program, mode, "exec", NULL};
    execve(program, args, environ);
    fail(__LINE__);
  }
  reap(grandchild);
}

/* A page made read-only, then a forked grandchild asks. */
static void fork_after(void) {
  CHECK(mprotect((void *)stack_page(), PAGE, PROT_READ) == 0);
  pid_t grandchild = fork();
  CHECK(grandchild >= 0);
  if (grandchild == 0) {
    ask(FORK_AFTER);
    _exit(0);
  }
  reap(grandchild);
}

/* A page made read-only, then a vfork child asks about itself and exits,
 * and the parent asks. */
static void vfork_after(void) {
  CHECK(mprotect((void *)stack_page(), PAGE, PROT_READ) == 0);
  pid_t child = vfork();
  CHECK(child >= 0);
  if (child == 0) {
    ask(VFORK_AFTER);
    _exit(0);
  }
  reap(child);
  ask(VFORK_PARENT_AFTER);
}

/* The stack's top page and the page past the top of the user address space
 * (TASK_SIZE without randomization), made executable as well: Linux applies
 * that to the top page, then fails at the hole with ENOMEM. The top page
 * stays writable, since the stack's start is in it. */
static void partial(void) {
  long rc = mprotect((void *)(0x7ffffffff000UL - PAGE), 2 * PAGE,
                     PROT_READ | PROT_WRITE | PROT_EXEC);
  result(PARTIAL, rc, errno);
  point(PARTIAL, gettid_raw());
}

/* A page of the stack that a child sharing the address space stores into. */
static uintptr_t shared_page;

/* Whether that child protects the page instead ("protect FAMILY"). */
static int protecting;

/* What that child does: store into the page and exit, with a system call
 * alone, as a vfork child may; or protect the page, executable as well, and
 * exit, which on Linux changes its parent's stack too. */
static int share_and_store(void *argument) {
  (void)argument;
  if (protecting) {
    long rc = syscall(SYS_mprotect, shared_page, PAGE,
                      PROT_READ | PROT_WRITE | PROT_EXEC);
    return rc == 0 ? 0 : 91;
  }
  *(volatile unsigned char *)(shared_page + 17) = 0x91;
  return 0;
}

/* Prints whether the parent sees the store of a child that shared its
 * address space, or that the child protected the page. */
static void stored(int at) {
  if (protecting) {
    printf("protected %d\n", at);
    return;
  }
  int seen = *(volatile unsigned char *)(shared_page + 17) == 0x91;
  result(at, seen ? 0 : -1, seen ? 0 : EIO);
  *(volatile unsigned char *)(shared_page + 17) = 0;
  point(at, gettid_raw());
}

static void vforked(void) {
  shared_page = stack_page();
  pid_t child = vfork();
  CHECK(child >= 0);
  if (child == 0) {
    _exit(share_and_store(NULL));
  }
  reap(child);
  stored(VFORKED);
}

/* The stack of a clone or clone3 child that shares the address space. */
static char child_stack[64 * 1024] __attribute__((aligned(16)));

static void cloned(void) {
  shared_page = stack_page();
  pid_t child = clone(share_and_store, child_stack + sizeof(child_stack),
                      CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
  CHECK(child >= 0);
  reap(child);
  stored(CLONED);
}

/* The clone3 child: it starts on its own stack, so it returns through no
 * frame of the parent's. */
static void __attribute__((noreturn)) clone3_child(void) {
  syscall(SYS_exit, share_and_store(NULL));
  __builtin_unreachable();
}

static void cloned3(void) {
  shared_page = stack_page();
  struct {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
        stack_size, tls;
  } args = {
      .flags = CLONE_VM | CLONE_VFORK,
      .exit_signal = SIGCHLD,
      .stack = (uintptr_t)child_stack,
      .stack_size = sizeof(child_stack),
  };
  long rc = SYS_clone3;
  /* The child continues after the system call with its stack pointer at the
   * top of child_stack, 16-byte aligned, and calls clone3_child. */
  __asm__ volatile("syscall\n\t"
                   "test %%rax, %%rax\n\t"
                   "jnz 1f\n\t"
                   "call *%[child]\n\t"
                   "1:\n\t"
                   : "+a"(rc)
                   : "D"(&args), "S"(sizeof(args)), [child] "r"(clone3_child)
                   : "rcx", "r11", "memory");
  CHECK(rc > 0);
  reap((pid_t)rc);
  stored(CLONED3);
}

/* A sibling thread of a vfork child's parent: once the child runs, it
 * protects a page of the parent's stack, then lets the child go on. */
static int child_running[2], page_changed[2];

static void *change_while_vforked(void *argument) {
  (void)argument;
  char byte;
  CHECK(read(child_running[0], &byte, 1) == 1);
  CHECK(mprotect((void *)shared_page, PAGE,
                 PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
  CHECK(write(page_changed[1], "c", 1) == 1);
  return NULL;
}

static void vfork_sees(void) {
  shared_page = stack_page();
  CHECK(pipe2(child_running, O_CLOEXEC) == 0 &&
        pipe2(page_changed, O_CLOEXEC) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, change_while_vforked, NULL) == 0);
  pid_t child = vfork();
  CHECK(child >= 0);
  if (child == 0) {
    char byte;
    if (write(child_running[1], "r", 1) != 1 ||
        read(page_changed[0], &byte, 1) != 1) {
      _exit(92);
    }
    point(VFORK_SEES, gettid_raw());
    _exit(0);
  }
  reap(child);
  CHECK(pthread_join(thread, NULL) == 0);
}

static void spawned(void) {
  char *args[] = {program, mode, "spawned", NULL};
  pid_t child;
  CHECK(posix_spawn(&child, program, NULL, NULL, args, environ) == 0);
  reap(child);
  ask(SPAWN_PARENT);
}

static uintptr_t leader_page;
static pid_t leader_tid;

/* A sibling thread: it asks about the leader, then changes the leader's
 * stack, a page made read-only and read-write again. */
static void *sibling(void *argument) {
  (void)argument;
  point(SIBLING, leader_tid);
  CHECK(mprotect((void *)leader_page, PAGE, PROT_READ) == 0);
  CHECK(mprotect((void *)leader_page, PAGE, PROT_READ | PROT_WRITE) == 0);
  return NULL;
}

int main(int argc, char **argv) {
  CHECK(argc >= 2);
  program = argv[0];
  mode = argv[1];
  tool = strcmp(mode, "tool") == 0;
  pid_t tid = gettid_raw();
  if (argc >= 3 && strcmp(argv[2], "exec") == 0) {
    ask(EXECUTED);
    return 0;
  }
  if (argc >= 3 && strcmp(argv[2], "spawned") == 0) {
    ask(SPAWNED);
    return 0;
  }
  if (argc >= 4 && strcmp(argv[2], "protect") == 0) {
    protecting = 1;
    if (strcmp(argv[3], "vfork") == 0) {
      vforked();
    } else if (strcmp(argv[3], "clone") == 0) {
      cloned();
    } else {
      cloned3();
    }
    return 0;
  }
  ask(START);
  if (argc >= 3 && strcmp(argv[2], "start") == 0) {
    return 0;
  }

  in_child(kept);
  in_child(protected);
  in_child(guarded);
  in_child(executable);
  in_child(advised);
  in_child(huge);
  in_child(refused_hint);
  in_child(locked);
  in_child(remapped);
  in_child(forked);
  in_child(fork_after);
  in_child(vfork_after);
  in_child(partial);
  in_child(vforked);
  in_child(cloned);
  in_child(cloned3);
  in_child(vfork_sees);
  in_child(spawned);
  ask(PARENT_AGAIN);

  leader_tid = tid;
  leader_page = stack_page();
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, sibling, NULL) == 0);
  CHECK(pthread_join(thread, NULL) == 0);
  ask(SIBLING_CHANGED);

  /* A child process while it waits, then a number no task has. */
  int ready[2], release[2];
  CHECK(pipe2(ready, O_CLOEXEC) == 0 && pipe2(release, O_CLOEXEC) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(write(ready[1], "c", 1) == 1);
    char byte;
    CHECK(read(release[0], &byte, 1) == 1);
    _exit(0);
  }
  char byte;
  CHECK(read(ready[0], &byte, 1) == 1);
  point(CHILD, child);
  CHECK(write(release[1], "r", 1) == 1);
  reap(child);
  point(NO_TASK, 0x7fffffff);
  return 0;
}
