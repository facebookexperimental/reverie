/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Starts a second guest thread while the preload runtime is inside its
   bootstrap window, and keeps it alive until the runtime is ready.

   The executable is linked with -rdynamic, so its open64 interposes on the
   one the preload runtime imports. The runtime opens /proc/self/maps between
   its begin and ready traps, so the first such call runs this guest code on
   the bootstrapping thread inside the window. It creates a thread, waits for
   the thread's tagged syscall, and only then lets the runtime continue. The
   thread then blocks until main, which runs after the ready trap, releases
   it. Nothing here depends on timing: the thread's tagged call always lies
   inside the window, and its exit always follows the ready trap. */

#define THREAD_MARKER 0x74687264
#define MAIN_MARKER 0x6d61696e

static int selected, started;
static int reported[2], released[2];
static pthread_t thread;

static void select_mode(int argc, char** argv, char** envp) {
  (void)envp;
  selected = argc == 2 && strcmp(argv[1], "thread") == 0;
}

/* ELF preinit runs before the preload DSO's constructor. */
__attribute__((
    section(".preinit_array"),
    used)) static void (*const before_constructors)(int, char**, char**) =
    select_mode;

static void* body(void* unused) {
  (void)unused;
  char byte = 't';
  syscall(SYS_getpid, THREAD_MARKER);
  if (write(reported[1], &byte, 1) != 1) {
    _exit(30);
  }
  if (read(released[0], &byte, 1) != 1) {
    _exit(31);
  }
  return NULL;
}

static void start_thread_inside_bootstrap(void) {
  char byte;
  if (pipe2(reported, O_CLOEXEC) != 0 || pipe2(released, O_CLOEXEC) != 0) {
    _exit(20);
  }
  if (pthread_create(&thread, NULL, body, NULL) != 0) {
    _exit(21);
  }
  if (read(reported[0], &byte, 1) != 1) {
    _exit(22);
  }
}

int open64(const char* path, int flags, ...) {
  int permissions = 0;
  if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
    va_list arguments;
    va_start(arguments, flags);
    permissions = va_arg(arguments, int);
    va_end(arguments);
  }
  if (selected && !started && strcmp(path, "/proc/self/maps") == 0) {
    started = 1;
    start_thread_inside_bootstrap();
  }
  return (int)syscall(SYS_openat, AT_FDCWD, path, flags, permissions);
}

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  char byte = 'r';
  if (!selected) {
    return 9;
  }
  if (!started) {
    return 10;
  }
  syscall(SYS_getpid, MAIN_MARKER);
  if (write(released[1], &byte, 1) != 1) {
    return 11;
  }
  if (pthread_join(thread, NULL) != 0) {
    return 12;
  }
  puts("bootstrap-thread-joined");
  return 0;
}
