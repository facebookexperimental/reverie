/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include "frame_probe.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern void handle_syscall(void);
extern void handle_syscall_loader(void);
extern void frame_probe(uint64_t*) __attribute__((returns_twice));
extern void probe_scratch(void);
extern void probe_after(void);
extern void* get_syscall_return_address(void*);
extern size_t get_offsetof_syscall_return_address(void);
extern long vfork_return_from_child(void*);
void (*probe_handler)(void);
static uint64_t* active;
static int mode;
typedef long (*rust_router_fn)(int, void*, uint64_t*);
static rust_router_fn rust_router;

long runtime_syscall_router(
    long sc,
    long a,
    long b,
    long c,
    long d,
    long e,
    long f,
    void* frame) {
  (void)sc;
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  active[FRAME_BASE] = (uintptr_t)frame;
  active[FRAME_RETURN] = (uintptr_t)get_syscall_return_address(frame);
  active[FRAME_RETURN_OFFSET] = get_offsetof_syscall_return_address();
  if (rust_router != NULL)
    return rust_router(mode, frame, active);
  if (mode == 1) {
    long child = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (child != 0)
      return child;
  } else if (mode == 0) {
    return 0x55;
  }
  vfork_return_from_child(frame);
  _exit(98);
}

long ld_sc_handler(
    long sc,
    long a,
    long b,
    long c,
    long d,
    long e,
    long f,
    void* frame) {
  return runtime_syscall_router(sc, a, b, c, d, e, f, frame);
}

static unsigned check(const uint64_t* p, int child) {
  unsigned failures = 0;
  failures |= p[RETURNED_RSP] != p[ORIGINAL_RSP] ? 1 : 0;
  failures |= p[FRAME_RETURN] != (uintptr_t)probe_scratch ? 2 : 0;
  failures |= p[FRAME_RETURN_OFFSET] != 0x88 ? 4 : 0;
  failures |= p[FRAME_BASE] + 0x90 + 0x80 != p[ORIGINAL_RSP] ? 8 : 0;
  failures |= p[SCRATCH_SEEN] != 1 || p[RESULT_R12] != 0x1222 ? 16 : 0;
  failures |= ((p[RESULT_FLAGS] ^ p[EXPECTED_FLAGS]) & 0xcd5) != 0 ? 32 : 0;
  failures |= p[RESULT_R11] != p[EXPECTED_FLAGS] ? 64 : 0;
  failures |= p[RESULT_RBP] != 0xb0b0 || p[RESULT_R13] != 0x3131 ? 128 : 0;
  failures |= p[RESULT_RCX] != (uintptr_t)probe_after ? 256 : 0;
  failures |= child && p[RESULT_RAX] != 0 ? 512 : 0;
  for (size_t i = REDZONE_START; i < REDZONE_END; ++i)
    failures |= p[i] != UINT64_C(0x718293a4b5c6d7e8) ? 1024 : 0;
  if (rust_router != NULL) {
    failures |= p[RUST_FRAME_RETURN] != (uintptr_t)probe_scratch ? 8192 : 0;
    failures |= p[RUST_FRAME_FAKE_RETURN] != (uintptr_t)probe_after ? 16384 : 0;
    failures |= p[RUST_GUEST_RSP] != p[ORIGINAL_RSP] ? 32768 : 0;
  }
  return failures;
}

static int transfer(int fd, void* buffer, size_t length, int sending) {
  size_t done = 0;
  while (done < length) {
    ssize_t n = sending ? write(fd, (char*)buffer + done, length - done)
                        : read(fd, (char*)buffer + done, length - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    done += (size_t)n;
  }
  return 0;
}

int frame_probe_run(
    int requested_mode,
    int loader_entry,
    unsigned long flags,
    rust_router_fn callback) {
  if (requested_mode < 0 || requested_mode > 2 ||
      (flags != 0x647 && flags != 0xa96))
    return 2;
  mode = requested_mode;
  rust_router = callback;
  probe_handler = loader_entry ? handle_syscall_loader : handle_syscall;
  uint64_t result[PROBE_WORDS] = {0};
  active = result;
  result[EXPECTED_FLAGS] = flags;
  int pipefd[2];
  if (pipe(pipefd) != 0)
    return 2;
  frame_probe(result);
  if (mode == 1 && result[RESULT_RAX] == 0) {
    close(pipefd[0]);
    int rc = transfer(pipefd[1], result, sizeof(result), 1);
    _exit(rc == 0 ? (check(result, 1) != 0) : 2);
  }
  close(pipefd[1]);
  unsigned failures = check(result, mode == 2);
  int child_status = -1;
  uint64_t child[PROBE_WORDS] = {0};
  if (mode == 1) {
    pid_t pid = (pid_t)result[RESULT_RAX];
    if (pid <= 0)
      return 2;
    int captured = transfer(pipefd[0], child, sizeof(child), 0);
    pid_t reaped;
    do {
      reaped = waitpid(pid, &child_status, 0);
    } while (reaped < 0 && errno == EINTR);
    if (reaped != pid)
      return 2;
    // A failed capture must still reap this exact child and retain its status.
    failures |= captured != 0 ? 65536 : 0;
    failures |= check(child, 1);
    failures |=
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ? 2048 : 0;
  } else if (mode == 0 && result[RESULT_RAX] != 0x55)
    failures |= 4096;
  close(pipefd[0]);
  printf(
      "{\"mode\":\"%s\",\"entry\":\"%s\",\"failures\":%u,"
      "\"child_status\":%d,\"parent\":[",
      mode == 0 ? "normal" : (mode == 1 ? "fork" : "restore"),
      loader_entry ? "loader" : "guest",
      failures,
      child_status);
  for (size_t i = 0; i < PROBE_WORDS; ++i)
    printf("%s%lu", i ? "," : "", result[i]);
  printf("],\"child\":[");
  for (size_t i = 0; i < PROBE_WORDS; ++i)
    printf("%s%lu", i ? "," : "", child[i]);
  printf("]}\n");
  fflush(stdout);
  return failures != 0;
}

#ifndef FRAME_PROBE_LIBRARY
int main(int argc, char** argv) {
  if (argc != 4)
    return 2;
  int requested_mode;
  if (strcmp(argv[1], "normal") == 0)
    requested_mode = 0;
  else if (strcmp(argv[1], "fork") == 0)
    requested_mode = 1;
  else if (strcmp(argv[1], "restore") == 0)
    requested_mode = 2;
  else
    return 2;
  int loader_entry;
  if (strcmp(argv[2], "guest") == 0)
    loader_entry = 0;
  else if (strcmp(argv[2], "loader") == 0)
    loader_entry = 1;
  else
    return 2;
  char* end = NULL;
  unsigned long flags = strtoul(argv[3], &end, 16);
  if (*end)
    return 2;
  return frame_probe_run(requested_mode, loader_entry, flags, NULL);
}
#endif
