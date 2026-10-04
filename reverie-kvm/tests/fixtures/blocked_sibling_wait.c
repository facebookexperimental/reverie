/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Additive to cross_thread_waitid.c. That fixture's eight ready-child variants
 * and every existing assertion remain unchanged.
 * Host creates child-gate and waiter-ready FIFOs in this private working dir.
 * Host holds child-gate closed to progress until the real KVM Condvar waiter is
 * registered. Native comparison uses waiter-ready only (not native park proof).
 */
_Static_assert(sizeof(siginfo_t) == 128, "x86-64 siginfo ABI");
_Static_assert(offsetof(siginfo_t, si_pid) == 16, "x86-64 siginfo union");
_Static_assert(offsetof(siginfo_t, si_uid) == 20, "x86-64 UID field");
_Static_assert(offsetof(siginfo_t, si_status) == 24, "x86-64 status field");

enum { CHILD_STATUS = 73, ARENA_SIZE = 160, OUT = 16 };
struct context {
  int worker_creator, cancel, group_status, wait4_mode;
  pid_t process, leader;
  uid_t uid;
  int announced[2], acknowledged[2];
};
static struct context c;

static void fail(void) {
  static const char text[] = "blocked sibling wait failed\n";
  (void)write(2, text, sizeof(text) - 1);
  syscall(SYS_exit_group, 90);
  __builtin_unreachable();
}
static void operation_failure(
    const char* operation,
    int line,
    int fd,
    long result,
    int error,
    size_t expected) {
  char text[256];
  int length = snprintf(
      text,
      sizeof(text),
      "blocked sibling operation=%s line=%d fd=%d result=%ld errno=%d expected=%zu\n",
      operation,
      line,
      fd,
      result,
      error,
      expected);
  if (length > 0 && (size_t)length < sizeof(text))
    (void)write(2, text, (size_t)length);
  fail();
}
#define require(condition)                                             \
  do {                                                                 \
    int condition_ok = (condition);                                    \
    int condition_errno = errno;                                       \
    if (!condition_ok)                                                 \
      operation_failure(                                               \
          #condition, __LINE__, -1, condition_ok, condition_errno, 1); \
  } while (0)
static void send_bytes_at(int fd, const void* p, size_t n, int line) {
  errno = 0;
  ssize_t result = write(fd, p, n);
  int error = errno;
  if (result != (ssize_t)n)
    operation_failure("write", line, fd, result, error, n);
  require(result == (ssize_t)n);
}
static void receive_bytes_at(int fd, void* p, size_t n, int line) {
  errno = 0;
  ssize_t result = read(fd, p, n);
  int error = errno;
  if (result != (ssize_t)n)
    operation_failure("read", line, fd, result, error, n);
  require(result == (ssize_t)n);
}
#define send_bytes(fd, p, n) send_bytes_at((fd), (p), (n), __LINE__)
#define receive_bytes(fd, p, n) receive_bytes_at((fd), (p), (n), __LINE__)
static void say(const char* p, size_t n) {
  send_bytes(1, p, n);
}

static void no_child(pid_t pid) {
  int status = 0x12345678;
  errno = 0;
  long result = syscall(SYS_wait4, pid, &status, WNOHANG, NULL);
  int error = errno;
  require(result == -1 && error == ECHILD && status == 0x12345678);
  unsigned char actual[ARENA_SIZE], expected[ARENA_SIZE];
  memset(actual, 0xa5, sizeof(actual));
  memset(expected, 0xa5, sizeof(expected));
  const size_t offsets[] = {0, 4, 8, 16, 20, 24};
  for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
    memset(expected + OUT + offsets[i], 0, 4);
  errno = 0;
  result = syscall(SYS_waitid, P_ALL, 0, actual + OUT, WEXITED | WNOHANG, NULL);
  error = errno;
  require(result == -1 && error == ECHILD);
  require(memcmp(actual, expected, sizeof(actual)) == 0);
}

static void peek_or_consume(pid_t pid, int options) {
  unsigned char actual[ARENA_SIZE], expected[ARENA_SIZE];
  memset(actual, 0xa5, sizeof(actual));
  memset(expected, 0xa5, sizeof(expected));
  const size_t offsets[] = {0, 4, 8, 16, 20, 24};
  const uint32_t fields[] = {
      SIGCHLD, 0, CLD_EXITED, (uint32_t)pid, (uint32_t)c.uid, CHILD_STATUS};
  for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
    memcpy(expected + OUT + offsets[i], &fields[i], 4);
  errno = 0;
  long result = syscall(SYS_waitid, P_PID, pid, actual + OUT, options, NULL);
  int error = errno;
  require(
      !c.cancel); /* Successful exit_group must never return this syscall. */
  require(result == 0 && error == 0);
  require(memcmp(actual, expected, sizeof(actual)) == 0);
}

static void waiter(void) {
  pid_t child = 0;
  receive_bytes(c.announced[0], &child, sizeof(child));
  require(child > 0 && child != c.process);
  require(getpid() == c.process);
  pid_t tid = (pid_t)syscall(SYS_gettid);
  require((tid == c.leader) == c.worker_creator);
  int ready = open("waiter-ready", O_WRONLY | O_CLOEXEC);
  require(ready >= 0);
  int32_t announced[2] = {child, tid};
  send_bytes(ready, announced, sizeof(announced));
  require(close(ready) == 0);
  if (c.wait4_mode) {
    unsigned char actual[ARENA_SIZE], expected[ARENA_SIZE];
    memset(actual, 0xa5, sizeof(actual));
    memset(expected, 0xa5, sizeof(expected));
    const int status = CHILD_STATUS << 8;
    memcpy(expected + OUT, &status, sizeof(status));
    errno = 0;
    long result = syscall(SYS_wait4, child, actual + OUT, 0, NULL);
    int error = errno;
    require(!c.cancel);
    require(result == child && error == 0);
    require(memcmp(actual, expected, sizeof(actual)) == 0);
  } else {
    peek_or_consume(child, WEXITED | WNOWAIT); /* Actual first blocked wait. */
    peek_or_consume(child, WEXITED | WNOWAIT);
    peek_or_consume(child, WEXITED);
  }
  no_child(child);
  const char done = 'd';
  send_bytes(c.acknowledged[1], &done, 1);
}

static void creator(void) {
  pid_t child = fork();
  require(child >= 0);
  if (child == 0) {
    /* This also works in Direct's synchronous fork: a previously created
     * sibling receives our PID while the creator is still inside fork. */
    child = getpid();
    send_bytes(c.announced[1], &child, sizeof(child));
    errno = 0;
    int gate = open("child-gate", O_RDONLY | O_CLOEXEC);
    int gate_errno = errno;
    if (gate < 0)
      operation_failure("open child-gate", __LINE__, gate, gate, gate_errno, 0);
    require(gate >= 0);
    char release = 0;
    receive_bytes(gate, &release, 1);
    require(release == 'g');
    require(close(gate) == 0);
    say("child released\n", sizeof("child released\n") - 1);
    _exit(CHILD_STATUS);
  }
  /* Tool fork can return while the child is live; keep the creator alive.
   * Cancellation never supplies this acknowledgement. */
  char done = 0;
  receive_bytes(c.acknowledged[0], &done, 1);
  require(!c.cancel && done == 'd');
  no_child(child);
}

static void* peer(void* unused) {
  (void)unused;
  require(getpid() == c.process);
  char command = 0;
  receive_bytes(0, &command, 1);
  require(command == (c.cancel ? 'c' : 'w'));
  if (c.cancel) {
    say("peer exit_group\n", sizeof("peer exit_group\n") - 1);
    syscall(SYS_exit_group, c.group_status);
    __builtin_unreachable();
  }
  return NULL;
}
static void* sibling(void* unused) {
  (void)unused;
  if (c.worker_creator)
    creator();
  else
    waiter();
  return NULL;
}
int main(int argc, char** argv) {
  require(argc == 4);
  c.worker_creator = !strcmp(argv[1], "worker-child");
  require(c.worker_creator || !strcmp(argv[1], "leader-child"));
  c.group_status = !strcmp(argv[2], "cancel61") ? 61 : 0;
  c.cancel = !strcmp(argv[2], "cancel") || c.group_status == 61;
  require(c.cancel || !strcmp(argv[2], "publish"));
  c.wait4_mode = !strcmp(argv[3], "wait4");
  require(c.wait4_mode || !strcmp(argv[3], "waitid"));
  c.process = getpid();
  c.leader = (pid_t)syscall(SYS_gettid);
  c.uid = getuid();
  require(c.process == c.leader);
  require(pipe(c.announced) == 0 && pipe(c.acknowledged) == 0);
  pthread_t controller, thread;
  /* Stable creation order: configured root 3, controller 4, sibling 5, child 6.
   */
  require(pthread_create(&controller, NULL, peer, NULL) == 0);
  require(pthread_create(&thread, NULL, sibling, NULL) == 0);
  if (c.worker_creator)
    waiter();
  else
    creator();
  require(!c.cancel);
  require(pthread_join(thread, NULL) == 0);
  require(pthread_join(controller, NULL) == 0);
  require(
      close(c.announced[0]) == 0 && close(c.announced[1]) == 0 &&
      close(c.acknowledged[0]) == 0 && close(c.acknowledged[1]) == 0);
  say("blocked wait completed\n", sizeof("blocked wait completed\n") - 1);
  return 0;
}
