/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

_Static_assert(sizeof(siginfo_t) == 128, "siginfo ABI");
_Static_assert(offsetof(siginfo_t, si_pid) == 16, "child pid ABI");
_Static_assert(offsetof(siginfo_t, si_status) == 24, "child status ABI");
_Static_assert(offsetof(siginfo_t, si_utime) == 32, "child user clock ABI");
_Static_assert(offsetof(siginfo_t, si_stime) == 40, "child system clock ABI");
_Static_assert(sizeof(struct signalfd_siginfo) == 128, "signalfd ABI");

static volatile sig_atomic_t child_calls, other_calls, fault_calls;
static siginfo_t delivered;

static void fail(const char* what) {
  fprintf(stderr, "child-exit check failed: %s errno=%d\n", what, errno);
  _exit(90);
}
#define REQUIRE(condition, what) \
  do {                           \
    if (!(condition))            \
      fail(what);                \
  } while (0)

static void handler(int signal, siginfo_t* info, void* context) {
  if (signal == SIGCHLD) {
    memcpy(&delivered, info, sizeof(delivered));
    child_calls++;
  } else if (signal == SIGUSR1) {
    other_calls++;
  } else if (signal == SIGSEGV) {
    fault_calls++;
    ((ucontext_t*)context)->uc_mcontext.gregs[REG_RIP] += 3;
  } else {
    _exit(91);
  }
}

int main(int argc, char** argv) {
  REQUIRE(argc == 3, "arguments");
  int mode = atoi(argv[1]), tool = atoi(argv[2]);
  REQUIRE(mode >= 0 && mode <= 13 && (tool == 0 || tool == 1), "mode");
  alarm(5);
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  REQUIRE(sigprocmask(SIG_BLOCK, &mask, NULL) == 0, "block SIGCHLD");
  struct sigaction action = {0};
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO;
  if (mode == 0)
    action.sa_handler = SIG_DFL;
  if (mode == 3 || mode == 4)
    action.sa_handler = SIG_IGN;
  if (mode == 5)
    action.sa_flags |= SA_NOCLDWAIT;
  if (mode == 6)
    action.sa_flags |= SA_NOCLDSTOP;
  REQUIRE(sigaction(SIGCHLD, &action, NULL) == 0, "child disposition");
  if (mode == 10 || mode == 11) {
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    REQUIRE(
        sigaction(mode == 10 ? SIGUSR1 : SIGSEGV, &action, NULL) == 0,
        "boundary disposition");
  }
  int fd = -1;
  uid_t uid = getuid();
  pid_t child = fork();
  REQUIRE(child >= 0, "fork");
  if (child == 0)
    _exit(37);
  int status = 0x5a5a;
  errno = 0;
  pid_t waited = waitpid(child, &status, 0);
  if (mode == 3 || mode == 4 || mode == 5) {
    REQUIRE(
        waited == -1 && errno == ECHILD && status == 0x5a5a,
        "auto-reap status stays independent of signal queue");
  } else {
    REQUIRE(
        waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 37,
        "actual normal child status");
    status = 0x5a5a;
    errno = 0;
    REQUIRE(
        waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD &&
            status == 0x5a5a,
        "exactly one reap");
  }
  pid_t second = 0;
  if (mode == 13) {
    second = fork();
    REQUIRE(second >= 0, "second fork");
    if (second == 0)
      _exit(43);
    REQUIRE(
        waitpid(second, &status, 0) == second && WIFEXITED(status) &&
            WEXITSTATUS(status) == 43,
        "second actual normal child status");
    status = 0x5a5a;
    errno = 0;
    REQUIRE(
        waitpid(second, &status, WNOHANG) == -1 && errno == ECHILD &&
            status == 0x5a5a,
        "second child reaped exactly once");
  }
  // KVM deliberately refuses fork with a live virtual signalfd. Create the
  // receiver after wait, while SIGCHLD is still blocked, so this control tests
  // delivery and complete ABI output without claiming signalfd inheritance.
  if (mode == 2 || mode == 13) {
    fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    REQUIRE(fd >= 0, "signalfd creation");
  }
  int blocked = mode == 2 || mode == 4 || mode == 7 || mode == 13;
  if (!blocked)
    REQUIRE(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0, "unblock before queue");
  // Native Linux has already generated the event. The test Tool authenticates
  // the actual child/status and uses this otherwise ordinary getpid boundary
  // to exercise the explicit backend operation. This is not an automatic
  // backend child-exit producer or a Hermit scheduler test.
  pid_t parent = syscall(SYS_getpid, 0L, 0L, 0L, 0L, 0L, 0L);
  REQUIRE(
      syscall(SYS_getpid, 0x63686c64, mode, child, uid, second, 0L) == parent,
      "marker");
  if (mode == 10)
    REQUIRE(raise(SIGUSR1) == 0, "signal callback boundary");
  if (mode == 11)
    __asm__ volatile("xor %%rax, %%rax; .byte 0x48, 0x8b, 0x00" ::
                         : "rax", "memory");
  if (mode == 2 || mode == 13) {
    unsigned char output[160], expected[160];
    memset(output, 0xa5, sizeof(output));
    memcpy(expected, output, sizeof(output));
    REQUIRE(read(fd, output + 16, 128) == 128, "one full signalfd record");
    struct signalfd_siginfo record;
    memcpy(&record, output + 16, sizeof(record));
    REQUIRE(
        record.ssi_signo == SIGCHLD && record.ssi_errno == 0 &&
            record.ssi_code == CLD_EXITED &&
            record.ssi_pid == (unsigned)child && record.ssi_uid == uid &&
            record.ssi_status == 37,
        "signalfd child fields");
    if (tool)
      REQUIRE(
          record.ssi_utime == 11 && record.ssi_stime == 13,
          "signalfd CPU fields");
    struct signalfd_siginfo exact = {0};
    exact.ssi_signo = SIGCHLD;
    exact.ssi_code = CLD_EXITED;
    exact.ssi_pid = child;
    exact.ssi_uid = uid;
    exact.ssi_status = 37;
    exact.ssi_utime = record.ssi_utime;
    exact.ssi_stime = record.ssi_stime;
    memcpy(expected + 16, &exact, sizeof(exact));
    REQUIRE(
        memcmp(output, expected, sizeof(output)) == 0,
        "complete signalfd buffer");
    errno = 0;
    REQUIRE(
        read(fd, output + 16, 128) == -1 && errno == EAGAIN,
        "single consumption");
    REQUIRE(
        memcmp(output, expected, sizeof(output)) == 0,
        "empty read preserves entire buffer");
    REQUIRE(close(fd) == 0, "close signalfd");
  }
  if (mode == 7) {
    sigset_t pending;
    REQUIRE(child_calls == 0, "blocked event did not run handler");
    REQUIRE(
        sigpending(&pending) == 0 && sigismember(&pending, SIGCHLD) == 1,
        "blocked event remains pending");
    REQUIRE(
        sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0, "unblock pending event");
  }
  int expected_calls = (mode == 0 || mode == 2 || mode == 3 || mode == 4 ||
                        mode == 13 || (mode == 8 && tool))
      ? 0
      : 1;
  REQUIRE(child_calls == expected_calls, "exact child handler count");
  REQUIRE(
      other_calls == (mode == 10) && fault_calls == (mode == 11),
      "original signal and fault return paths");
  if (expected_calls) {
    int expected_status = mode == 9 && tool ? 43 : 37;
    REQUIRE(
        delivered.si_signo == SIGCHLD && delivered.si_errno == 0 &&
            delivered.si_code == CLD_EXITED && delivered.si_pid == child &&
            delivered.si_uid == uid && delivered.si_status == expected_status,
        "handler child fields");
    REQUIRE(
        delivered.si_utime >= 0 && delivered.si_stime >= 0,
        "nonnegative CPU clocks");
    if (tool) {
      siginfo_t exact = {0};
      exact.si_signo = SIGCHLD;
      exact.si_code = CLD_EXITED;
      exact.si_pid = child;
      exact.si_uid = uid;
      exact.si_status = expected_status;
      exact.si_utime = 11;
      exact.si_stime = 13;
      ((unsigned char*)&exact)[127] = 0xa5;
      REQUIRE(
          memcmp(&delivered, &exact, 128) == 0,
          "complete signal frame siginfo");
    }
  }
  sigset_t pending;
  REQUIRE(
      sigpending(&pending) == 0 && sigismember(&pending, SIGCHLD) == 0,
      "no residual child signal");
  puts("child-exit-receiver-checked");
  return 0;
}
