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
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
  RANGE_FIRST_FD = 196,
  VIRTUAL_IDENTITY_FD = 197,
  DBT_DIAGNOSTIC_FD = 198,
  RANGE_LAST_FD = 199,
};

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#ifndef P_PIDFD
#define P_PIDFD ((idtype_t)3)
#endif

static int pidfd_targets_virtual_child(void) {
  _Atomic int* gate = mmap(
      NULL,
      sizeof(*gate),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS,
      -1,
      0);
  if (gate == MAP_FAILED)
    return 1;
  atomic_init(gate, 0);

  pid_t child = fork();
  if (child < 0) {
    munmap(gate, sizeof(*gate));
    return 1;
  }
  if (child == 0) {
    while (atomic_load_explicit(gate, memory_order_acquire) == 0)
      syscall(SYS_sched_yield);
    _exit(42);
  }

  int fd = (int)syscall(SYS_pidfd_open, child, O_NONBLOCK);
  siginfo_t info = {0};
  errno = 0;
  int wait_result = fd < 0 ? 0 : waitid(P_PIDFD, (id_t)fd, &info, WEXITED);
  int wait_errno = errno;

  atomic_store_explicit(gate, 1, memory_order_release);
  int status = 0;
  pid_t reaped = waitpid(child, &status, 0);
  if (fd >= 0)
    close(fd);
  munmap(gate, sizeof(*gate));

  return fd >= 0 && wait_result == -1 && wait_errno == EAGAIN &&
          reaped == child && WIFEXITED(status) && WEXITSTATUS(status) == 42
      ? 0
      : 1;
}

static int pidfd_preserves_identity_and_flag_validation_order(void) {
  errno = 0;
  long fd = syscall(SYS_pidfd_open, INT32_MAX, 0);
  if (fd != -1 || errno != ESRCH)
    return 1;

  errno = 0;
  fd = syscall(SYS_pidfd_open, INT32_MAX, UINT32_C(0x40000000));
  return fd == -1 && errno == EINVAL ? 0 : 1;
}

static int install_range_neighbor_fds(void) {
  int source = open("/dev/null", O_RDONLY);
  if (source < 0)
    return 1;
  if (dup2(source, RANGE_FIRST_FD) != RANGE_FIRST_FD ||
      dup2(source, RANGE_LAST_FD) != RANGE_LAST_FD) {
    close(source);
    return 1;
  }
  if (source != RANGE_FIRST_FD && source != RANGE_LAST_FD)
    close(source);
  return 0;
}

static int fd_flags(int fd) {
  errno = 0;
  return fcntl(fd, F_GETFD);
}

static int close_range_preserves_internal_descriptors(void) {
#ifdef SYS_close_range
  const unsigned int unknown_flag = 1U << 31;
  if (install_range_neighbor_fds() != 0)
    return 1;

  errno = 0;
  if (syscall(SYS_close_range, RANGE_FIRST_FD, RANGE_LAST_FD, unknown_flag) !=
          -1 ||
      errno != EINVAL || fd_flags(RANGE_FIRST_FD) < 0 ||
      fd_flags(VIRTUAL_IDENTITY_FD) < 0 || fd_flags(DBT_DIAGNOSTIC_FD) < 0 ||
      fd_flags(RANGE_LAST_FD) < 0)
    return 2;

  if (syscall(SYS_close_range, RANGE_FIRST_FD, RANGE_LAST_FD, 0) != 0)
    return 3;
  if (fd_flags(RANGE_FIRST_FD) >= 0 || errno != EBADF)
    return 4;
  if (fd_flags(RANGE_LAST_FD) >= 0 || errno != EBADF)
    return 5;
  if (fd_flags(VIRTUAL_IDENTITY_FD) < 0 || fd_flags(DBT_DIAGNOSTIC_FD) < 0)
    return 6;

  if (install_range_neighbor_fds() != 0)
    return 7;
  if (syscall(
          SYS_close_range,
          RANGE_FIRST_FD,
          RANGE_LAST_FD,
          CLOSE_RANGE_CLOEXEC) != 0)
    return 8;
  int first_flags = fd_flags(RANGE_FIRST_FD);
  int identity_flags = fd_flags(VIRTUAL_IDENTITY_FD);
  int diagnostic_flags = fd_flags(DBT_DIAGNOSTIC_FD);
  int last_flags = fd_flags(RANGE_LAST_FD);
  if (first_flags < 0 || identity_flags < 0 || diagnostic_flags < 0 ||
      last_flags < 0 || (first_flags & FD_CLOEXEC) == 0 ||
      (last_flags & FD_CLOEXEC) == 0 || (identity_flags & FD_CLOEXEC) != 0 ||
      (diagnostic_flags & FD_CLOEXEC) != 0)
    return 9;

  if (fcntl(RANGE_FIRST_FD, F_SETFD, 0) != 0 ||
      fcntl(RANGE_LAST_FD, F_SETFD, 0) != 0)
    return 10;
  if (syscall(
          SYS_close_range,
          RANGE_FIRST_FD,
          RANGE_LAST_FD,
          CLOSE_RANGE_UNSHARE) != 0)
    return 11;
  if (fd_flags(RANGE_FIRST_FD) >= 0 || errno != EBADF)
    return 12;
  if (fd_flags(RANGE_LAST_FD) >= 0 || errno != EBADF)
    return 13;
  if (fd_flags(VIRTUAL_IDENTITY_FD) < 0 || fd_flags(DBT_DIAGNOSTIC_FD) < 0)
    return 14;
  return 0;
#else
  return 15;
#endif
}

// TODO-HUMAN-REVIEW(PR-154): Review deferred DBT identity and private-fd
// policy.
int main(void) {
  long pid = syscall(SYS_getpid);
  long ppid = syscall(SYS_getppid);
  long tid = syscall(SYS_gettid);

  if (syscall(SYS_close, VIRTUAL_IDENTITY_FD) != 0)
    return 1;
  errno = 0;
  if (fcntl(VIRTUAL_IDENTITY_FD, F_GETFD) < 0)
    return 2;
  if (pid != 3 || ppid != 1 || tid != 3)
    return 3;
  if (pidfd_targets_virtual_child() != 0)
    return 4;
  if (pidfd_preserves_identity_and_flag_validation_order() != 0)
    return 5;
  if (close_range_preserves_internal_descriptors() != 0)
    return 6;

  printf("pid=%ld ppid=%ld tid=%ld internal_fds=open\n", pid, ppid, tid);
  return 0;
}
