/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

typedef struct {
  pid_t virtual_pid;
  pid_t host_pid;
} child_identity_t;

static volatile sig_atomic_t signal_seen;
static int signal_ack_fd = -1;

static void handle_sigusr1(int signo) {
  char byte = 'S';
  (void)signo;
  signal_seen = 1;
  if (signal_ack_fd >= 0)
    (void)write(signal_ack_fd, &byte, sizeof(byte));
}

static int install_signal_handler(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_sigusr1;
  action.sa_flags = SA_RESTART;
  if (sigemptyset(&action.sa_mask) != 0)
    return 0;
  return sigaction(SIGUSR1, &action, NULL) == 0;
}

static int read_exact(int fd, void* buffer, size_t length) {
  size_t offset = 0;
  while (offset != length) {
    ssize_t count = read(fd, (char*)buffer + offset, length - offset);
    if (count > 0) {
      offset += (size_t)count;
    } else if (count < 0 && errno == EINTR) {
      continue;
    } else {
      return 0;
    }
  }
  return 1;
}

static int write_exact(int fd, const void* buffer, size_t length) {
  size_t offset = 0;
  while (offset != length) {
    ssize_t count = write(fd, (const char*)buffer + offset, length - offset);
    if (count > 0) {
      offset += (size_t)count;
    } else if (count < 0 && errno == EINTR) {
      continue;
    } else {
      return 0;
    }
  }
  return 1;
}

static pid_t proc_self_pid(void) {
  FILE* file = fopen("/proc/self/stat", "re");
  long value = -1;
  if (file == NULL)
    return -1;
  int matched = fscanf(file, "%ld", &value);
  fclose(file);
  return matched == 1 && value > 0 && value <= INT_MAX ? (pid_t)value : -1;
}

static pid_t pidfd_target_pid(int fd) {
  char path[64];
  char line[256];
  long value = -1;
  if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd) <= 0)
    return -1;
  FILE* file = fopen(path, "re");
  if (file == NULL)
    return -1;
  while (fgets(line, sizeof(line), file) != NULL) {
    if (sscanf(line, "Pid:\t%ld", &value) == 1)
      break;
  }
  fclose(file);
  return value > 0 && value <= INT_MAX ? (pid_t)value : -1;
}

static int signal_through_pidfd(int pidfd) {
  return syscall(SYS_pidfd_send_signal, pidfd, SIGUSR1, NULL, 0) == 0;
}

int main(void) {
  int child_ready[2];
  int child_ack[2];
  int child_release[2];
  child_identity_t child_identity;
  int status = 0;
  char byte = 'R';

  alarm(15);
  if (!install_signal_handler())
    return 1;

  pid_t virtual_self = (pid_t)syscall(SYS_getpid);
  pid_t host_self = proc_self_pid();
  if (virtual_self <= 0 || host_self <= 0 || virtual_self == host_self)
    return 2;

  errno = 0;
  if (syscall(SYS_pidfd_open, virtual_self, UINT_MAX) != -1 || errno != EINVAL)
    return 3;
  errno = 0;
  if (syscall(SYS_pidfd_open, INT_MAX, 0) != -1 || errno != ESRCH)
    return 4;
  /* Linux validates flags before PID lookup. Complete the self/unknown x
   * valid/invalid cross-product so DBT cannot synthesize ESRCH first. */
  errno = 0;
  if (syscall(SYS_pidfd_open, INT_MAX, UINT_MAX) != -1 || errno != EINVAL)
    return 15;

  int self_pidfd = (int)syscall(SYS_pidfd_open, virtual_self, 0);
  if (self_pidfd < 0 || pidfd_target_pid(self_pidfd) != host_self)
    return 5;
  signal_seen = 0;
  if (!signal_through_pidfd(self_pidfd))
    return 6;
  for (int spin = 0; spin != 1000 && !signal_seen; ++spin)
    sched_yield();
  if (!signal_seen || close(self_pidfd) != 0)
    return 7;

  if (pipe(child_ready) != 0 || pipe(child_ack) != 0 ||
      pipe(child_release) != 0)
    return 8;

  pid_t virtual_child = fork();
  if (virtual_child < 0)
    return 9;
  if (virtual_child == 0) {
    close(child_ready[0]);
    close(child_ack[0]);
    close(child_release[1]);
    signal_ack_fd = child_ack[1];
    signal_seen = 0;
    child_identity.virtual_pid = (pid_t)syscall(SYS_getpid);
    child_identity.host_pid = proc_self_pid();
    if (!install_signal_handler() || child_identity.virtual_pid <= 0 ||
        child_identity.host_pid <= 0 ||
        child_identity.virtual_pid == child_identity.host_pid ||
        !write_exact(child_ready[1], &child_identity, sizeof(child_identity)) ||
        !read_exact(child_release[0], &byte, sizeof(byte)) || !signal_seen)
      _exit(10);
    _exit(0);
  }

  close(child_ready[1]);
  close(child_ack[1]);
  close(child_release[0]);
  if (!read_exact(child_ready[0], &child_identity, sizeof(child_identity)) ||
      child_identity.virtual_pid != virtual_child ||
      child_identity.host_pid == virtual_child ||
      child_identity.host_pid == host_self) {
    (void)write_exact(child_release[1], &byte, sizeof(byte));
    return 11;
  }

  int child_pidfd = (int)syscall(SYS_pidfd_open, virtual_child, 0);
  if (child_pidfd < 0 ||
      pidfd_target_pid(child_pidfd) != child_identity.host_pid) {
    (void)write_exact(child_release[1], &byte, sizeof(byte));
    return 12;
  }
  if (!signal_through_pidfd(child_pidfd) ||
      !read_exact(child_ack[0], &byte, sizeof(byte)) || byte != 'S') {
    (void)write_exact(child_release[1], &byte, sizeof(byte));
    return 13;
  }
  byte = 'R';
  if (!write_exact(child_release[1], &byte, sizeof(byte)) ||
      waitpid(virtual_child, &status, 0) != virtual_child ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0 || close(child_pidfd) != 0)
    return 14;

  puts("pidfd-identity-ok");
  return 0;
}
