/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Regression fixture for native virtual-clock and virtual-resource
 * virtualization in copied (forked) DBT children.
 *
 * The DynamoRIO backend runs the Reverie Tool runtime only in the root of the
 * traced tree; copied/forked children are served entirely by the native-only
 * path. Before this fixture's fix, that path applied only identity
 * virtualization, so a forked child read real host time and real host rlimits
 * while the root process saw the deterministic native virtual clock and virtual
 * limits. This fixture reads clock_gettime through libc's vDSO path repeatedly
 * before and after two ordered children. The first child continues from fork;
 * the second execs this fixture so a new DynamoRIO client image remaps the
 * shared state and patches its newly loaded vDSO. It then starts two execed
 * children behind a pipe barrier, waits until both client images are ready, and
 * releases them to read the clock without waiting for either child first. The
 * harness checks the ordered lifecycle observations and the sorted union of the
 * concurrent observations as strictly increasing, fine-grained sequences. A
 * private COW counter, an exec-time reset, a frozen clock, duplicate values, or
 * a first-read-only match therefore cannot pass.
 *
 *   - Virtual CLOCK_MONOTONIC advances one microsecond per read across the
 *     complete process tree; no process restarts or owns a private clock.
 *   - Virtual RLIMIT_NOFILE is 1048576, distinct from a typical host soft
 * limit.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
  CLOCK_READS = 4,
  VIRTUAL_IDENTITY_FD = 197,
  DBT_DIAGNOSTIC_FD = 198,
};

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

// TODO-HUMAN-REVIEW(PR-shared-dbi-clock): Review the shared-clock lifecycle
// probe.
static int probe(const char* who) {
  struct rlimit rl = {0, 0};
  for (int read = 0; read < CLOCK_READS; ++read) {
    struct timespec ts = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
      return 1;
    unsigned long long nanoseconds =
        (unsigned long long)ts.tv_sec * 1000000000ULL +
        (unsigned long long)ts.tv_nsec;
    printf("%s_mono_ns[%d]=%llu\n", who, read, nanoseconds);
  }
  // Raw syscall: prlimit64(pid=0 -> current, new=NULL, old=&rl).
  if (syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, (void*)0, &rl) != 0)
    return 1;
  printf("%s_nofile=%llu\n", who, (unsigned long long)rl.rlim_cur);
  fflush(stdout);
  return 0;
}

static int wait_for_child(pid_t child) {
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0)
    return 1;
  return 0;
}

static int read_byte(int fd) {
  char value = 0;
  ssize_t result;
  do {
    result = read(fd, &value, 1);
  } while (result < 0 && errno == EINTR);
  return result == 1 ? 0 : 1;
}

static int write_byte(int fd) {
  const char value = 'x';
  ssize_t result;
  do {
    result = write(fd, &value, 1);
  } while (result < 0 && errno == EINTR);
  return result == 1 ? 0 : 1;
}

static int concurrent_child(const char* who, int ready_fd, int start_fd) {
  if (write_byte(ready_fd) != 0)
    return 1;
  close(ready_fd);
  if (read_byte(start_fd) != 0)
    return 1;
  close(start_fd);
  return probe(who);
}

static int run_concurrent_children(const char* self) {
  int ready[2] = {-1, -1};
  int start[2] = {-1, -1};
  pid_t children[2] = {-1, -1};
  const char* labels[2] = {"concurrent-child-a", "concurrent-child-b"};

  if (pipe(ready) != 0 || pipe(start) != 0)
    return 1;

  for (int child_index = 0; child_index < 2; ++child_index) {
    children[child_index] = fork();
    if (children[child_index] < 0)
      return 1;
    if (children[child_index] == 0) {
      char ready_fd[32];
      char start_fd[32];
      close(ready[0]);
      close(start[1]);
      snprintf(ready_fd, sizeof(ready_fd), "%d", ready[1]);
      snprintf(start_fd, sizeof(start_fd), "%d", start[0]);
      execl(
          "/proc/self/exe",
          self,
          "--concurrent-child",
          labels[child_index],
          ready_fd,
          start_fd,
          (char*)0);
      syscall(SYS_exit, 1);
    }
  }

  close(ready[1]);
  close(start[0]);
  if (read_byte(ready[0]) != 0 || read_byte(ready[0]) != 0 ||
      write_byte(start[1]) != 0 || write_byte(start[1]) != 0)
    return 1;
  close(ready[0]);
  close(start[1]);
  int first_status = wait_for_child(children[0]);
  int second_status = wait_for_child(children[1]);
  if (first_status != 0 || second_status != 0)
    return 1;
  return 0;
}

int main(int argc, char** argv) {
  if (argc == 2 && strcmp(argv[1], "--exec-child") == 0)
    return probe("exec-child");
  if (argc == 5 && strcmp(argv[1], "--concurrent-child") == 0)
    return concurrent_child(argv[2], atoi(argv[3]), atoi(argv[4]));

  if (probe("parent-before") != 0)
    return 1;

  pid_t child = fork();
  if (child < 0)
    return 2;
  if (child == 0) {
    int result = probe("fork-child");
    // _exit so the inherited stdio buffer is not flushed twice.
    syscall(SYS_exit, result);
  }
  if (wait_for_child(child) != 0)
    return 3;

  child = fork();
  if (child < 0)
    return 4;
  if (child == 0) {
#ifdef SYS_close_range
    if (syscall(
            SYS_close_range,
            VIRTUAL_IDENTITY_FD,
            DBT_DIAGNOSTIC_FD,
            CLOSE_RANGE_CLOEXEC) != 0 ||
        syscall(SYS_close_range, VIRTUAL_IDENTITY_FD, DBT_DIAGNOSTIC_FD, 0) !=
            0)
      syscall(SYS_exit, 5);
#else
    syscall(SYS_exit, 5);
#endif
    execl("/proc/self/exe", argv[0], "--exec-child", (char*)0);
    syscall(SYS_exit, 6);
  }
  if (wait_for_child(child) != 0)
    return 7;

  if (probe("parent-after") != 0)
    return 8;
  return run_concurrent_children(argv[0]) == 0 ? 0 : 9;
}
