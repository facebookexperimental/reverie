/* Copyright (c) Meta Platforms, Inc. and affiliates.
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

static volatile sig_atomic_t received;
static volatile sig_atomic_t bad_signal;
static pid_t expected_sender;
static int ack_fd = -1;

static void receive_signal(int signal, siginfo_t* info, void* context) {
  (void)context;
  int next = received + 1;
  if (signal != SIGUSR1 || info->si_code != SI_QUEUE ||
      info->si_pid != expected_sender || info->si_value.sival_int != next)
    bad_signal = 1;
  received = next;
  if (ack_fd >= 0) {
    char byte = (char)next;
    if (write(ack_fd, &byte, 1) != 1)
      bad_signal = 1;
  }
}

static int read_byte(int fd, char expected) {
  char value = 0;
  ssize_t count;
  do {
    count = read(fd, &value, 1);
  } while (count < 0 && errno == EINTR);
  return count == 1 && value == expected;
}

static int send_queued(int call, pid_t pid, pid_t tid, int value) {
  siginfo_t info;
  memset(&info, 0, sizeof(info));
  info.si_signo = SIGUSR1;
  info.si_code = SI_QUEUE;
  info.si_pid = expected_sender;
  info.si_uid = getuid();
  info.si_value.sival_int = value;
  return call ? syscall(SYS_rt_tgsigqueueinfo, pid, tid, SIGUSR1, &info)
              : syscall(SYS_rt_sigqueueinfo, pid, SIGUSR1, &info);
}

static pid_t host_pid(void) {
  FILE* file = fopen("/proc/self/stat", "re");
  long value = -1;
  if (file == NULL)
    return -1;
  int count = fscanf(file, "%ld", &value);
  fclose(file);
  return count == 1 && value > 0 && value <= INT_MAX ? (pid_t)value : -1;
}

static void print_errno_matrix(pid_t pid, pid_t tid) {
  const long pids[] = {pid, INT_MAX, 0};
  const long tids[] = {tid, INT_MAX, 0};
  const int signals[] = {0, NSIG};
  for (int call = 0; call < 2; ++call)
    for (int process = 0; process < 3; ++process)
      for (int thread = 0; thread < (call ? 3 : 1); ++thread)
        for (int pointer = 0; pointer < 3; ++pointer)
          for (int signal = 0; signal < 2; ++signal) {
            siginfo_t info;
            memset(&info, 0, sizeof(info));
            info.si_signo = signals[signal];
            info.si_code = pointer == 2 ? SI_USER : SI_QUEUE;
            info.si_pid = pid;
            info.si_uid = getuid();
            errno = 0;
            long result = call ? syscall(
                                     SYS_rt_tgsigqueueinfo,
                                     pids[process],
                                     tids[thread],
                                     signals[signal],
                                     pointer ? &info : NULL)
                               : syscall(
                                     SYS_rt_sigqueueinfo,
                                     pids[process],
                                     signals[signal],
                                     pointer ? &info : NULL);
            int error = errno;
            printf(
                "call=%d process=%d thread=%d info=%d signal=%d result=%ld "
                "errno=%d\n",
                call,
                process,
                thread,
                pointer,
                signal,
                result,
                error);
          }
}

int main(int argc, char** argv) {
  if (argc != 2)
    return 1;
  int dbt = strcmp(argv[1], "dbt") == 0;
  if (!dbt && strcmp(argv[1], "native") != 0)
    return 2;
  alarm(15);
  pid_t pid = (pid_t)syscall(SYS_getpid);
  pid_t tid = (pid_t)syscall(SYS_gettid);
  pid_t host = host_pid();
  if (host <= 0 || (dbt ? pid == host : pid != host))
    return 3;
  // The bounded test launcher starts this process as its own session leader.
  if (syscall(SYS_getpgrp) != pid || getpgid(0) != pid)
    return 4;

  print_errno_matrix(pid, tid);
  fflush(stdout);
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = receive_signal;
  action.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0)
    return 5;
  expected_sender = pid;
  for (int call = 0; call < 2; ++call) {
    if (send_queued(call, pid, tid, call + 1) != 0)
      return 6;
    for (int spin = 0; received != call + 1 && spin < 1000; ++spin)
      sched_yield();
    if (received != call + 1 || bad_signal)
      return 7;
  }

  int ready[2], acknowledgements[2], release[2];
  if (pipe(ready) != 0 || pipe(acknowledgements) != 0 || pipe(release) != 0)
    return 8;
  pid_t child = fork();
  if (child < 0)
    return 9;
  if (child == 0) {
    close(ready[0]);
    close(acknowledgements[0]);
    close(release[1]);
    received = 0;
    bad_signal = 0;
    ack_fd = acknowledgements[1];
    if (syscall(SYS_getpgrp) != pid || getpgid(0) != pid ||
        write(ready[1], "R", 1) != 1 || !read_byte(release[0], 'X'))
      _exit(10);
    _exit(received == 2 && bad_signal == 0 ? 0 : 11);
  }
  close(ready[1]);
  close(acknowledgements[1]);
  close(release[0]);
  if (!read_byte(ready[0], 'R'))
    return 12;
  for (int call = 0; call < 2; ++call) {
    if (send_queued(call, child, child, call + 1) != 0 ||
        !read_byte(acknowledgements[0], (char)(call + 1)))
      return 13;
  }
  int status;
  if (write(release[1], "X", 1) != 1 || waitpid(child, &status, 0) != child ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0)
    return 14;
  puts("queued-signal-identity=ok");
  return 0;
}
