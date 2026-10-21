/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Each case runs a burst of cheap syscalls, then one event that changes the
 * task (exec, a thread or process clone, fork, vfork, exit, a descriptor-table
 * change, a signal delivery), then another burst. Under a Tool that
 * subscribes to every syscall, each of those syscalls is one callback, so the
 * bursts cross the event with the callback state a thread keeps between
 * callbacks. Every line printed is a value Linux defines; the native run is
 * the oracle.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                  \
  do {                                                                    \
    if (!(condition)) {                                                   \
      fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__,       \
              #condition, errno);                                         \
      exit(90);                                                           \
    }                                                                     \
  } while (0)

static const char *self_path;

/* A burst of callbacks whose results Linux fixes for this task. */
static void burst(const char *label) {
  pid_t pid = getpid();
  pid_t ppid = getppid();
  pid_t tid = (pid_t)syscall(SYS_gettid);
  int same = 1;
  for (int i = 0; i < 64; i++) {
    same &= getpid() == pid;
    same &= getppid() == ppid;
    same &= (pid_t)syscall(SYS_gettid) == tid;
    same &= umask(022) == 022;
  }
  printf("%s burst %s\n", label, same ? "stable" : "CHANGED");
  fflush(stdout);
}

static void print_status(const char *label, int status) {
  if (WIFEXITED(status)) {
    printf("%s exited %d\n", label, WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    printf("%s signaled %d\n", label, WTERMSIG(status));
  } else {
    printf("%s status %#x\n", label, status);
  }
  fflush(stdout);
}

static int run_exec(void) {
  burst("exec-before");
  char *argv[] = {(char *)self_path, "exec-image", NULL};
  execv(self_path, argv);
  CHECK(!"execv returned");
  return 1;
}

static int run_exec_image(void) {
  burst("exec-after");
  return 0;
}

static void *thread_body(void *argument) {
  burst((const char *)argument);
  return (void *)(long)umask(022);
}

static int run_thread(void) {
  burst("thread-parent-before");
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, thread_body, "thread-child") == 0);
  void *result = NULL;
  CHECK(pthread_join(thread, &result) == 0);
  printf("thread joined %ld\n", (long)result);
  burst("thread-parent-after");
  return 0;
}

static int run_fork(void) {
  burst("fork-parent-before");
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    burst("fork-child");
    _exit(7);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child);
  print_status("fork child", status);
  burst("fork-parent-after");
  return 0;
}

static int run_clone_process(void) {
  burst("clone-parent-before");
  long child = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
  CHECK(child >= 0);
  if (child == 0) {
    burst("clone-child");
    _exit(9);
  }
  int status = 0;
  CHECK(waitpid((pid_t)child, &status, 0) == (pid_t)child);
  print_status("clone child", status);
  burst("clone-parent-after");
  return 0;
}

static int run_vfork(void) {
  burst("vfork-parent-before");
  pid_t child = vfork();
  CHECK(child >= 0);
  if (child == 0) {
    _exit(5);
  }
  int status = 0;
  CHECK(waitpid(child, &status, 0) == child);
  print_status("vfork child", status);
  burst("vfork-parent-middle");
  child = vfork();
  CHECK(child >= 0);
  if (child == 0) {
    char *argv[] = {(char *)self_path, "vfork-image", NULL};
    execv(self_path, argv);
    _exit(91);
  }
  CHECK(waitpid(child, &status, 0) == child);
  print_status("vfork exec child", status);
  burst("vfork-parent-after");
  return 0;
}

static int run_vfork_image(void) {
  burst("vfork-image");
  return 6;
}

static void *exiting_thread(void *argument) {
  (void)argument;
  burst("exit-thread");
  pthread_exit((void *)11);
}

static int run_exit(void) {
  burst("exit-before");
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, exiting_thread, NULL) == 0);
  void *result = NULL;
  CHECK(pthread_join(thread, &result) == 0);
  printf("exit thread result %ld\n", (long)result);
  burst("exit-after");
  syscall(SYS_exit_group, 3);
  return 1;
}

static int closed(int fd) {
  int result = fcntl(fd, F_GETFD);
  return result == -1 && errno == EBADF;
}

static int run_descriptors(void) {
  burst("descriptors-before");
  int pipe_fds[2];
  CHECK(pipe2(pipe_fds, O_CLOEXEC) == 0);
  int duplicate = dup(pipe_fds[1]);
  CHECK(duplicate >= 0);
  burst("descriptors-dup");
  CHECK(write(duplicate, "abc", 3) == 3);
  CHECK(close(duplicate) == 0);
  burst("descriptors-close");
  int moved = fcntl(pipe_fds[1], F_DUPFD_CLOEXEC, 50);
  CHECK(moved >= 50);
  CHECK(dup2(moved, pipe_fds[1]) == pipe_fds[1]);
  CHECK(write(moved, "def", 3) == 3);
  CHECK(close(moved) == 0);
  CHECK(close(pipe_fds[1]) == 0);
  burst("descriptors-moved");
  char buffer[16] = {0};
  ssize_t length = read(pipe_fds[0], buffer, sizeof buffer);
  printf("descriptors read %zd %.*s\n", length, (int)(length > 0 ? length : 0),
         buffer);
  ssize_t eof = read(pipe_fds[0], buffer, sizeof buffer);
  printf("descriptors eof %zd\n", eof);
  int moved_closed = closed(moved);
  int duplicate_closed = closed(duplicate);
  printf("descriptors closed %d %d\n", moved_closed, duplicate_closed);
  CHECK(close(pipe_fds[0]) == 0);
  burst("descriptors-after");
  return 0;
}

static volatile sig_atomic_t handled;

static void handler(int signal_number) {
  handled++;
  /* Syscalls inside the handler are callbacks inside the signal frame. */
  if (getpid() > 0 && signal_number == SIGUSR1) handled += 10;
}

static int run_signal(void) {
  burst("signal-before");
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = handler;
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  CHECK(raise(SIGUSR1) == 0);
  printf("signal raised handled %d\n", (int)handled);
  burst("signal-after-raise");
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  CHECK(sigprocmask(SIG_BLOCK, &block, NULL) == 0);
  CHECK(kill(getpid(), SIGUSR1) == 0);
  burst("signal-blocked");
  sigset_t pending;
  CHECK(sigpending(&pending) == 0);
  printf("signal pending %d handled %d\n", sigismember(&pending, SIGUSR1),
         (int)handled);
  CHECK(sigprocmask(SIG_UNBLOCK, &block, NULL) == 0);
  printf("signal unblocked handled %d\n", (int)handled);
  burst("signal-after");
  return 0;
}

int main(int argc, char **argv) {
  self_path = argv[0];
  CHECK(argc == 2);
  const char *which = argv[1];
  if (!strcmp(which, "exec")) return run_exec();
  if (!strcmp(which, "exec-image")) return run_exec_image();
  if (!strcmp(which, "thread")) return run_thread();
  if (!strcmp(which, "fork")) return run_fork();
  if (!strcmp(which, "clone-process")) return run_clone_process();
  if (!strcmp(which, "vfork")) return run_vfork();
  if (!strcmp(which, "vfork-image")) return run_vfork_image();
  if (!strcmp(which, "exit")) return run_exit();
  if (!strcmp(which, "descriptors")) return run_descriptors();
  if (!strcmp(which, "signal")) return run_signal();
  return 92;
}
