/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void sigchld_handler(int sig, siginfo_t* _info, void* _context) {
  if (sig != SIGCHLD) {
    fprintf(stderr, "unexpected signal %d != SIGCHLD\n", sig);
    abort();
  }
  char buf[256];
  int n = snprintf(buf, 256, "%d caught SIGCHLD\n", getpid());
  write(1, buf, n);
  _exit(0);
}

int main(int argc, char* argv[], char* envp[]) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigchld_handler;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;

  if (sigaction(SIGCHLD, &sa, NULL) != 0) {
    fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
    exit(1);
  }

  if (argc == 2 && strcmp(argv[1], "child") == 0) {
    printf("exec pid: %u\n", getpid());
    _exit(0);
  }

  pid_t pid = fork();

  if (pid < 0) {
    perror("fork failed: ");
    exit(1);
  } else if (pid == 0) {
    char* prog = argv[0];
    char* const newArgv[] = {prog, "child", NULL};
    printf("child pid: %u\n", getpid());
    execve(prog, newArgv, envp);
    printf("exec failed: %s\n", strerror(errno));
  } else {
    printf("parent pid: %u\n", getpid());
    struct timespec tp = {900, 0};
    nanosleep(&tp, NULL);
  }
}
