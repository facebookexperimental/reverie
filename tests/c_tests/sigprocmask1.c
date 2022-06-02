/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

static volatile int quit = 0;

static void handler(int sig, siginfo_t* info, void* ucontext) {
  static char msg[64];
  quit = 1;
  size_t n = snprintf(msg, 64, "[OK] received signal %u\n", info->si_signo);
  write(STDOUT_FILENO, msg, n);
}

int main(int argc, char* argv[]) {
  int ret;
  sigset_t sigset, sigset_old;
  struct sigaction old, new;

  memset(&old, 0, sizeof(old));
  memset(&new, 0, sizeof(new));

  sigemptyset(&sigset);
  sigemptyset(&sigset_old);
  sigaddset(&sigset, SIGALRM);
  sigaddset(&sigset, SIGVTALRM);

  new.sa_sigaction = handler;
  new.sa_mask = sigset;
  new.sa_flags = SA_RESTART | SA_SIGINFO;

  ret = sigaction(SIGALRM, &new, &old);
  if (ret < 0) {
    perror("rt_sigaction");
    exit(1);
  }

  ret = sigprocmask(SIG_UNBLOCK, &sigset, &sigset_old);
  assert(ret >= 0);

  ret = sigaction(SIGALRM, NULL, &old);
  if (ret < 0) {
    perror("rt_sigaction");
    exit(1);
  }

  assert((unsigned long)old.sa_sigaction == (unsigned long)handler);

  alarm(1);

  while (!quit)
    ;

  return 0;
}
