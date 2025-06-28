/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void dump_sa(const struct sigaction* sa) {
  printf("  struct sigaction @%p\n   ", sa);
  printf(
      "handler = %p, sigaction = %p, flags = %x, restorer = %p, sigset: \n   ",
      sa->sa_handler,
      sa->sa_sigaction,
      sa->sa_flags,
      sa->sa_restorer);
  for (int i = 0; i < sizeof(sigset_t) / sizeof(long); i++) {
    printf(" %016lx", sa->sa_mask.__val[i]);
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  int ret;
  sigset_t sigset;
  struct sigaction old, new;

  memset(&old, 0, sizeof(old));
  memset(&new, 0, sizeof(new));

  sigemptyset(&sigset);
  new.sa_sigaction = handler;
  new.sa_mask = sigset;
  new.sa_flags = SA_RESTART | SA_SIGINFO;

  ret = sigaction(SIGALRM, &new, &old);
  if (ret < 0) {
    perror("rt_sigaction");
    exit(1);
  }

  dump_sa(&new);

  ret = sigaction(SIGALRM, NULL, &old);
  if (ret < 0) {
    perror("rt_sigaction");
    exit(1);
  }

  dump_sa(&old);
  assert((unsigned long)old.sa_sigaction == (unsigned long)handler);

  alarm(1);

  while (!quit)
    ;

  return 0;
}
