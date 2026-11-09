/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Queues itself SIGUSR1 with sigqueue and value 77, and exits 0 when its
 * SA_SIGINFO handler saw SI_QUEUE with the value argv[1] names: "own" for
 * 77, the siginfo sigqueue sent, or "tool" for 4242, the siginfo the
 * tracer's Tool chose. Exits 4 or 5, naming what it saw on stderr,
 * otherwise.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile int seen_code = 1000;
static volatile int seen_value = -1;

static void handler(int sig, siginfo_t* info, void* context) {
  (void)sig;
  (void)context;
  seen_code = info->si_code;
  seen_value = info->si_value.sival_int;
}

int main(int argc, char** argv) {
  int want = (argc > 1 && strcmp(argv[1], "tool") == 0) ? 4242 : 77;
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0) {
    return 2;
  }
  union sigval value;
  value.sival_int = 77;
  /* Its result is not checked: the tracer's Tool injects a syscall in the
   * signal's callback, whose result the guest can see here instead. */
  (void)sigqueue(getpid(), SIGUSR1, value);
  if (seen_code != SI_QUEUE) {
    fprintf(stderr, "si_code %d\n", seen_code);
    return 4;
  }
  if (seen_value != want) {
    fprintf(stderr, "si_value %d, want %d\n", seen_value, want);
    return 5;
  }
  return 0;
}
