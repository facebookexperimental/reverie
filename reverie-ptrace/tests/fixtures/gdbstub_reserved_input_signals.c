/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int gate[2];
static int test_case;
static volatile sig_atomic_t handled;
static volatile sig_atomic_t info_code;
static volatile sig_atomic_t info_value;
static volatile sig_atomic_t handler_mask_ok;
static unsigned char child_stack[65536] __attribute__((aligned(16)));

static void caught(int signal, siginfo_t* info, void* context) {
  (void)context;
  sigset_t mask;
  if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0) {
    _exit(31);
  }
  handled = signal;
  info_code = info->si_code;
  info_value = info->si_value.sival_int;
  handler_mask_ok = info->si_signo == signal &&
      sigismember(&mask, SIGWINCH) == 1 && sigismember(&mask, signal) == 1;
}

static int expected_signal(void) {
  switch (test_case) {
    case 0:
    case 5:
      return SIGUSR1;
    case 3:
    case 6:
    case 7:
      return SIGUSR2;
    default:
      return 0;
  }
}

static int survivor(void* unused) {
  (void)unused;
  if (close(gate[1]) != 0) {
    return 32;
  }
  char byte = 0;
  // The test Tool owns a real blocking read and its copyout lease. Its reply
  // arrives only after the signal target closes the pipe or actually dies.
  if (syscall(SYS_write, -911, gate[0], &byte) != 0) {
    return 33;
  }
  if (handled != expected_signal()) {
    return 34;
  }
  if (syscall(SYS_write, -910, 0, 0) != 0) {
    return 35;
  }
  return close(gate[0]) == 0 ? 0 : 36;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    return 40;
  }
  test_case = atoi(argv[1]);
  if (test_case < 0 || test_case > 7) {
    return 41;
  }
  struct sigaction action = {0};
  action.sa_sigaction = caught;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0 ||
      sigaction(SIGUSR2, &action, NULL) != 0) {
    return 42;
  }
  struct sigaction fatal = {0};
  fatal.sa_handler = SIG_DFL;
  sigemptyset(&fatal.sa_mask);
  if (sigaction(SIGTERM, &fatal, NULL) != 0) {
    return 55;
  }
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGWINCH);
  if (sigprocmask(SIG_SETMASK, &mask, NULL) != 0 || pipe(gate) != 0) {
    return 43;
  }
  pid_t child = clone(survivor, child_stack + sizeof(child_stack),
      CLONE_VM | SIGCHLD, NULL);
  if (child < 0 || close(gate[0]) != 0) {
    return 44;
  }
  // Do not race the signal against acquisition of the survivor's native read
  // lease. This is a test Tool rendezvous, not a sleep or a changed timeout.
  long ready;
  do {
    ready = syscall(SYS_write, -912, 0, 0);
    if (ready < 0 || ready > 1) {
      return 45;
    }
  } while (ready == 0);
  union sigval value = {.sival_int = 4242};
  if (sigqueue(getpid(), SIGUSR1, value) != 0) {
    return 46;
  }
  if (test_case == 2) {
    return 47; // GDB must really deliver default-fatal SIGTERM, never suppress it.
  }
  if (handled != expected_signal()) {
    return 48;
  }
  if (handled != 0 && !handler_mask_ok) {
    return 49;
  }
  if (handled == SIGUSR1 && (info_code != SI_QUEUE || info_value != 4242)) {
    return 50;
  }
  if (handled == SIGUSR2 && (info_code != SI_USER || info_value != 0)) {
    return 51;
  }
  if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 ||
      sigismember(&mask, SIGWINCH) != 1 ||
      sigismember(&mask, SIGUSR1) != 0 || sigismember(&mask, SIGUSR2) != 0) {
    return 52;
  }
  if (close(gate[1]) != 0) {
    return 53;
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    return 54;
  }
  return 0;
}
