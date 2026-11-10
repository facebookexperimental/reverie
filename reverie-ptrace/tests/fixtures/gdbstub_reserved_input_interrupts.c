/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#define _GNU_SOURCE
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
static volatile sig_atomic_t valid_info;
static volatile sig_atomic_t valid_mask;
static unsigned char child_stack[65536] __attribute__((aligned(16)));

static void caught(int signal, siginfo_t* info, void* context) {
  (void)context;
  uint64_t mask = 0;
  if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &mask, sizeof(mask)) != 0)
    _exit(61);
  ++handled;
  int route = (test_case >> 3) & 7;
  int direct = route == 0 || route == 1 || route == 5;
  valid_info = signal == SIGUSR1 && info->si_signo == SIGUSR1 &&
      info->si_code == (direct ? SI_TKILL : SI_USER) &&
      info->si_value.sival_int == 0;
  valid_mask = mask == ((UINT64_C(1) << (SIGWINCH - 1)) |
                       (UINT64_C(1) << (SIGUSR1 - 1)));
}

static int survivor(void* unused) {
  (void)unused;
  if (close(gate[1]) != 0) return 62;
  char byte = 0;
  if (syscall(SYS_write, -911, gate[0], &byte) != 0) return 63;
  if (syscall(SYS_write, -910, 0, 0) != 0) return 64;
  return close(gate[0]) == 0 ? 0 : 65;
}

__attribute__((noinline)) static void breakpoint_site(void) {
  __asm__ volatile(".global input_interrupt_breakpoint\n"
                   "input_interrupt_breakpoint:\n"
                   "nop\nnop\nnop\n");
}

int main(int argc, char** argv) {
  if (argc != 2) return 70;
  test_case = atoi(argv[1]);
  int route = (test_case >> 3) & 7;
  int action = test_case & 7;
  struct sigaction sa = {0};
  sa.sa_sigaction = caught;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 71;
  uint64_t mask = UINT64_C(1) << (SIGWINCH - 1);
  if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &mask, NULL, sizeof(mask)) != 0 ||
      pipe(gate) != 0) return 72;
  if (test_case & 128) {
    pid_t writer = fork();
    if (writer < 0) return 84;
    if (writer == 0) {
      close(gate[0]);
      close(gate[1]);
      syscall(SYS_write, -930, 0, 0);
      _exit(85); // The transaction owner remains parked until fatal cleanup.
    }
  }
  pid_t child = clone(survivor, child_stack + sizeof(child_stack),
                     CLONE_VM | SIGCHLD, NULL);
  if (child < 0 || close(gate[0]) != 0) return 73;
  while (syscall(SYS_write, -912, 0, 0) == 0) {}
  if (syscall(SYS_write, -920, 0, 0) != 0) return 74;
  switch (route) {
    case 0:
      while (syscall(SYS_write, -922, 0, 0) == 0) {}
      break;
    case 1:
      if (syscall(SYS_write, -921, 0, 0) != 0) return 75;
      break;
    case 2:
      __asm__ volatile("int3");
      break;
    case 3:
    case 4:
      breakpoint_site();
      break;
    case 5: {
      pid_t temporary = vfork();
      if (temporary == 0) _exit(0);
      int status;
      if (temporary < 0 || waitpid(temporary, &status, 0) != temporary ||
          !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 76;
      break;
    }
    default:
      return 77;
  }
  if (action == 2 || action == 3) return 78; // C09/S09 must actually kill.
  if (handled != (action >= 4 ? 1 : 0)) return 79;
  if (handled && (!valid_info || !valid_mask)) return 80;
  mask = 0;
  if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &mask, sizeof(mask)) != 0 ||
      mask != (UINT64_C(1) << (SIGWINCH - 1))) return 81;
  if (close(gate[1]) != 0) return 82;
  int status;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) return 83;
  return 0;
}
