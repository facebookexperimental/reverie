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
#include <sys/syscall.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

struct kernel_sigaction {
  unsigned long sa__;
  unsigned long flags;
  unsigned long restorer;
  unsigned long masks;
};

// The SA_RESTORER the handler returns to. It must issue rt_sigreturn with the
// stack pointer exactly as the handler left it, where the kernel built the
// signal frame, so it is written in assembly. A C function calling syscall(2)
// works only if the compiler turns the call into a jump: the x86_64 build does,
// but the aarch64 build pushes a 16-byte frame record and calls, so the kernel
// read the frame 16 bytes too low and the process died after the handler.
extern void signal1_restorer(void);
#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl signal1_restorer\n"
    ".type signal1_restorer, @function\n"
    "signal1_restorer:\n"
    "  mov $15, %eax\n" // SYS_rt_sigreturn
    "  syscall\n"
    "  hlt\n"
    ".size signal1_restorer, . - signal1_restorer\n");
#elif defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl signal1_restorer\n"
    ".type signal1_restorer, %function\n"
    "signal1_restorer:\n"
    "  mov x8, #139\n" // SYS_rt_sigreturn
    "  svc #0\n"
    "  brk #0\n"
    ".size signal1_restorer, . - signal1_restorer\n");
#else
#error "no SA_RESTORER for this architecture"
#endif

static int rt_sigaction(
    int signum,
    const struct kernel_sigaction* new,
    struct kernel_sigaction* old) {
  unsigned long r =
      (unsigned long)syscall(SYS_rt_sigaction, signum, new, old, 8);
  if (r >= ~0xfffUL) {
    return (int)r;
  } else {
    return (int)r;
  }
}

static volatile int quit = 0;

static void handler(int sig, siginfo_t* info, void* ucontext) {
  static char msg[64];
  quit = 1;
  size_t n = snprintf(msg, 64, "[OK] received signal %u\n", info->si_signo);
  write(STDOUT_FILENO, msg, n);
}

extern int __restore_rt(void);

int main(int argc, char* argv[]) {
  int ret;
  struct kernel_sigaction old, new;

  memset(&old, 0, sizeof(old));
  memset(&new, 0, sizeof(new));

  new.sa__ = (unsigned long)handler;
  new.flags = SA_RESTART | SA_RESTORER | SA_SIGINFO;
  new.restorer = (unsigned long)signal1_restorer;

  ret = rt_sigaction(SIGALRM, &new, NULL);
  if (ret < 0) {
    perror("rt_sigaction");
    exit(1);
  }

  ret = rt_sigaction(SIGALRM, NULL, &old);
  if (ret < 0) {
    perror("rt_sigaction");
    exit(1);
  }

  assert(old.sa__ == (unsigned long)handler);

  alarm(1);

  while (!quit) {
    ;
  }

  return 0;
}
