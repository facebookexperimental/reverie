/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Hello from child"  >  %t1.expected
 * RUN: echo "Hello from parent" >> %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <asm/unistd.h>
#include <sys/wait.h>

long __syscall(int syscallno, long arg1, long arg2, long arg3, long arg4,
               long arg5, long arg6);

int main(int argc, char *argv[]) {

  int ret = __syscall(__NR_fork, 0L, 0L, 0L, 0L, 0L, 0L);

  if (ret != 0) {
    // Parent
    char string[] = "Hello from parent\n";
    int status;
    wait(&status);
    __syscall(__NR_write, 1, (long)string, 18, 0L, 0L, 0L);
  } else {
    // Child
    char string[] = "Hello from child\n";
    __syscall(__NR_write, 1, (long)string, 17, 0L, 0L, 0L);
  }

  return 0;
}

asm(".pushsection .text, \"ax\", @progbits\n"

    "__syscall:"
    ".internal __syscall\n"
    ".globl __syscall\n"
    ".type __syscall, @function\n"
#if defined(__x86_64__)
    "movq %rdi, %rax\n" /* place syscall number into %rax */
    "movq %rsi, %rdi\n" /* shift arg1 - arg5 */
    "movq %rdx, %rsi\n"
    "movq %rcx, %rdx\n"
    "movq %r8, %r10\n"
    "movq %r9, %r8\n"
    "movq 8(%rsp),%r9\n" /* arg6 is on the stack */
    "syscall\n"          /* do the system call */
    "ret\n"              /* return to caller */
#else
#error Unsupported target platform
#endif
    ".size __syscall, .-__syscall\n"
    ".popsection\n");
