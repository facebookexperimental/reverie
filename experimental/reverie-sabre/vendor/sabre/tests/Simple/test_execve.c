/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -D_EXEC_NAME=%t1 -o %t1
 * RUN: echo "Hello, world!" > %t1.expected
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual 1
 * RUN: sleep 2
 * RUN: diff %t1.actual %t1.expected
 */

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define xstr(a) str(a)
#define str(a) #a

#ifndef _EXEC_NAME
#define _EXEC_NAME a.out
#endif

int main(int argc, char **argv) {
  if (argc == 1) {
    printf("Hello, world!\n");
    fflush(NULL);
    return 0;
  }

  int pid = fork();
  if (pid == 0) {
    char *const args[] = {xstr(_EXEC_NAME), NULL};
    char *const envp[] = {NULL};
    execve(xstr(_EXEC_NAME), args, envp);
    assert(0);
  } else
    wait(NULL);

  return 0;
}
