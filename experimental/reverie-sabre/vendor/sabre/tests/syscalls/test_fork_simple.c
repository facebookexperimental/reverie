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

#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
  if (fork() == 0) {
    printf("Hello from child\n");
  } else {
    int status;
    wait(&status);
    printf("Hello from parent\n");
  }
  return 0;
}
