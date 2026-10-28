/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: echo "abc" >  %t1.expected
 * RUN: echo "def" >> %t1.expected
 * RUN: timeout 5 %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: diff %t1.actual %t1.expected
 */

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int pid = fork();
  if (pid == 0) {
    printf("abc\n");
  } else {
    wait(NULL);
    printf("def\n");
  }

  return 0;
}
