/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Child process started"  >  %t1.expected
 * RUN: echo "Now i am coming back to parent process" >> %t1.expected
 * RUN: echo "Value of n: 10" >> %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  int n = 10;
  pid_t pid = vfork(); //creating the child process
  if (pid == 0)        //if this is a chile process
  {
    printf("Child process started\n");
    _exit(0);
  } else //parent process execution
  {
    printf("Now i am coming back to parent process\n");
  }
  printf("Value of n: %d\n", n); //sample printing to check "n" value
  return 0;
}
