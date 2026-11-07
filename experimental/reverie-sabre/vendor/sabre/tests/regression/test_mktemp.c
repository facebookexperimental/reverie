/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * REQUIRES: rdtsc
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Success" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
  char template[] = "tmpXXXXXX";

  mktemp(template);

  assert(strlen(template) > 0);

  struct stat buf;
  assert(stat(template, &buf) == -1);

  printf("Success\n");
  return 0;
}
