/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Hello, world!" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  printf("Hello, world!\n");
  return 0;
}
