/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* REQUIRES: clang,tsan
 * RUN: ulimit -s 32768
 * RUN: %{gcc} -fsanitize=thread %s -o %t1
 * RUN: %{clang} -fsanitize=thread %s -o %t2
 * RUN: %{gcc} -fsanitize=address %s -o %t3
 * RUN: %{clang} -fsanitize=address %s -o %t4
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: %{sbr} %{sbr-id} -- %t2 &> %t2.actual
 * RUN: %{sbr} %{sbr-id} -- %t3 &> %t3.actual
 * RUN: %{sbr} %{sbr-id} -- %t4 &> %t4.actual
 * RUN: echo "Hello, world!" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 * RUN: diff %t2.actual %t1.expected
 * RUN: diff %t3.actual %t1.expected
 * RUN: diff %t4.actual %t1.expected
 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  printf("Hello, world!\n");
  return 0;
}
