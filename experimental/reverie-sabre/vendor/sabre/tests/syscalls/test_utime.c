/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

// RUN: %{cc} %s -o %t1
// RUN: touch %t3
// RUN: %{sbr} %{sbr-id} -- %t1 %t3 2>&1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <utime.h>

int main(int argc, char **argv) {
  char buf[1024];

  struct utimbuf t;
  t.actime = 10;
  t.modtime = 0;

  if (utime(argv[1], &t) < 0)
    return 1;

  return 0;
}
