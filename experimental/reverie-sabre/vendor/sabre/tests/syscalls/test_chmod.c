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

#include <sys/stat.h>

int main(int argc, char **argv) {

  if (chmod(argv[1], 00755) < 0)
    return 1;

  return 0;
}
