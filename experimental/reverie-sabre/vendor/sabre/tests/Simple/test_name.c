/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: rm -rf %t1
 * RUN: echo > %t5
 * RUN: %{cc} %s -o %t2
 * RUN: %{sbr} %{sbr-id} -- %t2 %t1 %t5 %t6 &> %t2.actual
 * RUN: echo -n > %t2.expected
 * RUN: diff %t2.actual %t2.expected
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>

/* Utility functions */

/* Tests */
static void test_mkdir(char *dirname) { assert(mkdir(dirname, 0777) == 0); }

static void test_rename(char *from, char *to) { assert(rename(from, to) == 0); }

static void test_unlink(char *filename) { assert(unlink(filename) == 0); }

int main(int argc, char **argv) {
  /* Set-up */

  /* Test */
  test_mkdir(argv[1]);
  test_rename(argv[2], argv[3]);
  test_unlink(argv[3]);

  /* Tear-down */

  return 0;
}
