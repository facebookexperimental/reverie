/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: echo "This is a test file" > %t2
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 %t2 &> %t1.actual
 * RUN: echo -n > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>

/* Utility functions */

/* Tests */
static void test_lseek(int fd) { assert(lseek(fd, 1, SEEK_SET) != -1); }

int main(int argc, char **argv) {
  /* Set-up */
  int fd = open(argv[1], O_RDWR);

  /* Test */
  test_lseek(fd);

  /* Tear-down */
  close(fd);

  return 0;
}
