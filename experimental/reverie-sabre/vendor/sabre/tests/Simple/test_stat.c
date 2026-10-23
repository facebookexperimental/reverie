/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: echo > %t1
 * RUN: ln -s -f %t1 %t1.link
 * RUN: %{cc} %s -o %t2
 * RUN: %{sbr} %{sbr-id} -- %t2 %t1 %t1.link &> %t2.actual
 * RUN: echo -n > %t2.expected
 * RUN: diff %t2.actual %t2.expected
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <assert.h>

#include <sys/syscall.h>

/* Utility functions */

/* Tests */

static void test_stat(char *filename) {
  struct stat s;
  assert(stat(filename, &s) != -1);
}

static void test_fstat(int fd) {
  struct stat s;
  assert(fstat(fd, &s) != -1);
}

static void test_lstat_readlink(char *filename) {
  struct stat s;
  char *linkname;
  ssize_t r;

  assert(lstat(filename, &s) != -1);

  linkname = malloc(s.st_size + 1);

  r = readlink(filename, linkname, s.st_size + 1);

  free(linkname);
}

static void test_statfs(char *filename) {
  struct statfs s;

  assert(statfs(filename, &s) != -1);
}

static void test_fstatfs(int fd) {
  struct statfs s;

  assert(fstatfs(fd, &s) != -1);
}

int main(int argc, char **argv) {
  /* Set-up */
  int fd = open(argv[1], O_RDONLY);

  /* Test */
  test_stat(argv[1]);
  test_lstat_readlink(argv[2]);
  test_statfs(argv[1]);
  test_fstatfs(fd);

  /* Tear-down */
  close(fd);

  return 0;
}
