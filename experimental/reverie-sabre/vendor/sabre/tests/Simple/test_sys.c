/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: echo "This is a test file" > %t2
 * RUN: %{cc} -std=c99 %s -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 %t2 &> %t1.actual
 * RUN: echo -n > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <assert.h>

/* Utility functions */

/* Tests */
static void test_getgid() {
  getgid();
  getegid();
}

static void test_getuid() {
  getuid();
  geteuid();
}

static void test_getpid() { getpid(); }

static void test_getrlimit() {
  struct rlimit rl;

  assert(getrlimit(RLIMIT_STACK, &rl) == 0);
}

static void test_prctl() {
  char buf[16];

  assert(prctl(PR_GET_NAME, buf, NULL, NULL, NULL) == 0);
}

static void test_times() {
  struct tms tms;

  assert(times(&tms) != -1);
}

static void test_uname() {
  struct utsname uts;

  assert(uname(&uts) == 0);
}

static void test_mmap(int fd) {
  assert(mmap(NULL, 16, PROT_READ, MAP_PRIVATE, fd, 0) != MAP_FAILED);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  /* Set-up */
  int fd = open(argv[1], O_RDONLY);

  /* Test */
  test_prctl();
  test_getgid();
  test_getpid();
  test_getuid();
  test_getrlimit();
  test_times();
  test_uname();

  test_mmap(fd);

  /* Tear-down */
  close(fd);

  return 0;
}
