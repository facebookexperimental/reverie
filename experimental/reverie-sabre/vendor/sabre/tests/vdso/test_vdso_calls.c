/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -g %s -o %t1
 * RUN: %{sbr} %{sbr-trc} --handle-vdso=special -- %t1 &> %t1.actual
 * RUN: [ $(grep "(vDSO)" %t1.actual | wc -l) -eq 4 ]
 * RUN: [ $(grep "time(0X0)" %t1.actual | wc -l) -eq 2 ]
 * RUN: [ $(grep "gettimeofday" %t1.actual | wc -l) -eq 2 ]
 * RUN: [ $(grep "clock_gettime" %t1.actual | wc -l) -eq 2 ]
 * RUN: [ $(grep "getcpu" %t1.actual | wc -l) -eq 2 ]
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Utility functions */

/* Tests */

static void test_all_vdso() {
  struct timespec ts;
  assert(clock_gettime(CLOCK_REALTIME, &ts) != -1);

  assert(sched_getcpu() != -1);

  struct timeval tv;
  assert(gettimeofday(&tv, NULL) == 0);

  assert(time(NULL) != -1);
}

static void test_clock_gettime() {
  struct timespec t;
  assert(syscall(SYS_clock_gettime, CLOCK_REALTIME, &t, NULL) == 0);
}

static void test_gettimeofday() {
  struct timeval t;
  assert(syscall(SYS_gettimeofday, &t, NULL, NULL) == 0);
}

static void test_time() { assert(syscall(SYS_time, NULL, NULL, NULL) != -1); }

static void test_getcpu() {
  int cpu, node;
  assert(syscall(SYS_getcpu, &cpu, &node, NULL) == 0);
}

int main(int argc, char **argv) {
  /* Set-up */

  /* Test */
  test_time();
  test_getcpu();
  test_gettimeofday();
  test_clock_gettime();
  test_all_vdso();

  /* Tear-down */

  printf("Success\n");

  return 0;
}
