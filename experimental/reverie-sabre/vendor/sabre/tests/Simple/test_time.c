/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t2
 * RUN: %{sbr} %{sbr-id} -- %t2 2>&1 > %t2.actual
 * RUN: echo "Success" > %t2.expected
 * RUN: diff %t2.actual %t2.expected
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <time.h>

#include <assert.h>

/* Utility functions */

/* Tests */
static void test_time() { assert(time(NULL) != -1); }

static void test_gettimeofday() {
  struct timeval tv;
  struct timezone tz;

  assert(gettimeofday(&tv, &tz) == 0);
}

static void test_clock_gettime() {
  struct timespec tp;

  assert(clock_gettime(CLOCK_REALTIME, &tp) == 0);
}

int main(int argc, char **argv) {
  /* Set-up */

  /* Test */
  test_time();
  test_gettimeofday();
  test_clock_gettime();

  /* Tear-down */
  printf("Success\n");

  return 0;
}
