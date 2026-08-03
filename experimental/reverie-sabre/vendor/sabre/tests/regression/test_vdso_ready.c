/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s %S/../../plugin_api/recursion_protector.c -pthread -o %t1
 * RUN: %t1
 */

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>

extern bool is_vdso_ready(void);

static void *check_vdso_ready(void *unused) {
  (void)unused;
  assert(is_vdso_ready());
  return NULL;
}

int main(void) {
  assert(is_vdso_ready());

  pthread_t thread;
  assert(pthread_create(&thread, NULL, check_vdso_ready, NULL) == 0);
  assert(pthread_join(thread, NULL) == 0);

  return 0;
}
