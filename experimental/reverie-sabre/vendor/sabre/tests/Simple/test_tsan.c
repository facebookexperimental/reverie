/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * XFAIL: *
 * REQUIRES: clang,tsan
 * RUN: ulimit -s 32768
 * RUN: %{gcc} -fsanitize=thread -fPIE -pie -g -O1 %s -o %t1
 * RUN: %{clang} -fsanitize=thread -fPIE -pie -g -O1 %s -o %t2
 * RUN: ! %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: ! %{sbr} %{sbr-id} -- %t2 &> %t2.actual
 * RUN: grep "WARNING: ThreadSanitizer: data race" %t1.actual
 * RUN: grep "WARNING: ThreadSanitizer: data race" %t2.actual
 * RUN: grep "Location is global 'Global' of size" %t1.actual
 * RUN: grep "Location is global 'Global' of size" %t2.actual
 */

// Currently this fails because TSan can't properly resolve symbols due to
// SaBRe.

#include <pthread.h>

int Global;

void *Thread1(void *x) {
  Global++;
  return NULL;
}

void *Thread2(void *x) {
  Global--;
  return NULL;
}

int main() {
  pthread_t t[2];
  pthread_create(&t[0], NULL, Thread1, NULL);
  pthread_create(&t[1], NULL, Thread2, NULL);
  pthread_join(t[0], NULL);
  pthread_join(t[1], NULL);
}
