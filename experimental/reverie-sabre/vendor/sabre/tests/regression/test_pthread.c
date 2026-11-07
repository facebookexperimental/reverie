/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -pthread -o %t1
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Hello from thread" > %t1.expected
 * RUN: echo "Hello from main" >> %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <pthread.h>
#include <stdio.h>

/* this function is run by the second thread */
void *thread_f(void *ignored) {
  printf("Hello from thread\n");
  return NULL;
}

int main() {

  /* this variable is our reference to the second thread */
  pthread_t thread;

  /* create a second thread which executes inc_x(&x) */
  if (pthread_create(&thread, NULL, thread_f, NULL)) {
    printf("Error creating thread\n");
    return 1;
  }

  /* wait for the second thread to finish */
  if (pthread_join(thread, NULL)) {
    printf("Error joining thread\n");
    return 2;
  }

  printf("Hello from main\n");

  return 0;
}
