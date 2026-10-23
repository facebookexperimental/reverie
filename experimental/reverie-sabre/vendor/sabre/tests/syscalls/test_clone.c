/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1 -lpthread
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: echo "Hello from parent"    >  %t1.expected
 * RUN: echo "Hello from child"     >> %t1.expected
 * RUN: echo "Goodbye from parent"  >> %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //Header file for sleep(). man 3 sleep for details.

// A normal C function that is executed as a thread
// when its name is specified in pthread_create()
void *myThreadFun(void *msg) {
  printf("Hello from %s\n", (char *)msg);
  return NULL;
}

int main() {
  pthread_t thread_id;
  char *msg = "child";

  printf("Hello from parent\n");

  pthread_create(&thread_id, NULL, myThreadFun, msg);
  pthread_join(thread_id, NULL);

  printf("Goodbye from parent\n");

  return 0;
}
