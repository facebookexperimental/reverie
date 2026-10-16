/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
#ifndef REVERIE_DBT_TEST_KERNEL_TASK_IDENTITY_H
#define REVERIE_DBT_TEST_KERNEL_TASK_IDENTITY_H
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct { pid_t pid; pid_t tid; } kernel_task_identity_t;

/* Procfs is an independent kernel witness in these standalone Tool fixtures;
 * it does not call a guest getter or the native task-membership lookup. */
static kernel_task_identity_t kernel_task_identity(void) {
  char path[64];
  kernel_task_identity_t identity = {0, 0};
  ssize_t size = readlink("/proc/thread-self", path, sizeof(path) - 1);
  if (size <= 0 || (size_t)size >= sizeof(path) - 1)
    return identity;
  path[size] = '\0';
  int pid, tid;
  char extra;
  if (sscanf(path, "%d/task/%d%c", &pid, &tid, &extra) == 2 && pid > 0 && tid > 0)
    identity = (kernel_task_identity_t){(pid_t)pid, (pid_t)tid};
  return identity;
}
#endif
