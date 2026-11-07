/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char child_stack[64 * 1024];

static int child_application(void* unused) {
  (void)unused;
  static const char marker[] = "UNADMITTED_CHILD_APPLICATION\n";
  (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
  _exit(77);
}

int main(void) {
  const char* mode = getenv("REVERIE_DBT_TEST_PID_NAMESPACE_CASE");
  if (mode == NULL)
    return 2;
  pid_t child;
  int for_children = strcmp(mode, "pid-for-children") == 0 ||
      strcmp(mode, "pid-for-children-vfork") == 0;
  if (for_children && unshare(CLONE_NEWPID) != 0) {
    perror("unshare PID namespace for children");
    return 3;
  }
  int vfork_case = strcmp(mode, "shared-vm-vfork") == 0 ||
      strcmp(mode, "pid-for-children-vfork") == 0;
  if (strcmp(mode, "shared-vm") == 0 || vfork_case) {
    int flags = CLONE_VM | SIGCHLD;
    if (!for_children)
      flags |= CLONE_NEWPID;
    if (vfork_case)
      flags |= CLONE_VFORK;
    child = clone(child_application, child_stack + sizeof(child_stack), flags, NULL);
  } else {
    if (strcmp(mode, "separate-vm") != 0 && !for_children)
      return 4;
    unsigned long flags = (for_children ? 0 : CLONE_NEWPID) | SIGCHLD;
    child = (pid_t)syscall(SYS_clone, flags, 0, 0, 0, 0);
    if (child == 0)
      child_application(NULL);
  }
  if (child < 0) {
    perror("valid nested PID clone");
    return 5;
  }
  int status;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 101)
    return 6;
  puts("nested-pid-child-refused-before-application");
  return 0;
}
