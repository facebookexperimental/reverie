/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char clone_vm_stack[64 * 1024];

static int clone_vm_child(void *unused) {
  (void)unused;
  (void)getuid();
  return 0;
}

static int wait_ok(pid_t child) {
  int status = 0;
  return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0;
}

static int finish_child(pid_t child) {
  if (child < 0)
    return 0;
  if (child == 0)
    _exit(0);
  return wait_ok(child);
}

int main(void) {
  errno = 0;
  long invalid = syscall(SYS_clone, CLONE_SIGHAND | SIGCHLD, 0, 0, 0, 0);
  if (invalid != -1 || errno != EINVAL)
    return 1;

#ifdef SYS_clone3
  errno = 0;
  long malformed_clone3 = syscall(SYS_clone3, NULL, 0);
  if (malformed_clone3 != -1)
    return 8;
#endif

  errno = 0;
  long invalid_again = syscall(SYS_clone, CLONE_SIGHAND | SIGCHLD, 0, 0, 0, 0);
  if (invalid_again != -1 || errno != EINVAL)
    return 7;

  if (!finish_child((pid_t)syscall(SYS_fork)))
    return 2;
  if (!finish_child((pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0)))
    return 3;

  pid_t clone_vm_child_pid =
      clone(clone_vm_child, clone_vm_stack + sizeof(clone_vm_stack),
            CLONE_VM | SIGCHLD, NULL);
  if (clone_vm_child_pid < 0 || !wait_ok(clone_vm_child_pid))
    return 6;

#ifdef SYS_clone3
  struct clone_args args = {.exit_signal = SIGCHLD};
  if (!finish_child((pid_t)syscall(SYS_clone3, &args, sizeof(args))))
    return 4;
#endif

  if (!finish_child((pid_t)syscall(SYS_vfork)))
    return 5;

  puts("process-clone-results-ok");
  return 0;
}
