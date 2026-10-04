/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_for_success(pid_t child) {
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(void) {
  pid_t child = vfork();
  if (child < 0) {
    perror("vfork refusal case");
    return 2;
  }
  if (child == 0) {
    errno = 0;
    int descriptor = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) {
      close(descriptor);
      _exit(81);
    }
    _exit(errno == EPERM ? 0 : 82);
  }
  if (!wait_for_success(child))
    return 3;

  child = vfork();
  if (child < 0) {
    perror("vfork open/exec case");
    return 4;
  }
  if (child == 0) {
    int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0)
      _exit(errno == EPERM ? 91 : 92);
    close(descriptor);
    execl("/bin/true", "true", NULL);
    _exit(93);
  }

  if (!wait_for_success(child))
    return 5;
  puts("vfork-open-exec-ok");
  return 0;
}
