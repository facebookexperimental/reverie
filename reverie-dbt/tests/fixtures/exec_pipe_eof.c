/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if (argc == 1) {
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) != 0 ||
        fcntl(pipe_fds[0], F_SETFD, 0) != 0)
      return 1;
    char reader[32];
    snprintf(reader, sizeof(reader), "%d", pipe_fds[0]);
    char* const arguments[] = {argv[0], reader, NULL};
    execv("/proc/self/exe", arguments);
    return 2;
  }
  if (argc != 2)
    return 3;

  struct pollfd reader = {.fd = atoi(argv[1]), .events = POLLIN};
  // The exec closed the only guest writer. A client helper from the old image
  // must also have released its file table before any successor guest runs.
  // A blocking read would hide the race by waiting for that helper to exit.
  if (poll(&reader, 1, 0) != 1 || (reader.revents & POLLHUP) == 0)
    return 4;
  char byte;
  if (read(reader.fd, &byte, 1) != 0)
    return 5;
  puts("exec-pipe-eof-ok");
  return 0;
}
