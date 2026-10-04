/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ELF preinit runs before the preload DSO's constructors. This is a real
   second exec while the first image is waiting for its runtime handshake. */
static void replace_before_constructors(int argc, char** argv, char** envp) {
  if (argc != 4 || strcmp(argv[1], "start") != 0) {
    return;
  }
  int ids = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
  char text[32];
  int length = snprintf(text, sizeof(text), "%ld\n", (long)getpid());
  if (ids < 0 || length <= 0 || write(ids, text, length) != length ||
      close(ids) != 0) {
    _exit(10);
  }
  char* next[] = {argv[0], "after", argv[2], argv[3], NULL};
  execve(next[0], next, envp);
  _exit(11);
}

__attribute__((
    section(".preinit_array"),
    used)) static void (*const before_constructors)(int, char**, char**) =
    replace_before_constructors;

int main(int argc, char** argv) {
  if (argc != 4 || strcmp(argv[1], "after") != 0) {
    return 12;
  }
  int marker = open(argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
  return marker < 0 || close(marker) != 0 ? 13 : 0;
}
