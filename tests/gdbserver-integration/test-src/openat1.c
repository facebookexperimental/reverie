/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int segv(int sig, siginfo_t* info, void* u) {
  unsigned char* ip = info->si_addr;
  printf("received signal: %d, si_addr: %p\n", sig, ip);

  for (int i = 0; i < 8; i++) {
    printf("%02x ", (int)ip[i] & 0xff);
  }
  printf("\n");

  return 0;
}

int main(int argc, char* argv[]) {
  struct sigaction sa, old_sa;
  const char* file = "/dev/urandom";
  int fd;

  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_RESETHAND | SA_SIGINFO;

  sigaction(SIGSEGV, &sa, &old_sa);

  fd = open(file, 0);
  printf("openat1: %d\n", fd);
  if (fd < 0) {
    fprintf(stderr, "open %s, error: %s\n", file, strerror(errno));
  }

  fd = open(file, 0);
  printf("openat1: %d\n", fd);
  if (fd < 0) {
    fprintf(stderr, "open %s, error: %s\n", file, strerror(errno));
  }

  return 0;
}
