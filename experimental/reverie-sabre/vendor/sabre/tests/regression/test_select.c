/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: echo -n "Test contents" >  %t1.expected
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
 * RUN: diff %t1.actual %t1.expected
 */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TO_SEND "Test contents"

struct metadata {
  int fd;
};

#define MAXEVENTS 64

int main(int argc, char **argv) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
    printf("Failed to create Unix-domain socket pair\n");
    exit(-1);
  }

  int pid = fork();
  if (pid > 0) { // in parent
    close(sv[1]);
    int sock = sv[0];

    const char *to_send = TO_SEND;

    fd_set active_fd_set, ready_fd_set;

    FD_ZERO(&active_fd_set);
    FD_SET(sock, &active_fd_set);

    while (1) {
      ready_fd_set = active_fd_set;
      if (select(sock + 1, NULL, &ready_fd_set, NULL, NULL) < 0) {
        printf("Error\n");
        return 1;
      }

      if (FD_ISSET(sock, &ready_fd_set)) {
        write(sock, to_send, strlen(to_send));
        close(sock);

        return 0;
      }
    }
  } else { // in child
    close(sv[0]);
    int sock = sv[1];

    fd_set active_fd_set, ready_fd_set;

    FD_ZERO(&active_fd_set);
    FD_SET(sock, &active_fd_set);

    while (1) {
      char buffer[256];

      ready_fd_set = active_fd_set;
      if (select(sock + 1, &ready_fd_set, NULL, NULL, NULL) < 0) {
        printf("Error\n");
        return 1;
      }

      if (FD_ISSET(sock, &ready_fd_set)) {
        ssize_t nbytes = read(sock, buffer, strlen("Test contents"));
        write(1, buffer, nbytes);
        close(sock);

        return 0;
      }
    }
  }

  // Dead code
  assert(0);
  return 1;
}
