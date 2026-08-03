/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -o %t1
 * RUN: echo "Test contents" >  %t1.expected
 * RUN: %{sbr} %{sbr-id} -- %t1 %t1.expected &> %t1.actual
 * RUN: diff %t1.actual %t1.expected
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void test_send(int socket, int fd) // send fd by socket
{
  struct msghdr msg = {0};
  char buf[CMSG_SPACE(sizeof(fd))];
  memset(buf, '\0', sizeof(buf));
  struct iovec io = {.iov_base = "ABC", .iov_len = 3};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

  *((int *)CMSG_DATA(cmsg)) = fd;

  msg.msg_controllen = cmsg->cmsg_len;

  if (sendmsg(socket, &msg, 0) < 0) {
    printf("Failed to send message\n");
    exit(-1);
  }
}

static int test_receive(int socket) // receive fd from socket
{
  struct msghdr msg = {0};

  char m_buffer[256];
  struct iovec io = {.iov_base = m_buffer, .iov_len = sizeof(m_buffer)};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_flags = INT_MAX;

  union {
    struct cmsghdr cm;
    char space[CMSG_SPACE(sizeof(int))];
  } cmsg;
  msg.msg_control = cmsg.space;
  msg.msg_controllen = sizeof(cmsg);

  if (recvmsg(socket, &msg, 0) < 0) {
    printf("Failed to receive message\n");
    exit(-1);
  }

  if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
    printf("Truncated data");
    exit(-1);
  }

  unsigned char *data = CMSG_DATA((&cmsg.cm));

  int fd = *((int *)data);
  return fd;
}

int main(int argc, char **argv) {
  const char *filename = argv[1];

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
    printf("Failed to create Unix-domain socket pair\n");
    exit(-1);
  }

  int pid = fork();
  if (pid > 0) // in parent
  {
    close(sv[1]);
    int sock = sv[0];

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
      printf("Failed to open file %s for reading\n", filename);
      exit(-1);
    }

    test_send(sock, fd);

    close(fd);
    nanosleep(&(struct timespec){.tv_sec = 1, .tv_nsec = 500000000}, 0);
  } else // in child
  {
    close(sv[0]);
    int sock = sv[1];

    nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 500000000}, 0);

    int fd = test_receive(sock);
    char buffer[256];
    ssize_t nbytes;
    while ((nbytes = read(fd, buffer, sizeof(buffer))) > 0)
      write(1, buffer, nbytes);
    close(fd);
  }
  return 0;
}
