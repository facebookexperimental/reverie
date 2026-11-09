/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Sets up descriptor state that no syscall reads without changing it (an
 * eventfd's count, a Unix socket's queued SCM_RIGHTS descriptors, record
 * locks, a flock lock), and at each numbered point asks the Tool for the
 * descriptor's status with tuxcall, which Linux does not implement. The
 * Tool records what Guest::descriptor_status answered. Standard output
 * names the result of the guest's own flock(2). It also passes descriptors
 * the executor keeps itself, and a memfd of its own, through SCM_RIGHTS,
 * and opens a file the Tool's process holds a POSIX lock on.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ASK 0x6664696e666fL

enum {
  EVENTFD_WRITTEN = 1,
  EVENTFD_READ,
  SOCKET_SENDER,
  SOCKET_RECEIVER,
  SOCKET_RECEIVED,
  RECORD_LOCKS,
  FLOCK_HELD,
  INHERITED,
  SIGNALFD,
  CAPTURED,
  CLOSED,
  NEGATIVE,
  CARRIER,
  CARRIER_RECEIVED,
  CAPTURED_DUPLICATE,
  CAPTURED_RECEIVED,
  MEMFD,
  MEMFD_RECEIVED,
  SUPERVISOR_LOCK,
};

#define CHECK(condition)                                                  \
  do {                                                                    \
    if (!(condition)) {                                                   \
      fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__,       \
              #condition, errno);                                         \
      exit(90);                                                           \
    }                                                                     \
  } while (0)

static void ask(long point, long fd) { syscall(SYS_tuxcall, ASK, fd, point); }

/* Sends one byte with two copies of fd attached, or receives such a message
 * and closes the descriptors it carried. */
static void rights(int socket, int fd, int send) {
  char byte = 0;
  struct iovec iov = {.iov_base = &byte, .iov_len = 1};
  union {
    char buffer[CMSG_SPACE(2 * sizeof(int))];
    struct cmsghdr align;
  } control;
  memset(&control, 0, sizeof(control));
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.buffer,
      .msg_controllen = sizeof(control.buffer),
  };
  int fds[2] = {fd, fd};
  if (send) {
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(header), fds, sizeof(fds));
    CHECK(sendmsg(socket, &message, 0) == 1);
  } else {
    CHECK(recvmsg(socket, &message, MSG_CMSG_CLOEXEC) == 1);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    CHECK(header != NULL && header->cmsg_type == SCM_RIGHTS);
    memcpy(fds, CMSG_DATA(header), sizeof(fds));
    CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);
  }
}

/* Sends fd alone in one SCM_RIGHTS message on a datagram socket. */
static void send_one(int socket, int fd) {
  char byte = 0;
  struct iovec iov = {.iov_base = &byte, .iov_len = 1};
  union {
    char buffer[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } control;
  memset(&control, 0, sizeof(control));
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.buffer,
      .msg_controllen = sizeof(control.buffer),
  };
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(header), &fd, sizeof(fd));
  CHECK(sendmsg(socket, &message, 0) == 1);
}

/* Receives the descriptor send_one sent. */
static int receive_one(int socket) {
  char byte = 0;
  struct iovec iov = {.iov_base = &byte, .iov_len = 1};
  union {
    char buffer[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } control;
  memset(&control, 0, sizeof(control));
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.buffer,
      .msg_controllen = sizeof(control.buffer),
  };
  CHECK(recvmsg(socket, &message, MSG_CMSG_CLOEXEC) == 1);
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  CHECK(header != NULL && header->cmsg_type == SCM_RIGHTS);
  int fd;
  memcpy(&fd, CMSG_DATA(header), sizeof(fd));
  return fd;
}

static void record_lock(int fd, int command, short type, off_t start,
                        off_t length) {
  struct flock lock = {
      .l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = length};
  CHECK(fcntl(fd, command, &lock) == 0);
}

int main(void) {
  int eventfd_fd = eventfd(0, EFD_CLOEXEC);
  CHECK(eventfd_fd >= 0);
  uint64_t value = 3;
  CHECK(write(eventfd_fd, &value, sizeof(value)) == sizeof(value));
  value = 4;
  CHECK(write(eventfd_fd, &value, sizeof(value)) == sizeof(value));
  ask(EVENTFD_WRITTEN, eventfd_fd);
  CHECK(read(eventfd_fd, &value, sizeof(value)) == sizeof(value) && value == 7);
  ask(EVENTFD_READ, eventfd_fd);

  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
  rights(pair[0], eventfd_fd, 1);
  ask(SOCKET_SENDER, pair[0]);
  ask(SOCKET_RECEIVER, pair[1]);
  rights(pair[1], -1, 0);
  ask(SOCKET_RECEIVED, pair[1]);

  int locked = open("locked", O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  CHECK(locked >= 0);
  record_lock(locked, F_SETLK, F_WRLCK, 0, 10);
  record_lock(locked, F_OFD_SETLK, F_RDLCK, 100, 0);
  ask(RECORD_LOCKS, locked);

  int flocked = open("flocked", O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  CHECK(flocked >= 0);
  int locked_result = flock(flocked, LOCK_EX);
  printf("flock %d\n", locked_result == 0 ? 0 : errno);
  ask(FLOCK_HELD, flocked);

  /* Standard input is a description the launcher locked with flock. */
  ask(INHERITED, STDIN_FILENO);

  sigset_t mask;
  CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR1) == 0);
  int signal_fd = signalfd(-1, &mask, SFD_CLOEXEC);
  CHECK(signal_fd >= 0);
  ask(SIGNALFD, signal_fd);

  ask(CAPTURED, STDOUT_FILENO);

  CHECK(close(flocked) == 0);
  ask(CLOSED, flocked);
  ask(NEGATIVE, -1);

  int datagrams[2];
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, datagrams) == 0);
  /* A synthetic /proc file, received after the sender closed its copy. */
  int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  CHECK(maps >= 0);
  ask(CARRIER, maps);
  send_one(datagrams[0], maps);
  CHECK(close(maps) == 0);
  ask(CARRIER_RECEIVED, receive_one(datagrams[1]));
  /* Captured standard output, duplicated and received. */
  int duplicate = dup(STDOUT_FILENO);
  CHECK(duplicate >= 0);
  ask(CAPTURED_DUPLICATE, duplicate);
  send_one(datagrams[0], STDOUT_FILENO);
  ask(CAPTURED_RECEIVED, receive_one(datagrams[1]));
  /* The guest's own memfd, with a lock of its description, received after
   * the sender closed its copy. */
  int memfd = memfd_create("guest-object", MFD_CLOEXEC);
  CHECK(memfd >= 0);
  record_lock(memfd, F_OFD_SETLK, F_RDLCK, 0, 0);
  ask(MEMFD, memfd);
  send_one(datagrams[0], memfd);
  CHECK(close(memfd) == 0);
  ask(MEMFD_RECEIVED, receive_one(datagrams[1]));

  /* A file the Tool's process holds a POSIX lock on. */
  int shared = open("shared", O_RDWR | O_CLOEXEC);
  CHECK(shared >= 0);
  ask(SUPERVISOR_LOCK, shared);
  printf("done\n");
  return 0;
}
