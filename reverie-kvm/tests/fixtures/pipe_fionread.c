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
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                           \
  do {                                                                     \
    if (!(x)) {                                                            \
      fprintf(stderr, "line=%d check=%s errno=%d\n", __LINE__, #x, errno); \
      exit(71);                                                            \
    }                                                                      \
  } while (0)
#define SIZE 16384
static unsigned char* guard;
static unsigned char expected[SIZE];
static unsigned queries;
static const char* program_path;

static void reset(void) {
  CHECK(mprotect(guard, SIZE, PROT_READ | PROT_WRITE) == 0);
  memset(guard, 0xa5, SIZE);
  memset(expected, 0xa5, SIZE);
}

static void
query_at(uint64_t fd, uint64_t cmd, uintptr_t address, int error, int count) {
  errno = 0;
  long result = syscall(SYS_ioctl, fd, cmd, address);
  int saved = errno;
  CHECK(mprotect(guard, SIZE, PROT_READ | PROT_WRITE) == 0);
  if (error == 0) {
    CHECK(
        address >= (uintptr_t)guard && address + 4 <= (uintptr_t)guard + SIZE);
    memcpy(expected + (address - (uintptr_t)guard), &count, 4);
  }
  if (result != (error ? -1 : 0) || saved != error ||
      memcmp(guard, expected, SIZE)) {
    fprintf(
        stderr,
        "query=%u fd=%llu cmd=%llx result=%ld errno=%d expected_errno=%d expected_count=%d full_buffer=%d\n",
        queries,
        (unsigned long long)fd,
        (unsigned long long)cmd,
        result,
        saved,
        error,
        count,
        memcmp(guard, expected, SIZE) == 0);
    exit(72);
  }
  ++queries;
}

static void query(int fd, int count) {
  reset();
  query_at((unsigned)fd, FIONREAD, (uintptr_t)guard + 123, 0, count);
}

static void refused(int fd, int error) {
  reset();
  query_at((unsigned)fd, FIONREAD, (uintptr_t)guard + 123, error, 0);
  reset();
  query_at((unsigned)fd, FIONREAD, UINTPTR_MAX - 1, error, 0);
}

static void send_rights(int socket, int* fds, size_t n) {
  char byte = 'R';
  struct iovec iov = {&byte, 1};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(2 * sizeof(int))];
  } control = {0};
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.bytes,
      .msg_controllen = CMSG_SPACE(n * sizeof(int))};
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(n * sizeof(int));
  memcpy(CMSG_DATA(cmsg), fds, n * sizeof(int));
  CHECK(sendmsg(socket, &message, 0) == 1);
}

static void receive_rights(int socket, int* fds, size_t n) {
  char byte = 0;
  struct iovec iov = {&byte, 1};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(2 * sizeof(int))];
  } control = {0};
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.bytes,
      .msg_controllen = sizeof(control.bytes)};
  CHECK(recvmsg(socket, &message, MSG_CMSG_CLOEXEC) == 1 && byte == 'R');
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message);
  CHECK(
      cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS);
  CHECK(
      cmsg->cmsg_len == CMSG_LEN(n * sizeof(int)) &&
      message.msg_flags == MSG_CMSG_CLOEXEC);
  memcpy(fds, CMSG_DATA(cmsg), n * sizeof(int));
  for (size_t i = 0; i < n; ++i)
    CHECK(fcntl(fds[i], F_GETFD) == FD_CLOEXEC);
}

static void pipe_basics(void) {
  int p[2];
  char data[16] = {0};
  CHECK(pipe(p) == 0);
  query(p[0], 0);
  query(p[1], 0);
  CHECK(write(p[1], "abcdefg", 7) == 7);
  query(p[0], 7);
  query(p[1], 7);
  query(p[0], 7);
  reset();
  query_at(
      (unsigned)p[0] + (1ULL << 32), FIONREAD, (uintptr_t)guard + 123, 0, 7);
  reset();
  query_at(
      (unsigned)p[1], FIONREAD | (1ULL << 32), (uintptr_t)guard + 123, 0, 7);
  reset();
  query_at((unsigned)p[0], 0x12345678, UINTPTR_MAX - 1, ENOTTY, 0);
  for (int mode = 0; mode < 7; ++mode) {
    reset();
    uintptr_t address = (uintptr_t)guard + 123;
    if (mode == 0)
      CHECK(mprotect(guard, SIZE, PROT_READ) == 0);
    if (mode == 1)
      CHECK(mprotect(guard, SIZE, PROT_NONE) == 0);
    if (mode == 2)
      address = 0;
    if (mode == 3)
      address = UINTPTR_MAX - 1;
    if (mode >= 4) {
      CHECK(mprotect(guard + 4096, 4096, PROT_NONE) == 0);
      address = (uintptr_t)guard + 4096 - (mode - 3);
    }
    query_at((unsigned)p[0], FIONREAD, address, EFAULT, 0);
    reset();
    query_at(100000, FIONREAD, address, EBADF, 0);
    query(p[1], 7);
  }
  CHECK(read(p[0], data, 3) == 3 && memcmp(data, "abc", 3) == 0);
  query(p[0], 4);
  query(p[1], 4);
  CHECK(close(p[1]) == 0);
  query(p[0], 4);
  CHECK(read(p[0], data, sizeof(data)) == 4 && memcmp(data, "defg", 4) == 0);
  query(p[0], 0);
  CHECK(read(p[0], data, 1) == 0);
  CHECK(close(p[0]) == 0);
}

struct thread_case {
  int reader;
  int writer;
  int result;
};
static void* thread_alias(void* raw) {
  struct thread_case* c = raw;
  int replacement = dup(c->reader);
  CHECK(replacement >= 0);
  CHECK(close(c->reader) == 0 && dup2(replacement, c->reader) == c->reader);
  CHECK(close(replacement) == 0 && write(c->writer, "T", 1) == 1);
  c->result = 37;
  return (void*)37;
}

static void pipe_aliases(void) {
  int p[2], sockets[2], aliases[4], received[2];
  char data[8] = {0};
  CHECK(pipe(p) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  CHECK(write(p[1], "abc", 3) == 3);
  aliases[0] = dup(p[0]);
  aliases[1] = dup2(p[0], 70);
  aliases[2] = dup3(p[0], 71, O_CLOEXEC);
  aliases[3] = fcntl(p[0], F_DUPFD_CLOEXEC, 72);
  for (int i = 0; i < 4; ++i) {
    CHECK(aliases[i] >= 0);
    query(aliases[i], 3);
    CHECK(close(aliases[i]) == 0);
  }
  send_rights(sockets[0], p, 1);
  receive_rights(sockets[1], received, 1);
  query(received[0], 3);
  CHECK(close(received[0]) == 0);
  // Both pipe endpoints are now queued, then every sending descriptor closes.
  send_rights(sockets[0], p, 2);
  int old_reader = p[0], old_writer = p[1];
  CHECK(close(p[0]) == 0 && close(p[1]) == 0);
  int regular = open("alias-reuse", O_CREAT | O_RDWR | O_TRUNC, 0600);
  CHECK(regular >= 0);
  CHECK(
      dup2(regular, old_reader) == old_reader &&
      dup2(regular, old_writer) == old_writer);
  receive_rights(sockets[1], p, 2);
  query(p[0], 3);
  query(p[1], 3);
  CHECK(read(p[0], data, 3) == 3 && memcmp(data, "abc", 3) == 0);
  query(p[0], 0);
  if (regular != old_reader && regular != old_writer)
    CHECK(close(regular) == 0);
  CHECK(close(old_reader) == 0 && close(old_writer) == 0);
  // CLONE_FILES replacement in an ordinary pthread must remain visible.
  struct thread_case c = {.reader = p[0], .writer = p[1], .result = 0};
  pthread_t thread;
  void* value = 0;
  CHECK(pthread_create(&thread, 0, thread_alias, &c) == 0);
  CHECK(
      pthread_join(thread, &value) == 0 && value == (void*)37 &&
      c.result == 37);
  query(p[0], 1);
  CHECK(read(p[0], data, 1) == 1 && data[0] == 'T');
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    query(p[0], 0);
    CHECK(write(p[1], "F", 1) == 1);
    _exit(0);
  }
  int status = -1;
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  query(p[0], 1);
  CHECK(read(p[0], data, 1) == 1 && data[0] == 'F');
  CHECK(write(p[1], "E", 1) == 1 && fcntl(p[0], F_SETFD, 0) == 0);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char descriptor[32];
    snprintf(descriptor, sizeof(descriptor), "%d", p[0]);
    execl(program_path, program_path, "exec-pipe", descriptor, (char*)0);
    _exit(74);
  }
  CHECK(waitpid(child, &status, 0) == child && status == 0);
  CHECK(read(p[0], data, 1) == 1 && data[0] == 'E');
  // A real guest pipe at a stdio number is not captured output.
  int saved = dup(1);
  CHECK(saved >= 0 && dup2(p[0], 1) == 1);
  query(1, 0);
  CHECK(dup2(saved, 1) == 1 && close(saved) == 0);
  CHECK(
      close(p[0]) == 0 && close(p[1]) == 0 && close(sockets[0]) == 0 &&
      close(sockets[1]) == 0);
}

static void fifo_and_packet(void) {
  char data[16] = {0};
  int p[2];
  CHECK(mkfifo("named-fifo", 0600) == 0);
  int fd = open("named-fifo", O_RDWR | O_NONBLOCK);
  CHECK(fd >= 0);
  query(fd, 0);
  CHECK(write(fd, "fifo", 4) == 4);
  query(fd, 4);
  int pathfd = open("named-fifo", O_PATH);
  CHECK(pathfd >= 0);
  refused(pathfd, EBADF);
  CHECK(read(fd, data, sizeof(data)) == 4 && memcmp(data, "fifo", 4) == 0);
  CHECK(close(pathfd) == 0 && close(fd) == 0 && unlink("named-fifo") == 0);
  CHECK(pipe2(p, O_DIRECT | O_NONBLOCK) == 0);
  CHECK(write(p[1], "abc", 3) == 3 && write(p[1], "defgh", 5) == 5);
  query(p[0], 8);
  query(p[1], 8);
  CHECK(read(p[0], data, 2) == 2 && memcmp(data, "ab", 2) == 0);
  query(p[0], 5);
  CHECK(read(p[0], data, sizeof(data)) == 5 && memcmp(data, "defgh", 5) == 0);
  query(p[0], 0);
  CHECK(close(p[0]) == 0 && close(p[1]) == 0);
}

static void excluded(int native) {
  int sockets[2], received[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  int fd = open("regular", O_CREAT | O_TRUNC | O_RDWR, 0600);
  CHECK(fd >= 0);
  CHECK(write(fd, "abcdefg", 7) == 7 && lseek(fd, 0, SEEK_SET) == 0);
  if (native)
    query(fd, 7);
  else
    refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  fd = memfd_create("plain-memfd", 0);
  CHECK(fd >= 0);
  CHECK(write(fd, "abcdefg", 7) == 7 && lseek(fd, 0, SEEK_SET) == 0);
  if (native)
    query(fd, 7);
  else
    refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  for (int transferred = 0; transferred < 3; ++transferred) {
    fd = open("/proc/self/status", O_RDONLY);
    CHECK(fd >= 0 && lseek(fd, 3, SEEK_SET) == 3);
    int duplicate = dup(fd);
    CHECK(duplicate >= 0);
    if (transferred) {
      send_rights(sockets[0], &fd, 1);
      if (transferred == 2) {
        CHECK(close(fd) == 0 && close(duplicate) == 0);
      }
      receive_rights(sockets[1], received, 1);
      if (transferred == 1)
        CHECK(close(fd) == 0 && close(duplicate) == 0);
      fd = received[0];
    }
    if (native)
      query(fd, -3);
    else
      refused(fd, ENOTTY);
    if (!transferred) {
      if (native)
        query(duplicate, -3);
      else
        refused(duplicate, ENOTTY);
      CHECK(close(duplicate) == 0);
    }
    CHECK(close(fd) == 0);
  }
  CHECK(write(sockets[0], "sock", 4) == 4);
  if (native)
    query(sockets[1], 4);
  else
    refused(sockets[1], ENOTTY);
  char bytes[4];
  CHECK(read(sockets[1], bytes, 4) == 4 && memcmp(bytes, "sock", 4) == 0);
  CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  fd = eventfd(0, 0);
  CHECK(fd >= 0);
  refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  fd = signalfd(-1, &mask, SFD_NONBLOCK);
  CHECK(fd >= 0);
  refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  CHECK(fd >= 0);
  refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  fd = syscall(SYS_pidfd_open, getpid(), 0);
  CHECK(fd >= 0);
  refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  fd = open("/proc", O_RDONLY | O_DIRECTORY);
  CHECK(fd >= 0);
  refused(fd, ENOTTY);
  CHECK(close(fd) == 0);
  puts(
      native ? "excluded-native-behavior-checked"
             : "excluded-kvm-refusals-checked");
}

static void capture(void) {
  int sockets[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  for (int standard = 1; standard <= 2; ++standard) {
    refused(standard, ENOTTY);
    int alias = dup(standard);
    CHECK(alias >= 0);
    refused(alias, ENOTTY);
    send_rights(sockets[0], &alias, 1);
    CHECK(close(alias) == 0 && close(standard) == 0);
    int regular = open("capture-reuse", O_CREAT | O_RDWR, 0600);
    CHECK(regular >= 0);
    int received;
    receive_rights(sockets[1], &received, 1);
    refused(received, ENOTTY);
    CHECK(close(regular) == 0 && close(received) == 0);
  }
  CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
}

int main(int argc, char** argv) {
  alarm(15);
  CHECK((argc == 2 || argc == 3) && sysconf(_SC_PAGESIZE) == 4096);
  program_path = argv[0];
  guard =
      mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(guard != MAP_FAILED);
  if (strcmp(argv[1], "exec-pipe") == 0) {
    CHECK(argc == 3);
    query(atoi(argv[2]), 1);
  } else if (strcmp(argv[1], "supported") == 0) {
    pipe_basics();
    pipe_aliases();
    fifo_and_packet();
    puts("pipe-fionread-supported-checked");
  } else if (strcmp(argv[1], "native-excluded") == 0)
    excluded(1);
  else if (strcmp(argv[1], "kvm-excluded") == 0)
    excluded(0);
  else if (strcmp(argv[1], "capture") == 0)
    capture();
  else
    return 73;
  CHECK(munmap(guard, SIZE) == 0);
  return 0;
}
