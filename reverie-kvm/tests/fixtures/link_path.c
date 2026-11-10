/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Makes one object or state at a time (a file, an unlinked file, a pipe, a
 * socket, an eventfd, a signalfd, a memfd, /dev/null, standard output and a
 * descriptor made of it, a descriptor received through SCM_RIGHTS, a closed
 * descriptor, the image, the working directory, a subdirectory as the
 * working directory and once it is removed, a /proc file, a pidfd, a
 * timerfd, an epoll, a sibling thread's links, a child process's links, the
 * child as a zombie and reaped, numbers that name no task, and the image
 * again after an exec through a hard link and once that link is unlinked)
 * and at each numbered point asks the Tool for one link of a thread with
 * tuxcall, which Linux does not implement; the Tool records what
 * Guest::link_path answered.
 * Run with the mode "native", it reads the same link with readlink(2)
 * instead: its text, or the errno of the read. Standard output lists every
 * point, in order, with the inode the guest's fstat reports for each object
 * whose name holds one, and the process ID, which a /proc file's name holds.
 *
 * Usage: link_path MODE DIRECTORY [after-exec]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ASK 0x6c696e6b70617468L

/* The link asked about, as the Tool decodes it. */
enum { DESCRIPTOR = 0, EXECUTABLE = 1, WORKING_DIRECTORY = 2 };

enum {
  REGULAR = 1,
  DELETED,
  PIPE,
  SOCKET,
  EVENTFD,
  SIGNALFD,
  MEMFD,
  DEV_NULL,
  STDOUT,
  STDOUT_DUP,
  RECEIVED,
  CLOSED,
  NEGATIVE_FD,
  EXE,
  CWD,
  SUBDIR_CWD,
  REMOVED_CWD,
  PROC_FILE,
  PIDFD,
  TIMERFD,
  EPOLL,
  SIBLING_FD,
  SIBLING_EXE,
  SIBLING_CWD,
  CHILD_FD,
  CHILD_EXE,
  CHILD_CWD,
  ZOMBIE_CHILD,
  REAPED_CHILD,
  HOST_PARENT,
  NO_TASK,
  ZERO,
  NEGATIVE,
  EXEC_EXE,
  EXEC_DELETED_EXE,
  POINTS,
};

#define CHECK(condition)                                                  \
  do {                                                                    \
    if (!(condition)) {                                                   \
      fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__,       \
              #condition, errno);                                         \
      exit(90);                                                           \
    }                                                                     \
  } while (0)

static int native;

/* What one point read: the link's text, or the errno of the read, and the
 * inode fstat reported for the object, if its name holds one. */
struct seen {
  int asked;
  int error;
  ssize_t length;
  char text[PATH_MAX];
  int has_inode;
  unsigned long long inode;
};
static struct seen seen[POINTS];

static pid_t gettid_raw(void) { return (pid_t)syscall(SYS_gettid); }

/* One point: under a Tool, ask it for link `kind` of thread `tid`
 * (descriptor `fd` for DESCRIPTOR); natively, read the link. */
static void point(int point, long tid, int kind, int fd) {
  seen[point].asked = 1;
  if (!native) {
    syscall(SYS_tuxcall, ASK, tid, (long)point, (long)kind, (long)fd);
    return;
  }
  char path[96];
  if (kind == DESCRIPTOR) {
    snprintf(path, sizeof(path), "/proc/%ld/fd/%d", tid, fd);
  } else if (kind == EXECUTABLE) {
    snprintf(path, sizeof(path), "/proc/%ld/exe", tid);
  } else {
    snprintf(path, sizeof(path), "/proc/%ld/cwd", tid);
  }
  ssize_t length = readlink(path, seen[point].text, sizeof(seen[point].text));
  if (length < 0) {
    seen[point].error = errno;
  } else {
    seen[point].length = length;
  }
}

/* Keeps the inode the guest's fstat of `fd` reports, for `point`. */
static void inode(int point, int fd) {
  struct stat status;
  CHECK(fstat(fd, &status) == 0);
  seen[point].has_inode = 1;
  seen[point].inode = (unsigned long long)status.st_ino;
}

/* Lists points `first` to `last`. */
static void report(int first, int last) {
  printf("pid %d\n", getpid());
  for (int i = first; i <= last; i++) {
    if (!seen[i].asked) {
      printf("point %d missed\n", i);
    } else if (!native) {
      printf("point %d asked\n", i);
    } else if (seen[i].error != 0) {
      printf("point %d errno %d\n", i, seen[i].error);
    } else {
      printf("point %d text ", i);
      for (ssize_t j = 0; j < seen[i].length; j++) {
        printf("%02x", (unsigned char)seen[i].text[j]);
      }
      printf("\n");
    }
    if (seen[i].has_inode) {
      printf("inode %d %llu\n", i, seen[i].inode);
    }
  }
  CHECK(fflush(stdout) == 0);
}

static int create(const char *name) {
  int fd = open(name, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  CHECK(fd >= 0);
  return fd;
}

/* Sends descriptor `fd` through socket `socket` in one SCM_RIGHTS message. */
static void send_descriptor(int socket, int fd) {
  char byte = 'x';
  struct iovec vector = {.iov_base = &byte, .iov_len = 1};
  union {
    char buffer[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } control;
  memset(&control, 0, sizeof(control));
  struct msghdr message = {.msg_iov = &vector,
                           .msg_iovlen = 1,
                           .msg_control = control.buffer,
                           .msg_controllen = sizeof(control.buffer)};
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &fd, sizeof(int));
  CHECK(sendmsg(socket, &message, 0) == 1);
}

/* Receives the one descriptor of the next SCM_RIGHTS message on `socket`. */
static int receive_descriptor(int socket) {
  char byte;
  struct iovec vector = {.iov_base = &byte, .iov_len = 1};
  union {
    char buffer[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } control;
  memset(&control, 0, sizeof(control));
  struct msghdr message = {.msg_iov = &vector,
                           .msg_iovlen = 1,
                           .msg_control = control.buffer,
                           .msg_controllen = sizeof(control.buffer)};
  CHECK(recvmsg(socket, &message, MSG_CMSG_CLOEXEC) == 1);
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  CHECK(header != NULL && header->cmsg_level == SOL_SOCKET &&
        header->cmsg_type == SCM_RIGHTS);
  int fd;
  memcpy(&fd, CMSG_DATA(header), sizeof(int));
  return fd;
}

static int sibling_ready[2], sibling_release[2];

/* A sibling thread, which waits while the leader asks about its links. */
static void *sibling(void *argument) {
  (void)argument;
  pid_t tid = gettid_raw();
  CHECK(write(sibling_ready[1], &tid, sizeof(tid)) == sizeof(tid));
  char byte;
  CHECK(read(sibling_release[0], &byte, 1) == 1);
  return NULL;
}

/* After an exec through the hard link `relinked`: the image is the file
 * the exec named, and once that link is unlinked, it is unlinked. */
static int after_exec(const char *relinked) {
  pid_t tid = gettid_raw();
  point(EXEC_EXE, tid, EXECUTABLE, 0);
  CHECK(unlink(relinked) == 0);
  point(EXEC_DELETED_EXE, tid, EXECUTABLE, 0);
  report(EXEC_EXE, EXEC_DELETED_EXE);
  return 0;
}

int main(int argc, char **argv) {
  CHECK(argc >= 3);
  native = strcmp(argv[1], "native") == 0;
  const char *directory = argv[2];
  char relinked[PATH_MAX];
  CHECK(snprintf(relinked, sizeof(relinked), "%s/relinked", directory) <
        (int)sizeof(relinked));
  CHECK(chdir(directory) == 0);
  if (argc > 3 && strcmp(argv[3], "after-exec") == 0) {
    return after_exec(relinked);
  }
  pid_t tid = gettid_raw();

  /* A file, and one unlinked while it is open. */
  int regular = create("regular");
  point(REGULAR, tid, DESCRIPTOR, regular);
  int deleted = create("deleted");
  CHECK(unlink("deleted") == 0);
  point(DELETED, tid, DESCRIPTOR, deleted);
  CHECK(close(deleted) == 0);

  /* Objects without a path, each named by its kind. */
  int pipe_fds[2];
  CHECK(pipe2(pipe_fds, O_CLOEXEC) == 0);
  point(PIPE, tid, DESCRIPTOR, pipe_fds[0]);
  inode(PIPE, pipe_fds[0]);
  CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0);
  int sockets[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
  point(SOCKET, tid, DESCRIPTOR, sockets[0]);
  inode(SOCKET, sockets[0]);
  CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  int event = eventfd(0, EFD_CLOEXEC);
  CHECK(event >= 0);
  point(EVENTFD, tid, DESCRIPTOR, event);
  CHECK(close(event) == 0);
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  int signals = signalfd(-1, &mask, SFD_CLOEXEC);
  CHECK(signals >= 0);
  point(SIGNALFD, tid, DESCRIPTOR, signals);
  /* A backend may refuse a fork while a signalfd is open. */
  CHECK(close(signals) == 0);
  int memory = memfd_create("link-path-memfd", MFD_CLOEXEC);
  CHECK(memory >= 0);
  point(MEMFD, tid, DESCRIPTOR, memory);
  CHECK(close(memory) == 0);
  int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
  CHECK(null >= 0);
  point(DEV_NULL, tid, DESCRIPTOR, null);
  CHECK(close(null) == 0);

  /* Standard output, and a descriptor made of it. */
  point(STDOUT, tid, DESCRIPTOR, 1);
  inode(STDOUT, 1);
  int duplicate = dup(1);
  CHECK(duplicate >= 0);
  point(STDOUT_DUP, tid, DESCRIPTOR, duplicate);
  inode(STDOUT_DUP, duplicate);
  CHECK(close(duplicate) == 0);

  /* A file received through SCM_RIGHTS after the sender closed its own. */
  int channel[2];
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, channel) == 0);
  int sent = create("received");
  send_descriptor(channel[0], sent);
  CHECK(close(sent) == 0);
  int received = receive_descriptor(channel[1]);
  point(RECEIVED, tid, DESCRIPTOR, received);
  CHECK(close(received) == 0 && close(channel[0]) == 0 &&
        close(channel[1]) == 0);

  /* Descriptors the table does not hold. */
  int closed = create("closed");
  CHECK(close(closed) == 0);
  point(CLOSED, tid, DESCRIPTOR, closed);
  point(NEGATIVE_FD, tid, DESCRIPTOR, -1);

  /* The image and the working directory: the test's directory, then a
   * subdirectory, and the subdirectory once it is removed. */
  point(EXE, tid, EXECUTABLE, 0);
  point(CWD, tid, WORKING_DIRECTORY, 0);
  char subdirectory[PATH_MAX];
  CHECK(snprintf(subdirectory, sizeof(subdirectory), "%s/subdir", directory) <
        (int)sizeof(subdirectory));
  CHECK(mkdir(subdirectory, 0700) == 0);
  CHECK(chdir(subdirectory) == 0);
  point(SUBDIR_CWD, tid, WORKING_DIRECTORY, 0);
  CHECK(rmdir(subdirectory) == 0);
  point(REMOVED_CWD, tid, WORKING_DIRECTORY, 0);
  CHECK(chdir(directory) == 0);

  /* A /proc file, a pidfd, a timerfd and an epoll. */
  int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  CHECK(maps >= 0);
  point(PROC_FILE, tid, DESCRIPTOR, maps);
  CHECK(close(maps) == 0);
  int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
  CHECK(pidfd >= 0);
  point(PIDFD, tid, DESCRIPTOR, pidfd);
  CHECK(close(pidfd) == 0);
  int timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  CHECK(timer >= 0);
  point(TIMERFD, tid, DESCRIPTOR, timer);
  CHECK(close(timer) == 0);
  int watcher = epoll_create1(EPOLL_CLOEXEC);
  CHECK(watcher >= 0);
  point(EPOLL, tid, DESCRIPTOR, watcher);
  CHECK(close(watcher) == 0);

  /* A sibling thread's links, asked by this thread while it waits. */
  CHECK(pipe2(sibling_ready, O_CLOEXEC) == 0 &&
        pipe2(sibling_release, O_CLOEXEC) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, sibling, NULL) == 0);
  pid_t sibling_tid;
  CHECK(read(sibling_ready[0], &sibling_tid, sizeof(sibling_tid)) ==
        sizeof(sibling_tid));
  point(SIBLING_FD, sibling_tid, DESCRIPTOR, regular);
  point(SIBLING_EXE, sibling_tid, EXECUTABLE, 0);
  point(SIBLING_CWD, sibling_tid, WORKING_DIRECTORY, 0);
  CHECK(write(sibling_release[1], "r", 1) == 1);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(close(sibling_ready[0]) == 0 && close(sibling_ready[1]) == 0 &&
        close(sibling_release[0]) == 0 && close(sibling_release[1]) == 0);

  /* A child process's links while it waits with a file open in a working
   * directory of its own, then the child as a zombie and reaped. */
  int child_ready[2], child_release[2];
  CHECK(pipe2(child_ready, O_CLOEXEC) == 0 &&
        pipe2(child_release, O_CLOEXEC) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    int held = create("child-file");
    CHECK(mkdir("childdir", 0700) == 0 && chdir("childdir") == 0);
    CHECK(write(child_ready[1], &held, sizeof(held)) == sizeof(held));
    char byte;
    CHECK(read(child_release[0], &byte, 1) == 1);
    _exit(0);
  }
  CHECK(close(child_ready[1]) == 0 && close(child_release[0]) == 0);
  int held;
  CHECK(read(child_ready[0], &held, sizeof(held)) == sizeof(held));
  point(CHILD_FD, child, DESCRIPTOR, held);
  point(CHILD_EXE, child, EXECUTABLE, 0);
  point(CHILD_CWD, child, WORKING_DIRECTORY, 0);
  CHECK(write(child_release[1], "r", 1) == 1);
  siginfo_t info;
  CHECK(waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT) == 0);
  point(ZOMBIE_CHILD, child, EXECUTABLE, 0);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  point(REAPED_CHILD, child, EXECUTABLE, 0);
  CHECK(close(child_ready[0]) == 0 && close(child_release[1]) == 0);

  /* Numbers that name no guest thread: this process's parent, one no task
   * has, zero and a negative one. */
  point(HOST_PARENT, getppid(), EXECUTABLE, 0);
  point(NO_TASK, 0x7fffffff, EXECUTABLE, 0);
  point(ZERO, 0, EXECUTABLE, 0);
  point(NEGATIVE, -1, EXECUTABLE, 0);

  CHECK(close(regular) == 0);
  CHECK(unlink("regular") == 0 && unlink("received") == 0 &&
        unlink("closed") == 0 && unlink("child-file") == 0 &&
        rmdir("childdir") == 0);
  report(REGULAR, NEGATIVE);

  /* The image, again, after an exec through a hard link to it. */
  CHECK(link(argv[0], relinked) == 0);
  char *const arguments[] = {relinked, argv[1], argv[2], "after-exec", NULL};
  execv(relinked, arguments);
  CHECK(!"execv returned");
  return 1;
}
