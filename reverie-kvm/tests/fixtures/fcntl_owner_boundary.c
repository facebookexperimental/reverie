#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                  \
  do {                                                                     \
    if (!(expression)) {                                                   \
      fprintf(stderr, "line=%d check=%s errno=%d\n", __LINE__, #expression, \
              errno);                                                      \
      exit(71);                                                            \
    }                                                                      \
  } while (0)

enum { ALIASES = 6 };

static long raw_fcntl(int fd, int command, uintptr_t argument) {
  return syscall(SYS_fcntl, fd, command, argument);
}

static void exact_configuration(int fd, pid_t owner, int signal) {
  // Raw F_GETOWN is required: libc may implement its wrapper with GETOWN_EX.
  CHECK(raw_fcntl(fd, F_GETOWN, 0) == owner);
  CHECK(raw_fcntl(fd, F_GETSIG, 0) == signal);
  struct f_owner_ex value = {.type = -1, .pid = -1};
  CHECK(raw_fcntl(fd, F_GETOWN_EX, (uintptr_t)&value) == 0);
  CHECK(value.type == F_OWNER_PID && value.pid == owner);
}

static void refused_owner_commands(int fd, pid_t self) {
  struct f_owner_ex input = {.type = F_OWNER_PID, .pid = self};
  struct f_owner_ex output = {.type = -37, .pid = -41};
  const struct f_owner_ex unchanged = output;
  const int commands[] = {
      F_SETOWN, F_GETOWN, F_SETSIG, F_GETSIG, F_SETOWN_EX, F_GETOWN_EX};
  const uintptr_t arguments[] = {
      (uintptr_t)self, 0, SIGUSR2, 0, (uintptr_t)&input, (uintptr_t)&output};
  for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
    errno = 0;
    CHECK(raw_fcntl(fd, commands[i], arguments[i]) == -1 && errno == ENOSYS);
  }
  CHECK(memcmp(&output, &unchanged, sizeof(output)) == 0);
}

static void refused_async_and_export(int fd, const int sockets[2]) {
  int before = (int)raw_fcntl(fd, F_GETFL, 0);
  CHECK(before >= 0 && (before & O_ASYNC) == 0);
  errno = 0;
  CHECK(raw_fcntl(fd, F_SETFL, before | O_ASYNC) == -1 && errno == ENOSYS);
  CHECK(raw_fcntl(fd, F_GETFL, 0) == before);

  char payload = 'R';
  struct iovec iov = {.iov_base = &payload, .iov_len = 1};
  union {
    struct cmsghdr alignment;
    unsigned char bytes[CMSG_SPACE(sizeof(int))];
  } control = {0};
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control.bytes,
      .msg_controllen = sizeof(control.bytes)};
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &fd, sizeof(fd));
  errno = 0;
  CHECK(sendmsg(sockets[0], &message, 0) == -1 && errno == ENOSYS);

  // The refusal precedes both payload and rights delivery. No blocking receive
  // can hide an accidental send, and every untouched receive byte is checked.
  payload = 'X';
  memset(control.bytes, 0xa5, sizeof(control.bytes));
  errno = 0;
  CHECK(recvmsg(sockets[1], &message, MSG_DONTWAIT) == -1 && errno == EAGAIN);
  CHECK(payload == 'X' && message.msg_controllen == sizeof(control.bytes));
  CHECK(message.msg_flags == 0);
  for (unsigned i = 0; i < sizeof(control.bytes); ++i)
    CHECK(control.bytes[i] == 0xa5);
}

int main(void) {
  int pipe_fds[2], sockets[2], aliases[ALIASES];
  CHECK(pipe(pipe_fds) == 0);
  CHECK(pipe_fds[0] > STDERR_FILENO && pipe_fds[1] > STDERR_FILENO);
  CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
  CHECK(sockets[0] > STDERR_FILENO && sockets[1] > STDERR_FILENO);
  // Only guest-created descriptors are mutated; standard host descriptors are
  // never replaced or used as owner/flag-setting targets.
  aliases[0] = pipe_fds[0];
  aliases[1] = dup(pipe_fds[0]);
  aliases[2] = dup2(pipe_fds[0], 70);
  aliases[3] = dup3(pipe_fds[0], 71, O_CLOEXEC);
  aliases[4] = fcntl(pipe_fds[0], F_DUPFD, 72);
  aliases[5] = fcntl(pipe_fds[0], F_DUPFD_CLOEXEC, 73);
  for (int i = 0; i < ALIASES; ++i)
    CHECK(aliases[i] > STDERR_FILENO);

  pid_t parent = getpid();
  CHECK(raw_fcntl(aliases[0], F_SETOWN, parent) == 0);
  CHECK(raw_fcntl(aliases[0], F_SETSIG, SIGUSR1) == 0);
  for (int i = 0; i < ALIASES; ++i)
    exact_configuration(aliases[i], parent, SIGUSR1);

  static const char child_marker[] = "child six=36 async=6 export=6 own_pipe=1\n";
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    pid_t self = getpid();
    CHECK(self != parent);
    for (int i = 0; i < ALIASES; ++i) {
      refused_owner_commands(aliases[i], self);
      refused_async_and_export(aliases[i], sockets);
    }

    // A new pipe belongs to this child and has an independent configuration
    // domain. Configuration alone never enables asynchronous delivery.
    int own[2];
    CHECK(pipe(own) == 0);
    CHECK(own[0] > STDERR_FILENO && own[1] > STDERR_FILENO);
    CHECK(raw_fcntl(own[0], F_SETOWN, self) == 0);
    CHECK(raw_fcntl(own[0], F_SETSIG, SIGUSR2) == 0);
    exact_configuration(own[0], self, SIGUSR2);
    char byte = 0;
    CHECK(write(own[1], "C", 1) == 1);
    CHECK(read(own[0], &byte, 1) == 1 && byte == 'C');
    CHECK(close(own[0]) == 0 && close(own[1]) == 0);

    // The parent requires this marker and the actual child's successful wait
    // status; returning success without executing the child body cannot pass.
    CHECK(write(pipe_fds[1], child_marker, sizeof(child_marker)) ==
          sizeof(child_marker));
    _exit(0);
  }

  int status = -1;
  CHECK(waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  char received[sizeof(child_marker)] = {0};
  CHECK(read(aliases[0], received, sizeof(received)) == sizeof(received));
  CHECK(memcmp(received, child_marker, sizeof(received)) == 0);
  for (int i = 0; i < ALIASES; ++i)
    exact_configuration(aliases[i], parent, SIGUSR1);

  // Closing one binding and clearing all configuration must not reset the
  // permanent shared guards. Re-duplication must retain the same description.
  CHECK(close(aliases[1]) == 0);
  aliases[1] = dup(aliases[0]);
  CHECK(aliases[1] > STDERR_FILENO);
  CHECK(raw_fcntl(aliases[0], F_SETOWN, 0) == 0);
  CHECK(raw_fcntl(aliases[0], F_SETSIG, 0) == 0);
  for (int i = 0; i < ALIASES; ++i) {
    exact_configuration(aliases[i], 0, 0);
    refused_async_and_export(aliases[i], sockets);
  }
  for (int i = 0; i < ALIASES; ++i)
    CHECK(close(aliases[i]) == 0);
  CHECK(close(pipe_fds[1]) == 0);
  CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  puts("fowner boundary child_six=36 child_async=6 child_export=6 "
       "parent_exact=6 cleared_guards=6 pipe_io=1");
  return 0;
}
