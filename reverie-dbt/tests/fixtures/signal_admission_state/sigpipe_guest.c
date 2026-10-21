#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static volatile sig_atomic_t count, bad;
static pid_t expected_pid;
static int expected_code;
static uid_t expected_uid;
static void require(int ok, const char *message) {
  if (!ok) { fprintf(stderr, "SIGPIPE guest failure: %s\n", message); exit(41); }
}
static void handler(int sig, siginfo_t *si, void *context) {
  (void)context;
  if (sig != SIGPIPE || si->si_signo != SIGPIPE || si->si_pid != expected_pid ||
      si->si_code != expected_code || si->si_errno != 0 || si->si_uid != expected_uid)
    bad = 1;
  ++count;
}
static void queue(int code, pid_t physical) {
  siginfo_t info = {0};
  info.si_signo = SIGPIPE;
  info.si_code = code;
  info.si_pid = physical;
  info.si_uid = getuid();
  require(syscall(SYS_rt_tgsigqueueinfo, physical, syscall(SYS_gettid),
                  SIGPIPE, &info) == 0, "queue caller-authored colliding bytes");
}
static void read_info(int fd, int vector, pid_t pid, int code) {
  struct signalfd_siginfo si = {0};
  struct iovec chunks[] = {{&si, 31}, {(char *)&si + 31, sizeof(si) - 31}};
  ssize_t n = vector ? readv(fd, chunks, 2) : read(fd, &si, sizeof(si));
  require(n == sizeof(si), "consume complete existing signalfd record");
  require(si.ssi_signo == SIGPIPE && si.ssi_code == code && si.ssi_errno == 0 &&
              si.ssi_pid == (uint32_t)pid && si.ssi_uid == getuid(),
          "signalfd preserves exact origin-specific sender identity");
  sigset_t pending;
  require(sigpending(&pending) == 0 && !sigismember(&pending, SIGPIPE),
          "signalfd consumption leaves no duplicate signal");
}
int main(int argc, char **argv) {
  require(argc == 2, "one mode");
  int native = !strcmp(argv[1], "native");
  int replace = !strcmp(argv[1], "replace");
  require(native || replace || !strcmp(argv[1], "project"), "known mode");
  pid_t physical = getpid();
  pid_t projected = native ? physical : 7777;
  require(native || physical != projected, "projection differs from real identity");
  expected_uid = getuid();
  struct sigaction sa = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
  sigemptyset(&sa.sa_mask);
  require(sigaction(SIGPIPE, &sa, NULL) == 0, "install actual handler");
  int pipefd[2];
  require(pipe(pipefd) == 0 && close(pipefd[0]) == 0, "closed-reader pipe");
  char byte = 'x';
  struct iovec iov = {&byte, 1};
  expected_pid = replace ? physical : projected;
  expected_code = SI_USER;
  require(write(pipefd[1], &byte, 1) == -1 && errno == EPIPE,
          "actual write EPIPE");
  require(count == 1 && !bad, "caught write uses selected sender projection");
  require(syscall(SYS_pwritev2, pipefd[1], &iov, 1, -1L, -1L, 0) == -1 && errno == EPIPE,
          "actual pwritev2 EPIPE");
  require(count == 2 && !bad, "caught pwritev2 uses selected sender projection");
  expected_pid = physical;
  queue(SI_USER, physical);
  require(count == 3 && !bad, "identical queued SI_USER bytes remain caller-owned");
  expected_code = SI_TKILL;
  queue(SI_TKILL, physical);
  require(count == 4 && !bad, "queued SI_TKILL bytes remain caller-owned");
  sigset_t blocked;
  sigemptyset(&blocked); sigaddset(&blocked, SIGPIPE);
  require(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0, "block application SIGPIPE");
  int fd = signalfd(-1, &blocked, SFD_CLOEXEC);
  require(fd >= 0, "existing signalfd owner");
  require(write(pipefd[1], &byte, 1) == -1 && errno == EPIPE, "blocked EPIPE");
  read_info(fd, 0, projected, SI_USER);
  require(writev(pipefd[1], &iov, 1) == -1 && errno == EPIPE, "blocked vector EPIPE");
  read_info(fd, 1, projected, SI_USER);
  queue(SI_USER, physical); read_info(fd, 0, physical, SI_USER);
  queue(SI_TKILL, physical); read_info(fd, 1, physical, SI_TKILL);
  require(close(fd) == 0 && count == 4 && !bad,
          "all signalfd records consumed without handler delivery");
  /* Without signalfd, the first blocked standard signal owns the pending
   * payload. A later EPIPE must not retag that retained queued record. */
  expected_code = SI_USER;
  expected_pid = physical;
  queue(SI_USER, physical);
  sigset_t pending;
  require(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE),
          "caller-owned record is actually pending before EPIPE");
  require(write(pipefd[1], &byte, 1) == -1 && errno == EPIPE && count == 4,
          "later EPIPE arrives while old record remains blocked");
  require(sigprocmask(SIG_UNBLOCK, &blocked, NULL) == 0 && count == 5 && !bad,
          "coalescing preserves old caller payload and delivers it once");
  require(close(pipefd[1]) == 0, "close writer");
  puts("SIGPIPE guest: EPIPE handler/read/readv and queued collision preserved");
  return 0;
}
