/* The creator forks BEFORE opening its TCP socket. The recipient therefore
 * cannot inherit a backend-reserved stdin or any socket File. A regular-file
 * setup gate pins the creator's ordinary socket entries for read-only host
 * observation before the real exit/close. No production ioctl is emulated. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* The uid a signal from this process carries: its own. KVM leaves getuid to
   the Tool (Detcore) and refuses it in a run without one, and its signals
   then carry uid 0. errno is preserved, as this may run in a signal handler. */
static uid_t sender_uid(void) {
  int saved = errno;
  long uid = syscall(SYS_getuid);
  uid_t result = uid == -1 && errno == ENOSYS ? 0 : (uid_t)uid;
  errno = saved;
  return result;
}

#define PATTERN_LIMIT (8u * 1024u * 1024u)
#define SIOCOUTQ_TEST 0x5411
#define SIOCOUTQNSD_TEST 0x894b
static int record_fd;
static pid_t creator_pid;
static uid_t creator_uid;
static volatile sig_atomic_t calls;
static volatile sig_atomic_t valid_info;

static void store_bytes(off_t offset, const void *value, size_t size) {
  if (pwrite(record_fd, value, size, offset) != (ssize_t)size) _exit(90);
}
static void store(off_t offset, unsigned char byte) { store_bytes(offset, &byte, 1); }
static void fail(int code) { store(4, (unsigned char)code); _exit(code); }
#define REQUIRE(c, code) do { if (!(c)) fail(code); } while (0)
static void await(off_t offset) {
  unsigned char byte = 0;
  do {
    REQUIRE(pread(record_fd, &byte, 1, offset) == 1, 91);
    if (!byte) syscall(SYS_sched_yield);
  } while (!byte);
  REQUIRE(byte == 1, 92);
}
static void caught(int signal, siginfo_t *info, void *context) {
  (void)context;
  ++calls;
  valid_info = signal == SIGUSR1 && info->si_signo == SIGUSR1 &&
      info->si_errno == 0 && info->si_code == SI_USER &&
      info->si_pid == creator_pid && info->si_uid == creator_uid;
}
static void recipient(int native) {
  /* No TCP socket exists at fork: nothing can be inherited or closed here. */
  REQUIRE(getppid() == creator_pid, 22);
  sigset_t one, empty;
  sigemptyset(&one); sigaddset(&one, SIGUSR1); sigemptyset(&empty);
  REQUIRE(sigprocmask(SIG_BLOCK, &one, 0) == 0, 23);
  struct sigaction action = {0};
  action.sa_sigaction = caught; action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  REQUIRE(sigaction(SIGUSR1, &action, 0) == 0, 24);
  int setting = -1;
  REQUIRE(prctl(PR_GET_PDEATHSIG, &setting, 0, 0, 0) == 0 && setting == 0, 25);
  REQUIRE(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0, 26);
  REQUIRE(prctl(PR_GET_PDEATHSIG, &setting, 0, 0, 0) == 0 && setting == SIGUSR1, 27);
  store(0, 1);
  if (native) {
    errno = 0;
    REQUIRE(sigsuspend(&empty) == -1 && errno == EINTR, 28);
    REQUIRE(sigprocmask(SIG_UNBLOCK, &one, 0) == 0, 29);
  } else {
    REQUIRE(sigprocmask(SIG_UNBLOCK, &one, 0) == 0, 30);
    errno = 0;
    REQUIRE(syscall(SYS_pause) == -1 && errno == EINTR, 31);
  }
  REQUIRE(calls == 1 && valid_info == 1, 32);
  sigset_t pending;
  REQUIRE(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 0, 33);
  store(1, 1);
  static const char result[] = "pdeathsig process-linger child-completed=1\n";
  REQUIRE(write(STDOUT_FILENO, result, sizeof(result)-1) == sizeof(result)-1, 34);
  store(2, 1);
  _exit(0);
}
static int create_queued_socket(unsigned long port, int native) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(fd >= 3 && fd != record_fd, 40);
  int32_t recorded_fd = fd;
  store_bytes(12, &recorded_fd, sizeof(recorded_fd));
  int send_buffer = 16384;
  REQUIRE(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0, 41);
  struct linger linger = {1, 600};
  REQUIRE(setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) == 0, 42);
  struct sockaddr_in address = {0};
  address.sin_family = AF_INET;
  address.sin_port = htons((uint16_t)port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0, 43);
  int flags = fcntl(fd, F_GETFL);
  REQUIRE(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, 44);
  uint64_t sent = 0;
  unsigned char bytes[4096];
  for (;;) {
    REQUIRE(sent < PATTERN_LIMIT, 45);
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)((sent+i)*131u+17u);
    size_t length = PATTERN_LIMIT - sent < sizeof(bytes) ? (size_t)(PATTERN_LIMIT - sent) : sizeof(bytes);
    ssize_t result = write(fd, bytes, length);
    if (result < 0) { REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK, 46); break; }
    REQUIRE(result > 0, 47);
    sent += (uint64_t)result;
  }
  REQUIRE(sent > 0 && sent <= PATTERN_LIMIT, 48);
  REQUIRE(fcntl(fd, F_SETFL, flags) == 0, 49);
  store_bytes(16, &sent, sizeof(sent));
  if (native) {
    int32_t outq = 0, unsent = 0;
    REQUIRE(ioctl(fd, SIOCOUTQ_TEST, &outq) == 0 && outq > 0, 50);
    REQUIRE(ioctl(fd, SIOCOUTQNSD_TEST, &unsent) == 0 && unsent > 0, 51);
    struct linger actual = {0}; socklen_t length = sizeof(actual);
    REQUIRE(getsockopt(fd, SOL_SOCKET, SO_LINGER, &actual, &length) == 0 &&
        length == sizeof(actual) && actual.l_onoff == 1 && actual.l_linger == 600, 52);
    uint64_t cookie = 0; length = sizeof(cookie);
    REQUIRE(getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &length) == 0 &&
        length == sizeof(cookie) && cookie != 0, 53);
    store_bytes(24, &outq, sizeof(outq)); store_bytes(28, &unsent, sizeof(unsent));
    int32_t on = actual.l_onoff, seconds = actual.l_linger;
    store_bytes(32, &on, sizeof(on)); store_bytes(36, &seconds, sizeof(seconds));
    store_bytes(40, &cookie, sizeof(cookie));
  }
  /* Controlled mode's guest APIs deliberately do not expose these queries:
   * host reads the actual socket, without duplicating it, while this gate
   * permits only pread/sched_yield and no descriptor mutation. */
  store(6, 1);
  await(7);
  return fd;
}
int main(int argc, char **argv) {
  if (argc != 4) return 10;
  record_fd = open(argv[2], O_RDWR | O_CLOEXEC);
  if (record_fd < 0) return 11;
  char *end = 0; unsigned long port = strtoul(argv[3], &end, 10);
  REQUIRE(end && !*end && port > 0 && port <= 65535, 12);
  int explicit_close = !strcmp(argv[1], "close");
  int native = explicit_close || !strcmp(argv[1], "native");
  REQUIRE(native || !strcmp(argv[1], "controlled"), 13);
  await(5);
  if (!explicit_close) {
    creator_pid = getpid(); creator_uid = sender_uid();
    int setting = -1;
    REQUIRE(prctl(PR_GET_PDEATHSIG, &setting, 0, 0, 0) == 0 && setting == 0, 14);
    pid_t child = fork();
    REQUIRE(child >= 0, 15);
    if (!child) recipient(native);
    int32_t recorded_pid = child;
    store_bytes(8, &recorded_pid, sizeof(recorded_pid));
  }
  /* Critical order: no socket or backend stdin existed when fork ran. */
  int fd = create_queued_socket(port, native);
  if (explicit_close) { REQUIRE(close(fd) == 0, 16); store(3, 1); }
  _exit(0);
}
