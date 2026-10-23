#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t handled;
static unsigned char stack[65536] __attribute__((aligned(16)));
static int child(void* unused) {
  (void)unused;
  return 0;
}
static void handler(int signal, siginfo_t* info, void* context) {
  (void)context;
  unsigned char expected[128] = {0};
  int code = SI_KERNEL;
  memcpy(expected, &signal, sizeof(signal));
  memcpy(expected + 8, &code, sizeof(code));
  if (signal != SIGALRM || memcmp(info, expected, sizeof(expected)))
    _exit(71);
  if (++handled != 1)
    _exit(72);
}
static int pending(void) {
  sigset_t mask;
  if (sigpending(&mask))
    _exit(73);
  return sigismember(&mask, SIGALRM);
}
int main(int argc, char** argv) {
  if (argc != 2)
    return 2;
  int mode = atoi(argv[1]);
  struct sigaction action = {0};
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  if (mode == 2 || mode == 3)
    action.sa_handler = SIG_IGN;
  if (mode == 7)
    action.sa_handler = SIG_DFL;
  if (sigaction(SIGALRM, &action, NULL))
    return 3;
  sigset_t selected;
  sigemptyset(&selected);
  sigaddset(&selected, SIGALRM);
  int blocked = mode == 1 || mode == 3 || mode == 4 || mode == 8;
  if (blocked && sigprocmask(SIG_BLOCK, &selected, NULL))
    return 4;
  int fd = -1;
  if (mode == 8) {
    fd = signalfd(-1, &selected, SFD_NONBLOCK);
    if (fd < 0)
      return 5;
  }
  pid_t expected_pid = getpid();
  // The Tool publishes two alarms, or probes refusal after a returning fork.
  long result = syscall(SYS_getpid, 0x616c726d, mode);
  // A Tool-injected fork child resumes the marked boundary with result zero.
  if (mode == 9 && result == 0)
    _exit(0);
  if (result != expected_pid)
    return 6;
  if (mode == 7)
    return 74; // Default disposition must have terminated us.
  if (mode == 9) {
    if (handled || pending())
      return 17;
  } else if (mode == 2 || mode == 6) {
    if (handled || pending())
      return 7;
  } else if (mode == 8) {
    if (handled || !pending())
      return 8;
    struct signalfd_siginfo actual, expected = {0};
    memset(&actual, 0xa5, sizeof(actual));
    expected.ssi_signo = SIGALRM;
    expected.ssi_code = SI_KERNEL;
    if (read(fd, &actual, sizeof(actual)) != sizeof(actual) ||
        memcmp(&actual, &expected, sizeof(actual)))
      return 9;
    if (handled || pending())
      return 10;
    close(fd);
  } else {
    if (blocked || mode == 5) {
      if (handled || !pending())
        return 11;
      if (mode == 3) {
        action.sa_sigaction = handler;
        if (sigaction(SIGALRM, &action, NULL))
          return 12;
      }
      if (mode == 4) {
        action.sa_handler = SIG_IGN;
        if (sigaction(SIGALRM, &action, NULL) || pending())
          return 13;
      }
      if (mode == 5) {
        // Shared ownership must survive the Tool's reblock. The backend refuses
        // sibling creation while a process-pending signal lacks a recipient.
        errno = 0;
        if (clone(
                child,
                stack + sizeof(stack),
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                    CLONE_THREAD | CLONE_SYSVSEM,
                NULL,
                NULL,
                NULL,
                NULL) != -1 ||
            errno != ENOSYS)
          return 14;
      }
      if (sigprocmask(SIG_UNBLOCK, &selected, NULL))
        return 15;
    }
    if (handled != (mode == 4 ? 0 : 1) || pending())
      return 16;
  }
  puts("process-alarm-boundary-checked");
  return 0;
}
