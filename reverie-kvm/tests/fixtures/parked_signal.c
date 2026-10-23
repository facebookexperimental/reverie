#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
static volatile sig_atomic_t handled, bad;
static char alternate[32768], changed_alternate[32768];
static char* expected_alternate = alternate;
static int expected_blocked;
static int restart_writer = -1;
static void handler(int sig, siginfo_t* info, void* ctx) {
  char here;
  ucontext_t* context = ctx;
  if (sig != SIGALRM || info->si_signo != SIGALRM ||
      info->si_code != SI_KERNEL ||
      (uintptr_t)&here < (uintptr_t)expected_alternate ||
      (uintptr_t)&here >= (uintptr_t)(expected_alternate + sizeof alternate))
    bad = 1;
  sigset_t mask;
  if (sigprocmask(SIG_SETMASK, NULL, &mask) ||
      sigismember(&mask, SIGALRM) != expected_blocked)
    bad = 2;
  if (context->uc_stack.ss_sp != expected_alternate ||
      sigismember(&context->uc_sigmask, SIGALRM) != expected_blocked)
    bad = 3;
  handled++;
  if (restart_writer >= 0 && write(restart_writer, "r", 1) != 1)
    bad = 4;
}
int main(int argc, char** argv) {
  if (argc != 2)
    return 1;
  int mode = atoi(argv[1]);
  if (mode == 16) {
    expected_alternate = changed_alternate;
    expected_blocked = 1;
  }
  stack_t changed = {
      .ss_sp = changed_alternate, .ss_size = sizeof changed_alternate};
  stack_t alt = {.ss_sp = alternate, .ss_size = sizeof alternate};
  if (sigaltstack(&alt, NULL))
    return 2;
  struct sigaction action = {
      .sa_sigaction = handler,
      .sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTART};
  if (mode == 17)
    action.sa_flags &= ~SA_RESTART;
  sigemptyset(&action.sa_mask);
  if (mode == 0)
    action.sa_handler = SIG_IGN;
  if (mode == 4)
    action.sa_handler = SIG_DFL;
  if (sigaction(SIGALRM, &action, NULL))
    return 3;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  int fd = -1;
  if ((mode >= 6 && mode <= 10) || mode == 13) {
    if (sigprocmask(SIG_BLOCK, &set, NULL))
      return 4;
    fd = signalfd(-1, &set, SFD_NONBLOCK);
    if (fd < 0)
      return 5;
  }
  char data[8] = {0};
  if (mode >= 17 && mode <= 19) {
    int pipefd[2];
    if (pipe2(pipefd, O_NONBLOCK))
      return 14;
    fd = pipefd[0];
    if (mode == 18)
      restart_writer = pipefd[1];
    if (mode == 19 && write(pipefd[1], "abc", 3) != 3)
      return 15;
  }
  errno = 0;
  long result = (mode >= 17 && mode <= 19)
      ? syscall(SYS_read, fd, data, sizeof data, 0x7061726b, mode, &handled)
      : syscall(SYS_getpid, 0x7061726b, mode, &set, fd, &changed);
  if (mode >= 17 && mode <= 19) {
    if (handled != 1 || bad)
      return 16;
    if (mode == 17 && (result != -1 || errno != EINTR || data[0]))
      return 17;
    if (mode == 18 && (result != 1 || data[0] != 'r' || data[1]))
      return 18;
    if (mode == 19 && (result != 3 || memcmp(data, "abc", 3) || data[3]))
      return 19;
    char extra;
    errno = 0;
    if (read(fd, &extra, 1) != -1 || errno != EAGAIN)
      return 20;
    sigset_t pending;
    if (sigpending(&pending) || sigismember(&pending, SIGALRM))
      return 21;
    puts("parked-signal-checked");
    return 0;
  }
  if (mode == 8 || mode == 9 || mode == 13) {
    if (result != 123)
      return 6;
    errno = 0;
    result = (mode == 8 || mode == 13)
        ? syscall(SYS_read, fd, (void*)1, 128)
        : syscall(SYS_rt_sigtimedwait, &set, (void*)1, NULL, 8);
    if (result != -1 || errno != EFAULT)
      return 7;
    result = 123;
  }
  if (mode == 2 || mode == 3 || mode == 12 || mode == 16) {
    if (result != -1 || errno != (mode == 12 ? EFAULT : EINTR) ||
        handled != 1 || bad)
      return 8;
    if (syscall(SYS_getpid) != 1)
      return 9;
    sigset_t restored;
    stack_t restored_stack;
    if (sigprocmask(SIG_SETMASK, NULL, &restored) ||
        sigismember(&restored, SIGALRM) != expected_blocked ||
        sigaltstack(NULL, &restored_stack) ||
        restored_stack.ss_sp != expected_alternate ||
        (restored_stack.ss_flags & SS_ONSTACK))
      return 13;
  } else if (mode == 4 || mode == 5 || mode == 10 || mode == 11 || mode == 13)
    return 10;
  else if (result != 123 || handled || bad)
    return 11;
  sigset_t pending;
  if (sigpending(&pending) || sigismember(&pending, SIGALRM))
    return 12;
  puts("parked-signal-checked");
  return 0;
}
