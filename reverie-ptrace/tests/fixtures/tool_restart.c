/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Guest for the Tool-manufactured syscall-restart tests
// (reverie-ptrace/tests/tool_restart.rs).
//
// Every syscall under test goes through one asm site, `restart_site`. The
// per-site trap and hook counters are printed when a preloaded runtime
// provides them (`reverie_liteinst_site_trap_count` and
// `reverie_liteinst_site_hook_count`), and as "-" otherwise: under plain
// ptrace nothing is preloaded, so every expected line ends in
// "traps=- hooks=-".
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Must match tool_restart.rs.
#define WARM_FD 0x7e56
#define MAGIC_FD 0x7e57
#define QUERY_FD 0x7e58
#define NESTED_FD 0x7e59
#define STRESS_SIGNALS 300

// long restart_site(long nr, long a0, long a1, long a2, long a3)
__asm__(".text\n"
        ".p2align 4\n"
        ".global restart_site\n"
        ".type restart_site,@function\n"
        "restart_site:\n"
        ".cfi_startproc\n"
        "mov %rdi, %rax\n"
        "mov %rsi, %rdi\n"
        "mov %rdx, %rsi\n"
        "mov %rcx, %rdx\n"
        "mov %r8, %r10\n"
        ".global restart_site_syscall\n"
        "restart_site_syscall:\n"
        "syscall\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "ret\n"
        ".cfi_endproc\n"
        ".size restart_site, .-restart_site\n");

extern long restart_site(long nr, long a0, long a1, long a2, long a3);
extern unsigned char restart_site_syscall;

typedef uint64_t (*count_fn)(uint64_t);

static void print_site_counts(void) {
  count_fn traps = (count_fn)dlsym(RTLD_DEFAULT, "reverie_liteinst_site_trap_count");
  count_fn hooks = (count_fn)dlsym(RTLD_DEFAULT, "reverie_liteinst_site_hook_count");
  uint64_t site = (uint64_t)(uintptr_t)&restart_site_syscall;
  if (traps == NULL || hooks == NULL) {
    printf(" traps=- hooks=-\n");
  } else {
    printf(" traps=%" PRIu64 " hooks=%" PRIu64 "\n", traps(site), hooks(site));
  }
}

// The first call through the site: a subscribed read the Tool answers with 0.
static void warm_up(void) {
  long result = restart_site(SYS_read, WARM_FD, 0, 0, 0);
  if (result != 0) {
    fprintf(stderr, "warm-up read returned %ld\n", result);
    exit(30);
  }
}

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

// A real kernel interruption: a 400 ms nanosleep through the site, with a
// SIGURG (ignored by default, but still reported to a ptracer) at 100 ms.
static int interrupted_sleep(void) {
  timer_t timer;
  struct sigevent event;
  memset(&event, 0, sizeof(event));
  event.sigev_notify = SIGEV_THREAD_ID;
  event.sigev_signo = SIGURG;
  event._sigev_un._tid = (pid_t)syscall(SYS_gettid);
  if (timer_create(CLOCK_MONOTONIC, &event, &timer) != 0) {
    perror("timer_create");
    return 31;
  }
  struct itimerspec when;
  memset(&when, 0, sizeof(when));
  when.it_value.tv_nsec = 100 * 1000 * 1000;
  warm_up();
  if (timer_settime(timer, 0, &when, NULL) != 0) {
    perror("timer_settime");
    return 32;
  }
  struct timespec request = {.tv_sec = 0, .tv_nsec = 400 * 1000 * 1000};
  struct timespec remaining = {0, 0};
  int64_t start = now_ns();
  long result = restart_site(SYS_nanosleep, (long)&request, (long)&remaining, 0, 0);
  int64_t elapsed = now_ns() - start;
  printf("sleep-result=%ld slept-enough=%d", result, elapsed >= 400 * 1000 * 1000);
  print_site_counts();
  return 0;
}

static int pipe_write_fd;

static void *late_writer(void *unused) {
  (void)unused;
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 400 * 1000 * 1000};
  nanosleep(&pause, NULL);
  if (write(pipe_write_fd, "x", 1) != 1) {
    exit(41);
  }
  return NULL;
}

// A real kernel ERESTARTSYS: a blocking pipe readv through the site (the Tool
// subscribes read, not readv), with a SIGURG (ignored by default, but still
// reported to a ptracer) at 100 ms and the data written at 400 ms. The readv
// must restart and return the byte, never -512 or EINTR.
static int interrupted_readv(void) {
  int fds[2];
  if (pipe(fds) != 0) {
    perror("pipe");
    return 40;
  }
  pipe_write_fd = fds[1];
  timer_t timer;
  struct sigevent event;
  memset(&event, 0, sizeof(event));
  event.sigev_notify = SIGEV_THREAD_ID;
  event.sigev_signo = SIGURG;
  event._sigev_un._tid = (pid_t)syscall(SYS_gettid);
  if (timer_create(CLOCK_MONOTONIC, &event, &timer) != 0) {
    perror("timer_create");
    return 31;
  }
  struct itimerspec when;
  memset(&when, 0, sizeof(when));
  when.it_value.tv_nsec = 100 * 1000 * 1000;
  warm_up();
  pthread_t writer;
  if (pthread_create(&writer, NULL, late_writer, NULL) != 0) {
    return 42;
  }
  if (timer_settime(timer, 0, &when, NULL) != 0) {
    perror("timer_settime");
    return 32;
  }
  char byte = 0;
  struct iovec iov = {.iov_base = &byte, .iov_len = 1};
  long result = restart_site(SYS_readv, fds[0], (long)&iov, 1, 0);
  if (pthread_join(writer, NULL) != 0) {
    return 43;
  }
  printf("readv-result=%ld byte=%c", result, byte == 0 ? '0' : byte);
  print_site_counts();
  return 0;
}

// A completed syscall with a signal pending on return: SIGURG (ignored by
// default, but still reported to a ptracer) that the thread sends itself. A
// re-executed tgkill would make the Tool see a second SIGURG.
static int completed_with_pending_signal(void) {
  warm_up();
  long result = restart_site(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGURG, 0);
  printf("tgkill-result=%ld", result);
  print_site_counts();
  return 0;
}

static pid_t stress_target;
static volatile int stress_done;

// The number of SIGURG signal stops the Tool has seen so far.
static long tool_signal_count(void) { return syscall(SYS_read, QUERY_FD, 0, 0); }

static void *stress_sender(void *unused) {
  (void)unused;
  for (long i = 0; i < STRESS_SIGNALS; ++i) {
    if (syscall(SYS_tgkill, getpid(), stress_target, SIGURG) != 0) {
      perror("tgkill");
      exit(34);
    }
    // Standard signals coalesce: wait until the Tool has seen this one before
    // sending the next, so every signal must be reported exactly once.
    int64_t deadline = now_ns() + (int64_t)10 * 1000 * 1000 * 1000;
    while (tool_signal_count() < i + 1) {
      if (now_ns() > deadline) {
        fprintf(stderr, "signal %ld never reached the Tool\n", i);
        exit(35);
      }
      struct timespec pause = {.tv_sec = 0, .tv_nsec = 20 * 1000};
      nanosleep(&pause, NULL);
    }
  }
  __atomic_store_n(&stress_done, 1, __ATOMIC_SEQ_CST);
  return NULL;
}

// SIGURG races the site's unsubscribed syscalls: it can arrive before the
// private-page step (never run), during a sleep (interrupted), or as the
// syscall completes. Every result must be the real one, and every signal must
// reach the Tool exactly once.
static int stress(void) {
  warm_up();
  stress_target = (pid_t)syscall(SYS_gettid);
  long parent = getppid();
  pthread_t sender;
  if (pthread_create(&sender, NULL, stress_sender, NULL) != 0) {
    return 36;
  }
  long iterations = 0;
  long bad = 0;
  while (!__atomic_load_n(&stress_done, __ATOMIC_SEQ_CST)) {
    if (restart_site(SYS_getppid, 0, 0, 0, 0) != parent) {
      ++bad;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 50 * 1000};
    if (restart_site(SYS_nanosleep, (long)&pause, 0, 0, 0) != 0) {
      ++bad;
    }
    ++iterations;
  }
  if (pthread_join(sender, NULL) != 0) {
    return 37;
  }
  printf("stress-bad=%ld ran=%d tool-signals=%ld", bad, iterations > 0,
         tool_signal_count());
  print_site_counts();
  return 0;
}

// The guest's own seccomp filter traps getppid (SECCOMP_RET_TRAP), so the
// kernel queues a synchronous SIGSYS at syscall entry, ahead of the
// single-step report the tracer's private-page step queues at exit.
static int seccomp_trap(void) {
  warm_up();
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
    perror("seccomp");
    return 39;
  }
  long result = restart_site(SYS_getppid, 0, 0, 0, 0);
  printf("getppid-result=%ld", result);
  print_site_counts();
  return 0;
}

static volatile sig_atomic_t sigsys_handled;

static void count_sigsys(int signo) {
  (void)signo;
  sigsys_handled += 1;
}

// A synchronous-class SIGSYS (positive si_code) the thread queues to itself
// while it is blocked, then an rt_sigsuspend through the site whose temporary
// mask unblocks it. The syscall returns at once, and at its exit Linux
// dequeues the SIGSYS ahead of the tracer's single-step report, while the
// temporary mask and its pending restore are in force. The handler must run
// once, the sleep must fail with EINTR, and the restored mask must block
// SIGSYS again.
static int held_sigsuspend(void) {
  warm_up();
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = count_sigsys;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGSYS, &action, NULL) != 0) {
    return 40;
  }
  sigset_t block, old;
  sigemptyset(&block);
  sigaddset(&block, SIGSYS);
  if (sigprocmask(SIG_BLOCK, &block, &old) != 0) {
    return 41;
  }
  siginfo_t info;
  memset(&info, 0, sizeof(info));
  info.si_signo = SIGSYS;
  info.si_code = 1; // SYS_SECCOMP, a positive (synchronous-class) code
  if (syscall(SYS_rt_tgsigqueueinfo, getpid(), syscall(SYS_gettid), SIGSYS, &info) != 0) {
    perror("rt_tgsigqueueinfo");
    return 42;
  }
  sigset_t wait_mask = old;
  sigdelset(&wait_mask, SIGSYS);
  long result = restart_site(SYS_rt_sigsuspend, (long)&wait_mask, 8, 0, 0);
  sigset_t now;
  if (sigprocmask(SIG_SETMASK, NULL, &now) != 0) {
    return 43;
  }
  printf("sigsuspend-result=%ld handled=%d blocked=%d", result, (int)sigsys_handled,
         sigismember(&now, SIGSYS));
  print_site_counts();
  return 0;
}

static volatile sig_atomic_t handled;
static volatile sig_atomic_t nested_ok;
static long expected_parent;

// Counts deliveries. The handler also calls through the site, so a syscall
// nests inside the signal that decides the restart.
static void guest_handler(int signo) {
  (void)signo;
  handled += 1;
  if (restart_site(SYS_getppid, 0, 0, 0, 0) == expected_parent) {
    nested_ok += 1;
  }
}

// The Tool answers the first nested read with -ERESTARTSYS and no signal,
// then with NESTED_RESULT.
#define NESTED_RESULT 4244

// Makes a syscall that itself restarts while the interrupted magic read's
// restart is still undecided (the handler runs before its outcome).
static void nested_restart_handler(int signo) {
  (void)signo;
  handled += 1;
  char byte = 0;
  if (restart_site(SYS_read, NESTED_FD, (long)&byte, 1, 0) == NESTED_RESULT) {
    nested_ok += 1;
  }
}

// The magic read, which the Tool answers after `restarts` restart codes.
// Branch-only work after the magic read returns, so a timer the Tool set at
// the deciding signal expires before the guest makes another syscall.
static int spin_after_read;

static int magic_read(int with_handled) {
  char byte = 0;
  warm_up();
  long result = restart_site(SYS_read, MAGIC_FD, (long)&byte, 1, 0);
  if (spin_after_read) {
    for (volatile long i = 0; i < 1000000; i++) {
    }
  }
  printf("read-result=%ld", result);
  if (with_handled) {
    printf(" handled=%d nested-ok=%d", (int)handled, (int)nested_ok);
  }
  print_site_counts();
  return 0;
}

// SIGUSR1 gets a guest handler, with or without SA_RESTART.
static int handled_read_with(void (*handler)(int), int flags) {
  expected_parent = getppid();
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handler;
  action.sa_flags = flags;
  if (sigaction(SIGUSR1, &action, NULL) != 0) {
    return 38;
  }
  return magic_read(1);
}

static int handled_read(int flags) {
  return handled_read_with(guest_handler, flags);
}

// Counts deliveries without making any syscall, so no stop can come between
// the delivery and the handler's return.
static void quiet_handler(int signo) {
  (void)signo;
  handled += 1;
}

static sigjmp_buf longjmp_env;
static volatile sig_atomic_t after_sleep;

static void longjmp_alarm(int signo) {
  (void)signo;
  siglongjmp(longjmp_env, 1);
}

// Inside the handler that decides the magic read's restart, an unsubscribed
// 400 ms nanosleep through the site is interrupted by SIGALRM at 50 ms, whose
// handler siglongjmps back here. The nanosleep's own restart is abandoned, so
// the handler returns to the magic read with a newer restart abandoned above
// it.
static void longjmp_handler(int signo) {
  (void)signo;
  handled += 1;
  if (sigsetjmp(longjmp_env, 1) == 0) {
    struct itimerval alarm_at;
    memset(&alarm_at, 0, sizeof(alarm_at));
    alarm_at.it_value.tv_usec = 50 * 1000;
    setitimer(ITIMER_REAL, &alarm_at, NULL);
    struct timespec request = {.tv_sec = 0, .tv_nsec = 400 * 1000 * 1000};
    restart_site(SYS_nanosleep, (long)&request, 0, 0, 0);
    after_sleep += 1;
  }
}

static int longjmp_read(int flags) {
  struct sigaction alarm_action;
  memset(&alarm_action, 0, sizeof(alarm_action));
  alarm_action.sa_handler = longjmp_alarm;
  if (sigaction(SIGALRM, &alarm_action, NULL) != 0) {
    return 60;
  }
  int rc = handled_read_with(longjmp_handler, flags);
  printf("after-sleep=%d\n", (int)after_sleep);
  return rc;
}

// Abandons `count` unsubscribed 400 ms nanosleeps through the site, each
// interrupted by SIGALRM at 3 ms, whose handler (`longjmp_alarm`) siglongjmps
// back here. Every iteration calls the site from the same frame.
static void abandon_sleeps(int count) {
  for (int i = 0; i < count; i++) {
    if (sigsetjmp(longjmp_env, 1) == 0) {
      struct itimerval alarm_at;
      memset(&alarm_at, 0, sizeof(alarm_at));
      alarm_at.it_value.tv_usec = 3 * 1000;
      setitimer(ITIMER_REAL, &alarm_at, NULL);
      struct timespec request = {.tv_sec = 0, .tv_nsec = 400 * 1000 * 1000};
      restart_site(SYS_nanosleep, (long)&request, 0, 0, 0);
      after_sleep += 1;
    }
  }
}

// More abandoned restarts than `LITEINST_PENDING_RESTART_LIMIT`.
#define ABANDONED_RESTARTS 70

static void abandoning_handler(int signo) {
  (void)signo;
  handled += 1;
  abandon_sleeps(ABANDONED_RESTARTS);
}

// The handler that decides the magic read's restart abandons many nested
// restarts, then returns to the magic read.
static int abandoning_read(int flags) {
  struct sigaction alarm_action;
  memset(&alarm_action, 0, sizeof(alarm_action));
  alarm_action.sa_handler = longjmp_alarm;
  if (sigaction(SIGALRM, &alarm_action, NULL) != 0) {
    return 60;
  }
  int rc = handled_read_with(abandoning_handler, flags);
  printf("after-sleep=%d\n", (int)after_sleep);
  return rc;
}

// Edits the interrupted read's saved rax as a handler may: an interrupted
// read (-EINTR) returns 777 instead, and a restarted one (rax is the syscall
// number again) restarts as close(MAGIC_FD), which fails with EBADF.
static void edit_rax_handler(int signo, siginfo_t *info, void *context) {
  (void)signo;
  (void)info;
  ucontext_t *uc = context;
  handled += 1;
  if (uc->uc_mcontext.gregs[REG_RAX] == -EINTR) {
    uc->uc_mcontext.gregs[REG_RAX] = 777;
  } else if (uc->uc_mcontext.gregs[REG_RAX] == SYS_read) {
    uc->uc_mcontext.gregs[REG_RAX] = SYS_close;
  }
}

// Edits a register the syscall itself clobbers (r11), which the guest cannot
// observe after the syscall.
static void edit_r11_handler(int signo, siginfo_t *info, void *context) {
  (void)signo;
  (void)info;
  ucontext_t *uc = context;
  handled += 1;
  uc->uc_mcontext.gregs[REG_R11] ^= 0x10000;
}

static int siginfo_read_with(void (*handler)(int, siginfo_t *, void *), int flags) {
  expected_parent = getppid();
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = handler;
  action.sa_flags = SA_SIGINFO | flags;
  if (sigaction(SIGUSR1, &action, NULL) != 0) {
    return 38;
  }
  return magic_read(1);
}

static volatile sig_atomic_t in_fork_child;
static volatile int fork_child_exit = -1;

// Forks inside the handler that decides the magic read's restart. The child
// returns from its copy of the handler to its own copy of the interrupted
// read and reports that read's result as its exit code; the parent waits
// first, so the child's restarted read (if any) reaches the Tool before the
// parent's.
static void fork_handler(int signo) {
  (void)signo;
  handled += 1;
  long child = syscall(SYS_fork);
  if (child == 0) {
    in_fork_child = 1;
    return;
  }
  int status = 0;
  if (child < 0 || waitpid((pid_t)child, &status, 0) != child) {
    fork_child_exit = -2;
  } else {
    fork_child_exit = WIFEXITED(status) ? WEXITSTATUS(status) : 100 + WTERMSIG(status);
  }
}

static int fork_read(int flags) {
  // SIGCHLD stays blocked, so the child's exit reaches neither the parent's
  // Tool nor its handler.
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0) {
    return 61;
  }
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = fork_handler;
  action.sa_flags = flags;
  if (sigaction(SIGUSR1, &action, NULL) != 0) {
    return 38;
  }
  char byte = 0;
  warm_up();
  long result = restart_site(SYS_read, MAGIC_FD, (long)&byte, 1, 0);
  if (in_fork_child) {
    _exit(result == 4243 ? 43 : result == -EINTR ? 4 : 99);
  }
  printf("read-result=%ld handled=%d child-exit=%d", result, (int)handled,
         fork_child_exit);
  print_site_counts();
  return 0;
}

// The guest installs its own SIGTRAP handler after the warm-up, and the Tool
// sends SIGTRAP.
static int sigtrap_read(void) {
  char byte = 0;
  warm_up();
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = quiet_handler;
  if (sigaction(SIGTRAP, &action, NULL) != 0) {
    return 62;
  }
  long result = restart_site(SYS_read, MAGIC_FD, (long)&byte, 1, 0);
  printf("read-result=%ld handled=%d", result, (int)handled);
  print_site_counts();
  return 0;
}

static volatile sig_atomic_t reaped;

static void reap_children(int signo) {
  (void)signo;
  int saved = errno;
  while (waitpid(-1, NULL, WNOHANG) > 0) {
    reaped += 1;
  }
  errno = saved;
}

// The shell pattern: an SA_RESTART SIGCHLD handler that reaps, and a child
// exit that becomes deliverable while a syscall is in progress. SIGCHLD is
// blocked until the child is a zombie; the magic read passes the blocked set
// as its buffer so the Tool can unblock it from inside the syscall (by an
// injected rt_sigprocmask) before returning -ERESTARTSYS. Linux restarts the
// read after the handler because of SA_RESTART. The warm-up runs before the
// fork.
static int sigchld_read(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = reap_children;
  action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if (sigaction(SIGCHLD, &action, NULL) != 0) {
    return 50;
  }
  sigset_t chld;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chld, NULL) != 0) {
    return 51;
  }
  warm_up();
  pid_t child = fork();
  if (child < 0) {
    return 52;
  }
  if (child == 0) {
    _exit(0);
  }
  siginfo_t info;
  memset(&info, 0, sizeof(info));
  if (waitid(P_PID, child, &info, WEXITED | WNOWAIT) != 0) {
    return 53;
  }
  long result = restart_site(SYS_read, MAGIC_FD, (long)&chld, 1, 0);
  printf("read-result=%ld reaped=%d", result, (int)reaped);
  print_site_counts();
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return 2;
  }
  const char *mode = argv[1];
  if (strcmp(mode, "read") == 0) {
    return magic_read(0);
  }
  if (strcmp(mode, "handler") == 0) {
    return handled_read(0);
  }
  if (strcmp(mode, "handler-restart") == 0) {
    return handled_read(SA_RESTART);
  }
  if (strcmp(mode, "handler-nested") == 0) {
    return handled_read_with(nested_restart_handler, 0);
  }
  if (strcmp(mode, "handler-nested-restart") == 0) {
    return handled_read_with(nested_restart_handler, SA_RESTART);
  }
  if (strcmp(mode, "handler-quiet-spin") == 0) {
    spin_after_read = 1;
    return handled_read_with(quiet_handler, 0);
  }
  if (strcmp(mode, "handler-quiet-spin-restart") == 0) {
    spin_after_read = 1;
    return handled_read_with(quiet_handler, SA_RESTART);
  }
  if (strcmp(mode, "handler-longjmp") == 0) {
    return longjmp_read(0);
  }
  if (strcmp(mode, "handler-longjmp-restart") == 0) {
    return longjmp_read(SA_RESTART);
  }
  if (strcmp(mode, "handler-abandon") == 0) {
    return abandoning_read(0);
  }
  if (strcmp(mode, "handler-abandon-restart") == 0) {
    return abandoning_read(SA_RESTART);
  }
  if (strcmp(mode, "handler-edit-rax") == 0) {
    return siginfo_read_with(edit_rax_handler, 0);
  }
  if (strcmp(mode, "handler-edit-rax-restart") == 0) {
    return siginfo_read_with(edit_rax_handler, SA_RESTART);
  }
  if (strcmp(mode, "handler-edit-r11") == 0) {
    return siginfo_read_with(edit_r11_handler, 0);
  }
  if (strcmp(mode, "handler-fork") == 0) {
    return fork_read(0);
  }
  if (strcmp(mode, "handler-fork-restart") == 0) {
    return fork_read(SA_RESTART);
  }
  if (strcmp(mode, "handler-sigtrap") == 0) {
    return sigtrap_read();
  }
  if (strcmp(mode, "sigchld") == 0) {
    return sigchld_read();
  }
  if (strcmp(mode, "sleep") == 0) {
    return interrupted_sleep();
  }
  if (strcmp(mode, "readv") == 0) {
    return interrupted_readv();
  }
  if (strcmp(mode, "tgkill") == 0) {
    return completed_with_pending_signal();
  }
  if (strcmp(mode, "stress") == 0) {
    return stress();
  }
  if (strcmp(mode, "seccomp") == 0) {
    return seccomp_trap();
  }
  if (strcmp(mode, "sigsuspend-held") == 0) {
    return held_sigsuspend();
  }
  return 3;
}
