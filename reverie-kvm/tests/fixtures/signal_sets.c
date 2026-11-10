/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Sets up signal state one case at a time (a pending signal for the thread,
 * one for the process, actions, a real-time signal queued twice, a full
 * mask, a handler's mask, a sibling thread's state, a child process and its
 * second thread, the child as a zombie and reaped, a thread waiting in
 * sigtimedwait) and at each numbered point asks the Tool for a thread's
 * signal sets with tuxcall, which Linux does not implement; the Tool records
 * what Guest::signal_sets answered.
 * Run natively with the argument "native", it reads the same thread's
 * status file at the same point instead: its state letter and the five sets
 * Linux shows, or the errno of the read. Standard output then lists every
 * point, in order, and the results of the calls whose answers differ by
 * backend.
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ASK 0x736967736574L

enum {
  SELF_PENDING = 1,
  SHARED_PENDING,
  ACTIONS,
  REALTIME,
  FULL_MASK,
  IN_HANDLER,
  AFTER_HANDLER,
  SIBLING,
  LEADER_FROM_SIBLING,
  CHILD_READS_PARENT,
  PARENT_READS_CHILD,
  CHILD_SIBLING,
  ZOMBIE_CHILD,
  REAPED_CHILD,
  NO_TASK,
  ZERO,
  NEGATIVE,
  WAITING,
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

/* What a native run read at each point: the state letter and the five sets,
 * or the errno of the read. Written in handlers and by a child process too,
 * so nothing here allocates or prints; the child sends its one point to the
 * parent through a pipe. */
struct seen {
  int asked;
  int error;
  char state;
  unsigned long long sets[5];
};
static struct seen seen[POINTS];

static pid_t gettid_raw(void) { return (pid_t)syscall(SYS_gettid); }

/* The set on one status line, as render_sigset_t prints it. */
static unsigned long long parse_set(const char *text) {
  unsigned long long value = 0;
  for (int i = 0; i < 16; i++) {
    char c = text[i];
    value = value << 4 |
            (unsigned long long)(c >= 'a' ? c - 'a' + 10 : c - '0');
  }
  return value;
}

/* Reads thread `tid`'s status file, whatever its process, and keeps its
 * state letter and five sets for `point`. */
static void read_status(int point, long tid) {
  static const char *labels[5] = {"SigPnd:\t", "ShdPnd:\t", "SigBlk:\t",
                                  "SigIgn:\t", "SigCgt:\t"};
  char path[64];
  char text[8192];
  snprintf(path, sizeof(path), "/proc/%ld/status", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    seen[point].error = errno;
    return;
  }
  ssize_t length = 0;
  for (;;) {
    ssize_t count = read(fd, text + length, sizeof(text) - 1 - length);
    if (count <= 0) {
      break;
    }
    length += count;
  }
  close(fd);
  text[length] = 0;
  const char *state = strstr(text, "\nState:\t");
  if (state == NULL) {
    seen[point].error = -1;
    return;
  }
  seen[point].state = state[strlen("\nState:\t")];
  for (int i = 0; i < 5; i++) {
    const char *line = strstr(text, labels[i]);
    if (line == NULL) {
      seen[point].error = -1;
      return;
    }
    seen[point].sets[i] = parse_set(line + strlen(labels[i]));
  }
}

/* One point: under a Tool, ask it about thread `tid`; natively, read the
 * thread's status file. */
static void point(int point, long tid) {
  seen[point].asked = 1;
  if (native) {
    read_status(point, tid);
  } else {
    syscall(SYS_tuxcall, ASK, tid, (long)point);
  }
}

static void set_mask(int how, const sigset_t *set) {
  /* The raw call: glibc's sigprocmask leaves out its two internal signals,
   * where the kernel leaves out SIGKILL and SIGSTOP. */
  CHECK(syscall(SYS_rt_sigprocmask, how, set, NULL, 8) == 0);
}

static void block_one(int signal) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signal);
  set_mask(SIG_BLOCK, &set);
}

static void unblock_one(int signal) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signal);
  set_mask(SIG_UNBLOCK, &set);
}

/* Takes one pending instance of `signal`, which the caller blocks. */
static int take(int signal) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signal);
  struct timespec zero = {0, 0};
  return sigtimedwait(&set, NULL, &zero);
}

static void on_signal(int signal) {
  (void)signal;
  point(IN_HANDLER, gettid_raw());
}

static void on_other(int signal) { (void)signal; }

/* Starts from no handler, no ignored signal and an empty mask, whatever the
 * launcher left: an exec keeps SIG_IGN actions and the mask. */
static void reset(void) {
  for (int signal = 1; signal <= 64; signal++) {
    if (signal == SIGKILL || signal == SIGSTOP) {
      continue;
    }
    /* The kernel's struct: handler, flags, restorer, mask. */
    unsigned long action[4] = {(unsigned long)SIG_DFL, 0, 0, 0};
    CHECK(syscall(SYS_rt_sigaction, signal, action, NULL, 8) == 0);
  }
  sigset_t empty;
  sigemptyset(&empty);
  set_mask(SIG_SETMASK, &empty);
}

static int ready[2], release[2];
static pid_t leader;

static void *sibling(void *argument) {
  (void)argument;
  /* Its own mask, which no other thread has. */
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGINT);
  set_mask(SIG_SETMASK, &set);
  pid_t tid = gettid_raw();
  CHECK(write(ready[1], &tid, sizeof(tid)) == sizeof(tid));
  char byte;
  CHECK(read(release[0], &byte, 1) == 1);
  /* The leader now waits for this thread; ask about it. */
  point(LEADER_FROM_SIBLING, leader);
  CHECK(take(SIGUSR1) == SIGUSR1);
  CHECK(write(ready[1], &tid, sizeof(tid)) == sizeof(tid));
  return NULL;
}

static int child_ready[2], child_release[2], thread_ready[2],
    thread_release[2];

static int waiter_ready[2];

/* Waits in sigtimedwait for SIGUSR1, with SIGUSR1 and SIGUSR2 blocked. While
 * it sleeps there, Linux's mask for it is its own without the signals it
 * waits for (do_sigtimedwait). A backend that answers the call at once,
 * with EAGAIN, finds it asked again. */
static void *waiter(void *argument) {
  (void)argument;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  set_mask(SIG_SETMASK, &set);
  pid_t tid = gettid_raw();
  CHECK(write(waiter_ready[1], &tid, sizeof(tid)) == sizeof(tid));
  sigset_t wanted;
  sigemptyset(&wanted);
  sigaddset(&wanted, SIGUSR1);
  struct timespec patience = {60, 0};
  int got;
  while ((got = sigtimedwait(&wanted, NULL, &patience)) < 0 &&
         errno == EAGAIN) {
  }
  CHECK(got == SIGUSR1);
  return NULL;
}

/* Waits until thread `tid` sleeps in rt_sigtimedwait: its state S, and the
 * call it is in, the first field of /proc/<tid>/syscall, that one. */
static void await_sigtimedwait(long tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%ld/syscall", tid);
  for (int i = 0; i < 10000; i++) {
    char text[256] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    ssize_t length = read(fd, text, sizeof(text) - 1);
    close(fd);
    struct seen state = {0};
    seen[WAITING] = state;
    read_status(WAITING, tid);
    if (length > 0 && atol(text) == SYS_rt_sigtimedwait &&
        seen[WAITING].state == 'S') {
      return;
    }
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
  }
  CHECK(!"the waiter never slept in rt_sigtimedwait");
}

/* The child process's second thread: it blocks SIGQUIT and queues it to
 * itself. */
static void *child_thread(void *argument) {
  (void)argument;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGQUIT);
  set_mask(SIG_SETMASK, &set);
  pid_t tid = gettid_raw();
  CHECK(syscall(SYS_tgkill, getpid(), tid, SIGQUIT) == 0);
  CHECK(write(thread_ready[1], &tid, sizeof(tid)) == sizeof(tid));
  char byte;
  CHECK(read(thread_release[0], &byte, 1) == 1);
  return NULL;
}

/* The child process, in two phases while the parent asks about it. First,
 * with one thread: its own actions, a signal pending for that thread and
 * one for the process, and a question about its parent, which waits for it
 * meanwhile. Then, with the process's signal taken, a second thread, since
 * a backend may refuse a new thread while a process-directed signal waits
 * for a recipient. It exits holding the first thread's pending signal. */
static void run_child(pid_t parent) {
  /* Only the parent reads child_ready and writes child_release. */
  CHECK(close(child_ready[0]) == 0 && close(child_release[1]) == 0);
  CHECK(signal(SIGINT, SIG_IGN) != SIG_ERR);
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR2);
  sigaddset(&set, SIGTERM);
  set_mask(SIG_SETMASK, &set);
  CHECK(syscall(SYS_tgkill, getpid(), gettid_raw(), SIGUSR2) == 0);
  CHECK(kill(getpid(), SIGTERM) == 0);
  point(CHILD_READS_PARENT, parent);
  /* The parent cannot see the child's copy of `seen`. */
  pid_t self = getpid();
  CHECK(write(child_ready[1], &self, sizeof(self)) == sizeof(self));
  CHECK(write(child_ready[1], &seen[CHILD_READS_PARENT],
              sizeof(seen[CHILD_READS_PARENT])) ==
        sizeof(seen[CHILD_READS_PARENT]));
  char byte;
  CHECK(read(child_release[0], &byte, 1) == 1);

  CHECK(take(SIGTERM) == SIGTERM);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, child_thread, NULL) == 0);
  pid_t second;
  CHECK(read(thread_ready[0], &second, sizeof(second)) == sizeof(second));
  CHECK(write(child_ready[1], &second, sizeof(second)) == sizeof(second));
  CHECK(read(child_release[0], &byte, 1) == 1);
  CHECK(write(thread_release[1], "r", 1) == 1);
  CHECK(pthread_join(thread, NULL) == 0);
  _exit(0);
}

int main(int argc, char **argv) {
  native = argc > 1 && strcmp(argv[1], "native") == 0;
  reset();
  pid_t pid = getpid();
  pid_t tid = gettid_raw();
  leader = tid;

  /* A signal the thread blocks and sends to itself: pending for it alone. */
  block_one(SIGUSR1);
  CHECK(syscall(SYS_tgkill, pid, tid, SIGUSR1) == 0);
  point(SELF_PENDING, tid);
  CHECK(take(SIGUSR1) == SIGUSR1);
  unblock_one(SIGUSR1);

  /* One it sends to its process, which blocks it in every thread: pending
   * for the process. */
  block_one(SIGUSR2);
  CHECK(kill(pid, SIGUSR2) == 0);
  point(SHARED_PENDING, tid);
  CHECK(take(SIGUSR2) == SIGUSR2);
  unblock_one(SIGUSR2);

  /* Ignored, caught, and two kept at the default: SIGCHLD, which is ignored
   * by default, and SIGSTOP, whose action Linux refuses to change. */
  CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = on_signal;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGWINCH);
  CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
  CHECK(signal(SIGCHLD, SIG_DFL) != SIG_ERR);
  errno = 0;
  int stop_result = signal(SIGSTOP, SIG_IGN) == SIG_ERR ? errno : 0;
  point(ACTIONS, tid);

  /* A real-time signal queued twice, blocked. */
  int realtime = SIGRTMIN;
  block_one(realtime);
  union sigval value = {.sival_int = 1};
  int queued[2];
  for (int i = 0; i < 2; i++) {
    queued[i] = sigqueue(pid, realtime, value) == 0 ? 0 : errno;
  }
  point(REALTIME, tid);
  int taken = 0;
  while (take(realtime) == realtime) {
    taken++;
  }
  unblock_one(realtime);

  /* Every signal blocked. */
  sigset_t full, empty;
  sigfillset(&full);
  sigemptyset(&empty);
  set_mask(SIG_SETMASK, &full);
  point(FULL_MASK, tid);
  set_mask(SIG_SETMASK, &empty);

  /* A handler's mask: the mask at delivery, its sa_mask and its signal. */
  block_one(SIGPIPE);
  CHECK(syscall(SYS_tgkill, pid, tid, SIGUSR2) == 0);
  point(AFTER_HANDLER, tid);
  unblock_one(SIGPIPE);

  /* Another thread's sets, asked by this one, and this one's, asked by the
   * other. */
  CHECK(signal(SIGUSR1, on_other) != SIG_ERR);
  CHECK(pipe2(ready, O_CLOEXEC) == 0 && pipe2(release, O_CLOEXEC) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, sibling, NULL) == 0);
  pid_t sibling_tid;
  CHECK(read(ready[0], &sibling_tid, sizeof(sibling_tid)) ==
        sizeof(sibling_tid));
  CHECK(syscall(SYS_tgkill, pid, sibling_tid, SIGUSR1) == 0);
  point(SIBLING, sibling_tid);
  CHECK(write(release[1], "r", 1) == 1);
  CHECK(read(ready[0], &sibling_tid, sizeof(sibling_tid)) ==
        sizeof(sibling_tid));
  CHECK(pthread_join(thread, NULL) == 0);

  /* Another process: a child asks about this process while it waits, and
   * this process asks about the child's two threads while they wait, then
   * about the child as a zombie and once it is reaped. */
  CHECK(pipe2(child_ready, O_CLOEXEC) == 0 &&
        pipe2(child_release, O_CLOEXEC) == 0 &&
        pipe2(thread_ready, O_CLOEXEC) == 0 &&
        pipe2(thread_release, O_CLOEXEC) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    run_child(pid);
  }
  /* So that a child that dies early ends the reads below with end of file. */
  CHECK(close(child_ready[1]) == 0 && close(child_release[0]) == 0 &&
        close(thread_ready[0]) == 0 && close(thread_ready[1]) == 0 &&
        close(thread_release[0]) == 0 && close(thread_release[1]) == 0);
  pid_t announced;
  CHECK(read(child_ready[0], &announced, sizeof(announced)) ==
        sizeof(announced));
  CHECK(read(child_ready[0], &seen[CHILD_READS_PARENT],
             sizeof(seen[CHILD_READS_PARENT])) ==
        sizeof(seen[CHILD_READS_PARENT]));
  CHECK(announced == child);
  point(PARENT_READS_CHILD, child);
  CHECK(write(child_release[1], "r", 1) == 1);
  pid_t second;
  CHECK(read(child_ready[0], &second, sizeof(second)) == sizeof(second));
  point(CHILD_SIBLING, second);
  CHECK(write(child_release[1], "r", 1) == 1);
  siginfo_t info;
  CHECK(waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT) == 0);
  point(ZOMBIE_CHILD, child);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  point(REAPED_CHILD, child);

  /* A thread waiting in sigtimedwait, asked about while it waits. */
  CHECK(pipe2(waiter_ready, O_CLOEXEC) == 0);
  CHECK(pthread_create(&thread, NULL, waiter, NULL) == 0);
  pid_t waiter_tid;
  CHECK(read(waiter_ready[0], &waiter_tid, sizeof(waiter_tid)) ==
        sizeof(waiter_tid));
  if (native) {
    await_sigtimedwait(waiter_tid);
  }
  point(WAITING, waiter_tid);
  CHECK(syscall(SYS_tgkill, pid, waiter_tid, SIGUSR1) == 0);
  CHECK(pthread_join(thread, NULL) == 0);

  /* Numbers that name no thread: one no task has, zero and a negative
   * one. */
  point(NO_TASK, 0x7fffffff);
  point(ZERO, 0);
  point(NEGATIVE, -1);

  printf("sigstop %d\n", stop_result);
  printf("sigqueue %d %d taken %d\n", queued[0], queued[1], taken);
  for (int i = 1; i < POINTS; i++) {
    if (!seen[i].asked) {
      printf("point %d missed\n", i);
    } else if (!native) {
      printf("point %d asked\n", i);
    } else if (seen[i].error != 0) {
      printf("point %d errno %d\n", i, seen[i].error);
    } else {
      printf("point %d %c %016llx %016llx %016llx %016llx %016llx\n", i,
             seen[i].state, seen[i].sets[0], seen[i].sets[1],
             seen[i].sets[2], seen[i].sets[3], seen[i].sets[4]);
    }
  }
  return 0;
}
