/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Standalone, bounded by the caller. Compile the actual terminal_read.c with
 * -DRVK_READ_TEST -std=c11 -pthread -fexceptions, matching production, plus
 * test-only -fno-pie -no-pie to select the measured read PLT diagnostic ABI.
 * Gate hooks are C-only and contain no
 * cancellation point, including the public-return/disable interval.
 *
 * Full suite: TMPDIR=/absolute/private/tmp ./terminal_read_protocol
 * The caller owns CPU/memory/pids/wall/output bounds. The default aggregate
 * requires complete, valid, stable provider inventory before and after both
 * live task queries. Equal nonempty exported bytes from one positive read
 * followed by EOF may match with any such inventory; unavailable labels
 * require the exact qualified profile.
 * Malformed, unreadable or changing inventory fails. No provider directory,
 * fixed deployment key or ignore flag is used.
 * --context-mode MODE selects one additive C15 control; it does not qualify
 * the other fourteen controls. Run the full suite as a separate positive. */
#define _GNU_SOURCE
#include "../src/terminal_read.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "test gates must be lock-free");

enum { EVENT_COUNT = RVK_READ_TEST_AFTER_JOIN + 1 };
static _Atomic unsigned reached[EVENT_COUNT];
static _Atomic bool hold[EVENT_COUNT];
static _Atomic bool released[EVENT_COUNT];
static _Atomic int event_tid[EVENT_COUNT];
static _Atomic bool capture_context;
static _Atomic bool context_mask_fault;
static const char* context_mode = "live";
static struct {
  sigset_t mask;
  stack_t altstack;
  int mask_error;
  int altstack_result;
  int altstack_errno;
  int mask_fault_error;
} child_context;

void rvk_read_test_hook(struct rvk_read* op, enum rvk_read_test_event event) {
  (void)op;
  atomic_store_explicit(
      &event_tid[event], (int)syscall(SYS_gettid), memory_order_relaxed);
  if (event == RVK_READ_TEST_BEFORE_ENABLE && atomic_load(&capture_context)) {
    /* This hook runs only with child cancellation disabled. The return hook
     * remains atomics/pause only; no context query runs in that interval. */
    if (atomic_load(&context_mask_fault)) {
      sigset_t discriminator;
      assert(sigemptyset(&discriminator) == 0);
      assert(sigaddset(&discriminator, SIGUSR1) == 0);
      child_context.mask_fault_error =
          pthread_sigmask(SIG_UNBLOCK, &discriminator, NULL);
    }
    child_context.mask_error =
        pthread_sigmask(SIG_SETMASK, NULL, &child_context.mask);
    child_context.altstack_result = sigaltstack(NULL, &child_context.altstack);
    child_context.altstack_errno = errno;
  }
  atomic_fetch_add_explicit(&reached[event], 1, memory_order_release);
  while (atomic_load_explicit(&hold[event], memory_order_relaxed) &&
         !atomic_load_explicit(&released[event], memory_order_acquire)) {
    __asm__ volatile("pause" ::: "memory");
  }
}

static void reset(void) {
  atomic_store(&capture_context, false);
  atomic_store(&context_mask_fault, false);
  memset(&child_context, 0, sizeof(child_context));
  for (unsigned i = 0; i < EVENT_COUNT; ++i) {
    atomic_store(&reached[i], 0);
    atomic_store(&hold[i], false);
    atomic_store(&released[i], false);
    atomic_store(&event_tid[i], 0);
  }
}

static uint64_t monotonic_ns(void) {
  struct timespec now;
  assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static void await_event(enum rvk_read_test_event event) {
  uint64_t deadline = monotonic_ns() + 5000000000;
  while (atomic_load_explicit(&reached[event], memory_order_acquire) == 0) {
    assert(monotonic_ns() < deadline);
    struct timespec pause = {.tv_nsec = 1000000};
    nanosleep(&pause, NULL);
  }
}

static void gate(enum rvk_read_test_event event) {
  atomic_store(&hold[event], true);
}

static void release(enum rvk_read_test_event event) {
  atomic_store_explicit(&released[event], true, memory_order_release);
}

static struct rvk_read_snapshot snapshot(struct rvk_read* op) {
  struct rvk_read_snapshot state = {0};
  assert(rvk_read_snapshot(op, &state) == 0);
  return state;
}

static struct rvk_read_snapshot outcome(struct rvk_read* op) {
  for (;;) {
    uint64_t epoch = rvk_read_epoch(op);
    struct rvk_read_snapshot state = snapshot(op);
    if (state.outcome != RVK_READ_PENDING) {
      return state;
    }
    assert(rvk_read_wait(op, epoch) == 0);
  }
}

static struct rvk_read* prepare(int fd) {
  int error = -1;
  struct rvk_read* op = rvk_read_new(fd, 1, 0, &error);
  assert(op != NULL && error == 0);
  return op;
}

static int null_fd(void) {
  int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  return fd;
}

static int inotify_fd(bool nonblocking) {
  int fd = inotify_init1(IN_CLOEXEC | (nonblocking ? IN_NONBLOCK : 0));
  assert(fd >= 0);
  return fd;
}

static void print_proc_file(const char* path) {
  FILE* file = fopen(path, "re");
  assert(file != NULL);
  char line[4096];
  printf("BEGIN %s\n", path);
  while (fgets(line, sizeof(line), file) != NULL) {
    assert(fputs(line, stdout) >= 0);
  }
  assert(!ferror(file));
  assert(fclose(file) == 0);
  printf("END %s\n", path);
}

struct call {
  struct rvk_read* op;
  int result;
};

static void* start_call(void* opaque) {
  struct call* call = opaque;
  call->result = rvk_read_start(call->op);
  return NULL;
}

static void* cancel_call(void* opaque) {
  struct call* call = opaque;
  call->result = rvk_read_request_cancel(call->op);
  return NULL;
}

static void* finish_call(void* opaque) {
  struct call* call = opaque;
  call->result = rvk_read_finish(call->op);
  return NULL;
}

static pthread_t launch(void* (*entry)(void*), struct call* call) {
  pthread_t thread;
  call->result = -1;
  assert(pthread_create(&thread, NULL, entry, call) == 0);
  return thread;
}

static void joined(pthread_t thread, struct call* call, int expected) {
  assert(pthread_join(thread, NULL) == 0);
  assert(call->result == expected);
}

static void finish_and_destroy(struct rvk_read* op, int fd) {
  assert(rvk_read_finish(op) == 0);
  struct rvk_read_snapshot state = snapshot(op);
  assert(state.senders == 0);
  assert(state.state == RVK_READ_JOINED || state.state == RVK_READ_NO_THREAD);
  assert(rvk_read_finish(op) == 0); /* Does not join a second time. */
  assert(rvk_read_destroy(op) == 0);
  assert(fcntl(fd, F_GETFD) >= 0); /* C never owns/closes the endpoint. */
  assert(close(fd) == 0);
}

static void before_start(void) {
  reset();
  int fd = inotify_fd(false);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_request_cancel(op) == 0);
  assert(rvk_read_start(op) == 0);
  struct rvk_read_snapshot state = outcome(op);
  assert(state.terminal && state.outcome == RVK_READ_NOT_STARTED);
  assert(state.state == RVK_READ_NO_THREAD && !state.handle_published);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CREATE]) == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_READ]) == 0);
  finish_and_destroy(op, fd);
  puts("PASS terminal-before-start: no pthread/read/join");
}

static void before_create(void) {
  reset();
  gate(RVK_READ_TEST_BEFORE_CREATE);
  gate(RVK_READ_TEST_BEFORE_ENABLE);
  int fd = inotify_fd(false);
  struct rvk_read* op = prepare(fd);
  struct call creator = {.op = op};
  pthread_t thread = launch(start_call, &creator);
  await_event(RVK_READ_TEST_BEFORE_CREATE);
  assert(rvk_read_request_cancel(op) == 0);
  assert(!snapshot(op).handle_published);
  release(RVK_READ_TEST_BEFORE_CREATE);
  await_event(RVK_READ_TEST_BEFORE_ENABLE);
  joined(thread, &creator, 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 1);
  release(RVK_READ_TEST_BEFORE_ENABLE);
  assert(outcome(op).outcome == RVK_READ_CANCELED);
  finish_and_destroy(op, fd);
  puts("PASS terminal-during-create: latched through handle publication");
}

static void before_publication(void) {
  reset();
  gate(RVK_READ_TEST_AFTER_CREATE);
  gate(RVK_READ_TEST_BEFORE_ENABLE);
  int fd = inotify_fd(false);
  struct rvk_read* op = prepare(fd);
  struct call creator = {.op = op};
  pthread_t thread = launch(start_call, &creator);
  await_event(RVK_READ_TEST_AFTER_CREATE);
  await_event(RVK_READ_TEST_BEFORE_ENABLE);
  assert(rvk_read_request_cancel(op) == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 0);
  release(RVK_READ_TEST_AFTER_CREATE);
  joined(thread, &creator, 0);
  assert(snapshot(op).handle_published);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 1);
  release(RVK_READ_TEST_BEFORE_ENABLE);
  assert(outcome(op).outcome == RVK_READ_CANCELED);
  finish_and_destroy(op, fd);
  puts("PASS terminal-before-handle-publication: queued public cancellation");
}

static void early_completion(void) {
  reset();
  gate(RVK_READ_TEST_AFTER_CREATE);
  int fd = null_fd();
  struct rvk_read* op = prepare(fd);
  struct call creator = {.op = op};
  pthread_t thread = launch(start_call, &creator);
  await_event(RVK_READ_TEST_AFTER_CREATE);
  struct rvk_read_snapshot state = outcome(op);
  assert(state.outcome == RVK_READ_RETURNED && state.result == 0);
  assert(!state.handle_published);
  assert(rvk_read_request_cancel(op) == 0);
  release(RVK_READ_TEST_AFTER_CREATE);
  joined(thread, &creator, 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 0);
  assert(snapshot(op).outcome == RVK_READ_RETURNED);
  finish_and_destroy(op, fd);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 1);
  puts("PASS early-completion: no send window; one physical join");
}

static void normal_completion(void) {
  reset();
  gate(RVK_READ_TEST_AFTER_OUTCOME);
  int fd = null_fd();
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_AFTER_OUTCOME);
  struct rvk_read_snapshot state = outcome(op);
  assert(state.outcome == RVK_READ_RETURNED && state.result == 0);
  assert(!state.terminal && state.error_number == 0);
  assert(rvk_read_destroy(op) == EBUSY);
  struct call finisher = {.op = op};
  pthread_t thread = launch(finish_call, &finisher);
  await_event(RVK_READ_TEST_BEFORE_JOIN);
  assert(snapshot(op).state == RVK_READ_JOINING);
  assert(atomic_load(&reached[RVK_READ_TEST_AFTER_JOIN]) == 0);
  assert(rvk_read_destroy(op) == EBUSY);
  assert(fcntl(fd, F_GETFD) >= 0);
  release(RVK_READ_TEST_AFTER_OUTCOME);
  joined(thread, &finisher, 0);
  assert(!snapshot(op).terminal);
  finish_and_destroy(op, fd);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 0);
  puts("PASS normal-zero: outcome is not retirement; one join before release");
}

static void before_read(void) {
  reset();
  gate(RVK_READ_TEST_BEFORE_READ);
  int fd = inotify_fd(false);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_BEFORE_READ);
  assert(rvk_read_finish(op) == EBUSY);
  assert(rvk_read_destroy(op) == EBUSY);
  assert(rvk_read_request_cancel(op) == 0);
  release(RVK_READ_TEST_BEFORE_READ);
  assert(outcome(op).outcome == RVK_READ_CANCELED);
  assert(atomic_load(&reached[RVK_READ_TEST_AFTER_READ]) == 0);
  finish_and_destroy(op, fd);
  puts("PASS pre-public-read: sticky cancellation; no fabricated result");
}

/* This samples the actual target thread's kernel syscall state. The hook alone
 * is deliberately insufficient: require SYS_read with exact fd/address/count.
 * A five-second deadline is failure, never a synthesized successful wake. */
static void await_kernel_read(int tid, int fd) {
  char path[128];
  assert(snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid) > 0);
  uint64_t deadline = monotonic_ns() + 5000000000;
  for (;;) {
    FILE* file = fopen(path, "re");
    assert(file != NULL);
    char line[512];
    assert(fgets(line, sizeof(line), file) != NULL);
    assert(fclose(file) == 0);
    long number;
    unsigned long arg0, arg1, arg2;
    if (sscanf(line, "%ld %lx %lx %lx", &number, &arg0, &arg1, &arg2) == 4 &&
        number == SYS_read && arg0 == (unsigned long)fd && arg1 == 1 &&
        arg2 == 0) {
      char stat_path[128];
      assert(
          snprintf(
              stat_path, sizeof(stat_path), "/proc/self/task/%d/stat", tid) >
          0);
      FILE* stat_file = fopen(stat_path, "re");
      assert(stat_file != NULL);
      char stat_line[4096];
      assert(fgets(stat_line, sizeof(stat_line), stat_file) != NULL);
      assert(fclose(stat_file) == 0);
      char* comm_end = strrchr(stat_line, ')');
      assert(comm_end != NULL);
      if (comm_end[1] == ' ' && comm_end[2] == 'S') {
        printf("KERNEL_READ tid=%d fd=%d syscall=%s", tid, fd, line);
        printf("KERNEL_THREAD_STAT %s", stat_line);
        assert(
            snprintf(
                stat_path, sizeof(stat_path), "/proc/self/task/%d/wchan", tid) >
            0);
        print_proc_file(stat_path);
        return;
      }
    }
    assert(monotonic_ns() < deadline);
    struct timespec pause = {.tv_nsec = 1000000};
    nanosleep(&pause, NULL);
  }
}

static void inside_kernel(void) {
  reset();
  int fd = inotify_fd(false);
  int flags = fcntl(fd, F_GETFL);
  int guest_alias = dup(fd);
  assert(guest_alias >= 0);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_BEFORE_READ);
  await_kernel_read(atomic_load(&event_tid[RVK_READ_TEST_BEFORE_READ]), fd);
  assert(snapshot(op).outcome == RVK_READ_PENDING);
  assert(rvk_read_finish(op) == EBUSY);

  /* Retain the actual operation fd while a different guest-facing alias is
   * closed/reused. A reused alias must not redirect this prepared invocation.
   */
  assert(close(guest_alias) == 0);
  int replacement = null_fd();
  if (replacement != guest_alias) {
    assert(dup2(replacement, guest_alias) == guest_alias);
    assert(close(replacement) == 0);
  }
  assert(fcntl(fd, F_GETFL) == flags);
  assert(rvk_read_request_cancel(op) == 0);
  assert(outcome(op).outcome == RVK_READ_CANCELED);
  assert(fcntl(fd, F_GETFL) == flags);
  finish_and_destroy(op, fd);
  char byte;
  assert(read(guest_alias, &byte, 1) == 0);
  assert(close(guest_alias) == 0);
  puts("PASS inside-kernel: exact staging args, unchanged flags, alias reuse");
}

static void returned_before_disable(void) {
  reset();
  gate(RVK_READ_TEST_AFTER_READ);
  int fd = inotify_fd(true);
  int flags = fcntl(fd, F_GETFL);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_AFTER_READ);
  assert(snapshot(op).outcome == RVK_READ_PENDING);
  assert(rvk_read_request_cancel(op) == 0);
  release(RVK_READ_TEST_AFTER_READ);
  struct rvk_read_snapshot state = outcome(op);
  assert(state.outcome == RVK_READ_RETURNED);
  assert(state.result == -1 && state.read_errno == EAGAIN && state.terminal);
  assert(fcntl(fd, F_GETFL) == flags);
  finish_and_destroy(op, fd);
  puts(
      "PASS public-return-before-disable: real EAGAIN retained on late cancel");
}

static void delayed_sender(void) {
  reset();
  gate(RVK_READ_TEST_BEFORE_READ);
  gate(RVK_READ_TEST_BEFORE_CANCEL);
  gate(RVK_READ_TEST_AFTER_CANCEL);
  gate(RVK_READ_TEST_AFTER_JOIN);
  int fd = null_fd();
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_BEFORE_READ);
  struct call sender = {.op = op};
  pthread_t sender_thread = launch(cancel_call, &sender);
  await_event(RVK_READ_TEST_BEFORE_CANCEL);
  assert(snapshot(op).senders == 1);
  release(RVK_READ_TEST_BEFORE_READ);
  assert(outcome(op).outcome == RVK_READ_RETURNED);
  struct call finisher = {.op = op};
  pthread_t finish_thread = launch(finish_call, &finisher);
  await_event(RVK_READ_TEST_DISARMED);
  struct rvk_read_snapshot state = snapshot(op);
  assert(state.state == RVK_READ_DISARMED && state.senders == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 0);
  assert(rvk_read_request_cancel(op) == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 1);

  release(RVK_READ_TEST_BEFORE_CANCEL);
  await_event(RVK_READ_TEST_AFTER_CANCEL);
  state = snapshot(op);
  assert(state.state == RVK_READ_DISARMED && state.senders == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 0);
  release(RVK_READ_TEST_AFTER_CANCEL);
  joined(sender_thread, &sender, 0);
  await_event(RVK_READ_TEST_AFTER_JOIN);
  assert(snapshot(op).state == RVK_READ_JOINING);
  assert(rvk_read_request_cancel(op) == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 1);
  release(RVK_READ_TEST_AFTER_JOIN);
  joined(finish_thread, &finisher, 0);
  assert(rvk_read_request_cancel(op) == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 1);
  assert(snapshot(op).outcome == RVK_READ_RETURNED);
  finish_and_destroy(op, fd);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 1);
  puts(
      "PASS delayed-sender: drain before join; fresh sends refused through retirement");
}

struct watched_directory {
  char path[4096];
  int dir;
};

static struct watched_directory watch_directory(int fd) {
  struct watched_directory watch;
  const char* tmp = getenv("TMPDIR");
  assert(tmp != NULL && tmp[0] == '/');
  int length =
      snprintf(watch.path, sizeof(watch.path), "%s/terminal-read-XXXXXX", tmp);
  assert(length > 0 && (size_t)length < sizeof(watch.path));
  assert(mkdtemp(watch.path) == watch.path);
  watch.dir = open(watch.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(watch.dir >= 0);
  assert(inotify_add_watch(fd, watch.path, IN_CREATE) >= 0);
  return watch;
}

static void queue_event(struct watched_directory* watch) {
  int created = openat(
      watch->dir, "event", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  assert(created >= 0);
  assert(close(created) == 0);
}

static void remove_watch(struct watched_directory* watch) {
  assert(unlinkat(watch->dir, "event", 0) == 0);
  assert(close(watch->dir) == 0);
  assert(rmdir(watch->path) == 0);
}

static void queued_event(void) {
  reset();
  int fd = inotify_fd(false);
  struct watched_directory watch = watch_directory(fd);
  queue_event(&watch);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  struct rvk_read_snapshot state = outcome(op);
  assert(state.outcome == RVK_READ_RETURNED);
  assert(state.result == -1 && state.read_errno == EINVAL);
  assert(!state.terminal && state.error_number == 0);
  assert(rvk_read_finish(op) == 0);
  _Alignas(struct inotify_event) char events[4096];
  ssize_t count = read(fd, events, sizeof(events));
  assert(count >= (ssize_t)sizeof(struct inotify_event));
  struct inotify_event* event = (void*)events;
  assert((event->mask & IN_CREATE) != 0);
  assert((size_t)count >= sizeof(*event) + event->len);
  assert(event->len > 0 && strcmp(event->name, "event") == 0);
  finish_and_destroy(op, fd);
  remove_watch(&watch);
  puts("PASS queued-inotify: actual EINVAL and retained event");
}

static void creation_error(void) {
  reset();
  int fd = null_fd();
  struct rvk_read* op = prepare(fd);
  rvk_read_test_fail(op, RVK_READ_ERROR_CREATE, EAGAIN);
  assert(rvk_read_start(op) == EAGAIN);
  struct rvk_read_snapshot state = snapshot(op);
  assert(
      state.error_phase == RVK_READ_ERROR_CREATE &&
      state.error_number == EAGAIN);
  assert(state.outcome == RVK_READ_NOT_STARTED && !state.handle_published);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_READ]) == 0);
  finish_and_destroy(op, fd);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 0);
  puts("PASS create-error: typed no-thread failure, no fallback read");
}

static void cancellation_error(bool fail_join) {
  reset();
  int fd = inotify_fd(false);
  struct watched_directory watch = watch_directory(fd);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_BEFORE_READ);
  await_kernel_read(atomic_load(&event_tid[RVK_READ_TEST_BEFORE_READ]), fd);
  rvk_read_test_fail(op, RVK_READ_ERROR_CANCEL, ESRCH);
  assert(rvk_read_request_cancel(op) == ESRCH);
  struct rvk_read_snapshot state = snapshot(op);
  assert(state.outcome == RVK_READ_PENDING && state.senders == 0);
  assert(
      state.error_phase == RVK_READ_ERROR_CANCEL &&
      state.error_number == ESRCH);
  assert(rvk_read_finish(op) == EBUSY);
  assert(rvk_read_destroy(op) == EBUSY);
  queue_event(
      &watch); /* Real endpoint completion, never fabricated progress. */
  state = outcome(op);
  assert(state.outcome == RVK_READ_RETURNED);
  assert(state.result == -1 && state.read_errno == EINVAL);
  assert(
      state.error_phase == RVK_READ_ERROR_CANCEL &&
      state.error_number == ESRCH);
  if (fail_join) {
    rvk_read_test_fail(op, RVK_READ_ERROR_JOIN, EDEADLK);
    assert(rvk_read_finish(op) == EDEADLK);
    state = snapshot(op);
    assert(state.state == RVK_READ_JOIN_FAILED && state.handle_published);
    assert(
        state.error_phase == RVK_READ_ERROR_CANCEL &&
        state.error_number == ESRCH);
    assert(rvk_read_finish(op) == EDEADLK);
    assert(rvk_read_destroy(op) == EBUSY);
    assert(rvk_read_request_cancel(op) == 0);
    assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 1);
    assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 1);
    assert(fcntl(fd, F_GETFD) >= 0);
    remove_watch(&watch);
    /* Intentionally retain op, fd, and unjoined thread until process exit.
     * This is a failed retirement, not a synthetic join or safe destroy. */
    puts(
        "PASS injected-join-error: first failure and ownership retained until process exit");
  } else {
    assert(rvk_read_finish(op) == 0);
    state = snapshot(op);
    assert(state.state == RVK_READ_JOINED);
    assert(
        state.error_phase == RVK_READ_ERROR_CANCEL &&
        state.error_number == ESRCH);
    finish_and_destroy(op, fd);
    remove_watch(&watch);
    puts(
        "PASS injected-cancel-error: real event completion; first error retained");
  }
}

static void wake_epoch(void) {
  reset();
  int fd = null_fd();
  struct rvk_read* op = prepare(fd);
  uint64_t epoch = rvk_read_epoch(op);
  assert(rvk_read_wake(op) == 0);
  assert(rvk_read_wait(op, epoch) == 0); /* Wake before wait cannot be lost. */
  assert(snapshot(op).outcome == RVK_READ_PENDING);
  assert(!snapshot(op).terminal);
  assert(rvk_read_finish(op) == 0);
  finish_and_destroy(op, fd);
  puts("PASS wake-before-wait: no lost wake or invented terminal outcome");
}

static void context_error(const char* operation, const char* path, int error) {
  fflush(stdout);
  fprintf(
      stderr,
      "CONTEXT_ERROR operation=%s path=%s errno=%d (%s)\n",
      operation,
      path,
      error,
      strerror(error));
  fflush(stderr);
  abort();
}

static void context_file(const char* path, char* buffer, size_t capacity) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    context_error("open", path, errno);
  }
  size_t used = 0;
  for (;;) {
    if (used == capacity - 1) {
      context_error("read-buffer-limit", path, EOVERFLOW);
    }
    ssize_t count = read(fd, buffer + used, capacity - 1 - used);
    if (count < 0) {
      context_error("read", path, errno);
    }
    if (count == 0) {
      break;
    }
    used += (size_t)count;
  }
  buffer[used] = '\0';
  if (close(fd) != 0) {
    context_error("close", path, errno);
  }
}

static void status_field(
    const char* status,
    const char* field,
    char* value,
    size_t capacity) {
  size_t length = strlen(field);
  for (const char* line = status; *line != '\0';) {
    const char* end = strchr(line, '\n');
    if (end == NULL) {
      end = line + strlen(line);
    }
    if ((size_t)(end - line) > length && strncmp(line, field, length) == 0 &&
        line[length] == ':') {
      size_t size = (size_t)(end - line) - length - 1;
      if (size >= capacity) {
        context_error("status-field-limit", field, EOVERFLOW);
      }
      memcpy(value, line + length + 1, size);
      value[size] = '\0';
      return;
    }
    line = *end == '\0' ? end : end + 1;
  }
  context_error("missing-status-field", field, ENODATA);
}

static uint64_t thread_start(int tid, const char* role) {
  char path[128], data[4096];
  assert(snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid) > 0);
  context_file(path, data, sizeof(data));
  printf("CONTEXT_STAT role=%s %s", role, data);
  char* comm_end = strrchr(data, ')');
  assert(comm_end != NULL && comm_end[1] == ' ');
  char* remaining;
  char* token = strtok_r(comm_end + 2, " ", &remaining);
  for (unsigned field = 3; field < 22; ++field) {
    assert(token != NULL);
    token = strtok_r(NULL, " ", &remaining);
  }
  assert(token != NULL);
  errno = 0;
  char* end;
  unsigned long long start = strtoull(token, &end, 10);
  assert(errno == 0 && end != token && *end == '\0');
  return (uint64_t)start;
}

enum attribute_kind {
  ATTRIBUTE_VALUE,
  ATTRIBUTE_OPEN_ERROR,
  ATTRIBUTE_READ_ERROR,
  ATTRIBUTE_CLOSE_ERROR,
  ATTRIBUTE_TRUNCATED,
};

struct attribute_query {
  int tid;
  uint64_t start;
  char path[128];
  enum attribute_kind kind;
  int open_result, open_errno;
  ssize_t last_read;
  int read_errno;
  unsigned reads;
  int close_result, close_errno;
  bool eof;
  size_t length;
  unsigned char bytes[4096];
};

static void print_attribute(
    const struct attribute_query* query,
    const char* origin) {
  printf(
      "CONTEXT_ATTRIBUTE origin=%s tid=%d start=%llu path=%s kind=%u "
      "open=%d open_errno=%d reads=%u last_read=%zd read_errno=%d "
      "close=%d close_errno=%d eof=%d length=%zu bytes_hex=",
      origin,
      query->tid,
      (unsigned long long)query->start,
      query->path,
      (unsigned)query->kind,
      query->open_result,
      query->open_errno,
      query->reads,
      query->last_read,
      query->read_errno,
      query->close_result,
      query->close_errno,
      query->eof,
      query->length);
  for (size_t i = 0; i < query->length; ++i) {
    printf("%02x", query->bytes[i]);
  }
  putchar('\n');
  assert(fflush(stdout) == 0);
}

/* Both tasks are held alive while these independent queries run. An error
 * collecting one attribute must not suppress the other attribute query. No
 * retry, whitespace/NUL normalization, or replacement label is permitted. */
static struct attribute_query query_attribute_path(
    int tid,
    uint64_t start,
    const char* path,
    const char* origin) {
  struct attribute_query query = {
      .tid = tid,
      .start = start,
      .open_result = -1,
      .last_read = -2,
      .close_result = -2,
  };
  int length = snprintf(query.path, sizeof(query.path), "%s", path);
  assert(length > 0 && (size_t)length < sizeof(query.path));
  errno = 0;
  query.open_result = open(query.path, O_RDONLY | O_CLOEXEC);
  query.open_errno = errno;
  if (query.open_result < 0) {
    query.kind = ATTRIBUTE_OPEN_ERROR;
    return query;
  }
  for (;;) {
    /* Preserve the original 4096-byte buffer and its exact refusal bound. */
    if (query.length == sizeof(query.bytes) - 1) {
      query.kind = ATTRIBUTE_TRUNCATED;
      break;
    }
    errno = 0;
    query.last_read = read(
        query.open_result,
        query.bytes + query.length,
        sizeof(query.bytes) - 1 - query.length);
    query.read_errno = errno;
    ++query.reads;
    printf(
        "CONTEXT_ATTRIBUTE_READ origin=%s tid=%d start=%llu path=%s index=%u "
        "return=%zd errno=%d offset=%zu\n",
        origin,
        tid,
        (unsigned long long)start,
        query.path,
        query.reads,
        query.last_read,
        query.read_errno,
        query.length);
    if (query.last_read < 0) {
      query.kind = ATTRIBUTE_READ_ERROR;
      break;
    }
    if (query.last_read == 0) {
      query.eof = true;
      query.kind = ATTRIBUTE_VALUE;
      break;
    }
    query.length += (size_t)query.last_read;
  }
  errno = 0;
  query.close_result = close(query.open_result);
  query.close_errno = errno;
  if (query.close_result != 0 && query.kind == ATTRIBUTE_VALUE) {
    query.kind = ATTRIBUTE_CLOSE_ERROR;
  }
  return query;
}

static struct attribute_query query_attribute(int tid, uint64_t start) {
  char path[128];
  int length =
      snprintf(path, sizeof(path), "/proc/self/task/%d/attr/current", tid);
  assert(length > 0 && (size_t)length < sizeof(path));
  return query_attribute_path(tid, start, path, "actual-task-query");
}

static struct attribute_query
live_attribute(int tid, uint64_t start, const char* role) {
  assert(thread_start(tid, role) == start);
  struct attribute_query result = query_attribute(tid, start);
  print_attribute(&result, "actual-live-query");
  assert(thread_start(tid, role) == start);
  return result;
}

enum provider_profile {
  PROVIDER_UNCLASSIFIED,
  PROVIDER_EXPORTED_BYTES,
  PROVIDER_CURRENT_UNAVAILABLE,
};

enum inventory_problem {
  INVENTORY_RECOGNIZED,
  INVENTORY_QUERY_ERROR,
  INVENTORY_MALFORMED,
  INVENTORY_CHANGING,
  INVENTORY_VALID,
};

struct provider_classification {
  enum provider_profile profile;
  enum inventory_problem problem;
};

static bool complete_attribute(const struct attribute_query* q);

/* Source-grounded seed, not a name-based permission to ignore errors:
 * Linux include/linux/lsm_hook_defs.h defines getprocattr's default -EINVAL.
 * The matching kernel ELF's complete capability_hooks and ima_hooks tables
 * provide no getprocattr; bpf_lsm_hooks registers the generated
 * bpf_lsm_getprocattr default stub. Exact installed hook tables
 * and proc_pid_attr_read/security_getprocattr/bpf_lsm_getprocattr were
 * inspected in CONTEXT-FINDING.md, SHA256
 * c3db390aad32c95611a75bc78e5dc7f104d5b6b33c9ff58dc45910b46f149c7b.
 * This profile authorizes unavailable-label ONLY for both actual initial
 * -1/EINVAL observations. BPF
 * remains active and attachments are not enumerated: no policy equivalence or
 * absence of mediation is inferred. Kernel/build/config identify provenance,
 * not an acceptance key. This table authorizes only the unavailable-label
 * interpretation; another spelling never authorizes an error result.
 *
 * Generic byte observation: the matching proc_pid_attr_read calls
 * security_getprocattr, returns nonpositive results directly, and transports
 * a positive provider byte count with simple_read_from_buffer. The retained
 * complete disassemblies have SHA256
 * 2bfd9eac0dba85db813248d8e403816e4018a780260ef7daa33a722e3143a6a7
 * and 63c9301197afc61885abf55e191f6935c4fb857065a6d3b4e836e88bd40b6e7b.
 * Every read invokes getprocattr again. After valid stable inventory
 * collection, exactly one nonempty positive read followed by EOF can compare
 * the bytes from that first invocation without splicing separately generated
 * values. Empty EOF exports no label. The comparison requires no provider
 * allowlist and does not assert equality of every LSM policy or mediation. */
static const struct {
  const char* inventory;
  enum provider_profile profile;
} provider_profiles[] = {
    {"capability,bpf,ima", PROVIDER_CURRENT_UNAVAILABLE},
};

static bool valid_inventory(const struct attribute_query* q) {
  if (!complete_attribute(q) || q->length == 0) {
    return false;
  }
  size_t start = 0;
  while (start < q->length) {
    size_t end = start;
    while (end < q->length && q->bytes[end] != ',') {
      unsigned char c = q->bytes[end];
      if (!((c >= 'a' && c <= 'z') ||
            (end > start && ((c >= '0' && c <= '9') || c == '_')))) {
        return false;
      }
      ++end;
    }
    if (end == start) {
      return false;
    }
    for (size_t prior = 0; prior < start;) {
      size_t prior_end = prior;
      while (prior_end < start && q->bytes[prior_end] != ',') {
        ++prior_end;
      }
      if (prior_end - prior == end - start &&
          memcmp(q->bytes + prior, q->bytes + start, end - start) == 0) {
        return false;
      }
      prior = prior_end + 1;
    }
    if (end == q->length) {
      return true;
    }
    start = end + 1;
  }
  return false; /* Trailing comma, whitespace/newline and embedded NUL are
                   invalid. */
}

static struct provider_classification classify_inventory(
    const struct attribute_query* before,
    const struct attribute_query* after) {
  struct provider_classification result = {
      PROVIDER_UNCLASSIFIED, INVENTORY_QUERY_ERROR};
  if (!complete_attribute(before) || !complete_attribute(after)) {
    return result;
  }
  if (!valid_inventory(before) || !valid_inventory(after)) {
    result.problem = INVENTORY_MALFORMED;
    return result;
  }
  if (before->reads != 2 || after->reads != 2) {
    return result;
  }
  if (before->length != after->length ||
      memcmp(before->bytes, after->bytes, before->length) != 0) {
    result.problem = INVENTORY_CHANGING;
    return result;
  }
  for (unsigned i = 0;
       i < sizeof(provider_profiles) / sizeof(provider_profiles[0]);
       ++i) {
    size_t length = strlen(provider_profiles[i].inventory);
    if (before->length == length &&
        memcmp(before->bytes, provider_profiles[i].inventory, length) == 0) {
      result.profile = provider_profiles[i].profile;
      result.problem = INVENTORY_RECOGNIZED;
      return result;
    }
  }
  result.profile = PROVIDER_EXPORTED_BYTES;
  result.problem = INVENTORY_VALID;
  return result;
}

static enum provider_profile require_inventory(
    const struct attribute_query* before,
    const struct attribute_query* after,
    const char* origin) {
  struct provider_classification result = classify_inventory(before, after);
  const char* problems[] = {
      "recognized", "query-error", "malformed", "changing", "valid"};
  const char* profiles[] = {
      "unclassified", "exported-bytes-only", "observed-unavailable"};
  /* Profile records error-interpretation eligibility; the separate attribute
   * decision reports whether these actual queries exported bytes or failed. */
  printf(
      "CONTEXT_PROVIDER_DECISION origin=%s profile=%s reason=%s mode=%s\n",
      origin,
      profiles[result.profile],
      problems[result.problem],
      context_mode);
  assert(fflush(stdout) == 0);
  if ((result.problem != INVENTORY_RECOGNIZED &&
       result.problem != INVENTORY_VALID) ||
      result.profile == PROVIDER_UNCLASSIFIED) {
    context_error("provider-inventory-oracle", context_mode, EPROTO);
  }
  return result.profile;
}

static struct attribute_query
live_inventory(int tid, uint64_t start, const char* phase) {
  struct attribute_query result =
      query_attribute_path(tid, start, "/sys/kernel/security/lsm", phase);
  print_attribute(&result, phase);
  return result;
}

static void provider_provenance(int tid, uint64_t start) {
  struct utsname kernel;
  errno = 0;
  int result = uname(&kernel);
  int error = errno;
  printf(
      "CONTEXT_KERNEL_PROVENANCE uname_return=%d errno=%d release=%s acceptance_key=no\n",
      result,
      error,
      result == 0 ? kernel.release : "<unavailable>");
  /* Optional bounded diagnostics. Their exact failure/truncation records do
   * not substitute for the mandatory active-provider inventory above. */
  struct attribute_query notes = query_attribute_path(
      tid, start, "/sys/kernel/notes", "kernel-notes-provenance");
  print_attribute(&notes, "kernel-notes-provenance");
  puts(
      "CONTEXT_PROVIDER_LIMIT runtime_bpf_enumeration=not-performed "
      "attachments=unknown policy_equivalence=not-claimed "
      "kernel_config=not-collected");
}

enum attribute_decision {
  ATTRIBUTE_REJECT,
  ATTRIBUTE_EQUAL,
  ATTRIBUTE_UNAVAILABLE
};

static bool initial_einval(const struct attribute_query* q) {
  /* errno is diagnostic only after successful open/close/read calls. */
  return q->kind == ATTRIBUTE_READ_ERROR && q->open_result >= 0 &&
      q->reads == 1 && q->last_read == -1 && q->read_errno == EINVAL &&
      q->length == 0 && !q->eof && q->close_result == 0;
}

static bool complete_attribute(const struct attribute_query* q) {
  return q->kind == ATTRIBUTE_VALUE && q->open_result >= 0 && q->reads >= 1 &&
      q->last_read == 0 && q->eof && q->length < sizeof(q->bytes) - 1 &&
      q->close_result == 0;
}

static bool single_exported_attribute(const struct attribute_query* q) {
  /* The collector starts at offset zero and records each read. Two reads,
   * final EOF and nonzero length mean one positive read returned every byte.
   * Another positive read would splice a fresh getprocattr invocation. */
  return complete_attribute(q) && q->reads == 2 && q->length > 0;
}

static enum attribute_decision classify_attributes(
    const struct attribute_query* left,
    const struct attribute_query* right,
    enum provider_profile profile) {
  if (left->tid <= 0 || right->tid <= 0 || left->start == 0 ||
      right->start == 0) {
    return ATTRIBUTE_REJECT;
  }
  if ((profile == PROVIDER_EXPORTED_BYTES ||
       profile == PROVIDER_CURRENT_UNAVAILABLE) &&
      single_exported_attribute(left) && single_exported_attribute(right)) {
    return left->length == right->length &&
            memcmp(left->bytes, right->bytes, left->length) == 0
        ? ATTRIBUTE_EQUAL
        : ATTRIBUTE_REJECT;
  }
  if (profile == PROVIDER_CURRENT_UNAVAILABLE && initial_einval(left) &&
      initial_einval(right)) {
    return ATTRIBUTE_UNAVAILABLE;
  }
  return ATTRIBUTE_REJECT;
}

static enum attribute_decision require_attributes(
    const struct attribute_query* left,
    const struct attribute_query* right,
    enum provider_profile profile,
    const char* origin,
    const char* error_operation) {
  enum attribute_decision decision = classify_attributes(left, right, profile);
  printf(
      "CONTEXT_ATTRIBUTE_DECISION origin=%s decision=%s mode=%s\n",
      origin,
      decision == ATTRIBUTE_EQUAL             ? "exact-label-bytes"
          : decision == ATTRIBUTE_UNAVAILABLE ? "unavailable-label"
                                              : "rejected",
      context_mode);
  assert(fflush(stdout) == 0);
  if (decision == ATTRIBUTE_REJECT) {
    context_error(error_operation, context_mode, EPROTO);
  }
  return decision;
}

static void
fixture_value(struct attribute_query* q, const void* bytes, size_t length) {
  int fd = memfd_create("context-label-fixture", MFD_CLOEXEC);
  assert(fd >= 0);
  assert(write(fd, bytes, length) == (ssize_t)length);
  assert(lseek(fd, 0, SEEK_SET) == 0);
  char path[128];
  int count = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  assert(count > 0 && (size_t)count < sizeof(path));
  *q = query_attribute_path(q->tid, q->start, path, "real-memfd-label-fixture");
  assert(close(fd) == 0);
}

static void fixture_error(struct attribute_query* q, int error) {
  /* Explicit fault record, unlike the real memfd/invalid-task collectors. */
  q->kind = ATTRIBUTE_READ_ERROR;
  q->open_result = 100;
  q->open_errno = 0;
  q->close_result = q->close_errno = 0;
  q->last_read = -1;
  q->read_errno = error;
  q->reads = 1;
  q->length = 0;
  q->eof = false;
}

static enum provider_profile classifier_inventory(
    struct attribute_query before,
    struct attribute_query after,
    const char* inventory) {
  /* All classifier modes derive their profile from explicit synthetic bytes;
   * the live tasks contribute identities, never inventory or outcome values. */
  fixture_value(&before, inventory, strlen(inventory));
  fixture_value(&after, inventory, strlen(inventory));
  print_attribute(&before, "classifier-fixture-provider-before");
  print_attribute(&after, "classifier-fixture-provider-after");
  return require_inventory(&before, &after, "classifier-fixture-inventory");
}

static bool inventory_fixture(
    struct attribute_query before,
    struct attribute_query after,
    struct attribute_query left,
    struct attribute_query right) {
  if (strncmp(context_mode, "inventory-", 10) != 0) {
    return false;
  }
  printf("CONTEXT_TEST_FAULT mode=%s origin=inventory-fixture\n", context_mode);
  if (strcmp(context_mode, "inventory-missing") == 0) {
    fixture_value(&before, "capability,bpf,ima", 18);
    after = query_attribute_path(
        0,
        0,
        "/proc/self/task/0/attr/current",
        "inventory-query-fixture-missing-task-zero");
    assert(after.kind == ATTRIBUTE_OPEN_ERROR && after.open_errno == ENOENT);
  } else if (strcmp(context_mode, "inventory-truncated") == 0) {
    fixture_value(&before, "capability,bpf,ima", 18);
    unsigned char bytes[4095];
    memset(bytes, 'x', sizeof(bytes));
    fixture_value(&after, bytes, sizeof(bytes));
  } else {
    const char* left;
    const char* right;
    if (strcmp(context_mode, "inventory-malformed") == 0) {
      left = right = "capability,,bpf,ima";
    } else if (strcmp(context_mode, "inventory-unknown") == 0) {
      left = right = "capability,bpf,ima,fixture_unknown";
    } else {
      assert(strcmp(context_mode, "inventory-changing") == 0);
      left = "capability,bpf,ima";
      right = "capability,ima,bpf";
    }
    fixture_value(&before, left, strlen(left));
    fixture_value(&after, right, strlen(right));
  }
  print_attribute(&before, "inventory-fixture-before");
  print_attribute(&after, "inventory-fixture-after");
  enum provider_profile profile =
      require_inventory(&before, &after, "inventory-fixture");
  if (strcmp(context_mode, "inventory-unknown") == 0) {
    /* Valid spelling is sufficient only for complete successful observations.
     * Keep this negative's paired-EINVAL premise explicit on every host. */
    fixture_error(&left, EINVAL);
    fixture_error(&right, EINVAL);
    print_attribute(&left, "inventory-fixture-creator");
    print_attribute(&right, "inventory-fixture-helper");
    require_attributes(
        &left,
        &right,
        profile,
        "inventory-fixture",
        "provider-inventory-oracle");
  }
  puts("UNEXPECTED_ACCEPTANCE negative inventory fixture");
  return true;
}

/* These records exercise the same classifier but never replace or relabel the
 * actual observations printed above. A rejected fixture aborts (134); accepted
 * bad fixtures return success, which the caller MUST treat as a failed negative
 * control. Synthetic equal labels test bytes after an embedded NUL. */
static void attribute_fixture(
    struct attribute_query left,
    struct attribute_query right) {
  if (strcmp(context_mode, "live") == 0 ||
      strcmp(context_mode, "mask-mismatch") == 0) {
    return;
  }
  printf(
      "CONTEXT_TEST_FAULT mode=%s origin=classifier-fixture\n", context_mode);
  bool nonlegacy = strcmp(context_mode, "equal-labels-nonlegacy") == 0 ||
      strcmp(context_mode, "unqualified-provider") == 0;
  enum provider_profile profile = classifier_inventory(
      left,
      right,
      nonlegacy ? "capability,bpf,ima,fixture_unknown" : "capability,bpf,ima");
  if (strcmp(context_mode, "equal-labels") == 0 ||
      strcmp(context_mode, "equal-labels-nonlegacy") == 0 ||
      strcmp(context_mode, "label-mismatch") == 0 ||
      strcmp(context_mode, "label-length") == 0) {
    fixture_value(&left, "a\0x", 3);
    fixture_value(
        &right,
        strcmp(context_mode, "label-mismatch") == 0 ? "a\0y" : "a\0x",
        strcmp(context_mode, "label-length") == 0 ? 4 : 3);
  } else if (strcmp(context_mode, "empty-labels") == 0) {
    fixture_value(&left, "", 0);
    fixture_value(&right, "", 0);
  } else if (strcmp(context_mode, "query-asymmetry") == 0) {
    fixture_value(&left, "a\0x", 3);
    fixture_error(&right, EINVAL);
  } else if (strcmp(context_mode, "query-errors") == 0) {
    fixture_error(&left, EINVAL);
    fixture_error(&right, EACCES);
  } else if (strcmp(context_mode, "query-eperm") == 0) {
    fixture_error(&left, EPERM);
    fixture_error(&right, EPERM);
  } else if (strcmp(context_mode, "truncated-label") == 0) {
    fixture_value(&left, "a\0x", 3);
    unsigned char bytes[4095];
    memset(bytes, 'x', sizeof(bytes));
    fixture_value(&right, bytes, sizeof(bytes));
  } else if (strcmp(context_mode, "missing-task") == 0) {
    /* Linux task IDs are strictly positive. 0 cannot name a live userspace
     * thread here; require the actual proc open to reject it, not an old TID.
     */
    fixture_value(&left, "a\0x", 3);
    right = query_attribute(0, 0);
    print_attribute(&right, "actual-query-of-invalid-task-zero");
    assert(right.kind == ATTRIBUTE_OPEN_ERROR && right.open_errno == ENOENT);
  } else {
    assert(strcmp(context_mode, "unqualified-provider") == 0);
    fixture_error(&left, EINVAL);
    fixture_error(&right, EINVAL);
  }
  print_attribute(&left, "classifier-fixture-creator");
  print_attribute(&right, "classifier-fixture-helper");
  require_attributes(
      &left, &right, profile, "classifier-fixture", "attribute-oracle");
  if (strcmp(context_mode, "equal-labels") == 0) {
    puts(
        "PASS synthetic-label-classifier: equal length and all bytes including NUL suffix");
  } else if (strcmp(context_mode, "equal-labels-nonlegacy") == 0) {
    puts(
        "PASS synthetic-nonlegacy-label-classifier: stable valid inventory; "
        "equal exported bytes including NUL suffix");
  } else {
    puts("UNEXPECTED_ACCEPTANCE negative context fixture");
  }
}

static void compare_link(int creator, int helper, const char* suffix) {
  char paths[2][256], targets[2][4096];
  struct stat identity[2];
  int tids[2] = {creator, helper};
  for (unsigned i = 0; i < 2; ++i) {
    int length = snprintf(
        paths[i], sizeof(paths[i]), "/proc/self/task/%d/%s", tids[i], suffix);
    assert(length > 0 && (size_t)length < sizeof(paths[i]));
    ssize_t count = readlink(paths[i], targets[i], sizeof(targets[i]) - 1);
    if (count < 0) {
      context_error("readlink", paths[i], errno);
    }
    if ((size_t)count == sizeof(targets[i]) - 1) {
      context_error("readlink-buffer-limit", paths[i], EOVERFLOW);
    }
    targets[i][count] = '\0';
    if (stat(paths[i], &identity[i]) != 0) {
      context_error("stat", paths[i], errno);
    }
    printf(
        "CONTEXT_LINK tid=%d field=%s target=%s dev=%llu ino=%llu\n",
        tids[i],
        suffix,
        targets[i],
        (unsigned long long)identity[i].st_dev,
        (unsigned long long)identity[i].st_ino);
  }
  assert(fflush(stdout) == 0);
  assert(strcmp(targets[0], targets[1]) == 0);
  assert(identity[0].st_dev == identity[1].st_dev);
  assert(identity[0].st_ino == identity[1].st_ino);
}

static void compare_context_state(int creator, int helper) {
  char creator_status[32768], helper_status[32768], path[128];
  assert(
      snprintf(path, sizeof(path), "/proc/self/task/%d/status", creator) > 0);
  context_file(path, creator_status, sizeof(creator_status));
  assert(snprintf(path, sizeof(path), "/proc/self/task/%d/status", helper) > 0);
  context_file(path, helper_status, sizeof(helper_status));
  const char* fields[] = {
      "Uid",
      "Gid",
      "Groups",
      "CapInh",
      "CapPrm",
      "CapEff",
      "CapBnd",
      "CapAmb",
      "NoNewPrivs",
      "Seccomp",
      "Seccomp_filters",
      "SigBlk",
      "Umask"};
  for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    char left[16384], right[16384];
    status_field(creator_status, fields[i], left, sizeof(left));
    status_field(helper_status, fields[i], right, sizeof(right));
    printf(
        "CONTEXT_STATUS field=%s creator=%s helper=%s\n",
        fields[i],
        left,
        right);
    assert(fflush(stdout) == 0);
    assert(strcmp(left, right) == 0);
  }
  /* Pending signals are recorded, never asserted inherited by the new thread.
   */
  const char* pending[] = {"SigPnd", "ShdPnd"};
  for (unsigned i = 0; i < sizeof(pending) / sizeof(pending[0]); ++i) {
    char left[256], right[256];
    status_field(creator_status, pending[i], left, sizeof(left));
    status_field(helper_status, pending[i], right, sizeof(right));
    printf(
        "CONTEXT_PENDING field=%s creator=%s helper=%s\n",
        pending[i],
        left,
        right);
  }
  const char* links[] = {
      "ns/user",
      "ns/mnt",
      "ns/pid",
      "ns/pid_for_children",
      "ns/net",
      "ns/uts",
      "ns/ipc",
      "ns/cgroup",
      "ns/time",
      "ns/time_for_children",
      "cwd",
      "root"};
  for (unsigned i = 0; i < sizeof(links) / sizeof(links[0]); ++i) {
    compare_link(creator, helper, links[i]);
  }
}

enum { READ_PLT_LEGACY_BYTES = 6, READ_PLT_ENDBR64_BYTES = 10 };
static const unsigned char read_plt_endbr64[] = {0xf3, 0x0f, 0x1e, 0xfa};

/* Only these two complete x86-64 encodings are supported. In particular this
 * does not scan for a jump, follow another thunk, or accept other prefixes. */
static bool decode_read_plt(
    const unsigned char* bytes,
    size_t length,
    uintptr_t callable,
    uintptr_t* slot) {
  size_t jump;
  if (length == READ_PLT_LEGACY_BYTES) {
    jump = 0;
  } else if (
      length == READ_PLT_ENDBR64_BYTES &&
      memcmp(bytes, read_plt_endbr64, sizeof(read_plt_endbr64)) == 0) {
    jump = sizeof(read_plt_endbr64);
  } else {
    return false;
  }
  if (bytes[jump] != 0xff || bytes[jump + 1] != 0x25 ||
      callable > UINTPTR_MAX - length) {
    return false;
  }
  int32_t displacement;
  memcpy(&displacement, bytes + jump + 2, sizeof(displacement));
  uintptr_t next = callable + length;
  if (displacement < 0) {
    /* Widen before negation so INT32_MIN is defined. */
    uintptr_t magnitude = (uintptr_t)(-(int64_t)displacement);
    if (next < magnitude)
      return false;
    *slot = next - magnitude;
  } else {
    uintptr_t magnitude = (uintptr_t)displacement;
    if (next > UINTPTR_MAX - magnitude)
      return false;
    *slot = next + magnitude;
  }
  return true;
}

static bool same_read_plt(
    const unsigned char* left,
    size_t left_length,
    const unsigned char* right,
    size_t right_length) {
  return (left_length == READ_PLT_LEGACY_BYTES ||
          left_length == READ_PLT_ENDBR64_BYTES) &&
      left_length == right_length && memcmp(left, right, left_length) == 0;
}

static void qualify_read_plt_decoder(void) {
  const uintptr_t callable = UINT64_C(0x100000000);
  const int32_t displacements[] = {0, 24, -24, INT32_MAX, INT32_MIN};
  for (unsigned form = 0; form < 2; ++form) {
    size_t jump = form ? sizeof(read_plt_endbr64) : 0;
    size_t length = jump + READ_PLT_LEGACY_BYTES;
    unsigned char bytes[READ_PLT_ENDBR64_BYTES] = {0};
    if (form)
      memcpy(bytes, read_plt_endbr64, sizeof(read_plt_endbr64));
    bytes[jump] = 0xff;
    bytes[jump + 1] = 0x25;
    uintptr_t slot;
    for (unsigned i = 0; i < sizeof(displacements) / sizeof(displacements[0]);
         ++i) {
      int32_t displacement = displacements[i];
      memcpy(bytes + jump + 2, &displacement, sizeof(displacement));
      assert(decode_read_plt(bytes, length, callable, &slot));
      assert(
          slot ==
          (uintptr_t)((int64_t)callable + (int64_t)length + displacement));
    }
    /* Every short input refuses before reading an absent displacement byte. */
    for (size_t short_length = 0; short_length < length; ++short_length) {
      assert(!decode_read_plt(bytes, short_length, callable, &slot));
    }
    assert(!decode_read_plt(bytes, length + 1, callable, &slot));
    for (size_t i = 0; i < jump + 2; ++i) {
      unsigned char changed[READ_PLT_ENDBR64_BYTES];
      memcpy(changed, bytes, sizeof(changed));
      changed[i] ^= 1;
      assert(!decode_read_plt(changed, length, callable, &slot));
    }
    assert(same_read_plt(bytes, length, bytes, length));
    for (size_t i = 0; i < length; ++i) {
      unsigned char changed[READ_PLT_ENDBR64_BYTES];
      memcpy(changed, bytes, sizeof(changed));
      changed[i] ^= 1;
      assert(!same_read_plt(bytes, length, changed, length));
    }
    assert(!same_read_plt(
        bytes,
        length,
        bytes,
        form ? READ_PLT_LEGACY_BYTES : READ_PLT_ENDBR64_BYTES));
    int32_t displacement = 0;
    memcpy(bytes + jump + 2, &displacement, sizeof(displacement));
    assert(!decode_read_plt(bytes, length, UINTPTR_MAX - length + 1, &slot));
    displacement = 1;
    memcpy(bytes + jump + 2, &displacement, sizeof(displacement));
    assert(!decode_read_plt(bytes, length, UINTPTR_MAX - length, &slot));
    displacement = -(int32_t)length - 1;
    memcpy(bytes + jump + 2, &displacement, sizeof(displacement));
    assert(!decode_read_plt(bytes, length, 0, &slot));
  }
  const struct {
    unsigned char bytes[14];
    size_t length;
  } malformed[] = {
      {{0xf3, 0x0f, 0x1e, 0xfb, 0xff, 0x25}, 10}, /* ENDBR32 */
      {{0xf2, 0xff, 0x25}, 7}, /* BND */
      {{0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25}, 11},
      {{0x3e, 0xff, 0x25}, 7}, /* NOTRACK */
      {{0xff, 0x15}, 6}, /* indirect call */
      {{0xff, 0x24}, 6}, /* other ModRM */
      {{0xff, 0x35}, 6},
      {{0xe9}, 5}, /* direct jump */
      {{0x90, 0xff, 0x25}, 7}, /* NOP + jump */
      {{0x66, 0x90, 0xff, 0x25}, 8},
      {{0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x15}, 10},
      {{0xf3, 0x0f, 0x1e, 0xfa, 0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25}, 14},
  };
  uintptr_t slot;
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
    assert(!decode_read_plt(
        malformed[i].bytes, malformed[i].length, callable, &slot));
  }
  /* A complete jump at every other offset must not turn into a scan. */
  for (size_t offset = 1; offset <= 8; ++offset) {
    unsigned char shifted[14] = {0};
    shifted[offset] = 0xff;
    shifted[offset + 1] = 0x25;
    assert(!decode_read_plt(
        shifted, offset + READ_PLT_LEGACY_BYTES, callable, &slot));
  }
}

struct read_dispatch {
  uintptr_t callable;
  unsigned char plt[READ_PLT_ENDBR64_BYTES];
  size_t plt_length;
  uintptr_t slot;
  uintptr_t target;
  void* next_read;
  Dl_info binding;
};

/* This diagnostic qualifies the two explicit x86-64, non-PIE ELF PLT forms:
 * ff25+disp32, with or without one exact ENDBR64 immediately before the jump.
 * A canonical function address can identify read@plt in the executable. Keep
 * that observation distinct from the live destination. This process asserts
 * live PLT/GOT/public-dlsym agreement and stability and records dladdr/maps.
 * The external sealed qualification additionally binds these exact bytes/slot
 * to the executable's public read R_X86_64_JUMP_SLOT and the destination to the
 * mapped libc's public read symbol. An ordinary Cargo invocation enforces the
 * in-process assertions and full aggregate; it does not claim that additional
 * independent ELF association merely from dlsym agreement or printed maps.
 * Unsupported instruction layouts fail; there is no guessed decoding path,
 * private libc lookup or forced binding call. The test-only -fno-pie -no-pie
 * selection is explicit above; production compiler flags are unchanged. */
static struct read_dispatch observe_read_dispatch(const char* phase) {
  _Static_assert(
      sizeof(uintptr_t) == 8, "dispatch qualification requires x86-64");
  struct read_dispatch result = {
      .callable = (uintptr_t)(void*)read, .plt_length = READ_PLT_LEGACY_BYTES};
  const volatile unsigned char* code =
      (const volatile unsigned char*)result.callable;
  for (size_t i = 0; i < sizeof(read_plt_endbr64); ++i) {
    result.plt[i] = code[i];
  }
  /* Inspect the six-byte legacy window (prefix and opcode for CET) before
   * reading any additional displacement bytes. */
  for (size_t i = sizeof(read_plt_endbr64); i < READ_PLT_LEGACY_BYTES; ++i) {
    result.plt[i] = code[i];
  }
  if (memcmp(result.plt, read_plt_endbr64, sizeof(read_plt_endbr64)) == 0 &&
      result.plt[4] == 0xff && result.plt[5] == 0x25) {
    result.plt_length = READ_PLT_ENDBR64_BYTES;
  }
  for (size_t i = READ_PLT_LEGACY_BYTES; i < result.plt_length; ++i) {
    result.plt[i] = code[i];
  }
  printf(
      "CONTEXT_READ_PLT phase=%s callable=%p plt_hex=",
      phase,
      (void*)result.callable);
  for (size_t i = 0; i < result.plt_length; ++i) {
    printf("%02x", result.plt[i]);
  }
  putchar('\n');
  assert(fflush(stdout) == 0);
  if (!decode_read_plt(
          result.plt, result.plt_length, result.callable, &result.slot)) {
    context_error("unsupported-read-plt-layout", phase, ENOTSUP);
  }
  assert(result.slot % sizeof(uintptr_t) == 0);
  /* A fresh aligned ABI word load at each observation, even under optimization.
   */
  result.target = *(const volatile uintptr_t*)result.slot;
  assert(result.target != 0);
  (void)dlerror();
  result.next_read = dlsym(RTLD_NEXT, "read");
  const char* error = dlerror();
  if (error != NULL || result.next_read == NULL) {
    printf(
        "CONTEXT_READ_DLSYM_ERROR phase=%s error=%s\n",
        phase,
        error != NULL ? error : "null-symbol");
    context_error("public-read-dlsym", phase, ENOENT);
  }
  printf(
      "CONTEXT_READ_GOT phase=%s slot=%p target=%p next_read=%p\n",
      phase,
      (void*)result.slot,
      (void*)result.target,
      result.next_read);
  assert(fflush(stdout) == 0);
  assert(result.target == (uintptr_t)result.next_read);
  assert(dladdr((void*)result.target, &result.binding) != 0);
  assert(result.binding.dli_fname != NULL && result.binding.dli_fbase != NULL);
  assert(
      result.binding.dli_sname != NULL &&
      result.binding.dli_saddr == result.next_read);
  printf(
      "CONTEXT_READ_DISPATCH phase=%s callable=%p plt_hex=",
      phase,
      (void*)result.callable);
  for (size_t i = 0; i < result.plt_length; ++i) {
    printf("%02x", result.plt[i]);
  }
  printf(
      " slot=%p target=%p next_read=%p dso=%s base=%p symbol=%s symbol_address=%p\n",
      (void*)result.slot,
      (void*)result.target,
      result.next_read,
      result.binding.dli_fname,
      result.binding.dli_fbase,
      result.binding.dli_sname,
      result.binding.dli_saddr);
  assert(fflush(stdout) == 0);
  return result;
}

static void compare_read_dispatch(
    const struct read_dispatch* before,
    const struct read_dispatch* after) {
  assert(before->callable == after->callable);
  assert(same_read_plt(
      before->plt, before->plt_length, after->plt, after->plt_length));
  assert(before->slot == after->slot);
  assert(before->target == after->target);
  assert(before->next_read == after->next_read);
  assert(strcmp(before->binding.dli_fname, after->binding.dli_fname) == 0);
  assert(before->binding.dli_fbase == after->binding.dli_fbase);
  assert(strcmp(before->binding.dli_sname, after->binding.dli_sname) == 0);
  assert(before->binding.dli_saddr == after->binding.dli_saddr);
  puts(
      "CONTEXT_READ_DISPATCH_STABLE callable=1 plt_bytes=1 slot=1 target=1 public_symbol=1 dso=1");
}

static void inherited_context(void) {
  qualify_read_plt_decoder();
  reset();
  gate(RVK_READ_TEST_BEFORE_ENABLE);
  atomic_store(&capture_context, true);
  atomic_store(&context_mask_fault, strcmp(context_mode, "mask-mismatch") == 0);
  int creator = (int)syscall(SYS_gettid);
  sigset_t original_mask, test_mask;
  assert(pthread_sigmask(SIG_SETMASK, NULL, &original_mask) == 0);
  test_mask = original_mask;
  assert(sigaddset(&test_mask, SIGUSR1) == 0);
  assert(pthread_sigmask(SIG_SETMASK, &test_mask, NULL) == 0);
  stack_t original_stack, creator_stack;
  assert(sigaltstack(NULL, &original_stack) == 0);
  assert((original_stack.ss_flags & SS_ONSTACK) == 0);
  size_t stack_size = (size_t)SIGSTKSZ;
  void* stack_memory = malloc(stack_size);
  assert(stack_memory != NULL);
  stack_t test_stack = {
      .ss_sp = stack_memory, .ss_size = stack_size, .ss_flags = 0};
  assert(sigaltstack(&test_stack, NULL) == 0);
  assert(sigaltstack(NULL, &creator_stack) == 0);

  int fd = null_fd();
  struct stat endpoint_before, endpoint_after;
  assert(fstat(fd, &endpoint_before) == 0);
  int endpoint_flags = fcntl(fd, F_GETFL);
  int descriptor_flags = fcntl(fd, F_GETFD);
  assert(endpoint_flags >= 0 && descriptor_flags >= 0);
  struct rvk_read* op = prepare(fd);
  assert(rvk_read_start(op) == 0);
  await_event(RVK_READ_TEST_BEFORE_ENABLE);
  int helper = atomic_load(&event_tid[RVK_READ_TEST_BEFORE_ENABLE]);
  assert(helper != creator && helper > 0);
  assert(atomic_load(&event_tid[RVK_READ_TEST_BEFORE_CREATE]) == creator);
  uint64_t creator_start = thread_start(creator, "creator");
  uint64_t helper_start = thread_start(helper, "helper");
  printf(
      "CONTEXT_IDENTITY creator=%d/%llu helper=%d/%llu\n",
      creator,
      (unsigned long long)creator_start,
      helper,
      (unsigned long long)helper_start);
  struct attribute_query providers_before =
      live_inventory(creator, creator_start, "actual-provider-before");
  struct attribute_query creator_lsm =
      live_attribute(creator, creator_start, "creator-query");
  struct attribute_query helper_lsm =
      live_attribute(helper, helper_start, "helper-query");
  struct attribute_query providers_after =
      live_inventory(creator, creator_start, "actual-provider-after");
  assert(thread_start(creator, "creator-after-queries") == creator_start);
  assert(thread_start(helper, "helper-after-queries") == helper_start);
  if (atomic_load(&context_mask_fault)) {
    puts(
        "CONTEXT_TEST_FAULT mode=mask-mismatch origin=actual-helper-SIGUSR1-unblock");
  }
  assert(child_context.mask_fault_error == 0);
  if (child_context.mask_error != 0) {
    context_error("pthread_sigmask", "helper", child_context.mask_error);
  }
  if (child_context.altstack_result != 0) {
    context_error("sigaltstack", "helper", child_context.altstack_errno);
  }
  for (int signal = 1; signal < NSIG; ++signal) {
    if (sigismember(&test_mask, signal) !=
        sigismember(&child_context.mask, signal)) {
      printf(
          "CONTEXT_REJECT reason=signal-mask signal=%d creator=%d helper=%d\n",
          signal,
          sigismember(&test_mask, signal),
          sigismember(&child_context.mask, signal));
      assert(fflush(stdout) == 0);
    }
    assert(
        sigismember(&test_mask, signal) ==
        sigismember(&child_context.mask, signal));
  }
  assert(sigismember(&child_context.mask, SIGUSR1) == 1);
  printf(
      "CONTEXT_ALTSTACK creator_flags=%d creator_sp=%p creator_size=%zu "
      "helper_flags=%d helper_sp=%p helper_size=%zu\n",
      creator_stack.ss_flags,
      creator_stack.ss_sp,
      creator_stack.ss_size,
      child_context.altstack.ss_flags,
      child_context.altstack.ss_sp,
      child_context.altstack.ss_size);
  assert(fflush(stdout) == 0);
  assert((creator_stack.ss_flags & SS_DISABLE) == 0);
  assert((child_context.altstack.ss_flags & SS_DISABLE) != 0);
  assert((child_context.altstack.ss_flags & SS_ONSTACK) == 0);

  compare_context_state(creator, helper);
  enum provider_profile profile = require_inventory(
      &providers_before, &providers_after, "actual-live-inventory");
  provider_provenance(creator, creator_start);
  enum attribute_decision actual = require_attributes(
      &creator_lsm,
      &helper_lsm,
      profile,
      "actual-live-query",
      "attribute-oracle");
  if (!inventory_fixture(
          providers_before, providers_after, creator_lsm, helper_lsm)) {
    attribute_fixture(creator_lsm, helper_lsm);
  }

  Dl_info binding;
  assert(dladdr((void*)read, &binding) != 0);
  assert(binding.dli_fname != NULL && binding.dli_fbase != NULL);
  printf(
      "CONTEXT_READ_BINDING address=%p dso=%s base=%p symbol=%s symbol_address=%p\n",
      (void*)read,
      binding.dli_fname,
      binding.dli_fbase,
      binding.dli_sname != NULL ? binding.dli_sname : "<unknown>",
      binding.dli_saddr);
  puts(
      "CONTEXT_READ_PLT_DECODER legacy=1 endbr64=1 signed=1 malformed_rejected=1 truncated_rejected=1 overflow_rejected=1 stability_bytes=1 stability_length=1");
  struct read_dispatch dispatch_before = observe_read_dispatch("before-read");
  print_proc_file("/proc/self/maps");
  compare_context_state(creator, helper);
  assert(thread_start(creator, "creator-before-release") == creator_start);
  assert(thread_start(helper, "helper-before-release") == helper_start);
  assert(snapshot(op).outcome == RVK_READ_PENDING);
  assert(!snapshot(op).terminal && snapshot(op).error_number == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_READ]) == 0);
  release(RVK_READ_TEST_BEFORE_ENABLE);
  struct rvk_read_snapshot state = outcome(op);
  assert(
      state.outcome == RVK_READ_RETURNED && state.result == 0 &&
      !state.terminal);
  assert(state.error_phase == RVK_READ_ERROR_NONE && state.error_number == 0);
  printf(
      "CONTEXT_READ_OUTCOME outcome=%u result=%lld read_errno=%d terminal=%u "
      "error_phase=%u error_number=%d\n",
      state.outcome,
      (long long)state.result,
      state.read_errno,
      state.terminal,
      state.error_phase,
      state.error_number);
  assert(rvk_read_finish(op) == 0);
  state = snapshot(op);
  assert(state.state == RVK_READ_JOINED && state.senders == 0);
  assert(
      !state.terminal && state.error_phase == RVK_READ_ERROR_NONE &&
      state.error_number == 0);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_READ]) == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_AFTER_READ]) == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_AFTER_JOIN]) == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_CANCEL]) == 0);
  struct read_dispatch dispatch_after = observe_read_dispatch("after-join");
  compare_read_dispatch(&dispatch_before, &dispatch_after);
  print_proc_file("/proc/self/maps");
  assert(fstat(fd, &endpoint_after) == 0);
  assert(endpoint_after.st_dev == endpoint_before.st_dev);
  assert(endpoint_after.st_ino == endpoint_before.st_ino);
  assert(endpoint_after.st_rdev == endpoint_before.st_rdev);
  assert(endpoint_after.st_mode == endpoint_before.st_mode);
  assert(fcntl(fd, F_GETFL) == endpoint_flags);
  assert(fcntl(fd, F_GETFD) == descriptor_flags);
  printf(
      "CONTEXT_ENDPOINT fd=%d before_dev=%llu after_dev=%llu before_ino=%llu "
      "after_ino=%llu before_rdev=%llu after_rdev=%llu before_mode=%u after_mode=%u "
      "ofd_flags=%d descriptor_flags=%d owner_retained_until_join=1\n",
      fd,
      (unsigned long long)endpoint_before.st_dev,
      (unsigned long long)endpoint_after.st_dev,
      (unsigned long long)endpoint_before.st_ino,
      (unsigned long long)endpoint_after.st_ino,
      (unsigned long long)endpoint_before.st_rdev,
      (unsigned long long)endpoint_after.st_rdev,
      (unsigned)endpoint_before.st_mode,
      (unsigned)endpoint_after.st_mode,
      endpoint_flags,
      descriptor_flags);
  finish_and_destroy(op, fd);
  assert(atomic_load(&reached[RVK_READ_TEST_BEFORE_JOIN]) == 1);
  assert(atomic_load(&reached[RVK_READ_TEST_AFTER_JOIN]) == 1);
  errno = 0;
  assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
  puts(
      "CONTEXT_RETIREMENT physical_joins=1 cancel_sends=0 destroyed=1 owner_closed_fd=1");
  assert(sigaltstack(&original_stack, NULL) == 0);
  stack_t restored_stack;
  assert(sigaltstack(NULL, &restored_stack) == 0);
  assert(restored_stack.ss_flags == original_stack.ss_flags);
  assert(restored_stack.ss_sp == original_stack.ss_sp);
  assert(restored_stack.ss_size == original_stack.ss_size);
  assert(pthread_sigmask(SIG_SETMASK, &original_mask, NULL) == 0);
  sigset_t restored_mask;
  assert(pthread_sigmask(SIG_SETMASK, NULL, &restored_mask) == 0);
  for (int signal = 1; signal < NSIG; ++signal) {
    assert(
        sigismember(&restored_mask, signal) ==
        sigismember(&original_mask, signal));
  }
  assert(thread_start(creator, "creator-after-restoration") == creator_start);
  printf(
      "CONTEXT_RESTORATION mask_exact=1 altstack_exact=1 flags=%d sp=%p size=%zu\n",
      restored_stack.ss_flags,
      restored_stack.ss_sp,
      restored_stack.ss_size);
  free(stack_memory);
  atomic_store(&capture_context, false);
  printf(
      "PASS inherited-context-v2: matching credentials/namespaces/mask; "
      "new thread has disabled altstack; attribute=%s; read/join/ownership/restoration verified\n",
      actual == ATTRIBUTE_EQUAL ? "exact-label-bytes" : "unavailable-label");
}

int main(int argc, char** argv) {
  bool context_only = false;
  for (int i = 1; i < argc; ++i) {
    assert(i + 1 < argc);
    assert(strcmp(argv[i], "--context-mode") == 0 && !context_only);
    context_mode = argv[++i];
    context_only = true;
    const char* modes[] = {
        "live",
        "equal-labels",
        "equal-labels-nonlegacy",
        "empty-labels",
        "mask-mismatch",
        "query-asymmetry",
        "query-errors",
        "missing-task",
        "truncated-label",
        "label-mismatch",
        "label-length",
        "unqualified-provider",
        "query-eperm",
        "inventory-malformed",
        "inventory-unknown",
        "inventory-changing",
        "inventory-missing",
        "inventory-truncated"};
    bool known = false;
    for (unsigned j = 0; j < sizeof(modes) / sizeof(modes[0]); ++j) {
      known |= strcmp(context_mode, modes[j]) == 0;
    }
    assert(known);
  }
  printf(
      "terminal_read_protocol pid=%ld owner_tid=%ld\n",
      (long)getpid(),
      syscall(SYS_gettid));
  char executable[4096];
  ssize_t length =
      readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  assert(length >= 0 && (size_t)length < sizeof(executable) - 1);
  executable[length] = '\0';
  printf("EXECUTABLE %s\n", executable);
  print_proc_file("/proc/self/stat");
  print_proc_file("/proc/self/maps");
  printf(
      "CONTEXT_CONTROL mode=%s context_only=%d\n", context_mode, context_only);
  if (context_only) {
    inherited_context();
    assert(fflush(stdout) == 0);
    return 0;
  }
  before_start();
  before_create();
  before_publication();
  early_completion();
  normal_completion();
  before_read();
  inside_kernel();
  returned_before_disable();
  delayed_sender();
  queued_event();
  creation_error();
  cancellation_error(false);
  wake_epoch();
  assert(fflush(stdout) == 0);
  inherited_context();
  assert(fflush(stdout) == 0);
  /* Isolate the deliberately unretired join-error ownership. Do not reclaim
   * its operation to make leak checking or a retirement assertion pass. */
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    cancellation_error(true);
    assert(fflush(stdout) == 0);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  puts(
      "PASS all C protocol controls; injected retirement failure contained by process exit");
  return 0;
}
