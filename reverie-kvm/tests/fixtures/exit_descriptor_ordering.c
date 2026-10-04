/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * End-to-end descriptor lifetime fixture.
 *
 * The writer group is the original traced root in root-* modes. A reader is
 * forked before threads exist, so it has a separate descriptor table and is
 * not killed by the writer group's exit_group or fatal signal. The root has
 * no traced parent; its EOF cannot be protected by a live-parent wait barrier.
 *
 * In orphan-* modes the original traced root first exits. Its child observes
 * EOF and changed parent identity before it constructs the writer group, so
 * the group's direct traced parent is already terminal.
 *
 * Each peer announces that it is running, then blocks forever on a private
 * pipe that the writer group keeps open. No peer can exit voluntarily. Each
 * peer therefore retains the EOF pipe's inherited/shared writer references
 * until group teardown cancels it. The leader never explicitly closes the
 * EOF writer. The reader prints only after read returns zero.
 *
 * Future strict verification must additionally require exact stdout and empty
 * guest stderr. A matched root exit alone could hide a failed descendant.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define PEERS 2
#define WRITER_MARKER 0x454f4657
#define PEER_MARKER 0x454f4650

static int ready[2];
static int parked[2];

static void fail(const char* operation) {
  int saved = errno;
  dprintf(2, "kvm_group_exit_eof: %s: errno=%d\n", operation, saved);
  syscall(SYS_exit_group, 90);
  __builtin_unreachable();
}

static void write_exact(int fd, const void* buffer, size_t length) {
  const char* bytes = buffer;
  while (length) {
    ssize_t n = write(fd, bytes, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      fail("write");
    bytes += n;
    length -= (size_t)n;
  }
}

static void read_exact(int fd, void* buffer, size_t length) {
  char* bytes = buffer;
  while (length) {
    ssize_t n = read(fd, bytes, length);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      fail("read readiness");
    bytes += n;
    length -= (size_t)n;
  }
}

static void read_eof(int fd) {
  char byte;
  for (;;) {
    ssize_t n = read(fd, &byte, 1);
    if (n == 0)
      return;
    if (n < 0 && errno == EINTR)
      continue;
    /* The EOF pipe carries no payload. EAGAIN is not accepted as EOF. */
    fail("expected EOF on empty blocking pipe");
  }
}

static void* live_peer(void* unused) {
  (void)unused;
  write_exact(ready[1], "p", 1);
  /* Harmless on Linux and Hermit; the Reverie Tool uses this real callback. */
  (void)syscall(SYS_getpid, PEER_MARKER);
  char byte;
  for (;;) {
    ssize_t n = read(parked[0], &byte, 1);
    if (n < 0 && errno == EINTR)
      continue;
    /* Nobody writes or closes the parking pipe while this group is alive. */
    fail("live peer returned from permanent park");
  }
}

static void* group_issuer(void* unused) {
  (void)unused;
  syscall(SYS_exit_group, 0);
  __builtin_unreachable();
}

static void run_writer_group(
    const char* class_name,
    int fatal,
    int worker_issuer,
    const char* witness_fifo) {
  int eof[2];
  if (pipe(eof) || pipe(ready) || pipe(parked))
    fail("pipe");

  /* Fork while single-threaded. This reader owns an independent file table. */
  pid_t reader = fork();
  if (reader < 0)
    fail("fork reader");
  if (reader == 0) {
    if (close(eof[1]) || close(ready[0]) || close(parked[0]) ||
        close(parked[1]))
      fail("reader close");
    write_exact(ready[1], "r", 1);
    if (close(ready[1]))
      fail("reader ready close");
    read_eof(eof[0]);
    char message[128];
    int length = snprintf(
        message,
        sizeof(message),
        "reader: EOF class=%s termination=%s peers=%d\n",
        class_name,
        fatal ? "fatal" : "exit_group",
        PEERS);
    if (length < 0 || (size_t)length >= sizeof(message))
      fail("reader message");
    write_exact(1, message, (size_t)length);
    syscall(SYS_exit_group, 0);
    __builtin_unreachable();
  }
  if (close(eof[0]))
    fail("writer read-end close");

  /* Open the optional test witness only AFTER forking the independent reader.
     Therefore only this writer group inherits its write-end references. */
  if (witness_fifo && open(witness_fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC) < 0)
    fail("witness FIFO open");
  (void)syscall(SYS_getpid, WRITER_MARKER);

  /* These CLONE_THREAD/CLONE_FILES peers inherit eof[1]; never join them. */
  pthread_t peers[PEERS];
  for (int i = 0; i < PEERS; ++i) {
    int error = pthread_create(&peers[i], NULL, live_peer, NULL);
    if (error) {
      errno = error;
      fail("pthread_create");
    }
  }
  char acknowledgements[PEERS + 1];
  read_exact(ready[0], acknowledgements, sizeof(acknowledgements));
  int peer_count = 0, reader_count = 0;
  for (size_t i = 0; i < sizeof(acknowledgements); ++i) {
    peer_count += acknowledgements[i] == 'p';
    reader_count += acknowledgements[i] == 'r';
  }
  if (peer_count != PEERS || reader_count != 1)
    fail("unexpected readiness");

  char message[128];
  int length = snprintf(
      message,
      sizeof(message),
      "writer: class=%s termination=%s peers=%d\n",
      class_name,
      fatal ? "fatal" : "exit_group",
      PEERS);
  if (length < 0 || (size_t)length >= sizeof(message))
    fail("writer message");
  write_exact(1, message, (size_t)length);

  if (fatal) {
    /* Exact leader target, default fatal action: the whole thread group dies.
     */
    if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGTERM))
      fail("tgkill");
    for (;;)
      pause();
  }
  if (worker_issuer) {
    pthread_t issuer;
    int error = pthread_create(&issuer, NULL, group_issuer, NULL);
    if (error) {
      errno = error;
      fail("issuer pthread_create");
    }
    for (;;)
      pause();
  }
  syscall(SYS_exit_group, 0);
  __builtin_unreachable();
}

int main(int argc, char** argv) {
  if (argc != 2 && argc != 3) {
    dprintf(
        2,
        "usage: %s root-exit-group|orphan-exit-group|root-worker-exit-group|orphan-worker-exit-group|root-fatal|orphan-fatal [witness-fifo]\n",
        argv[0]);
    return 2;
  }
  int orphan = !strcmp(argv[1], "orphan-exit-group") ||
      !strcmp(argv[1], "orphan-fatal") ||
      !strcmp(argv[1], "orphan-worker-exit-group");
  int worker_issuer = !strcmp(argv[1], "root-worker-exit-group") ||
      !strcmp(argv[1], "orphan-worker-exit-group");
  int fatal =
      !strcmp(argv[1], "root-fatal") || !strcmp(argv[1], "orphan-fatal");
  if (!orphan && !worker_issuer && strcmp(argv[1], "root-exit-group") &&
      strcmp(argv[1], "root-fatal"))
    return 2;

  struct sigaction disposition = {0};
  disposition.sa_handler = SIG_DFL;
  sigemptyset(&disposition.sa_mask);
  if (sigaction(SIGTERM, &disposition, NULL))
    fail("SIGTERM default");
  sigset_t term;
  sigemptyset(&term);
  sigaddset(&term, SIGTERM);
  if (sigprocmask(SIG_UNBLOCK, &term, NULL))
    fail("SIGTERM unblock");

  if (orphan) {
    int parent_gone[2];
    if (pipe(parent_gone))
      fail("parent pipe");
    pid_t direct_parent = getpid();
    pid_t writer = fork();
    if (writer < 0)
      fail("fork writer");
    if (writer != 0) {
      /* The original root exits; do not wait for the future writer group. */
      syscall(SYS_exit_group, 0);
      __builtin_unreachable();
    }
    if (close(parent_gone[1]))
      fail("child parent pipe close");
    read_eof(parent_gone[0]);
    if (close(parent_gone[0]))
      fail("parent pipe read close");
    /* Linux closes files before reparenting. Await the actual identity change;
       under Detcore this is after the parent's exact terminal receipt. */
    while (getppid() == direct_parent)
      syscall(SYS_sched_yield);
  }
  run_writer_group(
      orphan ? "direct-parent-terminal" : "root",
      fatal,
      worker_issuer,
      argc == 3 ? argv[2] : NULL);
  __builtin_unreachable();
}
