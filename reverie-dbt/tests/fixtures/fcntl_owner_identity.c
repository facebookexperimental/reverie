/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Asynchronous-I/O owners, set through fcntl or through the socket ioctls
 * FIOSETOWN and SIOCSPGRP, name a process, thread or process group by ID.
 * Under DBT the guest sees virtual IDs while Linux resolves the number in the
 * host PID space, so a reading-back check alone cannot tell a correct owner
 * from a wrong one: setting the owner to an unrelated host task that happens to
 * carry the guest's number round-trips perfectly. Every owner below is
 * therefore also proven by delivery: with SIGUSR1 blocked, F_SETSIG(SIGUSR1)
 * and O_ASYNC set, a write to the pipe or socket makes Linux queue SIGUSR1 for
 * the owner during that write; the owner must find it pending, and its handler
 * must run once when it unblocks the signal.
 *
 * Only relational facts are printed, so the Linux run and the DBT run must
 * produce identical output.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int data[2];

static void fail(const char* what) {
  printf("FAIL %s errno=%d\n", what, errno);
  fflush(stdout);
  exit(1);
}

static volatile sig_atomic_t hits;

static void on_sigusr1(int signal) {
  (void)signal;
  hits++;
}

/* Report whether SIGUSR1 was pending for this process, then deliver it by
 * unblocking it briefly: 1 when it was pending and the handler ran once, 0
 * when it was not pending and the handler did not run, and 2 or 3 for the two
 * inconsistent combinations. sigpending and handler delivery are used rather
 * than sigtimedwait, whose zero-timeout form Detcore under DBT does not yet
 * answer from a pending signal. */
static int take_sigusr1(void) {
  sigset_t set;
  sigset_t pending;
  sig_atomic_t before = hits;
  if (sigpending(&pending) != 0)
    fail("sigpending");
  int was_pending = sigismember(&pending, SIGUSR1);
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0 ||
      sigprocmask(SIG_BLOCK, &set, NULL) != 0)
    fail("sigprocmask deliver");
  int ran = hits - before;
  if (was_pending)
    return ran == 1 ? 1 : 2;
  return ran == 0 ? 0 : 3;
}

/* Read back the one byte each write below sends, so the pipe is empty again.
 * Exactly one byte, rather than reading until EAGAIN: the DBT native client
 * currently retries a pipe EAGAIN until the pipe is ready, whatever the
 * descriptor's O_NONBLOCK says. */
static void drain(void) {
  char byte;
  if (read(data[0], &byte, 1) != 1)
    fail("read");
}

/* Write one byte, which signals the owner during the write, and report
 * whether this process received it. */
static int poke_self(void) {
  if (write(data[1], "x", 1) != 1)
    fail("write");
  int got = take_sigusr1();
  drain();
  return got;
}

/* The same check for a socket whose owner the socket ioctls set: write one
 * byte to the peer, then read it back. */
static int poke_socket(int sockets[2]) {
  char byte;
  if (write(sockets[1], "x", 1) != 1)
    fail("socket write");
  int got = take_sigusr1();
  if (read(sockets[0], &byte, 1) != 1)
    fail("socket read");
  return got;
}

#if !defined(__x86_64__)
#error "fcntl_owner_identity.c checks x86-64 syscall register preservation"
#endif

/* Issue a three-argument syscall directly and report whether Linux's ABI
 * promise held: the argument registers read back unchanged. */
static long
syscall3_preserving(long number, long a, long b, long c, int* kept) {
  register long rdi __asm__("rdi") = a;
  register long rsi __asm__("rsi") = b;
  register long rdx __asm__("rdx") = c;
  long result;
  __asm__ volatile("syscall"
                   : "=a"(result), "+r"(rdi), "+r"(rsi), "+r"(rdx)
                   : "0"(number)
                   : "rcx", "r11", "memory");
  *kept = rdi == a && rsi == b && rdx == c;
  return result;
}

static long raw_fcntl(int fd, int cmd, long arg) {
  return syscall(SYS_fcntl, fd, cmd, arg);
}

int main(void) {
  sigset_t set;
  pid_t me = getpid();
  pid_t tid = (pid_t)syscall(SYS_gettid);
  struct f_owner_ex owner;
  int rc;
  long lrc;

  struct sigaction action = {.sa_handler = on_sigusr1};
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0)
    fail("sigaction");
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
    fail("sigprocmask");
  if (pipe(data) != 0)
    fail("pipe");
  if (fcntl(data[0], F_SETFL, O_ASYNC | O_NONBLOCK) != 0)
    fail("F_SETFL");
  if (fcntl(data[0], F_SETSIG, SIGUSR1) != 0)
    fail("F_SETSIG");

  /* F_SETOWN with our own PID. */
  printf("setown-self rc=%ld\n", raw_fcntl(data[0], F_SETOWN, me));
  printf("getown-raw-is-self=%d\n", raw_fcntl(data[0], F_GETOWN, 0) == me);
  printf("getown-is-self=%d\n", fcntl(data[0], F_GETOWN) == me);
  printf("setown-self delivered=%d\n", poke_self());

  /* F_GETOWN_EX reads the owner F_SETOWN installed. */
  owner = (struct f_owner_ex){.type = -1, .pid = -1};
  rc = fcntl(data[0], F_GETOWN_EX, &owner);
  printf(
      "getown-ex rc=%d type=%d pid-is-self=%d\n",
      rc,
      owner.type,
      owner.pid == me);

  /* F_SETOWN_EX naming this thread. */
  owner = (struct f_owner_ex){.type = F_OWNER_TID, .pid = tid};
  printf("setown-ex-tid rc=%d\n", fcntl(data[0], F_SETOWN_EX, &owner));
  printf("setown-ex-tid struct-unchanged=%d\n", owner.pid == tid);
  owner = (struct f_owner_ex){.type = -1, .pid = -1};
  rc = fcntl(data[0], F_GETOWN_EX, &owner);
  printf(
      "getown-ex rc=%d type=%d pid-is-tid=%d\n",
      rc,
      owner.type,
      owner.pid == tid);
  printf("setown-ex-tid delivered=%d\n", poke_self());

  /* F_SETOWN_EX naming this process. */
  owner = (struct f_owner_ex){.type = F_OWNER_PID, .pid = me};
  printf("setown-ex-pid rc=%d\n", fcntl(data[0], F_SETOWN_EX, &owner));
  printf("setown-ex-pid delivered=%d\n", poke_self());

  /* Our process group, by both spellings. Depending on the launcher this
   * process leads its own group or is a member of the launcher's. */
  pid_t group = getpgrp();
  printf("group-is-self=%d\n", group == me);
  printf("setown-group rc=%ld\n", raw_fcntl(data[0], F_SETOWN, -group));
  printf("getown-is-group=%d\n", fcntl(data[0], F_GETOWN) == -group);
  owner = (struct f_owner_ex){.type = -1, .pid = -1};
  rc = fcntl(data[0], F_GETOWN_EX, &owner);
  printf(
      "getown-ex rc=%d type=%d pid-is-group=%d\n",
      rc,
      owner.type,
      owner.pid == group);
  /* Read through the raw syscall result rather than libc's syscall(): a group
   * ID below 4096 (the guest's own virtual IDs are small) comes back in the
   * range libc would report as an errno. */
  int kept = 0;
  long raw = syscall3_preserving(SYS_fcntl, data[0], F_GETOWN, 0, &kept);
  printf("getown-raw-is-group=%d\n", raw == -group);
  printf("setown-group delivered=%d\n", poke_self());
  owner = (struct f_owner_ex){.type = F_OWNER_PGRP, .pid = group};
  printf("setown-ex-pgrp rc=%d\n", fcntl(data[0], F_SETOWN_EX, &owner));
  printf("setown-ex-pgrp delivered=%d\n", poke_self());

  /* Linux preserves every argument register across a syscall, so a guest may
   * reuse them; a translated owner or a pointer to a translated copy must not
   * be left behind in them. */
  raw = syscall3_preserving(SYS_fcntl, data[0], F_SETOWN, me, &kept);
  printf("setown-raw rc=%ld registers-preserved=%d\n", raw, kept);
  owner = (struct f_owner_ex){.type = F_OWNER_PID, .pid = me};
  raw = syscall3_preserving(
      SYS_fcntl, data[0], F_SETOWN_EX, (long)(uintptr_t)&owner, &kept);
  printf("setown-ex-raw rc=%ld registers-preserved=%d\n", raw, kept);

  /* The socket ioctls FIOSETOWN/SIOCSPGRP and FIOGETOWN/SIOCGPGRP set and
   * read the same owner through an int, with F_SETOWN's encoding. */
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
    fail("socketpair");
  if (fcntl(sockets[0], F_SETFL, O_ASYNC | O_NONBLOCK) != 0)
    fail("socket F_SETFL");
  if (fcntl(sockets[0], F_SETSIG, SIGUSR1) != 0)
    fail("socket F_SETSIG");
  int who = me;
  rc = ioctl(sockets[0], FIOSETOWN, &who);
  printf("fiosetown-self rc=%d value-unchanged=%d\n", rc, who == me);
  who = 0;
  rc = ioctl(sockets[0], FIOGETOWN, &who);
  printf("fiogetown rc=%d is-self=%d\n", rc, who == me);
  printf("fiosetown-self delivered=%d\n", poke_socket(sockets));
  who = me;
  raw = syscall3_preserving(
      SYS_ioctl, sockets[0], FIOSETOWN, (long)(uintptr_t)&who, &kept);
  printf("fiosetown-raw rc=%ld registers-preserved=%d\n", raw, kept);
  who = -group;
  rc = ioctl(sockets[0], SIOCSPGRP, &who);
  printf("siocspgrp-group rc=%d\n", rc);
  who = 0;
  rc = ioctl(sockets[0], SIOCGPGRP, &who);
  printf("siocgpgrp rc=%d is-group=%d\n", rc, who == -group);
  printf("siocspgrp-group delivered=%d\n", poke_socket(sockets));
  who = INT_MAX - 1;
  errno = 0;
  rc = ioctl(sockets[0], FIOSETOWN, &who);
  printf("fiosetown-unknown rc=%d errno-is-esrch=%d\n", rc, errno == ESRCH);
  close(sockets[0]);
  close(sockets[1]);

  /* Another process: a forked child owns the descriptor and must receive the
   * signal; this process must not. */
  int go[2];
  if (pipe(go) != 0)
    fail("pipe go");
  pid_t child = fork();
  if (child < 0)
    fail("fork");
  if (child == 0) {
    char byte;
    close(go[1]);
    if (read(go[0], &byte, 1) != 1)
      _exit(3);
    _exit(take_sigusr1() == 1 ? 0 : 2);
  }
  close(go[0]);
  /* Linux resolves a group owner with find_vpid, so the PID of a task that
   * leads no group is accepted; no group answers to it, so F_GETOWN (read
   * through the raw result, not libc's F_GETOWN_EX emulation) reports none. */
  rc = (int)raw_fcntl(data[0], F_SETOWN, -child);
  raw = syscall3_preserving(SYS_fcntl, data[0], F_GETOWN, 0, &kept);
  printf("setown-nonleader-group rc=%d getown-raw-is-zero=%d\n", rc, raw == 0);
  printf("setown-child rc=%ld\n", raw_fcntl(data[0], F_SETOWN, child));
  printf("getown-is-child=%d\n", fcntl(data[0], F_GETOWN) == child);
  if (write(data[1], "x", 1) != 1)
    fail("write child");
  printf("setown-child parent-received=%d\n", take_sigusr1());
  drain();
  if (write(go[1], "g", 1) != 1)
    fail("write go");
  int status = 0;
  if (waitpid(child, &status, 0) != child)
    fail("waitpid");
  printf(
      "setown-child child-received=%d\n",
      WIFEXITED(status) && WEXITSTATUS(status) == 0);

  /* A process group outlives its leader while members remain: the reaped
   * leader's ID still names the group, and its member receives the signal. */
  int report[2];
  int go_member[2];
  if (pipe(report) != 0 || pipe(go_member) != 0)
    fail("pipe group");
  pid_t leader = fork();
  if (leader < 0)
    fail("fork leader");
  if (leader == 0) {
    if (setpgid(0, 0) != 0)
      _exit(4);
    pid_t member = fork();
    if (member == 0) {
      char byte;
      close(go_member[1]);
      if (read(go_member[0], &byte, 1) != 1)
        _exit(3);
      char got = take_sigusr1() == 1 ? '1' : '0';
      _exit(write(report[1], &got, 1) == 1 ? 0 : 5);
    }
    _exit(member > 0 ? 0 : 1);
  }
  close(go_member[0]);
  close(report[1]);
  if (waitpid(leader, &status, 0) != leader || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0)
    fail("leader");
  rc = (int)raw_fcntl(data[0], F_SETOWN, -leader);
  printf("setown-exited-leader-group rc=%d\n", rc);
  if (write(data[1], "x", 1) != 1)
    fail("write group");
  printf("setown-exited-leader-group parent-received=%d\n", take_sigusr1());
  drain();
  if (write(go_member[1], "g", 1) != 1)
    fail("write go member");
  char member_got = '?';
  if (read(report[0], &member_got, 1) != 1)
    fail("read member report");
  printf("setown-exited-leader-group member-received=%c\n", member_got);
  close(go_member[1]);
  close(report[0]);

  /* Linux's own refusals reach the guest unchanged. INT_MAX - 1 is above
   * PID_MAX_LIMIT, so no task, host or guest, has it. */
  errno = 0;
  lrc = raw_fcntl(data[0], F_SETOWN, INT_MAX - 1);
  printf("setown-unknown rc=%ld errno-is-esrch=%d\n", lrc, errno == ESRCH);
  owner = (struct f_owner_ex){.type = F_OWNER_PID, .pid = INT_MAX - 1};
  errno = 0;
  rc = fcntl(data[0], F_SETOWN_EX, &owner);
  printf("setown-ex-unknown rc=%d errno-is-esrch=%d\n", rc, errno == ESRCH);
  /* A bad descriptor is reported before an unknown owner, as on Linux. */
  errno = 0;
  lrc = raw_fcntl(-1, F_SETOWN, INT_MAX - 1);
  printf("setown-badfd rc=%ld errno-is-ebadf=%d\n", lrc, errno == EBADF);
  errno = 0;
  lrc = raw_fcntl(data[0], F_SETOWN, INT_MIN);
  printf("setown-intmin rc=%ld errno-is-einval=%d\n", lrc, errno == EINVAL);
  owner = (struct f_owner_ex){.type = 7, .pid = me};
  errno = 0;
  rc = fcntl(data[0], F_SETOWN_EX, &owner);
  printf("setown-ex-badtype rc=%d errno-is-einval=%d\n", rc, errno == EINVAL);
  errno = 0;
  lrc = raw_fcntl(data[0], F_SETOWN_EX, 8);
  printf("setown-ex-fault rc=%ld errno-is-efault=%d\n", lrc, errno == EFAULT);

  /* Owner zero clears the owner; nothing is signalled. */
  printf("setown-zero rc=%ld\n", raw_fcntl(data[0], F_SETOWN, 0));
  printf("getown-zero=%d\n", fcntl(data[0], F_GETOWN) == 0);
  printf("setown-zero delivered=%d\n", poke_self());

  printf("fcntl-owner-identity=ok\n");
  return 0;
}
