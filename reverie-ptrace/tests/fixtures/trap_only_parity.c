/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Guest for the trap-only LiteInst parity test. It exercises the classes the
 * preload hybrid refuses or special-cases (vfork, fork, exec by the root, a
 * delivered signal) so that a stop-by-stop comparison with plain ptrace is not
 * vacuous.
 *
 *   trap_only_parity            run the scenario, then exec itself as "exec"
 *   trap_only_parity exec       the post-exec image; exit 0
 *   trap_only_parity touch PATH create PATH and exit 0 (launch witness)
 *
 * The two runs of a comparison are independent, so host scheduling inside the
 * guest must not reach the stop trace. SIGCHLD is therefore kept blocked from
 * before each fork and vfork until after the matching waitpid, and is then
 * delivered when the old mask is restored. Unblocked, a child's exit could
 * overtake its parent's wait4 or not, and the parent's wait4 seccomp stop and
 * its SIGCHLD signal-delivery stop swapped order from run to run.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t usr1_seen;

static void on_usr1(int signal_number) {
  (void)signal_number;
  usr1_seen = 1;
}

int main(int argc, char** argv) {
  if (argc == 3 && strcmp(argv[1], "touch") == 0) {
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    return fd < 0 ? 20 : 0;
  }
  if (argc == 2 && strcmp(argv[1], "exec") == 0) {
    return 0;
  }

  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = on_usr1;
  if (sigaction(SIGUSR1, &action, NULL) != 0) {
    return 2;
  }

  int fd = open("/dev/null", O_WRONLY);
  if (fd < 0) {
    return 3;
  }
  static const char text[] = "trap-only parity\n";
  if (write(fd, text, sizeof text - 1) != (ssize_t)(sizeof text - 1)) {
    return 4;
  }
  close(fd);
  (void)getpid();
  (void)syscall(SYS_getppid);

  raise(SIGUSR1);
  if (!usr1_seen) {
    return 5;
  }

  sigset_t chld;
  sigset_t unblocked;
  sigemptyset(&chld);
  sigaddset(&chld, SIGCHLD);

  int status = 0;
  if (sigprocmask(SIG_BLOCK, &chld, &unblocked) != 0) {
    return 11;
  }
  pid_t child = fork();
  if (child == 0) {
    _exit(7);
  }
  if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 7) {
    return 6;
  }
  if (sigprocmask(SIG_SETMASK, &unblocked, NULL) != 0) {
    return 12;
  }

  if (sigprocmask(SIG_BLOCK, &chld, &unblocked) != 0) {
    return 13;
  }
  child = vfork();
  if (child == 0) {
    _exit(9);
  }
  if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 9) {
    return 8;
  }
  if (sigprocmask(SIG_SETMASK, &unblocked, NULL) != 0) {
    return 14;
  }

  char* const next[] = {argv[0], "exec", NULL};
  execv(argv[0], next);
  return 10;
}
