/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} %s -D_EXEC_NAME=%t1 -o %t1
 * RUN: echo "Hello, world!" >  %t1.expected
 * RUN: echo "1"             >> %t1.expected
 * RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual 1
 * RUN: sleep 2
 * RUN: diff %t1.actual %t1.expected
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define xstr(a) str(a)
#define str(a) #a

#ifndef _EXEC_NAME
#define _EXEC_NAME a.out
#endif

#define ISSET(t, f) ((t) & (f))

int signal_pipe[2];

static void handler(int s, siginfo_t *info, void *context) {
  unsigned char signo = (unsigned char)s;

  while (write(signal_pipe[1], &signo, sizeof(signo)) == -1) {
    if (errno != EINTR)
      break;
  }
}

int main(int argc, char **argv) {
  if (argc == 1) {
    printf("Hello, world!\n");
    fflush(NULL);
    return 0;
  }

  // Set up pipe and make it non-blocking
  int rval = pipe(signal_pipe);
  if (rval == -1)
    return -1;

  int flags = fcntl(signal_pipe[0], F_GETFL, 0);
  if (flags != -1 && !ISSET(flags, O_NONBLOCK))
    rval = fcntl(signal_pipe[0], F_SETFL, flags | O_NONBLOCK);
  if (rval != -1) {
    flags = fcntl(signal_pipe[1], F_GETFL, 0);
    if (flags != -1 && !ISSET(flags, O_NONBLOCK))
      rval = fcntl(signal_pipe[1], F_SETFL, flags | O_NONBLOCK);
  }

  // Set up signal handler
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_INTERRUPT;
  sa.sa_flags |= SA_SIGINFO;
  sa.sa_sigaction = handler;

  sigaction(SIGCHLD, &sa, NULL);

  // Fork
  int pid = fork();

  if (pid == 0) {
    // Child - execve
    char *const args[] = {xstr(_EXEC_NAME), NULL};
    char *const envp[] = {NULL};
    sleep(1);
    execve(xstr(_EXEC_NAME), args, envp);
    assert(0);
  }

  // Parent - poll on pipe
  struct pollfd fd;
  fd.fd = signal_pipe[0];
  fd.events = (POLLIN | POLLHUP);

  for (;;) {
    int ret = poll(&fd, 1, -1);
    if (ret > 0)
      break;
    else if (ret == -1 && errno != EINVAL)
      // Try again
      continue;
    else
      return -1;
  }

  unsigned char signo;

  if (fd.revents & POLLIN)
    read(signal_pipe[0], &signo, sizeof(signo));
  else {
    printf("Unexpected poll revents: %d\n", fd.revents);
    return -1;
  }

  printf("%d\n", signo == SIGCHLD);
  return 0;
}
