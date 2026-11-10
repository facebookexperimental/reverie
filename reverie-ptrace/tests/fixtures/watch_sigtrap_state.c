/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A guest for the watchpoint tests of tests/watchpoints_programs.rs. It asks
 * the Tool to arm a write watch on `word` with a clock_getres of a clock no
 * kernel has (ARM), and then, by its first argument:
 *
 * - mask: blocks SIGTRAP, writes the word, and prints whether SIGTRAP is
 *   still blocked. The hit's forced SIGTRAP unblocks it.
 * - handler: sends itself SIGUSR1, whose handler blocks every signal and
 *   writes the word; prints whether the handler still saw SIGTRAP blocked
 *   after the write.
 * - action: installs a SIGTRAP handler, blocks SIGTRAP, writes the word, and
 *   prints whether SIGTRAP is blocked and what its action is. The hit's
 *   forced SIGTRAP resets the action to SIG_DFL.
 * - children: installs a SIGTRAP handler, forks a child and starts a thread,
 *   each of which runs an int3; prints whether the child exited 0, and the
 *   child's and the thread's IDs.
 * - resethand: installs a SIGTRAP handler with SA_RESETHAND whose mask
 *   blocks SIGTRAP, and raises an int3. Linux delivers the trap, resets the
 *   action to the default, and runs the handler with SIGTRAP blocked; the
 *   handler writes the word. Prints the action after the handler and
 *   whether SIGTRAP is blocked there.
 * - untraced: clones a child that shares its signal-action table and that
 *   the tracer does not trace (CLONE_UNTRACED), so the table is one Reverie
 *   cannot read with confidence; then blocks SIGTRAP and writes the word.
 *   Prints whether SIGTRAP is still blocked.
 * - pending: blocks SIGUSR1, which it sends itself, asks the Tool to arm as
 *   SIGUSR1 is delivered (ARM_AT_SIGUSR1), and calls ppoll with a temporary
 *   mask that blocks SIGTRAP but not SIGUSR1. The call ends at once, and
 *   SIGUSR1 is delivered under the temporary mask, whose restore is
 *   pending. Prints the call's result and whether the handler ran.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ARM 0x57415443L
#define ARM_AT_SIGUSR1 0x55535231L

static volatile uint64_t word;
static volatile int handler_saw_blocked = -1;
static volatile int usr1_ran;
static volatile int trap_saw_blocked = -1;
static volatile pid_t thread_tid;

static long arm(void) {
  return syscall(SYS_clock_getres, ARM, &word);
}

static int sigtrap_blocked(void) {
  sigset_t now;
  sigprocmask(SIG_BLOCK, NULL, &now);
  return sigismember(&now, SIGTRAP);
}

static const char* blocked_word(int blocked) {
  return blocked == 1 ? "blocked" : "unblocked";
}

static void block(int signal) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signal);
  sigprocmask(SIG_BLOCK, &set, NULL);
}

static void catch_signal(int signal, void (*handler)(int), int mask_all) {
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = handler;
  if (mask_all) {
    sigfillset(&action.sa_mask);
  }
  sigaction(signal, &action, NULL);
}

static void send_self(int signal) {
  syscall(SYS_tgkill, getpid(), gettid(), signal);
}

static void write_in_handler(int signal) {
  (void)signal;
  word = 1;
  handler_saw_blocked = sigtrap_blocked();
  usr1_ran = 1;
}

static void note_usr1(int signal) {
  (void)signal;
  usr1_ran = 1;
}

static void on_trap(int signal) {
  (void)signal;
  word = 1;
  usr1_ran = 1;
  trap_saw_blocked = sigtrap_blocked();
}

/* A child process that shares this process's signal-action table and that
 * the tracer does not trace. It exits at once; with CLONE_VM it must not
 * return into this function's frame. */
static pid_t clone_untraced_sighand_child(void) {
  const size_t size = 1 << 16;
  char* stack = mmap(
      NULL,
      size,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
      -1,
      0);
  if (stack == MAP_FAILED) {
    return -1;
  }
  long flags = CLONE_VM | CLONE_SIGHAND | CLONE_UNTRACED | SIGCHLD;
  long child = syscall(SYS_clone, flags, stack + size, 0, 0, 0);
  if (child == 0) {
    syscall(SYS_exit, 0);
    __builtin_unreachable();
  }
  return (pid_t)child;
}

static void* run_int3(void* arg) {
  (void)arg;
  __asm__ volatile("int3");
  return NULL;
}

static void* run_int3_in_thread(void* arg) {
  thread_tid = gettid();
  return run_int3(arg);
}

int main(int argc, char** argv) {
  const char* mode = argc > 1 ? argv[1] : "";
  if (!strcmp(mode, "mask")) {
    if (arm()) {
      return 2;
    }
    block(SIGTRAP);
    word = 1;
    printf("after=%s\n", blocked_word(sigtrap_blocked()));
  } else if (!strcmp(mode, "handler")) {
    catch_signal(SIGUSR1, write_in_handler, 1);
    if (arm()) {
      return 2;
    }
    send_self(SIGUSR1);
    printf(
        "ran=%d in-handler=%s after=%s\n",
        usr1_ran,
        blocked_word(handler_saw_blocked),
        blocked_word(sigtrap_blocked()));
  } else if (!strcmp(mode, "action")) {
    catch_signal(SIGTRAP, on_trap, 0);
    if (arm()) {
      return 2;
    }
    block(SIGTRAP);
    word = 1;
    struct sigaction now;
    sigaction(SIGTRAP, NULL, &now);
    printf(
        "after=%s action=%s\n",
        blocked_word(sigtrap_blocked()),
        now.sa_handler == SIG_DFL ? "default" : "handler");
  } else if (!strcmp(mode, "resethand")) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_trap;
    action.sa_flags = SA_RESETHAND;
    sigaddset(&action.sa_mask, SIGTRAP);
    sigaction(SIGTRAP, &action, NULL);
    if (arm()) {
      return 2;
    }
    __asm__ volatile("int3");
    struct sigaction now;
    sigaction(SIGTRAP, &now, NULL);
    printf(
        "ran=%d in-handler=%s action=%s\n",
        usr1_ran,
        blocked_word(trap_saw_blocked),
        now.sa_handler == SIG_DFL ? "default" : "handler");
  } else if (!strcmp(mode, "untraced")) {
    if (clone_untraced_sighand_child() < 0) {
      return 2;
    }
    if (arm()) {
      return 2;
    }
    block(SIGTRAP);
    word = 1;
    printf("after=%s\n", blocked_word(sigtrap_blocked()));
  } else if (!strcmp(mode, "children")) {
    catch_signal(SIGTRAP, on_trap, 0);
    if (arm()) {
      return 2;
    }
    pid_t child = fork();
    if (child == 0) {
      run_int3(NULL);
      _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    pthread_t thread;
    pthread_create(&thread, NULL, run_int3_in_thread, NULL);
    pthread_join(thread, NULL);
    printf(
        "child=%d %d %d\n",
        WIFEXITED(status) && WEXITSTATUS(status) == 0,
        (int)child,
        (int)thread_tid);
  } else if (!strcmp(mode, "pending")) {
    catch_signal(SIGUSR1, note_usr1, 0);
    block(SIGUSR1);
    send_self(SIGUSR1);
    sigset_t temporary;
    sigemptyset(&temporary);
    sigaddset(&temporary, SIGTRAP);
    struct timespec timeout = {10, 0};
    if (syscall(SYS_clock_getres, ARM_AT_SIGUSR1, &word)) {
      return 2;
    }
    long ret = syscall(SYS_ppoll, NULL, 0, &timeout, &temporary, 8);
    int error = errno;
    printf(
        "ret=%ld eintr=%d ran=%d after=%s\n",
        ret,
        ret == -1 && error == EINTR,
        usr1_ran,
        blocked_word(sigtrap_blocked()));
  } else {
    return 3;
  }
  return 0;
}
