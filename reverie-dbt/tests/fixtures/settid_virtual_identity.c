/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* The TID words Linux stores for CLONE_PARENT_SETTID and CLONE_CHILD_SETTID
 * hold the TID the guest sees: the value clone returns, and the child's own
 * gettid. glibc keeps the CLONE_PARENT_SETTID word as a thread's TID, and
 * pthread_join waits on it.
 *
 * 1. A process clone with CLONE_PARENT_SETTID: the word equals clone's result.
 * 2. A thread clone with CLONE_PARENT_SETTID and CLONE_CHILD_CLEARTID, as
 *    pthread_create makes: the word equals the new thread's gettid. The thread
 *    is a raw clone whose child runs only system calls, as in
 *    thread_start_write.c, so no libc thread setup is involved.
 * 3. A process clone with CLONE_CHILD_SETTID, as fork makes: in the child, the
 *    word equals the child's getpid.
 * 4. A process clone3 with both flags and distinct words: the parent_tid word
 *    equals the result, and in the child the child_tid word equals getpid.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t parent_word = -1;
static pid_t thread_word = -1;
static _Atomic pid_t thread_seen = -1;
static _Atomic pid_t thread_clear = 1;
static pid_t child_word = -1;
static pid_t clone3_parent_word = -1;
static pid_t clone3_child_word = -1;

/* A standalone native client does not rewrite procfs readlink payloads. These
 * kernel witnesses deliberately bypass every getter/clone/SETTID projection.
 * Shared fixture output survives the separate address spaces of process clones;
 * it is observation data, not a runtime identity map.
 */
struct kernel_witness {
  pid_t process;
  pid_t child;
  pid_t child_word;
  pid_t cloned3;
  pid_t clone3_word;
};
static struct kernel_witness* kernel;
static char thread_kernel_path[64];
static long thread_kernel_path_length = -1;
static const char thread_self_path[] = "/proc/thread-self";

static pid_t tid_from_kernel_path(const char* path, pid_t expected_pid) {
  int pid = -1;
  int tid = -1;
  char extra;
  if (sscanf(path, "%d/task/%d%c", &pid, &tid, &extra) != 2 ||
      pid <= 0 || tid <= 0 || (expected_pid > 0 && pid != expected_pid))
    return -1;
  return (pid_t)tid;
}

static pid_t kernel_tid(void) {
  char path[64];
  ssize_t size = readlink(thread_self_path, path, sizeof(path) - 1);
  if (size <= 0 || (size_t)size >= sizeof(path) - 1)
    return -1;
  path[size] = '\0';
  return tid_from_kernel_path(path, 0);
}

/* struct clone_args from linux/sched.h, up to exit_signal. */
struct settid_clone_args {
  uint64_t flags;
  uint64_t pidfd;
  uint64_t child_tid;
  uint64_t parent_tid;
  uint64_t exit_signal;
  uint64_t stack;
  uint64_t stack_size;
  uint64_t tls;
};

static int exit_child(void* argument) {
  (void)argument;
  kernel->process = kernel_tid();
  return 0;
}

/* A thread clone whose child stores its own gettid in thread_seen and exits.
 * Returns clone's result in the parent. */
static long clone_recording_thread(void) {
  const size_t stack_size = 1024 * 1024;
  void* stack = mmap(
      NULL,
      stack_size,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
      -1,
      0);
  if (stack == MAP_FAILED)
    return -1;
  uintptr_t* child_stack = (uintptr_t*)((char*)stack + stack_size) - 4;
  child_stack[0] = (uintptr_t)&thread_seen;
  child_stack[1] = (uintptr_t)thread_self_path;
  child_stack[2] = (uintptr_t)thread_kernel_path;
  child_stack[3] = (uintptr_t)&thread_kernel_path_length;
  const unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES |
      CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID |
      CLONE_CHILD_CLEARTID;
  register void* clear_tid __asm__("r10") = &thread_clear;
  register unsigned long tls __asm__("r8") = 0;
  long result;
  __asm__ volatile(
      "syscall\n\t"
      "test %%rax, %%rax\n\t"
      "jnz 1f\n\t"
      /* readlink's kernel payload is independent of the following gettid. */
      "mov $89, %%eax\n\t"
      "mov 8(%%rsp), %%rdi\n\t"
      "mov 16(%%rsp), %%rsi\n\t"
      "mov $63, %%edx\n\t"
      "syscall\n\t"
      "mov 24(%%rsp), %%rdi\n\t"
      "mov %%rax, (%%rdi)\n\t"
      "mov $186, %%eax\n\t"
      "syscall\n\t"
      "mov (%%rsp), %%rdi\n\t"
      "movl %%eax, (%%rdi)\n\t"
      "mov $60, %%eax\n\t"
      "xor %%edi, %%edi\n\t"
      "syscall\n\t"
      "ud2\n\t"
      "1:"
      : "=a"(result)
      : "0"(SYS_clone),
        "D"(flags),
        "S"(child_stack),
        "d"(&thread_word),
        "r"(clear_tid),
        "r"(tls)
      : "rcx", "r11", "memory");
  return result;
}

static int check_child_word(void* argument) {
  (void)argument;
  kernel->child = kernel_tid();
  kernel->child_word = child_word;
  return child_word == getpid() ? 0 : 1;
}

static char* new_stack(void) {
  char* stack = malloc(1 << 16);
  if (stack == NULL) {
    perror("malloc");
    exit(1);
  }
  return stack + (1 << 16);
}

int main(void) {
  kernel = mmap(
      NULL, sizeof(*kernel), PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (kernel == MAP_FAILED) {
    perror("kernel witness mmap");
    return 1;
  }
  pid_t root_kernel = kernel_tid();
  int root_kernel_ok = root_kernel > 0 && getpid() == root_kernel &&
      syscall(SYS_gettid) == root_kernel;
  pid_t process = clone(
      exit_child,
      new_stack(),
      CLONE_PARENT_SETTID | SIGCHLD,
      NULL,
      &parent_word);
  if (process <= 0 || waitpid(process, NULL, 0) != process) {
    perror("process clone");
    return 1;
  }

  pid_t thread = (pid_t)clone_recording_thread();
  if (thread <= 0) {
    fprintf(stderr, "thread clone failed: %d\n", (int)thread);
    return 1;
  }
  /* The kernel clears thread_clear when the thread exits. */
  while (atomic_load_explicit(&thread_clear, memory_order_acquire) != 0)
    sched_yield();

  pid_t forked = clone(
      check_child_word,
      new_stack(),
      CLONE_CHILD_SETTID | SIGCHLD,
      NULL,
      NULL,
      NULL,
      &child_word);
  int status = 0;
  if (forked <= 0 || waitpid(forked, &status, 0) != forked) {
    perror("child-settid clone");
    return 1;
  }

  struct settid_clone_args clone3_args = {
      .flags = CLONE_PARENT_SETTID | CLONE_CHILD_SETTID,
      .child_tid = (uint64_t)(uintptr_t)&clone3_child_word,
      .parent_tid = (uint64_t)(uintptr_t)&clone3_parent_word,
      .exit_signal = SIGCHLD,
  };
  pid_t cloned3 = (pid_t)syscall(SYS_clone3, &clone3_args, sizeof(clone3_args));
  if (cloned3 == 0) {
    kernel->cloned3 = kernel_tid();
    kernel->clone3_word = clone3_child_word;
    _exit(clone3_child_word == getpid() ? 0 : 1);
  }
  int clone3_status = 0;
  if (cloned3 < 0 || waitpid(cloned3, &clone3_status, 0) != cloned3) {
    perror("clone3");
    return 1;
  }

  int parent_ok = parent_word == process;
  pid_t seen = atomic_load_explicit(&thread_seen, memory_order_acquire);
  int thread_ok = thread_word == thread && seen == thread;
  int child_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  int clone3_ok = clone3_parent_word == cloned3 && WIFEXITED(clone3_status) &&
      WEXITSTATUS(clone3_status) == 0;
  printf(
      "settid parent=%d thread=%d child=%d clone3=%d\n",
      parent_ok,
      thread_ok,
      child_ok,
      clone3_ok);
  pid_t thread_kernel = -1;
  if (thread_kernel_path_length > 0 && thread_kernel_path_length < 63)
    thread_kernel = tid_from_kernel_path(thread_kernel_path, root_kernel);
  int kernel_ok = root_kernel_ok && kernel->process > 0 &&
      process == kernel->process && parent_word == kernel->process &&
      thread_kernel > 0 && thread == thread_kernel &&
      thread_word == thread_kernel && seen == thread_kernel &&
      kernel->child > 0 && forked == kernel->child &&
      kernel->child_word == kernel->child && kernel->cloned3 > 0 &&
      cloned3 == kernel->cloned3 && clone3_parent_word == kernel->cloned3 &&
      kernel->clone3_word == kernel->cloned3;
  if (!kernel_ok) {
    fprintf(
        stderr,
        "kernel identity mismatch: root=%d process=%d/%d thread=%d/%d "
        "child=%d/%d clone3=%d/%d\n",
        root_kernel_ok, (int)process, (int)kernel->process,
        (int)thread, (int)thread_kernel, (int)forked, (int)kernel->child,
        (int)cloned3, (int)kernel->cloned3);
  }
  if (!parent_ok || !thread_ok || !child_ok || !clone3_ok) {
    fprintf(
        stderr,
        "process=%d parent_word=%d thread=%d thread_word=%d thread_seen=%d\n",
        (int)process,
        (int)parent_word,
        (int)thread,
        (int)thread_word,
        (int)seen);
    return 1;
  }
  return kernel_ok ? 0 : 1;
}
