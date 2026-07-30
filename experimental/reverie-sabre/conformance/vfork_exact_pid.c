#define _GNU_SOURCE

#include <asm/prctl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum { CHILD_STACK_SIZE = 1024 * 1024 };

static _Atomic int vfork_ready;
static _Atomic int ordinary_done;
static _Atomic int ordinary_result;

static void spin_until(_Atomic int *value) {
  while (atomic_load_explicit(value, memory_order_acquire) == 0) {
    __asm__ volatile("pause" ::: "memory");
  }
}

static int vfork_child(void *unused) {
  (void)unused;

  struct sigaction action = {0};
  action.sa_handler = SIG_IGN;
  errno = 0;
  int child_result =
      sigaction(SIGUSR1, &action, NULL) == -1 && errno == ENOSYS ? 0 : 1;

  atomic_store_explicit(&vfork_ready, 1, memory_order_release);
  spin_until(&ordinary_done);
  return child_result;
}

static void *ordinary_fork_thread(void *unused) {
  (void)unused;
  spin_until(&vfork_ready);

  long child = syscall(SYS_fork);
  if (child == 0) {
    long pid = syscall(SYS_getpid);
    syscall(SYS_exit, pid > 0 ? 0 : 2);
    __builtin_unreachable();
  }

  int result = 0;
  int status = 0;
  if (child < 0 || waitpid((pid_t)child, &status, 0) != child ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    result = 3;
  }
  atomic_store_explicit(&ordinary_result, result, memory_order_release);
  atomic_store_explicit(&ordinary_done, 1, memory_order_release);
  return NULL;
}

int main(void) {
  void *child_stack = malloc(CHILD_STACK_SIZE);
  if (child_stack == NULL) {
    perror("malloc");
    return 10;
  }

  unsigned long fs_base = 0;
  if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base) != 0) {
    perror("arch_prctl");
    return 11;
  }

  pthread_t worker;
  int error = pthread_create(&worker, NULL, ordinary_fork_thread, NULL);
  if (error != 0) {
    errno = error;
    perror("pthread_create");
    return 12;
  }

  int flags = CLONE_VM | CLONE_VFORK | CLONE_SETTLS | CLONE_SIGHAND | SIGCHLD;
  void *stack_top = (char *)child_stack + CHILD_STACK_SIZE;
  pid_t vfork_pid = clone(vfork_child, stack_top, flags, NULL, NULL,
                          (void *)(uintptr_t)fs_base, NULL);
  if (vfork_pid < 0) {
    perror("clone");
    return 13;
  }

  int status = 0;
  if (waitpid(vfork_pid, &status, 0) != vfork_pid) {
    perror("waitpid vfork");
    return 14;
  }
  error = pthread_join(worker, NULL);
  if (error != 0) {
    errno = error;
    perror("pthread_join");
    return 15;
  }

  free(child_stack);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "vfork child failed: status=%d\n", status);
    return 16;
  }
  if (atomic_load_explicit(&ordinary_result, memory_order_acquire) != 0) {
    fprintf(stderr, "ordinary fork child entered the vfork gate\n");
    return 17;
  }

  return 0;
}
