#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static int mode;
static _Atomic int peer_started, peer_release, peer_finished;
static _Atomic int target_entered, target_after, reuse_entered, nested_entered;
static volatile sig_atomic_t usr1_calls, usr2_calls, fault_calls;
static pthread_t nested;
static int raw_tid;
static char raw_stack[65536] __attribute__((aligned(16)));
static void handler(int sig) {
  if (sig == SIGUSR1)
    ++usr1_calls;
  else if (sig == SIGUSR2)
    ++usr2_calls;
  else if (sig == SIGSEGV)
    ++fault_calls;
  else
    _exit(40);
}
static void* peer(void* unused) {
  (void)unused;
  atomic_store(&peer_started, 1);
  while (!atomic_load(&peer_release))
    sched_yield();
  atomic_store(&peer_finished, 1);
  return (void*)(uintptr_t)41;
}
static void* nested_worker(void* unused) {
  (void)unused;
  atomic_store(&nested_entered, 1);
  return (void*)(uintptr_t)43;
}
static void* target(void* unused) {
  (void)unused;
  atomic_store(&target_entered, 1);
  if (mode == 8) {
    uintptr_t zero = 0;
    asm volatile("mov (%0), %%rax" : : "r"(zero) : "rax", "memory");
  } else if (mode == 9) {
    if (pthread_create(&nested, NULL, nested_worker, NULL))
      _exit(41);
  } else {
    syscall(SYS_getpid);
  }
  atomic_store(&target_after, 1);
  return (void*)(uintptr_t)37;
}
static int raw_target(void* unused) {
  target(unused);
  return 0;
}
static void* reuse(void* unused) {
  (void)unused;
  atomic_store(&reuse_entered, 1);
  return (void*)(uintptr_t)42;
}
int main(int argc, char** argv) {
  if (argc != 2)
    return 20;
  mode = atoi(argv[1]);
  alarm(15);
  if (mode <= 2 || mode == 24) {
    puts("unexpected-guest-entry");
    return 90;
  }
  if (mode == 12) {
    if (write(1, "terminal-before-exec\n", 21) != 21)
      return 21;
    char* next[] = {argv[0], "24", NULL};
    execv(argv[0], next);
    return 22;
  }
  struct sigaction action = {0};
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  // SIGUSR2 remains pending until the first handler's rt_sigreturn restores it.
  sigaddset(&action.sa_mask, SIGUSR2);
  if (sigaction(SIGUSR1, &action, NULL) || sigaction(SIGUSR2, &action, NULL) ||
      sigaction(SIGSEGV, &action, NULL))
    return 23;
  // Each diagnostic getpid below waits for that child's Tool exit observation.
  // It occurs before pthread_join, which can overwrite libc's cleared TID word
  // with -1, and before a later pthread_create can reuse the descriptor.
  pthread_t peer_thread, target_thread, reuse_thread;
  void* result = NULL;
  if (pthread_create(&peer_thread, NULL, peer, NULL))
    return 24;
  while (!atomic_load(&peer_started))
    sched_yield();
  if (mode == 7) {
    // Unlike pthread_create's libc bootstrap, raw clone does not temporarily
    // block every signal. This must exercise delivery before any child code.
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
        CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID |
        CLONE_CHILD_CLEARTID;
    if (clone(
            raw_target,
            raw_stack + sizeof(raw_stack),
            flags,
            NULL,
            &raw_tid,
            NULL,
            &raw_tid) < 0)
      return 25;
    syscall(SYS_getpid, 0x7465726dUL, 2UL);
    int observed;
    while ((observed = __atomic_load_n(&raw_tid, __ATOMIC_SEQ_CST)) > 0)
      syscall(SYS_futex, &raw_tid, FUTEX_WAIT, observed, NULL, NULL, 0);
  } else {
    if (pthread_create(&target_thread, NULL, target, NULL))
      return 25;
    syscall(SYS_getpid, 0x7465726dUL, 2UL);
    if (pthread_join(target_thread, &result))
      return 26;
  }
  if (atomic_load(&target_after) != (mode == 13))
    return 27;
  if (atomic_load(&target_entered) != (mode != 3 && mode != 7))
    return 28;
  if (usr1_calls != (mode == 6 || mode == 13) || usr2_calls || fault_calls)
    return 29;
  if (mode == 13 && result != (void*)(uintptr_t)37)
    return 30;
  if (mode == 9) {
    syscall(SYS_getpid, 0x7465726dUL, 3UL);
    if (pthread_join(nested, &result) || result != (void*)(uintptr_t)43 ||
        !atomic_load(&nested_entered))
      return 31;
  }
  if (pthread_create(&reuse_thread, NULL, reuse, NULL))
    return 32;
  syscall(SYS_getpid, 0x7465726dUL, mode == 9 ? 4UL : 3UL);
  if (pthread_join(reuse_thread, &result) || result != (void*)(uintptr_t)42 ||
      !atomic_load(&reuse_entered))
    return 33;
  atomic_store(&peer_release, 1);
  syscall(SYS_getpid, 0x7465726dUL, 1UL);
  if (pthread_join(peer_thread, &result) || result != (void*)(uintptr_t)41 ||
      !atomic_load(&peer_finished))
    return 34;
  puts("terminal-lifecycle-checked");
  return 0;
}
