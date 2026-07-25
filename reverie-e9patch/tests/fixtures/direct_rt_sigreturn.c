#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

struct kernel_sigaction {
  void (*handler)(int);
  unsigned long flags;
  void (*restorer)(void);
  uint64_t mask;
};

static volatile sig_atomic_t handled;

static void handler(int signal) {
  if (signal == SIGUSR1) {
    handled = 1;
  }
}

__attribute__((naked)) static void restorer(void) {
  __asm__ volatile("mov $15, %rax\n\t"
                   "syscall\n\t"
                   "ud2");
}

__attribute__((noinline)) static long
direct_rt_sigaction(int signal, const struct kernel_sigaction *action) {
  register long rax __asm__("rax") = SYS_rt_sigaction;
  register long r10 __asm__("r10") = sizeof(uint64_t);
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"((long)signal), "S"(action), "d"(0L), "r"(r10)
                   : "rcx", "r11", "memory");
  return rax;
}

int main(void) {
  const struct kernel_sigaction action = {
      .handler = handler,
      .flags = SA_RESTORER,
      .restorer = restorer,
      .mask = 0,
  };
  if (direct_rt_sigaction(SIGUSR1, &action) != 0) {
    return 2;
  }
  if (raise(SIGUSR1) != 0) {
    return 3;
  }
  return handled == 1 ? 0 : 4;
}
