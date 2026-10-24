#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The two real syscalls bracket user branches after exec initialization. */
int main(void) {
  if (syscall(SYS_getpgid, 0) < 0)
    return 2;
  sigset_t signals;
  if (sigemptyset(&signals) || sigaddset(&signals, SIGSTKFLT) ||
      sigprocmask(SIG_UNBLOCK, &signals, 0))
    return 5;
  for (volatile uint64_t index = 0; index < 1000000; ++index) {
    __asm__ volatile("" ::: "memory");
  }
  if (syscall(SYS_getpgid, 0) < 0)
    return 3;
  return syscall(SYS_write, 1, "survived", 8) == 8 ? 0 : 4;
}
