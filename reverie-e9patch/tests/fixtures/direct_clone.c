#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) static long direct_clone(void) {
  register long rax __asm__("rax") = SYS_clone;
  register long r10 __asm__("r10") = 0;
  register long r8 __asm__("r8") = 0;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"((long)SIGCHLD), "S"(0L), "d"(0L), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  return rax;
}

int main(void) {
  long child = direct_clone();
  if (child == 0) {
    _exit(0);
  }
  if (child < 0) {
    return 2;
  }

  int status = 0;
  if (waitpid((pid_t)child, &status, 0) != child) {
    return 3;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 4;
}
