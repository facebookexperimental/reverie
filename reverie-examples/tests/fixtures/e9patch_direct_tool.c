#include <stdint.h>

static long raw_getpid(void) {
  register long rax __asm__("rax") = 39;
  __asm__ volatile("syscall" : "+a"(rax) : : "rcx", "r11", "memory");
  return rax;
}

__attribute__((noreturn)) static void raw_exit_group(int status) {
  register long rax __asm__("rax") = 231;
  register long rdi __asm__("rdi") = status;
  __asm__ volatile("syscall" : "+a"(rax) : "D"(rdi) : "rcx", "r11", "memory");
  __builtin_unreachable();
}

int main(void) {
  raw_exit_group(raw_getpid() == 424242 ? 0 : 1);
}
