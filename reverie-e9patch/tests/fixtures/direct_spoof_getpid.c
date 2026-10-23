#include <sys/syscall.h>

int main(void) {
  register long result __asm__("rax") = SYS_getpid;
  __asm__ volatile("syscall" : "+a"(result) : : "rcx", "r11", "memory");
  return result == 424242 ? 0 : 1;
}
