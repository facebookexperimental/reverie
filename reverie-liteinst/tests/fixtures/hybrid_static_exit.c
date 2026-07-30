#include <stdint.h>

static long raw_syscall0(long number) {
  register long rax __asm__("rax") = number;
  __asm__ volatile("syscall" : "+a"(rax) : : "rcx", "r11", "memory");
  return rax;
}

static long raw_syscall1(long number, long arg0) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg0;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"(rdi)
                   : "rcx", "r11", "memory");
  return rax;
}

static long raw_syscall3(long number, long arg0, long arg1, long arg2) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg0;
  register long rsi __asm__("rsi") = arg1;
  register long rdx __asm__("rdx") = arg2;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"(rdi), "S"(rsi), "d"(rdx)
                   : "rcx", "r11", "memory");
  return rax;
}

static long raw_syscall4(long number, long arg0, long arg1, long arg2,
                         long arg3) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg0;
  register long rsi __asm__("rsi") = arg1;
  register long rdx __asm__("rdx") = arg2;
  register long r10 __asm__("r10") = arg3;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10)
                   : "rcx", "r11", "memory");
  return rax;
}

__attribute__((used, noinline, noreturn)) static void
start_from_stack(uintptr_t *stack) {
  if (stack[0] != 2) {
    raw_syscall1(60, 9);
    __builtin_unreachable();
  }

  const char *pid_path = (const char *)stack[2];
  long fd = raw_syscall4(257, -100, (long)pid_path, 1 | 64 | 512, 0600);
  if (fd < 0) {
    raw_syscall1(60, 10);
    __builtin_unreachable();
  }

  unsigned long pid = (unsigned long)raw_syscall0(39);
  char buffer[32];
  unsigned long cursor = sizeof(buffer);
  buffer[--cursor] = '\n';
  do {
    buffer[--cursor] = (char)('0' + pid % 10);
    pid /= 10;
  } while (pid != 0);

  if (raw_syscall3(1, fd, (long)&buffer[cursor], sizeof(buffer) - cursor) < 0) {
    raw_syscall1(60, 11);
    __builtin_unreachable();
  }
  raw_syscall1(3, fd);
  raw_syscall1(60, 0);
  __builtin_unreachable();
}

__asm__(".global _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "mov %rsp, %rdi\n"
        "and $-16, %rsp\n"
        "call start_from_stack\n"
        ".size _start, .-_start\n");
