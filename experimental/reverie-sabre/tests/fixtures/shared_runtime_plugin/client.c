/* getpid through libc's wrapper and through syscall(2), both sites the SaBRe
 * loader rewrites, then through short_getpid, whose site it cannot rewrite
 * (under the raw launch it stays a plain syscall and traps to the armed
 * filter), then an RDTSC, which the loader rewrites too, then a vDSO
 * clock_gettime. */
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

long short_getpid(void);

/* The site is a branch target followed by RET, so nothing around it can be
 * relocated to make room for a jump (as in prefixed_syscall's probe.S). */
__asm__(".text\n"
        ".globl short_getpid\n"
        ".type short_getpid,@function\n"
        "short_getpid:\n"
        "  mov $39, %eax\n"
        "  jmp short_getpid_site\n"
        ".size short_getpid,.-short_getpid\n"
        ".type short_getpid_site,@function\n"
        "short_getpid_site:\n"
        "  syscall\n"
        "  ret\n"
        ".size short_getpid_site,.-short_getpid_site\n");

int main(void) {
  long first = getpid();
  long second = syscall(SYS_getpid);
  long third = short_getpid();
  unsigned long long tsc = __rdtsc();
  struct timespec now;
  int clock = clock_gettime(CLOCK_MONOTONIC, &now);
  int clock_errno = errno;
  printf("%ld %ld %ld %#llx %d %d\n", first, second, third, tsc, clock,
         clock_errno);
  return 0;
}
