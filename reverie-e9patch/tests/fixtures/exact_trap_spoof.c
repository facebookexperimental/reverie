#include <stdint.h>
#include <sys/syscall.h>

struct fake_frame {
  uint64_t words[18];
};

extern char recovered_getpid_syscall;

/* Keep one genuine syscall site so e9tool maps the replacement payload. */
__attribute__((noinline, used)) static long recovered_getpid(void) {
  register long result __asm__("rax") = SYS_getpid;
  __asm__ volatile(".global recovered_getpid_syscall\n"
                   "recovered_getpid_syscall:\n"
                   "syscall"
                   : "+a"(result)
                   :
                   : "rcx", "r11", "memory");
  return result;
}

int main(void) {
  struct fake_frame frame = {0};
  frame.words[15] = SYS_getpid;
#ifdef SPOOF_PATCHED_SITE
  frame.words[17] = (uintptr_t)&recovered_getpid_syscall;
#else
  frame.words[17] = (uintptr_t)&main;
#endif

  /*
   * Call the real e9patch fallback stub, so both the marker and trap RIP are
   * exact. The fake frame names main(), not the recovered syscall site.
   */
  __asm__ volatile("call *%1"
                   :
                   : "D"(&frame), "r"((uintptr_t)0x70001000)
                   : "rax", "rcx", "r11", "memory");
  return 0;
}
