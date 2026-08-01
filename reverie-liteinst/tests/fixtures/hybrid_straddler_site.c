#include <stdio.h>
#include <unistd.h>

__asm__(".text\n"
        ".balign 64\n"
        ".global reverie_liteinst_straddler_getpid\n"
        ".type reverie_liteinst_straddler_getpid,@function\n"
        "reverie_liteinst_straddler_getpid:\n"
        "mov $39, %eax\n"
        ".rept 58\n"
        "nop\n"
        ".endr\n"
        ".global reverie_liteinst_straddler_site\n"
        "reverie_liteinst_straddler_site:\n"
        "syscall\n"
        ".rept 8\n"
        "nop\n"
        ".endr\n"
        "ret\n"
        ".size reverie_liteinst_straddler_getpid, "
        ".-reverie_liteinst_straddler_getpid\n");

extern long reverie_liteinst_straddler_getpid(void);

int main(void) {
  long expected = -1;
  for (unsigned i = 0; i < 8; ++i) {
    long observed = reverie_liteinst_straddler_getpid();
    if (expected == -1) {
      expected = observed;
    } else if (observed != expected) {
      return 10;
    }
  }
  puts("straddler-ptrace-fallback-ok");
  return 0;
}
