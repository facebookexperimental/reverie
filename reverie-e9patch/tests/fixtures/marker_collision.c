#include <stdint.h>
#include <sys/syscall.h>

struct fake_frame {
  uint64_t words[18];
};

int main(void) {
  struct fake_frame frame = {0};
  frame.words[15] = SYS_read;
  frame.words[17] = 0x401000;
  __asm__ volatile("movabs $0x7265766539653970, %%rax\n\t"
                   "mov %0, %%rdi\n\t"
                   "int3"
                   :
                   : "r"(&frame)
                   : "rax", "rdi", "memory");
  return 0;
}
