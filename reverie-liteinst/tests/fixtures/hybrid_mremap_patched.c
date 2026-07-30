#define _GNU_SOURCE
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

__asm__(".section .liteinst_move,\"ax\",@progbits\n"
        ".p2align 12\n"
        ".global reverie_liteinst_movable_getpid\n"
        ".type reverie_liteinst_movable_getpid,@function\n"
        "reverie_liteinst_movable_getpid:\n"
        "mov $39, %eax\n"
        ".global reverie_liteinst_movable_getpid_site\n"
        "reverie_liteinst_movable_getpid_site:\n"
        "syscall\n"
        ".rept 24\n"
        "nop\n"
        ".endr\n"
        "ret\n"
        ".size reverie_liteinst_movable_getpid, .-reverie_liteinst_movable_getpid\n"
        ".text\n");

extern long reverie_liteinst_movable_getpid(void);

int main(void) {
  long expected = reverie_liteinst_movable_getpid();
  if (reverie_liteinst_movable_getpid() != expected) {
    return 10;
  }

  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  uintptr_t old_page = (uintptr_t)&reverie_liteinst_movable_getpid & ~(page - 1);
  void *target_address = (void *)(uintptr_t)UINT64_C(0x30000000);
  void *target = mmap(target_address, page, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (target == MAP_FAILED || munmap(target, page) != 0) {
    return 11;
  }
  void *moved = mremap((void *)old_page, page, page,
                       MREMAP_MAYMOVE | MREMAP_FIXED, target);
  return moved == MAP_FAILED ? 12 : 13;
}
