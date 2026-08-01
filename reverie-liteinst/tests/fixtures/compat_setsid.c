#include <errno.h>
#include <stddef.h>

__asm__(".text\n"
        ".p2align 6\n"
        ".global reverie_liteinst_compat_setsid\n"
        ".type reverie_liteinst_compat_setsid,@function\n"
        "reverie_liteinst_compat_setsid:\n"
        "mov $112, %eax\n"
        ".global reverie_liteinst_compat_setsid_site\n"
        "reverie_liteinst_compat_setsid_site:\n"
        "syscall\n"
        ".fill 6, 1, 0x90\n"
        "ret\n"
        ".size reverie_liteinst_compat_setsid, "
        ".-reverie_liteinst_compat_setsid\n"
        ".p2align 6\n"
        ".global reverie_liteinst_compat_write\n"
        ".type reverie_liteinst_compat_write,@function\n"
        "reverie_liteinst_compat_write:\n"
        "mov $1, %eax\n"
        ".global reverie_liteinst_compat_write_site\n"
        "reverie_liteinst_compat_write_site:\n"
        "syscall\n"
        ".fill 6, 1, 0x90\n"
        "ret\n"
        ".size reverie_liteinst_compat_write, "
        ".-reverie_liteinst_compat_write\n");

extern long reverie_liteinst_compat_setsid(void);
extern long reverie_liteinst_compat_write(int fd, const void *buffer,
                                         size_t length);

int main(void) {
  static const char message[] = "setsid-rejected\n";
  if (reverie_liteinst_compat_setsid() != -EPERM) {
    return 1;
  }
  return reverie_liteinst_compat_write(1, message, sizeof(message) - 1) ==
                 sizeof(message) - 1
             ? 0
             : 2;
}
