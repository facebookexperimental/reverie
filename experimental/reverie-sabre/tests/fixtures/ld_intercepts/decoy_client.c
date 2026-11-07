/* A client that defines the three functions SaBRe intercepts in the dynamic
 * linker, and is built under a dynamic linker's name. Under the stand-in
 * dynamic linker it is never reached; under the real one it prints whether
 * its getppid reached the probe plugin (ROUTED) or ran natively (NATIVE). */
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DECOY(name)                                                            \
  __asm__(".text\n.globl " #name "\n.type " #name ",@function\n" #name         \
          ":\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n ret\n.size " #name \
          ",.-" #name "\n")

DECOY(_dl_init);
DECOY(_dl_map_object_deps);
DECOY(_dl_map_object);

int main(void) {
  puts(syscall(SYS_getppid) == (1L << 30) ? "ROUTED" : "NATIVE");
  return 0;
}
