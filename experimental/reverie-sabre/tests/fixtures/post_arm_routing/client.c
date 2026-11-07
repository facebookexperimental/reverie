/* Sets its own FS base to its current value through the libc syscall wrapper,
 * then prints the probe plugin's answer for getppid (see plugin.c), or the
 * native result if the plugin did not answer. */
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  unsigned long fs = 0;
  if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fs) != 0 ||
      syscall(SYS_arch_prctl, ARCH_SET_FS, fs) != 0)
    return 2;
  const long answered = 1L << 30;
  long result = (long)getppid();
  if (result < answered - 1000)
    printf("NATIVE=%ld\n", result);
  else
    printf("ROUTED=%ld\n", result - answered);
  return 0;
}
