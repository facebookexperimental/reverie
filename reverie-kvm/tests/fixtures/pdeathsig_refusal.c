/* Explicit unsupported-mode control: no claim that ENOSYS is Linux success. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  int value = -1;
  if (prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) || value != 0) return 10;
  errno = 0;
  if (prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) != -1 || errno != ENOSYS) return 11;
  value = -1;
  if (prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) || value != 0) return 12;
  if (prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0)) return 13;
  value = -1;
  if (prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) || value != 0) return 14;
  errno = 0;
  if (syscall(SYS_prctl, PR_SET_PDEATHSIG, (UINT64_C(1) << 32) | SIGUSR1,
              0, 0, 0) != -1 || errno != EINVAL) return 15;
  value = -1;
  if (prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) || value != 0) return 16;
  puts("pdeathsig nonzero-refused clear-and-query-zero width-invalid");
  return 0;
}
