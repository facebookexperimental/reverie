#include <errno.h>
#include <linux/random.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  void *allocation = malloc(1);
  if (allocation == NULL) {
    return 10;
  }
  free(allocation);

  uint8_t first[24];
  uint8_t second[16];
  if (syscall(SYS_getrandom, first, sizeof(first), GRND_NONBLOCK) !=
      (long)sizeof(first)) {
    return errno == 0 ? 11 : errno;
  }
  if (syscall(SYS_getrandom, second, sizeof(second), 0) !=
      (long)sizeof(second)) {
    return errno == 0 ? 12 : errno;
  }
  return 0;
}
