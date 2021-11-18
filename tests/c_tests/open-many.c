#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define assert(b) \
  if (!(b))       \
    abort();

int main(int argc, char* argv[]) {
  const char* file = "/etc/passwd";
  int fd;

  for (int i = 0; i < 1000; i++) {
    fd = open(file, O_RDONLY);
    assert(access(file, O_RDONLY) == 0);
    assert(fd >= 0);
    close(fd);
  }

  return 0;
}
