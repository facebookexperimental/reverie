#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if (argc != 2)
    return 90;
  int vector = strcmp(argv[1], "vector") == 0;
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return 91;
  if (strcmp(argv[1], "partitioned") == 0) {
    unsigned char all[70001];
    int alias = dup(fd), second = fcntl(fd, F_DUPFD_CLOEXEC, 20);
    if (alias < 0 || second < 20)
      return 94;
    size_t position = 0;
    for (unsigned iteration = 0; position < sizeof(all); ++iteration) {
      size_t count = iteration % 2 ? 4097 : 4093;
      if (count > sizeof(all) - position)
        count = sizeof(all) - position;
      ssize_t result;
      if (iteration % 2 && count >= 1056) {
        struct iovec parts[] = {
            {all + position, 17},
            {all + position + 17, 1039},
            {all + position + 1056, count - 1056}};
        result = readv(alias, parts, 3);
      } else {
        result = read(iteration % 3 ? second : fd, all + position, count);
      }
      if (result != (ssize_t)count)
        return 95;
      position += count;
    }
    if (close(fd) || close(alias) || close(second))
      return 96;
    return fwrite(all, 1, sizeof(all), stdout) == sizeof(all) ? 0 : 97;
  }
  unsigned char bytes[4096];
  struct iovec iov[] = {{bytes, 17}, {bytes + 17, 1039}, {bytes + 1056, 3040}};
  size_t total = 0;
  for (int i = 0; i < 17; ++i) {
    ssize_t n = vector ? readv(fd, iov, 3) : read(fd, bytes, sizeof(bytes));
    if (n != sizeof(bytes)) {
      fprintf(
          stderr,
          "%s iteration=%d total=%zu result=%zd errno=%d\n",
          argv[1],
          i,
          total,
          n,
          errno);
      return 92;
    }
    total += (size_t)n;
  }
  if (close(fd) != 0)
    return 93;
  printf("%s total=%zu\n", argv[1], total);
  return 0;
}
