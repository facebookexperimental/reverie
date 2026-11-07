#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* Run this executable from the normal executable test directory. Only argv[1]
 * is on the test-private noexec mount. argv[2] is the verified RX PT_LOAD offset.
 * This is a native preflight, not a fake private-loader callback. */
int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: native-noexec-probe ELF RX_FILE_OFFSET\n");
    return 2;
  }
  char* end = NULL;
  errno = 0;
  uint64_t offset = strtoull(argv[2], &end, 0);
  if (errno != 0 || end == argv[2] || *end != 0 || offset == 0 ||
      offset > INT64_MAX || offset % 4096 != 0 || sysconf(_SC_PAGESIZE) != 4096) {
    fprintf(stderr, "invalid x86_64 fixture offset/page size\n");
    return 2;
  }
  int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
  struct stat st;
  struct statvfs fs;
  if (fd < 0 || fstat(fd, &st) != 0 || fstatvfs(fd, &fs) != 0 ||
      !S_ISREG(st.st_mode) || st.st_size <= (off_t)offset || !(fs.f_flag & ST_NOEXEC)) {
    fprintf(stderr, "noexec input precondition not established\n");
    if (fd >= 0)
      close(fd);
    return 2;
  }
  /* Match the private loader's temporary write permission on a non-X segment. */
  void* first = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (first == MAP_FAILED) {
    perror("non-X file mmap");
    close(fd);
    return 2;
  }
  if (*(volatile unsigned char*)first != 0x7f) {
    fprintf(stderr, "input does not start with ELF header\n");
    munmap(first, 4096);
    close(fd);
    return 2;
  }
  errno = 0;
  void* executable = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE, fd, (off_t)offset);
  int error = errno;
  if (executable != MAP_FAILED) {
    fprintf(stderr, "noexec precondition failed: executable mmap succeeded\n");
    munmap(executable, 4096);
    munmap(first, 4096);
    close(fd);
    return 2;
  }
  if (munmap(first, 4096) != 0 || close(fd) != 0) {
    perror("preflight cleanup");
    return 2;
  }
  /* Linux mmap's noexec-mount refusal is EPERM. Other errors are not evidence. */
  if (error != EPERM) {
    fprintf(stderr, "unexpected executable mmap errno=%d (wanted EPERM)\n", error);
    return 2;
  }
  printf("NOEXEC_PROBE nonexec_mmap=ok executable_mmap=EPERM offset=0x%" PRIx64 "\n", offset);
  return 0;
}
