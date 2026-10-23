#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t handled, bad;
static void handler(int signal, siginfo_t* info, void* context) {
  (void)context;
  if (signal != SIGALRM || info->si_code != SI_KERNEL)
    bad = 1;
  handled++;
  if (write(1, "!", 1) != 1)
    bad = 2;
}

int main(int argc, char** argv) {
  if (argc != 2)
    return 1;
  int mode = atoi(argv[1]), fd = 1;
  struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGALRM, &action, NULL))
    return 2;
  if (mode == 1)
    fd = 2;
  if (mode == 2 || mode == 6 || mode == 7)
    fd = dup(1);
  if (mode == 3)
    fd = dup(2);
  if (fd < 0)
    return 3;
  if (mode == 5) {
    int file = open("backing", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (file < 0 || dup2(file, 1) != 1)
      return 4;
  }
  if (mode == 6 || mode == 7 || mode == 8) {
    if (close(fd))
      return 5;
    if (mode != 6) {
      int file = open("backing", O_CREAT | O_RDWR | O_TRUNC, 0600);
      if (file != fd)
        return 6;
    }
  }
  sigset_t blocked;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGALRM);
  if (mode == 15 && sigprocmask(SIG_BLOCK, &blocked, NULL))
    return 7;
  const char* data = "abc";
  size_t length = 3;
  if (mode == 13)
    data = (void*)(uintptr_t)-1;
  if (mode == 14) {
    length = 16 * 1024 * 1024 + 1;
    char* large = mmap(
        NULL,
        length,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (large == MAP_FAILED)
      return 8;
    memset(large, 'a', length);
    data = large;
  }
  unsigned long raw_fd = (unsigned long)fd;
  if (mode == 17 || mode == 19)
    raw_fd += 1UL << 32;
  if (mode == 18)
    raw_fd = (1UL << 32) | UINT32_MAX;
  errno = 0;
  long result = syscall(
      mode == 9 ? SYS_getpid : SYS_write,
      raw_fd,
      data,
      length,
      0x63617077UL,
      mode,
      0x9876UL);
  // Upper bits are ignored for lookup; mode 18 still names the invalid fd -1.
  if (mode == 6 || mode == 18) {
    if (result != -1 || errno != EBADF)
      return 9;
  } else if (mode == 13) {
    if (result != -1 || errno != EFAULT)
      return 10;
  } else if (mode == 14) {
    if (result != 16 * 1024 * 1024)
      return 11;
  } else if (mode == 9) {
    if (result != getpid())
      return 12;
  } else if (result != 3)
    return 13;
  int published = mode <= 3 || (mode >= 11 && mode <= 17);
  if (mode == 15) {
    if (handled || sigprocmask(SIG_UNBLOCK, &blocked, NULL))
      return 14;
  }
  if (handled != published || bad)
    return 15;
  sigset_t pending;
  if (sigpending(&pending) || sigismember(&pending, SIGALRM))
    return 16;
  return 0;
}
