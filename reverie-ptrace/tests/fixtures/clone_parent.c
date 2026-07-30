#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static int child_main(void *unused) {
  (void)unused;
  for (;;) {
    pause();
  }
}

int main(void) {
  const size_t stack_size = 1 << 20;
  void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED) {
    return 2;
  }
  if (clone(child_main, (char *)stack + stack_size, CLONE_PARENT | SIGCHLD,
            NULL) == -1) {
    return 3;
  }
  for (;;) {
    pause();
  }
}
