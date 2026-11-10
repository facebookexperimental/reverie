#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <ucontext.h>

int main(void) {
  printf("libc_ucontext_size=%zu\n", sizeof(ucontext_t));
  printf("libc_ucontext_sigmask=%zu\n", offsetof(ucontext_t, uc_sigmask));
  printf("libc_sigset_size=%zu\n", sizeof(sigset_t));
  return 0;
}
