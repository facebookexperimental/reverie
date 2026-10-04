/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct operation {
  uint64_t fd, buffer, number, rights;
  int64_t result;
  uint64_t returned, original;
};
extern void nested_pkey_call(struct operation*);
__asm__(
    ".text\n.global nested_pkey_call\n.type nested_pkey_call,@function\n"
    "nested_pkey_call:\n push %r12\n mov %rdi,%r12\n xor %ecx,%ecx\n rdpkru\n"
    "mov %rax,48(%r12)\n mov 24(%r12),%eax\n xor %ecx,%ecx\n xor %edx,%edx\n wrpkru\n lfence\n"
    "mov 16(%r12),%rax\n mov 0(%r12),%rdi\n mov 8(%r12),%rsi\n mov $1,%edx\n mov 24(%r12),%r10\n syscall\n"
    "mov %rax,32(%r12)\n xor %ecx,%ecx\n rdpkru\n mov %rax,40(%r12)\n mov 48(%r12),%eax\n"
    "xor %ecx,%ecx\n xor %edx,%edx\n wrpkru\n lfence\n pop %r12\n ret\n"
    ".size nested_pkey_call,.-nested_pkey_call\n");

int main(int argc, char** argv) {
  assert(argc == 2);
  unsigned a, b, c, d;
  __asm__ volatile("cpuid"
                   : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                   : "a"(0), "c"(0));
  if (a < 7)
    return 77;
  __asm__ volatile("cpuid"
                   : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                   : "a"(7), "c"(0));
  if (!(c & (1U << 4)))
    return 77;
  int key = syscall(SYS_pkey_alloc, 0, 0);
  assert(key == 1);
  // Explicitly set up the fixture's permissions. pkey_alloc's implicit
  // register side effect is outside this nested-forwarding comparison.
  __asm__ volatile("wrpkru\n lfence" ::"a"(0), "c"(0), "d"(0));
  size_t page = sysconf(_SC_PAGESIZE);
  unsigned char* buffer = mmap(
      NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(buffer != MAP_FAILED);
  assert(
      syscall(SYS_pkey_mprotect, buffer, page, PROT_READ | PROT_WRITE, key) ==
      0);
  *buffer = 0x35;
  int pipefd[2];
  assert(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0);
  int native = strcmp(argv[1], "native") == 0;
  for (unsigned rights = 0; rights < 3; ++rights) {
    struct operation op = {
        .fd = pipefd[1],
        .buffer = (uintptr_t)buffer,
        .number = native ? SYS_write : SYS_getpid,
        .rights = rights << 2};
    errno = E2BIG;
    nested_pkey_call(&op);
    assert(errno == E2BIG);
    assert(op.returned == op.rights);
    unsigned char received = 0;
    ssize_t count = read(pipefd[0], &received, 1);
    printf(
        "rights=%u result=%ld raw_errno=%ld remaining=%ld pipe=%u pkru=%lu\n",
        rights,
        op.result,
        op.result < 0 ? -op.result : 0,
        count,
        received,
        op.returned);
  }
  return 0;
}
