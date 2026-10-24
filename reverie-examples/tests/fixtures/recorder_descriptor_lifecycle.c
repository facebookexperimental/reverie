/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* No libc or dynamic loader: the recorder must see the chosen first syscall.
 * The vfork child uses only the assembly below, with no shared-stack writes.
 */
#include <asm/unistd.h>
#include <linux/fcntl.h>

#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)

static long child_identity[2] __attribute__((used));

static __attribute__((always_inline)) inline long
raw4(long number, long a, long b, long c, long d) {
  register long fourth __asm__("r10") = d;
  long result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "a"(number), "D"(a), "S"(b), "d"(c), "r"(fourth)
                   : "rcx", "r11", "memory");
  return result;
}

static int transfer(long number, long fd, void *bytes, long length) {
  char *cursor = bytes;
  while (length != 0) {
    long count = raw4(number, fd, (long)cursor, length, 0);
    if (count == -4) /* EINTR */
      continue;
    if (count <= 0 || count > length)
      return 0;
    cursor += count;
    length -= count;
  }
  return 1;
}

static int close_fd(long fd) {
  return raw4(__NR_close, fd, 0, 0, 0) == 0;
}

static __attribute__((noreturn)) void child_exit(long code) {
  raw4(__NR_exit, code, 0, 0, 0);
  __builtin_unreachable();
}

static __attribute__((noreturn)) void fork_child(long reader, long writer) {
  child_identity[0] = raw4(__NR_getpid, 0, 0, 0, 0);
  child_identity[1] = raw4(__NR_getppid, 0, 0, 0, 0);
  if (!close_fd(reader) ||
      raw4(__NR_dup3, writer, reader, O_CLOEXEC, 0) != reader ||
      !transfer(__NR_write, reader, child_identity, sizeof(child_identity)) ||
      !close_fd(reader) || !close_fd(writer))
    child_exit(90);
  child_exit(37);
}

/* Only the parent returns. The child keeps its fd numbers in registers,
 * writes identities to static storage, and exits without calling C or
 * touching the suspended parent's stack. close/dup3 affect its copied fd
 * table; the pipe's byte stream remains shared deliberately.
 */
extern long descriptor_vfork(long reader, long writer);
__asm__(
    ".text\n"
    ".type descriptor_vfork,@function\n"
    "descriptor_vfork:\n"
    "mov %rdi,%r8\n"
    "mov %rsi,%r9\n"
    "mov $" STRINGIFY(__NR_vfork) ",%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 2f\n"
    "mov $" STRINGIFY(__NR_getpid) ",%eax\n"
    "syscall\n"
    "mov %rax,child_identity(%rip)\n"
    "mov $" STRINGIFY(__NR_getppid) ",%eax\n"
    "syscall\n"
    "mov %rax,child_identity+8(%rip)\n"
    "mov %r8,%rdi\n"
    "mov $" STRINGIFY(__NR_close) ",%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 3f\n"
    "mov %r9,%rdi\n"
    "mov %r8,%rsi\n"
    "mov $0x80000,%edx\n" /* O_CLOEXEC */
    "mov $" STRINGIFY(__NR_dup3) ",%eax\n"
    "syscall\n"
    "cmp %r8,%rax\n"
    "jne 3f\n"
    "1:\n"
    "mov %r8,%rdi\n"
    "lea child_identity(%rip),%rsi\n"
    "mov $16,%edx\n"
    "mov $" STRINGIFY(__NR_write) ",%eax\n"
    "syscall\n"
    "cmp $-4,%rax\n" /* EINTR: the 16-byte pipe write is atomic. */
    "je 1b\n"
    "cmp $16,%rax\n"
    "jne 3f\n"
    "mov %r8,%rdi\n"
    "mov $" STRINGIFY(__NR_close) ",%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 3f\n"
    "mov %r9,%rdi\n"
    "mov $" STRINGIFY(__NR_close) ",%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 3f\n"
    "mov $37,%edi\n"
    "jmp 4f\n"
    "2: ret\n"
    "3: mov $90,%edi\n"
    "4: mov $" STRINGIFY(__NR_exit) ",%eax\n"
    "syscall\n"
    "ud2\n"
    ".size descriptor_vfork,.-descriptor_vfork\n");

static int first_open(int warm) {
  if (warm && raw4(__NR_getpid, 0, 0, 0, 0) <= 0)
    return 10;
  long fds[2];
  fds[0] = raw4(__NR_openat, AT_FDCWD, (long)"/dev/null",
                 O_RDONLY | O_CLOEXEC, 0);
  if (fds[0] < 0)
    return 11;
  /* Recorder's RPC after the first open occurs while that fd remains live. */
  fds[1] = raw4(__NR_openat, AT_FDCWD, (long)"/dev/null",
                 O_RDONLY | O_CLOEXEC, 0);
  if (fds[1] < 0)
    return 11;
  /* Retain both actual numbers even if either differs from native Linux. */
  if (!transfer(__NR_write, 1, fds, sizeof(fds)) ||
      !close_fd(fds[0]) || !close_fd(fds[1]))
    return 12;
  return 0;
}

static int lifetime(int copied_vfork) {
  long parent = raw4(__NR_getpid, 0, 0, 0, 0);
  int pipe_fds[2];
  if (parent <= 0 || raw4(__NR_pipe2, (long)pipe_fds, O_CLOEXEC, 0, 0) != 0)
    return 20;
  char initial = 'A';
  if (!transfer(__NR_write, pipe_fds[1], &initial, 1))
    return 21;
  long child = copied_vfork
      ? descriptor_vfork(pipe_fds[0], pipe_fds[1])
      : raw4(__NR_fork, 0, 0, 0, 0);
  if (child == 0)
    fork_child(pipe_fds[0], pipe_fds[1]);
  if (child < 0)
    return 22;
  int status = 0;
  long waited;
  do {
    waited = raw4(__NR_wait4, child, (long)&status, 0, 0);
  } while (waited == -4); /* EINTR */
  if (waited != child || status != (37 << 8))
    return 23;
  long parent_after = raw4(__NR_getpid, 0, 0, 0, 0);
  long flags = raw4(__NR_fcntl, pipe_fds[0], F_GETFD, 0, 0);
  long identity[2];
  char before = 0;
  if (!transfer(__NR_read, pipe_fds[0], &before, 1) ||
      !transfer(__NR_read, pipe_fds[0], identity, sizeof(identity)))
    return 24;
  char sent = 'P';
  char after = 0;
  if (!transfer(__NR_write, pipe_fds[1], &sent, 1) ||
      !transfer(__NR_read, pipe_fds[0], &after, 1) ||
      !close_fd(pipe_fds[1]) ||
      raw4(__NR_read, pipe_fds[0], (long)&sent, 1, 0) != 0 ||
      !close_fd(pipe_fds[0]))
    return 25;
  if (parent_after != parent || child == parent || identity[0] != child ||
      identity[1] != parent || flags != FD_CLOEXEC ||
      before != 'A' || after != 'P')
    return 26;
  long result[] = {parent, child, identity[0], identity[1], parent_after,
                   status, flags, before, after, pipe_fds[0], pipe_fds[1]};
  return transfer(__NR_write, 1, result, sizeof(result)) ? 0 : 27;
}

int descriptor_main(long *initial_stack) {
  char **argv = (char **)(initial_stack + 1);
  if (initial_stack[0] != 2)
    return 2;
  switch (argv[1][0]) {
  case 'c': return first_open(0);
  case 'w': return first_open(1);
  case 'f': return lifetime(0);
  case 'v': return lifetime(1);
  default: return 3;
  }
}

__asm__(
    ".text\n"
    ".globl _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "mov %rsp,%rdi\n"
    "and $-16,%rsp\n"
    "call descriptor_main\n"
    "mov %eax,%edi\n"
    "mov $" STRINGIFY(__NR_exit_group) ",%eax\n"
    "syscall\n"
    "ud2\n"
    ".size _start,.-_start\n"
    ".section .note.GNU-stack,\"\",@progbits\n");
