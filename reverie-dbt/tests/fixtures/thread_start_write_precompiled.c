/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Execute the shared child-entry blocks in the parent before creating a
 * thread. The native test then delays publication of that thread's identity
 * and checks its first shared-memory write. Reusing these compiled blocks
 * must not bypass admission. */
#define _GNU_SOURCE
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static _Atomic int written;
static _Atomic int child_tid = 1;
extern void warm_child_entry(void* marker);
extern long
create_raw_thread(unsigned long flags, void* stack, void* clear_tid);
__asm__(
    ".text\n"
    ".global warm_child_entry\n"
    ".type warm_child_entry,@function\n"
    "warm_child_entry:\n"
    "push %rdi\n"
    "mov $1,%r9\n"
    "xor %eax,%eax\n"
    "jmp child_clone_entry\n"
    ".global create_raw_thread\n"
    ".type create_raw_thread,@function\n"
    "create_raw_thread:\n"
    "mov %rdx,%r10\n"
    "xor %edx,%edx\n"
    "xor %r8d,%r8d\n"
    "xor %r9d,%r9d\n"
    "mov $56,%eax\n"
    "syscall\n"
    "child_clone_entry:\n"
    "test %rax,%rax\n"
    "jnz parent_return\n"
    "mov (%rsp),%rdi\n"
    "movl $1,(%rdi)\n"
    "test %r9,%r9\n"
    "jnz warm_return\n"
    "mov $60,%eax\n"
    "xor %edi,%edi\n"
    "syscall\n"
    "ud2\n"
    "warm_return:\n"
    "add $8,%rsp\n"
    "parent_return:\n"
    "ret\n");
int main(void) {
  const size_t size = 1024 * 1024;
  void* stack = mmap(
      NULL,
      size,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
      -1,
      0);
  if (stack == MAP_FAILED)
    return 1;
  uintptr_t* top = (uintptr_t*)((char*)stack + size) - 2;
  top[0] = (uintptr_t)&written;
  warm_child_entry(&written);
  if (atomic_load(&written) != 1)
    return 2;
  atomic_store(&written, 0);
  unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
      CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
  if (create_raw_thread(flags, top, &child_tid) <= 0)
    return 3;
  while (atomic_load(&child_tid) != 0)
    sched_yield();
  if (atomic_load(&written) != 1)
    return 4;
  puts("precompiled-thread-start-write=ok");
  return munmap(stack, size) != 0;
}
