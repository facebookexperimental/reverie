/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static _Atomic int written;
static _Atomic int child_tid = 1;

int main(void) {
  const size_t stack_size = 1024 * 1024;
  void* stack = mmap(
      NULL,
      stack_size,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
      -1,
      0);
  if (stack == MAP_FAILED)
    return 1;
  uintptr_t* child_stack = (uintptr_t*)((char*)stack + stack_size) - 2;
  child_stack[0] = (uintptr_t)&written;
  const unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES |
      CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_SETTID |
      CLONE_CHILD_CLEARTID;
  register void* clear_tid __asm__("r10") = &child_tid;
  register unsigned long tls __asm__("r8") = 0;
  long result;
  /* The child's first action is a shared-memory write, before any syscall or
   * libc thread setup can accidentally supply the missing admission barrier. */
  __asm__ volatile(
      "syscall\n\t"
      "test %%rax, %%rax\n\t"
      "jnz 1f\n\t"
      "mov (%%rsp), %%rdi\n\t"
      "movl $1, (%%rdi)\n\t"
      "mov $60, %%rax\n\t"
      "xor %%edi, %%edi\n\t"
      "syscall\n\t"
      "ud2\n\t"
      "1:"
      : "=a"(result)
      : "0"(SYS_clone),
        "D"(flags),
        "S"(child_stack),
        "d"(0L),
        "r"(clear_tid),
        "r"(tls)
      : "rcx", "r11", "memory");
  if (result <= 0)
    return 2;
  while (atomic_load_explicit(&child_tid, memory_order_acquire) != 0)
    sched_yield();
  if (atomic_load_explicit(&written, memory_order_acquire) != 1)
    return 3;
  if (munmap(stack, stack_size) != 0)
    return 4;
  puts("thread-start-write=ok");
  return 0;
}
