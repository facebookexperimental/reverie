/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* One of the many small shared objects of host_heap_many_dsos.c.
 *
 * Compiled once per index with -DHEAP_DSO_INDEX=<k> -shared -fPIC.  Each copy
 * has its own executable mapping and one raw getpid syscall site, so every
 * copy needs its own LiteInst trampoline arena (a site is hooked only through
 * the arena of the mapping that contains it).  A copy whose arena was not
 * allocated keeps trapping instead of being hooked.  The function has an
 * unwind-table entry because LiteInst's entry census leaves a site outside
 * every listed function on ptrace, which would also keep it trapping.
 */
#define HEAP_DSO_STR2(x) #x
#define HEAP_DSO_STR(x) HEAP_DSO_STR2(x)
#define HEAP_DSO_CAT2(a, b) a##b
#define HEAP_DSO_CAT(a, b) HEAP_DSO_CAT2(a, b)
#define HEAP_DSO_NAME(prefix) HEAP_DSO_STR(HEAP_DSO_CAT(prefix, HEAP_DSO_INDEX))

#ifndef HEAP_DSO_INDEX
#error "HEAP_DSO_INDEX must be defined"
#endif

__asm__(".text\n"
        ".p2align 4\n"
        ".global " HEAP_DSO_NAME(heap_dso_call_) "\n"
        ".type " HEAP_DSO_NAME(heap_dso_call_) ",@function\n"
        HEAP_DSO_NAME(heap_dso_call_) ":\n"
        ".cfi_startproc\n"
        "mov $39, %eax\n"
        ".global " HEAP_DSO_NAME(heap_dso_site_) "\n"
        HEAP_DSO_NAME(heap_dso_site_) ":\n"
        "syscall\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "ret\n"
        ".cfi_endproc\n"
        ".size " HEAP_DSO_NAME(heap_dso_call_) ", .-" HEAP_DSO_NAME(heap_dso_call_) "\n");
