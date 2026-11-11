/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * An in-guest runtime installs its Tool from its preload's constructor, before
 * main, and then handles this program's syscalls. A runtime thread-local whose
 * type needs dropping registers a thread-exit destructor on first access,
 * through libc's __cxa_thread_atexit_impl, and libc allocates the record for
 * it from this program's heap: the heap then holds allocations this program
 * never made.
 *
 * This program defines __cxa_thread_atexit_impl itself (the test links it with
 * -rdynamic, so the runtime's reference binds here), checks that the dynamic
 * linker resolves the name to this definition, and counts registrations at
 * main's entry and again at its end, after its own output syscalls. It runs no
 * destructors: a C program registers none, and leaving a runtime's
 * thread-local undestroyed at exit frees nothing that process exit does not.
 * It also prints the heap at main's entry, before the program allocates
 * anything.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <malloc.h>
#include <stdio.h>

static unsigned registrations;

int __cxa_thread_atexit_impl(void (*destructor)(void *), void *object, void *dso) {
    (void)destructor;
    (void)object;
    (void)dso;
    registrations++;
    return 0;
}

int main(void) {
    struct mallinfo2 heap = mallinfo2();
    unsigned before_main = registrations;
    int bound_here = dlsym(RTLD_DEFAULT, "__cxa_thread_atexit_impl") ==
                     (void *)__cxa_thread_atexit_impl;
    printf("heap at main: arena=%zu in_use=%zu\n", heap.arena, heap.uordblks);
    printf("__cxa_thread_atexit_impl resolves to this program: %s\n",
           bound_here ? "yes" : "no");
    printf("thread-exit destructors registered before main: %u\n", before_main);
    fflush(stdout);
    printf("thread-exit destructors registered by the end of main: %u\n", registrations);
    return 0;
}
