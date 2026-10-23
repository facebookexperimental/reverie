/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The child starts on its new stack and stays in syscalls without a Rust
 * or pthread return frame. This controlled fixture uses x86_64's entry ABI. */
extern long clone3_park_thread(struct clone_args *, size_t);
__asm__(".text\n"
        ".globl clone3_park_thread\n"
        "clone3_park_thread:\n"
        "mov $435, %eax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 2f\n"
        "1: mov $34, %eax\n"
        "syscall\n"
        "jmp 1b\n"
        "2: ret\n");

static const char *executable;

static void *exec_from_thread(void *ignored) {
    (void)ignored;
    char requested[32];
    snprintf(requested, sizeof(requested), "%ld", syscall(SYS_gettid));
    char *const arguments[] = {(char *)executable, "--replacement-image", requested, NULL};
    execv(executable, arguments);
    _exit(90);
}

int main(int argc, char **argv) {
    if (argc != 3)
        return 91;
    executable = argv[0];
    if (argv[1][2] == 'g') {
        int start = atoi(argv[2]);
        char byte;
        if (read(start, &byte, 1) != 1)
            return 92;
        close(start);
        pthread_t thread;
        if (pthread_create(&thread, NULL, exec_from_thread, NULL) != 0)
            return 93;
    } else {
        int requested = atoi(argv[2]);
        size_t stack_size = 65536;
        void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED)
            return 94;
        struct clone_args arguments = {
            .flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_FS | CLONE_FILES,
            .stack = (uint64_t)(uintptr_t)stack,
            .stack_size = stack_size,
            .set_tid = (uint64_t)(uintptr_t)&requested,
            .set_tid_size = 1,
        };
        long result = clone3_park_thread(&arguments, sizeof(arguments));
        if (result < 0) {
            errno = (int)-result;
            perror("same-group clone3 replacement");
            return 95;
        }
        if (result != requested)
            return 96;
    }
    for (;;)
        pause();
}
