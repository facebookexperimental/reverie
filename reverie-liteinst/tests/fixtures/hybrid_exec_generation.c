/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One real site serves both the warm-up and exec. Reusing it after a failed
   exec proves the old image still works; loading this same non-PIE executable
   again also reuses its virtual address in a different execution generation. */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global exec_generation_syscall\n"
    ".type exec_generation_syscall,@function\n"
    "exec_generation_syscall:\n"
    ".cfi_startproc\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "mov %r8, %r10\n"
    "mov %r9, %r8\n"
    "mov 8(%rsp), %r9\n"
    ".global exec_generation_site\n"
    "exec_generation_site:\n"
    "syscall\n"
    ".rept 16\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size exec_generation_syscall, .-exec_generation_syscall\n");

extern long exec_generation_syscall(long, long, long, long, long, long, long);
extern unsigned char exec_generation_site;
extern char** environ;

static int check_hot_calls(unsigned stage) {
  for (unsigned i = 0; i < 3; ++i) {
    long result =
        exec_generation_syscall(SYS_getpid, 0x6e786578, stage, i, 0, 0, 0);
    if (result != 0x4242) {
      return 20;
    }
  }
  return 0;
}

static uint64_t site_count(const char* symbol) {
  uint64_t (*count)(uint64_t) =
      (uint64_t (*)(uint64_t))dlsym(RTLD_DEFAULT, symbol);
  if (count == NULL) {
    _exit(21);
  }
  return count((uint64_t)(uintptr_t)&exec_generation_site);
}

int main(int argc, char** argv) {
  if (argc != 3) {
    return 9;
  }
  if (strcmp(argv[1], "marker") == 0) {
    FILE* marker = fopen(argv[2], "w");
    if (marker == NULL) {
      return 10;
    }
    fputs("uninstrumented entry\n", marker);
    return fclose(marker) != 0;
  }

  unsigned stage = (unsigned)strtoul(argv[2], NULL, 10);
  int cold = strcmp(argv[1], "cold") == 0;
  if (!cold && check_hot_calls(stage) != 0) {
    return 11;
  }

  if (strcmp(argv[1], "failed") == 0) {
    char* const missing_args[] = {
        (char*)"/definitely/missing/liteinst-exec", NULL};
    long first = exec_generation_syscall(
        SYS_execve,
        (long)missing_args[0],
        (long)missing_args,
        (long)environ,
        0,
        0,
        0);
    if (first != -ENOENT) {
      return 12;
    }
    long second = exec_generation_syscall(
        SYS_execveat,
        AT_FDCWD,
        (long)missing_args[0],
        (long)missing_args,
        (long)environ,
        0,
        0);
    if (second != -ENOENT || check_hot_calls(stage) != 0) {
      return 13;
    }
    if (site_count("reverie_liteinst_site_trap_count") != 1 ||
        site_count("reverie_liteinst_site_hook_count") != 7) {
      return 14;
    }
    puts("failed-exec-preserved");
    return 0;
  }

  if (strcmp(argv[1], "drop-selector") == 0 ||
      strcmp(argv[1], "drop-preload") == 0) {
    const char* variable = strcmp(argv[1], "drop-selector") == 0
        ? "REVERIE_LITEINST_HOST_RUNTIME"
        : "LD_PRELOAD";
    if (unsetenv(variable) != 0) {
      return 15;
    }
    char* const marker_args[] = {argv[0], (char*)"marker", argv[2], NULL};
    exec_generation_syscall(
        SYS_execve, (long)argv[0], (long)marker_args, (long)environ, 0, 0, 0);
    return 16;
  }

  if (!cold &&
      (site_count("reverie_liteinst_site_trap_count") != 1 ||
       site_count("reverie_liteinst_site_hook_count") != 2)) {
    return 17;
  }
  if (stage == 2) {
    if (cold && check_hot_calls(stage) != 0) {
      return 18;
    }
    puts("exec-generations-finished");
    return 0;
  }
  char next_stage[] = {(char)('0' + stage + 1), 0};
  char* const next_args[] = {argv[0], argv[1], next_stage, NULL};
  if (strcmp(argv[1], "execveat") == 0) {
    exec_generation_syscall(
        SYS_execveat,
        AT_FDCWD,
        (long)argv[0],
        (long)next_args,
        (long)environ,
        0,
        0);
  } else {
    exec_generation_syscall(
        SYS_execve, (long)argv[0], (long)next_args, (long)environ, 0, 0, 0);
  }
  return 19;
}
