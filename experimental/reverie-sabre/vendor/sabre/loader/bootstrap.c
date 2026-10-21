/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "bootstrap.h"

#include <elf.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

static bool requested;
static bool image_bound;
static bool state_taken;
static bool continuation_enabled;
static bool option_on_stack = true;

void sbr_bootstrap_option_from_launch(const char *value) {
  if (strcmp(value, "1") != 0)
    errx(EXIT_FAILURE, "invalid " SBR_BOOTSTRAP_ENV);
#ifndef __x86_64__
  errx(EXIT_FAILURE, "loader bootstrap requires x86-64");
#endif
  option_on_stack = false;
  requested = true;
}

/* A protocol violation is not an errno that guest libc may ignore or handle
 * by trying another path. This can run before client TLS and libc
 * initialization, so use only raw syscalls and constant storage.
 */
__attribute__((noreturn)) static void invalid_phase(const char *message,
                                                    unsigned long length) {
#ifdef __x86_64__
  long ignored;
  __asm__ volatile("syscall"
                   : "=a"(ignored)
                   : "0"(SYS_write), "D"(2), "S"(message), "d"(length)
                   : "rcx", "r11", "memory");
  __asm__ volatile("syscall"
                   : "=a"(ignored)
                   : "0"(SYS_exit_group), "D"(EXIT_FAILURE)
                   : "rcx", "r11", "memory");
  __builtin_unreachable();
#else
  (void)message;
  (void)length;
  abort();
#endif
}

__attribute__((noreturn)) static void invalid_random_phase(void) {
  static const char message[] =
      "SaBRe: getrandom outside initialized loader bootstrap phase\n";
  invalid_phase(message, sizeof(message) - 1);
}

__attribute__((noreturn)) static void invalid_limit_phase(void) {
  static const char message[] =
      "SaBRe: resource-limit read outside initialized loader bootstrap phase\n";
  invalid_phase(message, sizeof(message) - 1);
}

void sbr_bootstrap_configure(void) {
  const char *value = getenv(SBR_BOOTSTRAP_ENV);
  if (value == NULL)
    return;
  if (strcmp(value, "1") != 0)
    errx(EXIT_FAILURE, "invalid " SBR_BOOTSTRAP_ENV);
#ifndef __x86_64__
  errx(EXIT_FAILURE, "loader bootstrap requires x86-64");
#endif
  requested = true;
}

bool sbr_bootstrap_enabled(void) { return requested; }

/* This exported instruction must have one address even under IPA/LTO. GCC's
 * noclone and Clang's optnone prevent specialized copies of the inline asm.
 */
#ifdef __clang__
__attribute__((optnone))
#else
__attribute__((noclone))
#endif
__attribute__((noinline, used, visibility("default"))) long
sbr_bootstrap_request_v1(unsigned long operation, unsigned long arg1,
                         unsigned long arg2, unsigned long arg3,
                         unsigned long arg4) {
#ifdef __x86_64__
  register unsigned long r10 __asm__("r10") = arg2;
  register unsigned long r8 __asm__("r8") = arg3;
  register unsigned long r9 __asm__("r9") = arg4;
  long result;
  __asm__ volatile(".global sbr_bootstrap_syscall_v1\n"
                   "sbr_bootstrap_syscall_v1:\n"
                   "syscall"
                   : "=a"(result)
                   : "0"(SYS_prctl), "D"(SBR_BOOTSTRAP_OPTION), "S"(operation),
                     "d"(arg1), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return result;
#else
  (void)operation;
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return -ENOSYS;
#endif
}

void sbr_bootstrap_image(void *stack, void *entry) {
  if (!requested)
    return;
  if (image_bound || __atomic_load_n(&state_taken, __ATOMIC_ACQUIRE))
    errx(EXIT_FAILURE, "duplicate loader bootstrap image");

  /* unsetenv before load's find_auxv would shorten the environment without
   * moving auxv and make the original stack unparsable. Consume the private
   * option only once the final guest stack exists, moving the complete auxv
   * together with the remaining environment. The guest stack pointer and its
   * alignment, argv, and all other environment strings are unchanged. Erase
   * the original string too: the kernel's raw /proc/self/environ range still
   * contains it after the pointer array has been compacted.
   */
  if (!option_on_stack)
    goto request;
  uintptr_t *words = stack;
  uintptr_t *env = words + 1 + words[0] + 1;
  uintptr_t *option = NULL;
  uintptr_t *end = env;
  for (; *end != 0; ++end) {
    const char *value = (const char *)*end;
    if (strncmp(value, SBR_BOOTSTRAP_ENV "=", sizeof(SBR_BOOTSTRAP_ENV)) == 0) {
      if (option != NULL || strcmp(value, SBR_BOOTSTRAP_ENV "=1") != 0)
        errx(EXIT_FAILURE, "ambiguous private loader bootstrap environment");
      option = end;
    }
  }
  if (option == NULL)
    errx(EXIT_FAILURE,
         "private loader bootstrap environment missing from stack");
  ++end;
  while (end[0] != AT_NULL)
    end += 2;
  end += 2;
  memset((char *)*option, 0, strlen((char *)*option));
  memmove(option, option + 1, (char *)end - (char *)(option + 1));

request:;
  long result =
      sbr_bootstrap_request_v1(SBR_BOOTSTRAP_IMAGE, (unsigned long)stack,
                               (unsigned long)entry, SBR_BOOTSTRAP_VERSION, 0);
  if (result != 0)
    errx(EXIT_FAILURE, "loader bootstrap image refused: %ld", result);
  image_bound = true;
}

long sbr_bootstrap_getrandom(long buffer, long length, long flags,
                             void *wrapper_sp) {
  if (!requested)
    return -EPROTO;
  if (!image_bound || __atomic_load_n(&state_taken, __ATOMIC_ACQUIRE))
    invalid_random_phase();
  return sbr_bootstrap_request_v1(SBR_BOOTSTRAP_GETRANDOM, buffer, length,
                                  flags, (unsigned long)wrapper_sp);
}

/* The guest's dynamic loader and libc startup read resource limits before
 * the plugin exists; libc sizes default thread stacks from RLIMIT_STACK. The
 * supervisor answers such a read from Detcore's table, as Detcore answers it
 * once running, instead of letting the host's limit reach the guest. Only a
 * read is forwarded: the caller refuses a pre-plugin change itself.
 */
long sbr_bootstrap_prlimit(long pid, long resource, long old_limit,
                           void *wrapper_sp) {
  if (!requested)
    return -EPROTO;
  if (!image_bound || __atomic_load_n(&state_taken, __ATOMIC_ACQUIRE))
    invalid_limit_phase();
  return sbr_bootstrap_request_v1(SBR_BOOTSTRAP_PRLIMIT, pid, resource,
                                  old_limit, (unsigned long)wrapper_sp);
}

long sbr_bootstrap_getrlimit(long resource, long limit, void *wrapper_sp) {
  if (!requested)
    return -EPROTO;
  if (!image_bound || __atomic_load_n(&state_taken, __ATOMIC_ACQUIRE))
    invalid_limit_phase();
  return sbr_bootstrap_request_v1(SBR_BOOTSTRAP_GETRLIMIT, resource, limit, 0,
                                  (unsigned long)wrapper_sp);
}

int sbr_bootstrap_install_continuation(sbr_bootstrap_install_fn install) {
  if (requested || image_bound ||
      __atomic_load_n(&state_taken, __ATOMIC_ACQUIRE) || continuation_enabled)
    return -EPROTO;
  if (install == NULL)
    return 0;
  int result = install(sbr_bootstrap_take_state);
  if (result == -ENOTSUP)
    return 0;
  if (result != 0)
    return result;
  continuation_enabled = true;
  return 0;
}

long sbr_bootstrap_take_state(void *buffer, size_t capacity) {
  if (__atomic_load_n(&state_taken, __ATOMIC_ACQUIRE) ||
      (requested ? !image_bound : !continuation_enabled))
    return -EPROTO;
  if (buffer == NULL || capacity == 0 || capacity > SBR_BOOTSTRAP_MAX_STATE)
    return -EINVAL;
  bool expected = false;
  if (!__atomic_compare_exchange_n(&state_taken, &expected, true, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    return -EPROTO;
  long result =
      sbr_bootstrap_request_v1(SBR_BOOTSTRAP_TAKE_STATE, (unsigned long)buffer,
                               capacity, SBR_BOOTSTRAP_VERSION, 0);
  if (result > 0 && (unsigned long)result <= capacity) {
    return result;
  }
  /* A rejected or short-capacity request must not retire the supervisor's
   * state. An invalid successful response is never treated as an empty state.
   */
  __atomic_store_n(&state_taken, false, __ATOMIC_RELEASE);
  return result < 0 ? result : -EPROTO;
}
