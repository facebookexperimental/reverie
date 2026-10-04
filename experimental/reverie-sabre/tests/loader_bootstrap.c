/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Native protocol control: link the actual loader bootstrap implementation.
 * This is not a PRNG or Hermit syscall oracle. The supervisor writes explicit
 * transport sentinels, and the child must observe them at the real boundary.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bootstrap.h"

extern const unsigned char sbr_bootstrap_syscall_v1[];
static unsigned char aux_random[16];
static uintptr_t stack_words[13];
static char private_option[] = SBR_BOOTSTRAP_ENV "=1";
static char* option_string;
static bool raw_environment;
static sbr_bootstrap_take_fn continuation_take;
static unsigned installer_calls;
static bool concurrent_take_probe;
static int start_take[2];
static int completed_take[2];

static void* competing_take(void* unused) {
  (void)unused;
  unsigned char output[32];
  memset(output, 0x5a, sizeof(output));
  char ready;
  assert(read(start_take[0], &ready, 1) == 1);
  long result = continuation_take(output, sizeof(output));
  for (size_t i = 0; i < sizeof(output); ++i)
    assert(output[i] == 0x5a);
  assert(
      write(completed_take[1], &result, sizeof(result)) ==
      (ssize_t)sizeof(result));
  return NULL;
}

static int decline_continuation(sbr_bootstrap_take_fn take) {
  assert(take == sbr_bootstrap_take_state);
  ++installer_calls;
  return -ENOTSUP;
}

static int reject_continuation(sbr_bootstrap_take_fn take) {
  assert(take == sbr_bootstrap_take_state);
  ++installer_calls;
  return -EIO;
}

static int accept_continuation(sbr_bootstrap_take_fn take) {
  unsigned char bytes[32];
  assert(take == sbr_bootstrap_take_state);
  /* A setter cannot consume the transport before its successful return. */
  assert(take(bytes, sizeof(bytes)) == -EPROTO);
  ++installer_calls;
  continuation_take = take;
  return 0;
}

static void check_raw_environment(bool present) {
  unsigned char bytes[1024];
  FILE* file = fopen("/proc/self/environ", "rb");
  assert(file != NULL);
  size_t length = fread(bytes, 1, sizeof(bytes), file);
  assert(length < sizeof(bytes) && feof(file) && !ferror(file));
  assert(fclose(file) == 0);
  assert(
      (memmem(
           bytes,
           length,
           SBR_BOOTSTRAP_ENV "=1",
           sizeof(SBR_BOOTSTRAP_ENV "=1") - 1) != NULL) == present);
  assert(memmem(bytes, length, "BEFORE=unchanged", 16) != NULL);
  assert(memmem(bytes, length, "AFTER=unchanged", 15) != NULL);
}

static void prepare_stack(void) {
  memcpy(private_option, SBR_BOOTSTRAP_ENV "=1", sizeof(private_option));
  option_string = private_option;
  if (raw_environment) {
    char* value = getenv(SBR_BOOTSTRAP_ENV);
    assert(value != NULL && strcmp(value, "1") == 0);
    option_string = value - sizeof(SBR_BOOTSTRAP_ENV);
    assert(strcmp(option_string, SBR_BOOTSTRAP_ENV "=1") == 0);
    check_raw_environment(true);
  }
  uintptr_t initial[] = {
      1,
      (uintptr_t)"native-client",
      0,
      (uintptr_t)"BEFORE=unchanged",
      (uintptr_t)option_string,
      (uintptr_t)"AFTER=unchanged",
      0,
      AT_RANDOM,
      (uintptr_t)aux_random,
      AT_ENTRY,
      (uintptr_t)prepare_stack,
      AT_NULL,
      0};
  memcpy(stack_words, initial, sizeof(initial));
  memset(aux_random, 0x55, sizeof(aux_random));
}

static void child_body(bool fail_after_take) {
  alarm(8);
  if (!raw_environment)
    assert(setenv(SBR_BOOTSTRAP_ENV, "1", 1) == 0);
  sbr_bootstrap_configure();
  assert(sbr_bootstrap_enabled());
  assert(sbr_bootstrap_install_continuation(accept_continuation) == -EPROTO);
  assert(installer_calls == 0);
  prepare_stack();
  assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
  assert(raise(SIGSTOP) == 0);
  sbr_bootstrap_image(stack_words, prepare_stack);
  assert(stack_words[0] == 1 && stack_words[2] == 0);
  assert(strcmp((char*)stack_words[3], "BEFORE=unchanged") == 0);
  assert(strcmp((char*)stack_words[4], "AFTER=unchanged") == 0);
  assert(stack_words[5] == 0 && stack_words[6] == AT_RANDOM);
  assert(stack_words[7] == (uintptr_t)aux_random);
  assert(stack_words[8] == AT_ENTRY && stack_words[10] == AT_NULL);
  if (raw_environment)
    check_raw_environment(false);
  for (size_t i = 0; i < sizeof(private_option); ++i)
    assert(option_string[i] == 0);
  for (size_t i = 0; i < sizeof(aux_random); ++i)
    assert(aux_random[i] == 0xa0 + i);

  unsigned char output[32];
  memset(output, 0x5a, sizeof(output));
  uintptr_t wrapper = 0x12345678;
  assert(
      sbr_bootstrap_getrandom((long)output, 16, 0x80000001, &wrapper) ==
      -EINVAL);
  for (size_t i = 0; i < sizeof(output); ++i)
    assert(output[i] == 0x5a);
  assert(sbr_bootstrap_getrandom((long)output, 8, 1, &wrapper) == 8);
  assert(memcmp(output, "12345678", 8) == 0 && output[8] == 0x5a);
  assert(sbr_bootstrap_getrandom((long)output, 16, 0, &wrapper) == 16);
  assert(memcmp(output, "abcdefghijklmnop", 16) == 0 && output[16] == 0x5a);
  assert(sbr_bootstrap_take_state(output, 4) == -EMSGSIZE);
  assert(sbr_bootstrap_take_state(output, sizeof(output)) == 16);
  assert(memcmp(output, "opaque-state-once", 16) == 0 && output[16] == 0x5a);
  assert(sbr_bootstrap_take_state(output, sizeof(output)) == -EPROTO);
  if (fail_after_take) {
    sbr_bootstrap_getrandom((long)output, 8, 1, &wrapper);
    _exit(99);
  }
  _exit(0);
}

static void
read_memory(pid_t child, uintptr_t remote, void* local, size_t len) {
  struct iovec here = {local, len}, there = {(void*)remote, len};
  assert(process_vm_readv(child, &here, 1, &there, 1, 0) == (ssize_t)len);
}

static void
write_memory(pid_t child, uintptr_t remote, const void* local, size_t len) {
  struct iovec here = {(void*)local, len}, there = {(void*)remote, len};
  assert(process_vm_writev(child, &here, 1, &there, 1, 0) == (ssize_t)len);
}

static void continuation_child_body(void) {
  alarm(8);
  assert(unsetenv(SBR_BOOTSTRAP_ENV) == 0);
  sbr_bootstrap_configure();
  assert(!sbr_bootstrap_enabled());
  unsigned char output[32];
  memset(output, 0x5a, sizeof(output));
  assert(sbr_bootstrap_install_continuation(NULL) == 0);
  assert(installer_calls == 0);
  assert(sbr_bootstrap_take_state(output, sizeof(output)) == -EPROTO);
  assert(sbr_bootstrap_install_continuation(decline_continuation) == 0);
  assert(installer_calls == 1);
  assert(sbr_bootstrap_take_state(output, sizeof(output)) == -EPROTO);
  assert(sbr_bootstrap_install_continuation(reject_continuation) == -EIO);
  assert(installer_calls == 2);
  assert(sbr_bootstrap_take_state(output, sizeof(output)) == -EPROTO);
  assert(sbr_bootstrap_install_continuation(accept_continuation) == 0);
  assert(installer_calls == 3);
  assert(sbr_bootstrap_install_continuation(accept_continuation) == -EPROTO);
  assert(installer_calls == 3);
  assert(!sbr_bootstrap_enabled());
  sbr_bootstrap_image(NULL, NULL);
  assert(sbr_bootstrap_getrandom((long)output, 8, 1, NULL) == -EPROTO);
  assert(continuation_take(NULL, 0) == -EINVAL);
  pthread_t competitor;
  if (concurrent_take_probe)
    assert(pthread_create(&competitor, NULL, competing_take, NULL) == 0);
  assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
  assert(raise(SIGSTOP) == 0);
  assert(continuation_take(output, sizeof(output)) == -ESTALE);
  if (concurrent_take_probe)
    assert(pthread_join(competitor, NULL) == 0);
  assert(continuation_take(output, 4) == -EMSGSIZE);
  for (size_t i = 0; i < sizeof(output); ++i)
    assert(output[i] == 0x5a);
  assert(continuation_take(output, sizeof(output)) == 16);
  assert(memcmp(output, "continue-payload", 16) == 0 && output[16] == 0x5a);
  assert(continuation_take(output, sizeof(output)) == -EPROTO);
  assert(sbr_bootstrap_getrandom((long)output, 8, 1, NULL) == -EPROTO);
  _exit(0);
}

static void supervised_control(bool fail_after_take, bool continuation) {
  if (concurrent_take_probe) {
    assert(pipe(start_take) == 0);
    assert(pipe(completed_take) == 0);
  }
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    if (continuation)
      continuation_child_body();
    child_body(fail_after_take);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  assert(
      ptrace(
          PTRACE_SETOPTIONS,
          child,
          NULL,
          PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == 0);
  unsigned requests = 0;
  long pending = 0;
  int entering = 1;
  int handled = 0;
  for (unsigned stops = 0; stops < 100; ++stops) {
    assert(ptrace(PTRACE_SYSCALL, child, NULL, NULL) == 0);
    assert(waitpid(child, &status, 0) == child);
    if (WIFEXITED(status)) {
      assert(WEXITSTATUS(status) == (fail_after_take ? EXIT_FAILURE : 0));
      assert(requests == (continuation ? 3 : 6) && !handled);
      if (concurrent_take_probe) {
        close(start_take[0]);
        close(start_take[1]);
        close(completed_take[0]);
        close(completed_take[1]);
      }
      return;
    }
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));
    struct user_regs_struct regs;
    assert(ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0);
    if (entering && regs.orig_rax == SYS_prctl &&
        regs.rdi == SBR_BOOTSTRAP_OPTION) {
      assert(regs.rip == (uintptr_t)sbr_bootstrap_syscall_v1 + 2);
      assert(
          sbr_bootstrap_syscall_v1[0] == 0x0f &&
          sbr_bootstrap_syscall_v1[1] == 0x05);
      ++requests;
      if (continuation) {
        /* This checks actual loader transport, not the consumer's proof of
         * an exec/static image. No IMAGE or GETRANDOM request is permitted. */
        assert(regs.rsi == SBR_BOOTSTRAP_TAKE_STATE);
        assert(regs.r8 == SBR_BOOTSTRAP_VERSION && regs.r9 == 0);
        if (requests == 1) {
          assert(regs.r10 == 32);
          if (concurrent_take_probe) {
            /* Hold the real first TAKE at syscall entry. An untraced sibling
             * must be refused locally while that transfer is in flight.
             */
            assert(write(start_take[1], "!", 1) == 1);
            long result;
            assert(
                read(completed_take[0], &result, sizeof(result)) ==
                (ssize_t)sizeof(result));
            assert(result == -EPROTO);
          }
          pending = -ESTALE;
        } else if (requests == 2) {
          assert(regs.r10 == 4);
          pending = -EMSGSIZE;
        } else {
          assert(requests == 3 && regs.r10 == 32);
          write_memory(child, regs.rdx, "continue-payload", 16);
          pending = 16;
        }
      } else if (requests == 1) {
        assert(regs.rsi == SBR_BOOTSTRAP_IMAGE);
        assert(regs.rdx == (uintptr_t)stack_words);
        assert(regs.r10 == (uintptr_t)prepare_stack);
        assert(regs.r8 == SBR_BOOTSTRAP_VERSION && regs.r9 == 0);
        uintptr_t actual[12];
        read_memory(child, regs.rdx, actual, sizeof(actual));
        assert(actual[6] == AT_RANDOM && actual[7] == (uintptr_t)aux_random);
        unsigned char bytes[16];
        for (size_t i = 0; i < sizeof(bytes); ++i)
          bytes[i] = 0xa0 + i;
        write_memory(child, actual[7], bytes, sizeof(bytes));
        pending = 0;
      } else if (requests <= 4) {
        assert(regs.rsi == SBR_BOOTSTRAP_GETRANDOM);
        uintptr_t wrapper;
        read_memory(child, regs.r9, &wrapper, sizeof(wrapper));
        assert(wrapper == 0x12345678);
        if (requests == 2) {
          assert(regs.r10 == 16 && regs.r8 == 0x80000001);
          pending = -EINVAL;
        } else {
          assert(regs.r10 == (requests == 3 ? 8 : 16));
          assert(regs.r8 == (requests == 3 ? 1 : 0));
          write_memory(
              child,
              regs.rdx,
              requests == 3 ? "12345678" : "abcdefghijklmnop",
              regs.r10);
          pending = regs.r10;
        }
      } else {
        assert(regs.rsi == SBR_BOOTSTRAP_TAKE_STATE);
        assert(regs.r8 == SBR_BOOTSTRAP_VERSION && regs.r9 == 0);
        if (requests == 5) {
          assert(regs.r10 == 4);
          pending = -EMSGSIZE;
        } else {
          assert(regs.r10 == 32);
          write_memory(child, regs.rdx, "opaque-state-once", 16);
          pending = 16;
        }
      }
      handled = 1;
      regs.orig_rax = -1;
      assert(ptrace(PTRACE_SETREGS, child, NULL, &regs) == 0);
    } else if (!entering && handled) {
      regs.rax = pending;
      assert(ptrace(PTRACE_SETREGS, child, NULL, &regs) == 0);
      handled = 0;
    }
    entering = !entering;
  }
  assert(!"native protocol control exceeded stop bound");
}

static void absent_supervisor_control(void) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    assert(setenv(SBR_BOOTSTRAP_ENV, "1", 1) == 0);
    sbr_bootstrap_configure();
    prepare_stack();
    sbr_bootstrap_image(stack_words, prepare_stack);
    _exit(99);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
}

static void absent_continuation_supervisor_control(void) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    assert(unsetenv(SBR_BOOTSTRAP_ENV) == 0);
    sbr_bootstrap_configure();
    assert(sbr_bootstrap_install_continuation(accept_continuation) == 0);
    unsigned char output[32];
    memset(output, 0x5a, sizeof(output));
    long first = continuation_take(output, sizeof(output));
    /* The real kernel rejects this unknown prctl option. A second identical
     * errno (not local EPROTO) proves the failed take did not retire it.
     */
    assert(first < 0 && first != -EPROTO);
    assert(continuation_take(output, sizeof(output)) == first);
    for (size_t i = 0; i < sizeof(output); ++i)
      assert(output[i] == 0x5a);
    assert(sbr_bootstrap_getrandom((long)output, 8, 1, NULL) == -EPROTO);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void uninitialized_phase_control(void) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    assert(setenv(SBR_BOOTSTRAP_ENV, "1", 1) == 0);
    sbr_bootstrap_configure();
    sbr_bootstrap_getrandom(0, 0, 0, NULL);
    _exit(99);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
}

static void raw_environment_control(void) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    char* args[] = {"loader-bootstrap-control", "raw-environment", NULL};
    char* env[] = {
        "BEFORE=unchanged", SBR_BOOTSTRAP_ENV "=1", "AFTER=unchanged", NULL};
    /* exec makes these the kernel's actual raw environment bytes. The
     * ordinary supervised control then checks them before and after IMAGE.
     */
    execve("/proc/self/exe", args, env);
    _exit(99);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char** argv) {
  alarm(10);
  if (argc == 2 && strcmp(argv[1], "raw-environment") == 0) {
    raw_environment = true;
    supervised_control(false, false);
    return 0;
  }
  assert(argc == 1);
  assert(unsetenv(SBR_BOOTSTRAP_ENV) == 0);
  sbr_bootstrap_configure();
  assert(!sbr_bootstrap_enabled());
  sbr_bootstrap_image(NULL, NULL);
  assert(sbr_bootstrap_take_state(NULL, 0) == -EPROTO);
  supervised_control(false, false);
  supervised_control(true, false);
  supervised_control(false, true);
  concurrent_take_probe = true;
  supervised_control(false, true);
  concurrent_take_probe = false;
  uninitialized_phase_control();
  absent_supervisor_control();
  absent_continuation_supervisor_control();
  raw_environment_control();
  printf(
      "protocol=%lu version=%lu ops=%u,%u,%u max=%lu\n",
      SBR_BOOTSTRAP_OPTION,
      SBR_BOOTSTRAP_VERSION,
      SBR_BOOTSTRAP_IMAGE,
      SBR_BOOTSTRAP_GETRANDOM,
      SBR_BOOTSTRAP_TAKE_STATE,
      SBR_BOOTSTRAP_MAX_STATE);
  puts(
      "PASS: real IMAGE/auxv, original requests, refusal, once-only handoff; disabled compatibility; raw environment scrubbed; continuation concurrency and absent supervisor");
  return 0;
}
