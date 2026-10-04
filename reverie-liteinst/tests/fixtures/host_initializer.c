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
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

struct host_config {
  uint64_t version, straddler_staleness_ticks;
};
struct host_frame {
  uint64_t version, begin_rip, ready_rip, install_helper, helper_stack_top;
  uint64_t helper_return, helper_return_rip, syscall_trap_rip;
  uint64_t syscall_trap_return_rip, install_result;
};
struct install_result {
  uint64_t version, site_start, site_len, relocated_tail;
  uint64_t trampoline_start, trampoline_len;
  uint64_t arena_writable_start, arena_writable_len;
  uint64_t arena_executable_start, arena_executable_len;
  uint64_t instruction_len, straddle_prefix, complete;
};
static int (*initialize)(const struct host_config*);
static struct host_config config = {1, 0};
static struct host_frame saved_frame;
static volatile sig_atomic_t begins, readies, failures, reentry_result;

/* No injected guest executes this site. A real successful installation proves
 * the initializer prepared both the site table and a usable trampoline arena.
 */
extern char test_syscall_site[];
__asm__(
    ".text\n.p2align 6\n.global test_syscall_site\n"
    "test_syscall_site:\n .cfi_startproc\n"
    " syscall\n nop\n nop\n nop\n nop\n nop\n nop\n ret\n .cfi_endproc\n");

static void trap(int sig, siginfo_t* info, void* opaque) {
  (void)info;
  ucontext_t* context = opaque;
  uint64_t marker = context->uc_mcontext.gregs[REG_RAX];
  uint64_t rip = context->uc_mcontext.gregs[REG_RIP];
  const struct host_frame* frame =
      (const void*)(uintptr_t)context->uc_mcontext.gregs[REG_RDI];
  if (sig != SIGTRAP || !frame || frame->version != 5)
    _exit(80);
  if (marker == UINT64_C(0x7265766c69000001)) {
    if (begins || readies || rip != frame->begin_rip)
      _exit(81);
    saved_frame = *frame;
    begins = 1;
    /* The rejected reentry takes only the argument/atomic guard path. */
    reentry_result = initialize(&config);
    if (reentry_result != -EALREADY)
      _exit(82);
  } else if (marker == UINT64_C(0x7265766c69000002)) {
    if (begins != 1 || readies || failures || rip != frame->ready_rip)
      _exit(83);
    const uint64_t* saved = (const void*)&saved_frame;
    const uint64_t* current = (const void*)frame;
    for (size_t i = 0; i < sizeof(saved_frame) / sizeof(uint64_t); ++i)
      if (saved[i] != current[i])
        _exit(84);
    readies = 1;
  } else if (marker == UINT64_C(0x7265766c69000005)) {
    /* A failed preparation closes the handshake at the Ready site. */
    if (begins != 1 || readies || failures || rip != frame->ready_rip)
      _exit(86);
    const uint64_t* saved = (const void*)&saved_frame;
    const uint64_t* current = (const void*)frame;
    for (size_t i = 0; i < sizeof(saved_frame) / sizeof(uint64_t); ++i)
      if (saved[i] != current[i])
        _exit(87);
    failures = 1;
  } else {
    _exit(85);
  }
}

static void require(int condition, const char* message) {
  if (!condition) {
    fprintf(stderr, "%s\n", message);
    exit(1);
  }
}

static void refuse_file_opens(void) {
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat2, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
  require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
  require(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0, "seccomp");
}

int main(int argc, char** argv) {
  require(argc == 2, "mode");
  initialize = dlsym(RTLD_DEFAULT, "reverie_liteinst_initialize_host");
  require(initialize != NULL, "missing explicit host initializer");
  struct sigaction action = {.sa_sigaction = trap, .sa_flags = SA_SIGINFO};
  require(sigemptyset(&action.sa_mask) == 0, "sigemptyset");
  require(sigaction(SIGTRAP, &action, NULL) == 0, "sigaction");

  if (!strcmp(argv[1], "builtin-active")) {
    void (*legacy_initialize)(void) =
        dlsym(RTLD_DEFAULT, "reverie_liteinst_initialize");
    require(legacy_initialize != NULL, "missing legacy initializer");
    require(
        setenv("REVERIE_LITEINST_TOOL", "spoof-getpid", 1) == 0,
        "select built-in");
    legacy_initialize();
    require(syscall(SYS_getpid) == 424242, "shared built-in was not active");
    require(
        initialize(&config) == -EALREADY, "host accepted published dispatcher");
    require(begins == 0 && readies == 0, "host emitted a cross-mode handshake");
    puts("published-dispatcher-refused");
    return 0;
  }

  /* The default preload constructor was inert before main. None of these
   * selectors may be read or changed by the explicit host initialization. */
  require(
      setenv("REVERIE_LITEINST_HOST_RUNTIME", "not-selected", 1) == 0,
      "set host");
  require(setenv("REVERIE_LITEINST_TOOL", "invalid-tool", 1) == 0, "set tool");
  require(
      setenv(
          "REVERIE_LITEINST_STRADDLER_STALENESS_TICKS", "invalid-ticks", 1) ==
          0,
      "set straddler");
  require(initialize(NULL) == -EINVAL, "null configuration accepted");
  struct host_config bad = {2, 0};
  require(initialize(&bad) == -EINVAL, "unknown configuration accepted");
  require(
      begins == 0 && readies == 0,
      "invalid configuration consumed initialization");
  config.straddler_staleness_ticks = !strcmp(argv[1], "configured") ? 17000 : 0;
  int failure = !strcmp(argv[1], "preparation-failure");
  if (failure)
    refuse_file_opens();
  int result = initialize(&config);
  require(
      begins == 1 && reentry_result == -EALREADY,
      "missing Begin or reentry guard");
  if (failure) {
    require(
        result == -EPERM && readies == 0, "preparation failure reported Ready");
    require(failures == 1, "preparation failure did not close the handshake");
  } else {
    require(
        result == 0 && readies == 1, "actual initialization did not finish");
    require(failures == 0, "successful initialization reported a failure");
    /* The second argument is the tracer census's lowest entry after the
     * site. Nothing branches into test_syscall_site, so it is UINT64_MAX. */
    int64_t (*install)(uint64_t, uint64_t) =
        (void*)(uintptr_t)saved_frame.install_helper;
    int64_t tail = install((uintptr_t)test_syscall_site, UINT64_MAX);
    const struct install_result* installed =
        (void*)(uintptr_t)saved_frame.install_result;
    require(tail > 0, "actual patch helper failed");
    require(
        installed->version == 2 && installed->complete == 1 &&
            installed->site_start == (uintptr_t)test_syscall_site &&
            installed->instruction_len == 2 && installed->site_len == 8 &&
            installed->relocated_tail == (uint64_t)tail &&
            installed->arena_writable_start &&
            installed->arena_executable_start &&
            installed->arena_writable_len && installed->arena_executable_len,
        "missing initialized site/arena result");
    require(
        (unsigned char)test_syscall_site[0] != 0x0f,
        "helper did not patch site");
  }
  require(initialize(&config) == -EALREADY, "host initialization ran twice");
  require(
      begins == 1 && readies == !failure && failures == failure,
      "repeat changed handshake counts");
  require(
      !strcmp(getenv("REVERIE_LITEINST_HOST_RUNTIME"), "not-selected"),
      "host env changed");
  require(
      !strcmp(getenv("REVERIE_LITEINST_TOOL"), "invalid-tool"),
      "tool env changed");
  require(
      !strcmp(
          getenv("REVERIE_LITEINST_STRADDLER_STALENESS_TICKS"),
          "invalid-ticks"),
      "straddler env changed");
  puts(failure ? "preparation-failure-retained" : "explicit-host-initialized");
  return 0;
}
