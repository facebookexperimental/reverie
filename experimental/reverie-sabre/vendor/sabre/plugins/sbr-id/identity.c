/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
   This plugin simply intercepts all system calls and vDSO calls and
   reissues them.
*/

#include "real_syscall.h"
#include "sbr_api_defs.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static char *sabre_path;
static char *plugin_path;
static char *client_path;

bool is_vfork_through_clone3(long sc_no, long arg1) {
  struct clone_args *cl_args = (struct clone_args *)arg1;
  return sc_no == SYS_clone3 &&
         ((cl_args->flags & (CLONE_VM | CLONE_VFORK | SIGCHLD)) ==
          (CLONE_VM | CLONE_VFORK | SIGCHLD));
}

bool is_vfork_through_clone(long sc_no, long arg1) {
  unsigned long flags = (unsigned long)arg1;
  return (sc_no == SYS_clone && (flags & (CLONE_VM | CLONE_VFORK | SIGCHLD)) ==
                                    (CLONE_VM | CLONE_VFORK | SIGCHLD));
}

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {
  if (sc_no == SYS_clone && arg2 != 0) { // clone
    void *ret_addr = get_syscall_return_address(wrapper_sp);
    return clone_syscall(arg1, (void *)arg2, (void *)arg3, (void *)arg4, arg5,
                         ret_addr, NULL);
  } else if (sc_no == SYS_clone3 &&
             ((struct clone_args *)arg1)->stack != 0) { // clone3
    void *ret_addr = get_syscall_return_address(wrapper_sp);
    return clone3_syscall(arg1, arg2, arg3, 0, arg5, ret_addr, NULL);
  } else if (sc_no == SYS_execve) {
    if (access((char *)arg1, F_OK) != 0) {
      // TODO: Double check this is the correct way to return errors.
      return -ENOENT;
    }

    char **old_argv = (char **)arg2; // Just make our life easier.

    size_t old_argv_size = 0;
    for (int i = 0; old_argv[i] != NULL; i++) {
      old_argv_size++;
    }
    // argv is NULL terminated, and we should copy the NULL too.
    old_argv_size += 1;

    // We will be adding the minimum 3 args.
    // TODO: Support addition of plugin and sabre flags.
    char **n_argv = malloc((old_argv_size + 3) * sizeof(char *));
    assert(n_argv != NULL);
    // argv should always start with the path to the binary.
    // old_argv now has the old binary path by default so
    // we just append it.
    memcpy(n_argv + 3, old_argv, old_argv_size * sizeof(char *));

    n_argv[0] = sabre_path;
    n_argv[1] = plugin_path;
    n_argv[2] = "--";
    // Overwrite first argument of old_argv as sometimes this is not a valid
    // path.
    n_argv[3] = (char *)arg1;

    return real_syscall(SYS_execve, (long)sabre_path, (long)n_argv, arg3, arg4,
                        arg5, arg6);
  } else if (sc_no == SYS_readlink) {
    const char *pathname = (const char *)arg1;
    char *buf = (char *)arg2;
    size_t bufsize = (size_t)arg3;

    if (strcmp(pathname, "/proc/self/exe") == 0) {
      if (buf == NULL) {
        return -EFAULT;
      }

      // strncpy doesn't tell us how many bytes it copied, so we have to
      // calculate that ourselves. Plus, readlink should not append a NUL byte
      // to the end. Best to use memcpy here to mimic the kernel.
      size_t len = strlen(client_path);
      if (len > bufsize) {
        len = bufsize;
      }

      memcpy(buf, client_path, len);

      return len;
    }
  } else if (sc_no == SYS_vfork || is_vfork_through_clone(sc_no, arg1) ||
             is_vfork_through_clone3(sc_no, arg1)) {
    long pid = vfork_syscall();
    if (pid == 0) { // Child
      return vfork_return_from_child(wrapper_sp);
    }
    // Parent
    return pid;
  }

  return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
}

void_void_fn actual_clock_gettime = NULL;
void_void_fn actual_getcpu = NULL;
void_void_fn actual_gettimeofday = NULL;
void_void_fn actual_time = NULL;

typedef int clock_gettime_fn(clockid_t, struct timespec *);
int handle_vdso_clock_gettime(clockid_t arg1, struct timespec *arg2) {
  return ((clock_gettime_fn *)actual_clock_gettime)(arg1, arg2);
}

// arg3 has type: struct getcpu_cache *
typedef int getcpu_fn(unsigned *, unsigned *, void *);
int handle_vdso_getcpu(unsigned *arg1, unsigned *arg2, void *arg3) {
  return ((getcpu_fn *)actual_getcpu)(arg1, arg2, arg3);
}

typedef int gettimeofday_fn(struct timeval *, struct timezone *);
int handle_vdso_gettimeofday(struct timeval *arg1, struct timezone *arg2) {
  return ((gettimeofday_fn *)actual_gettimeofday)(arg1, arg2);
}

#ifdef __x86_64__
typedef int time_fn(time_t *);
int handle_vdso_time(time_t *arg1) { return ((time_fn *)actual_time)(arg1); }
#endif // __x86_64__

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)actual_fn;
  switch (sc_no) {
  case SYS_clock_gettime:
    actual_clock_gettime = actual_fn;
    return (void_void_fn)handle_vdso_clock_gettime;
  case SYS_getcpu:
    actual_getcpu = actual_fn;
    return (void_void_fn)handle_vdso_getcpu;
  case SYS_gettimeofday:
    actual_gettimeofday = actual_fn;
    return (void_void_fn)handle_vdso_gettimeofday;
#ifdef __x86_64__
  case SYS_time:
    actual_time = actual_fn;
    return (void_void_fn)handle_vdso_time;
#endif // __x86_64__
  default:
    return (void_void_fn)NULL;
  }
}

#ifdef __NX_INTERCEPT_RDTSC
long handle_rdtsc() {
  long high, low;

  asm volatile("rdtsc;" : "=a"(low), "=d"(high) : :);

  long ret = high;
  ret <<= 32;
  ret |= low;

  return ret;
}
#endif // __NX_INTERCEPT_RDTSC

void post_clone_hook(void *ctx) {
  assert(ctx == NULL);
  return;
}

void sbr_init(int *argc, char **argv[], sbr_icept_reg_fn fn_icept_reg,
              sbr_icept_vdso_callback_fn *vdso_callback,
              sbr_sc_handler_fn *syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
              sbr_rdtsc_handler_fn *rdtsc_handler,
#endif
              sbr_post_load_fn *post_load, char *sp, char *cp) {
  (void)fn_icept_reg; // unused
  (void)post_load;    // unused

  sabre_path = sp;
  plugin_path = (*argv)[0];
  client_path = cp;

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;

#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = handle_rdtsc;
#endif

  (*argc)--;
  (*argv)++;
}
