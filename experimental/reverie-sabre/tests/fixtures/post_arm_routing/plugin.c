/* Post-arm routing probe. Every observation is the plugin's own view of which
 * calls the loader routed to its handler:
 *   1   the plugin's own getuid(), made while handling the client's getppid();
 *   10  the plugin's own getpid(), made from post_load;
 *   100 the client's arch_prctl(ARCH_SET_FS), which the loader otherwise
 *       handles itself.
 * Before arming the loader runs all three natively; after the plugin reports
 * arming it must route all three here. The client's getppid() returns
 * ANSWERED plus the sum, or ANSWERED - 1000 if routing a nested call dropped
 * the plugin's domain. ANSWERED is above any process ID (pid_max is at most
 * 2^22), so a native getppid() cannot be mistaken for the handler's answer. */
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "real_syscall.h"
#include "sbr_api_defs.h"

bool calling_from_plugin(void);

#define ANSWERED (1L << 30)

static int report_armed;
/* The handler re-enters itself through libc calls; volatile keeps the
 * compiler from treating these as unobservable across those calls. */
static volatile long nested_getuid;
static volatile long post_load_getpid;
static volatile long set_fs;
static volatile int in_getppid;
static volatile int in_post_load;

static long handler(long nr, long a, long b, long c, long d, long e, long f,
                    void* sp) {
  (void)sp;
  if (nr == SYS_getuid && in_getppid) {
    nested_getuid++;
    return real_syscall(nr, a, b, c, d, e, f);
  }
  if (nr == SYS_getpid && in_post_load) {
    post_load_getpid++;
    return real_syscall(nr, a, b, c, d, e, f);
  }
  if (nr == SYS_arch_prctl && a == ARCH_SET_FS) {
    set_fs++;
    return real_syscall(nr, a, b, c, d, e, f);
  }
  if (nr == SYS_getppid && !in_getppid) {
    in_getppid = 1;
    (void)getuid();
    bool kept_domain = calling_from_plugin();
    in_getppid = 0;
    if (!kept_domain)
      return ANSWERED - 1000;
    return ANSWERED + nested_getuid + 10 * post_load_getpid + 100 * set_fs;
  }
  return real_syscall(nr, a, b, c, d, e, f);
}

#ifndef OMIT_POST_ARM_SYMBOL
int reverie_sabre_post_arm_routing_v1(void) {
  return report_armed;
}
#endif

static void post_load(bool is_static) {
  (void)is_static;
  in_post_load = 1;
  (void)getpid();
  in_post_load = 0;
}

#ifdef __NX_INTERCEPT_RDTSC
static long rdtsc(void) {
  unsigned lo, hi;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((long)hi << 32) | lo;
}
#endif

void sbr_init(
    int* argc,
    char*** argv,
    sbr_icept_reg_fn reg,
    sbr_icept_vdso_callback_fn* vdso,
    sbr_sc_handler_fn* syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
    sbr_rdtsc_handler_fn* rdtsc_handler,
#endif
    sbr_post_load_fn* post,
    char* loader,
    char* client) {
  (void)reg;
  (void)loader;
  (void)client;
  for (int i = 1; i < *argc; i++)
    if (strcmp((*argv)[i], "armed") == 0)
      report_armed = 1;
  *vdso = NULL;
  *syscall_handler = handler;
  *post = post_load;
#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = rdtsc;
#endif
}
