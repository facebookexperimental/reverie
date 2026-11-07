/* Answers every getppid that reaches it with 2^30, above any process ID.
 * Built with POST_ARM it also reports post-arm routing, so the loader sends
 * it every rewritten-site call (it arms no trap path of its own); built with
 * POST_ARM_ZERO it defines the report but returns zero. */
#define _GNU_SOURCE
#include <stddef.h>
#include <sys/syscall.h>
#include "real_syscall.h"
#include "sbr_api_defs.h"

static long handler(long nr, long a, long b, long c, long d, long e, long f,
                    void* sp) {
  (void)sp;
  if (nr == SYS_getppid)
    return 1L << 30;
  return real_syscall(nr, a, b, c, d, e, f);
}

#if defined(POST_ARM) || defined(POST_ARM_ZERO)
int reverie_sabre_post_arm_routing_v1(void) {
#ifdef POST_ARM_ZERO
  return 0;
#else
  return 1;
#endif
}
#endif

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
  (void)argc;
  (void)argv;
  (void)reg;
  (void)loader;
  (void)client;
  *vdso = NULL;
  *syscall_handler = handler;
  *post = NULL;
#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = rdtsc;
#endif
}
