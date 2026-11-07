/* Answers getppid with ANSWERED plus the route the loader passed to
 * reverie_sabre_routed_syscall_v1, plus 100 if any of the six arguments is
 * not the client's (11..16) or the frame pointer is NULL; or ANSWERED + 7
 * from its sbr_init handler.
 * ANSWERED is above any process ID. Built with UNARMED it reports no post-arm
 * routing; with OMIT_ROUTED it has no routed handler. */
#define _GNU_SOURCE
#include <stddef.h>
#include <sys/syscall.h>
#include "real_syscall.h"
#include "sbr_api_defs.h"

#define ANSWERED (1L << 30)

static long handler(long nr, long a, long b, long c, long d, long e, long f,
                    void* sp) {
  (void)sp;
  if (nr == SYS_getppid)
    return ANSWERED + 7;
  return real_syscall(nr, a, b, c, d, e, f);
}

#ifndef OMIT_ROUTED
long reverie_sabre_routed_syscall_v1(long route, long nr, long a, long b,
                                     long c, long d, long e, long f,
                                     void* sp) {
  if (nr == SYS_getppid) {
    int wrong = a != 11 || b != 12 || c != 13 || d != 14 || e != 15 ||
                f != 16 || sp == NULL;
    return ANSWERED + route + (wrong ? 100 : 0);
  }
  return real_syscall(nr, a, b, c, d, e, f);
}
#endif

int reverie_sabre_post_arm_routing_v1(void) {
#ifdef UNARMED
  return 0;
#else
  return 1;
#endif
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
