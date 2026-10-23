#define _GNU_SOURCE
#include <sys/syscall.h>
#include <time.h>
#include "real_syscall.h"
#include "sbr_api_defs.h"

/* A resolution no kernel reports, so the client can tell the plugin answered. */
#define MARKER_NSEC 12345

static long handler(long nr, long a, long b, long c, long d, long e, long f,
                    void* sp) {
  (void)sp;
  if (nr == SYS_clock_getres && a == CLOCK_MONOTONIC && b != 0) {
    struct timespec* res = (struct timespec*)b;
    res->tv_sec = 0;
    res->tv_nsec = MARKER_NSEC;
    return 0;
  }
  return real_syscall(nr, a, b, c, d, e, f);
}
#ifdef __NX_INTERCEPT_RDTSC
static long rdtsc(void) {
  unsigned a, d;
  __asm__ volatile("rdtsc" : "=a"(a), "=d"(d));
  return ((long)d << 32) | a;
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
