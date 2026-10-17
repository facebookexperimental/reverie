/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef LD_SC_HANDLER_H
#define LD_SC_HANDLER_H

#include <stdbool.h>

// Stack-only context for initial dynamic-image function-registration catch-up.
// No callback or thread-specific TLS address is retained in the registry.
struct intercept_tls_context {
  unsigned long caller;
  unsigned long loader;
};

#ifdef __x86_64__
bool enter_intercept_loader_tls(struct intercept_tls_context *context);
void load_intercept_tls(unsigned long address);
#endif

void load_client_tls();
void load_sabre_tls();

long runtime_syscall_router(long, long, long, long, long, long, long, void *);
long runtime_sigill_syscall_router(long, long, long, long, long, long, long,
                                   void *);
#if defined(__NX_INTERCEPT_RDTSC) && defined(__x86_64__)
long runtime_rdtsc_router(void);
#endif
void sbr_enable_post_arm_routing(void);
bool sbr_post_arm_routing(void);
void_void_fn ld_vdso_callback(long, void_void_fn);
void setup_plugin_vdso(sbr_icept_vdso_callback_fn);

#endif /* !LD_SC_HANDLER_H */
