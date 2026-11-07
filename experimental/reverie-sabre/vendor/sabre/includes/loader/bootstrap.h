/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef SBR_BOOTSTRAP_H
#define SBR_BOOTSTRAP_H

#include <stdbool.h>
#include <stddef.h>

/* Optional supervisor protocol. An ordinary kernel rejects this prctl option.
 * The supervisor must authenticate this instruction in the exact launched
 * loader, the stopped thread/image generation, and every pointed-to extent.
 * Neither the option number nor a request's argument shape is authority.
 * IMAGE is an acknowledgement only after the supervisor validates the real
 * final stack/auxv, finds exactly one writable 16-byte AT_RANDOM target, and
 * completes its initialization there. The loader does not validate auxv.
 *
 * Enabled execution must make no rewritten non-plugin getrandom call before
 * IMAGE. That includes loader-internal code between the initial rewrite and
 * the IMAGE stop; a future such call is a fatal unsupported phase, never a
 * fallback to host entropy. The native phase control checks that such a call
 * is fatal; it does not establish that no loader-internal caller exists.
 *
 * The supervisor must write no more than TAKE's capacity, retire the state
 * only after a successful bounded write, and reject subsequent takes (for
 * example with ESTALE). A failed/short-capacity transfer must not consume it.
 * The loader forwards negative errors verbatim; that does not authorize a
 * consumer to retry stale proof. Only its supervisor can establish freshness.
 * A zero/oversized success violates the protocol: the consumer must fail,
 * never retry by constructing fresh state or replaying random requests.
 */
#define SBR_BOOTSTRAP_OPTION 0x53425242UL
#define SBR_BOOTSTRAP_VERSION 1UL
#define SBR_BOOTSTRAP_MAX_STATE 4096UL
#define SBR_BOOTSTRAP_ENV "REVERIE_SABRE_BOOTSTRAP_V1"

enum sbr_bootstrap_operation {
  SBR_BOOTSTRAP_IMAGE = 1,
  SBR_BOOTSTRAP_GETRANDOM = 2,
  SBR_BOOTSTRAP_TAKE_STATE = 3,
  SBR_BOOTSTRAP_PRLIMIT = 4,
  SBR_BOOTSTRAP_GETRLIMIT = 5,
};

typedef long (*sbr_bootstrap_take_fn)(void *, size_t);
/* Installers run during single-threaded plugin preinitialization. Return 0
 * to accept; the continuation installer may return -ENOTSUP to decline.
 * Every other nonzero continuation return is fatal. The initial bootstrap
 * installer requires 0 and treats every nonzero return as fatal.
 */
typedef int (*sbr_bootstrap_install_fn)(sbr_bootstrap_take_fn);

void sbr_bootstrap_configure(void);
/* The bootstrap option arrived in a launch specification rather than in the
 * initial environment, so there is no stack entry to consume. VALUE is the
 * option's value, which must be "1" as in the environment. It is not put in
 * SaBRe's environment, where the plugin would carry it into exec'd images. */
void sbr_bootstrap_option_from_launch(const char *value);
bool sbr_bootstrap_enabled(void);
void sbr_bootstrap_image(void *stack, void *entry);
long sbr_bootstrap_getrandom(long buffer, long length, long flags,
                             void *wrapper_sp);
/* Called by premain with the optional continuation installer.
 * The installer symbol is reverie_sabre_install_loader_continuation_v1.
 * This authorizes transport only: the supervisor must authenticate a real
 * image transition (or its explicitly supported initial legacy image), return
 * a distinct typed continuation, and refuse missing/stale/duplicate proof.
 * It implies no IMAGE, GETRANDOM, auxv initialization or RNG state transfer.
 * Missing/NULL or -ENOTSUP leaves continuation disabled; 0 enables it only
 * after the installer returns; any other result is propagated as fatal.
 * Configure/IMAGE/install finish before plugin consumers start. TAKE itself
 * atomically claims the transfer: concurrent or retired takes return EPROTO,
 * and a failed transfer releases its claim without retiring the state.
 */
long sbr_bootstrap_prlimit(long pid, long resource, long old_limit,
                           void *wrapper_sp);
long sbr_bootstrap_getrlimit(long resource, long limit, void *wrapper_sp);
int sbr_bootstrap_install_continuation(sbr_bootstrap_install_fn install);
long sbr_bootstrap_take_state(void *buffer, size_t capacity);

/* A single exported, non-inlined syscall site for all three operations. IMAGE
 * carries final stack/entry/version/zero; GETRANDOM carries the original
 * buffer/length/flags/wrapper; TAKE carries output/capacity/version/zero.
 * There is no new IPC service, libc call, allocation, or TLS access here.
 */
long sbr_bootstrap_request_v1(unsigned long operation, unsigned long arg1,
                              unsigned long arg2, unsigned long arg3,
                              unsigned long arg4);

#endif
