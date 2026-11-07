/* Copyright © 2026 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SBR_BACKEND_STATS_ENV "REVERIE_SABRE_BACKEND_STATS_FD"
#define SBR_BACKEND_STATS_MAGIC UINT64_C(0x3154415453524253)
#define SBR_BACKEND_STATS_VERSION UINT32_C(2)
#define SBR_BACKEND_STATS_BUCKETS 15

enum sbr_patch_route {
  SBR_PATCH_JUMP_TRAMPOLINE = 0,
  SBR_PATCH_REWRITE_SIGILL_MARKER = 1,
  SBR_PATCH_PTRACE_INSTALLED_MARKER = 2,
  SBR_PATCH_ROUTE_COUNT = 3,
};

/* How a guest syscall reached the plugin. Syscalls the plugin itself issues
 * run natively and are not dispatches. */
enum sbr_dispatch_route {
  SBR_DISPATCH_TRAMPOLINE = 0,
  SBR_DISPATCH_SIGILL_MARKER = 1,
  SBR_DISPATCH_ROUTE_COUNT = 2,
};

enum sbr_slow_path {
  SBR_SLOW_PTRACE_SYSCALL_ENTRY = 0,
  SBR_SLOW_PTRACE_SYSCALL_EXIT = 1,
  SBR_SLOW_PTRACE_RAW_SYSCALL_REDIRECT = 2,
  SBR_SLOW_REWRITE_SIGILL_DISPATCH = 3,
  SBR_SLOW_PTRACE_INSTALLED_SIGILL_DISPATCH = 4,
  SBR_SLOW_RDTSC_SIGILL_DISPATCH = 5,
  SBR_SLOW_RDTSCP_SIGILL_DISPATCH = 6,
  SBR_SLOW_VFORK_CHILD_NATIVE_DISPATCH = 7,
  SBR_SLOW_VFORK_CHILD_REJECTED = 8,
  SBR_SLOW_LIBC_GETRANDOM_DETOUR = 9,
  SBR_SLOW_PATH_COUNT = 10,
};

struct sbr_backend_stats {
  uint64_t magic;
  uint32_t version;
  uint32_t size;
  uint64_t candidate_rips;
  uint64_t patched_rips;
  uint64_t classified_candidates;
  uint64_t cacheline_straddlers;
  uint64_t non_straddling;
  uint64_t instruction_lengths[SBR_BACKEND_STATS_BUCKETS];
  uint64_t straddle_after[SBR_BACKEND_STATS_BUCKETS];
  uint64_t patch_routes[SBR_PATCH_ROUTE_COUNT];
  uint64_t slow_paths[SBR_SLOW_PATH_COUNT];
  uint64_t dispatch_routes[SBR_DISPATCH_ROUTE_COUNT];
};

void sbr_backend_stats_init(void);
/* The stats descriptor setting from a launch specification, which does not
 * put it in SaBRe's environment. Call before sbr_backend_stats_init. */
void sbr_backend_stats_option_from_launch(const char *value);
/* Records a patched syscall instruction that starts at `instruction`. A
 * SIGILL-marker patch also names its marker's address, which is the address
 * the SIGILL handler sees; NULL for any other route. */
void sbr_backend_stats_record_patch(void *instruction,
                                    unsigned instruction_length,
                                    enum sbr_patch_route route,
                                    const void *marker);
void sbr_backend_stats_record_slow_path(enum sbr_slow_path path);
void sbr_backend_stats_record_dispatch(enum sbr_dispatch_route route);
bool sbr_backend_stats_is_rewrite_sigill_site(const void *rip);
