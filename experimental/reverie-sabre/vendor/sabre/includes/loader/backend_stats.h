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
#define SBR_BACKEND_STATS_VERSION UINT32_C(1)
#define SBR_BACKEND_STATS_BUCKETS 15

enum sbr_patch_route {
  SBR_PATCH_JUMP_TRAMPOLINE = 0,
  SBR_PATCH_REWRITE_SIGILL_MARKER = 1,
  SBR_PATCH_PTRACE_INSTALLED_MARKER = 2,
  SBR_PATCH_ROUTE_COUNT = 3,
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
};

void sbr_backend_stats_init(void);
void sbr_backend_stats_record_patch(void *rip, unsigned instruction_length,
                                    enum sbr_patch_route route);
void sbr_backend_stats_record_slow_path(enum sbr_slow_path path);
bool sbr_backend_stats_is_rewrite_sigill_site(const void *rip);
