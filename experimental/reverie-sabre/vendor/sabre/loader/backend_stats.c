/* Copyright © 2026 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "loader/backend_stats.h"

#include "loader/global_vars.h"
#include "macros.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct rewrite_sigill_site {
  const void *rip;
  struct rewrite_sigill_site *next;
};

static struct sbr_backend_stats *stats;
static struct rewrite_sigill_site *rewrite_sigill_sites;

static void increment(uint64_t *counter) {
  __atomic_fetch_add(counter, UINT64_C(1), __ATOMIC_RELAXED);
}

void sbr_backend_stats_init(void) {
  const char *value = getenv(SBR_BACKEND_STATS_ENV);
  if (value == NULL)
    return;

  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < 0 ||
      parsed > INT_MAX)
    _nx_fatal_printf("invalid %s value\n", SBR_BACKEND_STATS_ENV);

  int fd = (int)parsed;
  struct stat info;
  if (fstat(fd, &info) != 0 || info.st_size != sizeof(*stats))
    _nx_fatal_printf("invalid SaBRe backend stats descriptor\n");

  void *mapping =
      mmap(NULL, sizeof(*stats), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mapping == MAP_FAILED)
    _nx_fatal_printf("failed to map SaBRe backend stats descriptor\n");

  stats = mapping;
  if (stats->magic != SBR_BACKEND_STATS_MAGIC ||
      stats->version != SBR_BACKEND_STATS_VERSION ||
      stats->size != sizeof(*stats))
    _nx_fatal_printf("incompatible SaBRe backend stats descriptor\n");
}

void sbr_backend_stats_record_patch(void *rip, unsigned instruction_length,
                                    enum sbr_patch_route route) {
  if (stats == NULL)
    return;
  if (instruction_length == 0 ||
      instruction_length > SBR_BACKEND_STATS_BUCKETS ||
      route >= SBR_PATCH_ROUTE_COUNT)
    _nx_fatal_printf("invalid SaBRe patch statistics record\n");

  increment(&stats->candidate_rips);
  increment(&stats->patched_rips);
  increment(&stats->classified_candidates);
  increment(&stats->instruction_lengths[instruction_length - 1]);

  uintptr_t offset = (uintptr_t)rip & (uintptr_t)63;
  if (offset + instruction_length > 64) {
    unsigned prefix = 64 - offset;
    increment(&stats->cacheline_straddlers);
    increment(&stats->straddle_after[prefix - 1]);
  } else {
    increment(&stats->non_straddling);
  }
  increment(&stats->patch_routes[route]);

  if (route == SBR_PATCH_REWRITE_SIGILL_MARKER) {
    struct rewrite_sigill_site *site = malloc(sizeof(*site));
    if (site == NULL)
      _nx_fatal_printf("failed to retain SaBRe SIGILL patch identity\n");
    site->rip = rip;
    do {
      site->next = __atomic_load_n(&rewrite_sigill_sites, __ATOMIC_ACQUIRE);
    } while (!__atomic_compare_exchange_n(&rewrite_sigill_sites, &site->next,
                                          site, false, __ATOMIC_RELEASE,
                                          __ATOMIC_ACQUIRE));
  }
}

void sbr_backend_stats_record_slow_path(enum sbr_slow_path path) {
  if (stats == NULL)
    return;
  if (path >= SBR_SLOW_PATH_COUNT)
    _nx_fatal_printf("invalid SaBRe slow-path statistics record\n");
  increment(&stats->slow_paths[path]);
}

bool sbr_backend_stats_is_rewrite_sigill_site(const void *rip) {
  struct rewrite_sigill_site *site =
      __atomic_load_n(&rewrite_sigill_sites, __ATOMIC_ACQUIRE);
  while (site != NULL) {
    if (site->rip == rip)
      return true;
    site = site->next;
  }
  return false;
}
