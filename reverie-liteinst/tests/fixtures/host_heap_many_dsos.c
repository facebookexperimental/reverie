/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Exercises the LiteInst host constructor with many executable mappings.
 *
 * The program is linked (NEEDED, no dlopen) against HEAP_DSO_COUNT copies of
 * host_heap_dso.c, so all of them are mapped before the preload constructor
 * runs and each needs its own trampoline arena.  The constructor allocates a
 * transient maps buffer per executable mapping; a constructor heap that does
 * not reclaim it runs out, and a dropped arena silently turns that mapping's
 * site into a trap-only fallback.  The program reports:
 *   line 1: per-site activation (each site: 1 discovery trap, then hooks);
 *   line 2: eligible executable mappings and trampoline arena mappings;
 *   line 3: the constructor heap's high-water mark.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HEAP_DSO_COUNT
#error "HEAP_DSO_COUNT must be defined"
#endif

#define CALLS_PER_DSO 4

typedef uint64_t (*count_fn)(uint64_t);
typedef uint64_t (*value_fn)(void);
typedef long (*call_fn)(void);

static void* require(const char* name) {
  void* symbol = dlsym(RTLD_DEFAULT, name);
  if (symbol == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return symbol;
}

int main(void) {
  count_fn trap_count = (count_fn)require("reverie_liteinst_site_trap_count");
  count_fn hook_count = (count_fn)require("reverie_liteinst_site_hook_count");
  value_fn high_water =
      (value_fn)require("reverie_liteinst_host_init_heap_high_water");

  uint64_t traps = 0;
  uint64_t hooks = 0;
  unsigned calls = 0;
  unsigned hooked = 0;
  for (unsigned k = 0; k < HEAP_DSO_COUNT; ++k) {
    char name[64];
    snprintf(name, sizeof(name), "heap_dso_call_%u", k);
    call_fn call = (call_fn)require(name);
    snprintf(name, sizeof(name), "heap_dso_site_%u", k);
    uint64_t site = (uint64_t)(uintptr_t)require(name);
    long expected = -1;
    for (unsigned i = 0; i < CALLS_PER_DSO; ++i) {
      long observed = call();
      if (expected == -1) {
        expected = observed;
      } else if (observed != expected) {
        return 21;
      }
      ++calls;
    }
    uint64_t site_traps = trap_count(site);
    uint64_t site_hooks = hook_count(site);
    traps += site_traps;
    hooks += site_hooks;
    if (site_traps == 1 && site_hooks == CALLS_PER_DSO - 1) {
      ++hooked;
    }
  }

  FILE* maps = fopen("/proc/self/maps", "r");
  if (maps == NULL) {
    return 22;
  }
  /* Patching a site after the constructor can split an object's text into
   * several contiguous VMAs of the same file (the patched page is
   * re-protected), so contiguous executable VMAs of one inode count as the
   * single mapping the constructor saw. */
  unsigned exec_mappings = 0;
  unsigned trampoline_arenas = 0;
  unsigned long previous_end = 0;
  unsigned long previous_inode = 0;
  char line[4096];
  while (fgets(line, sizeof(line), maps) != NULL) {
    unsigned long start = 0;
    unsigned long end = 0;
    unsigned long inode = 0;
    char permissions[8] = {0};
    if (sscanf(
            line,
            "%lx-%lx %7s %*s %*s %lu",
            &start,
            &end,
            permissions,
            &inode) != 4) {
      return 23;
    }
    if (permissions[2] != 'x') {
      continue;
    }
    if (strstr(line, "liteinst2-trampoline") != NULL) {
      ++trampoline_arenas;
    } else if (
        strstr(line, "[vsyscall]") == NULL &&
        !(start == previous_end && inode == previous_inode)) {
      ++exec_mappings;
    }
    previous_end = end;
    previous_inode = inode;
  }
  fclose(maps);

  printf(
      "dsos=%u calls=%u traps=%" PRIu64 " hooks=%" PRIu64 " dsos_hooked=%u\n",
      (unsigned)HEAP_DSO_COUNT,
      calls,
      traps,
      hooks,
      hooked);
  printf(
      "exec_mappings=%u trampoline_arenas=%u\n",
      exec_mappings,
      trampoline_arenas);
  printf("init_heap_high_water=%" PRIu64 "\n", high_water());
  return 0;
}
