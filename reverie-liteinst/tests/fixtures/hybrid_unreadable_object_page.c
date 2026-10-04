/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A getpid site in this executable's text, called while one page of the
 * executable's own initialized data is PROT_NONE (review finding F7 on
 * https://github.com/rrnewton/reverie/pull/818).
 *
 * The tracer builds the site's entry census at the site's first call, from
 * every mapping of the executable that was readable when LiteInst reported
 * Ready, so it reads the page that this program has made unreadable since.
 * Native Linux runs the program to completion; the site has an unwind-table
 * entry and no branch, so LiteInst patches it.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_control_getpid\n"
    ".type reverie_liteinst_control_getpid,@function\n"
    "reverie_liteinst_control_getpid:\n"
    ".cfi_startproc\n"
    "mov $39, %eax\n"
    ".global reverie_liteinst_control_site\n"
    "reverie_liteinst_control_site:\n"
    "syscall\n"
    ".rept 6\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_control_getpid, "
    ".-reverie_liteinst_control_getpid\n");

extern long reverie_liteinst_control_getpid(void);
extern unsigned char reverie_liteinst_control_site;

/* One initialized page of .data, so part of the executable's file-backed
 * read-write mapping rather than of an anonymous .bss mapping. */
static volatile unsigned char guarded[4096]
    __attribute__((aligned(4096))) = {1};

typedef uint64_t (*count_fn)(uint64_t);

static count_fn load_count(const char* name) {
  count_fn function = (count_fn)dlsym(RTLD_DEFAULT, name);
  if (function == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return function;
}

int main(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  if (mprotect((void*)guarded, page, PROT_NONE) != 0) {
    return 21;
  }
  long pid = reverie_liteinst_control_getpid();
  for (unsigned i = 0; i < 16; ++i) {
    if (reverie_liteinst_control_getpid() != pid) {
      return 24;
    }
  }
  if (mprotect((void*)guarded, page, PROT_READ | PROT_WRITE) != 0) {
    return 22;
  }

  count_fn traps = load_count("reverie_liteinst_site_trap_count");
  count_fn hooks = load_count("reverie_liteinst_site_hook_count");
  uint64_t site = (uint64_t)(uintptr_t)&reverie_liteinst_control_site;
  printf(
      "control traps=%" PRIu64 " hooks=%" PRIu64 " guarded=%u\n",
      traps(site),
      hooks(site),
      (unsigned)guarded[0]);
  return 0;
}
