/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Two getpid sites that LiteInst must leave unpatched, and one control site
 * that it must patch (https://github.com/rrnewton/reverie/issues/812).
 *
 * A patch replaces the syscall and the bytes after it with a jump.
 * - reverie_liteinst_interior_getpid branches to the byte two past its
 *   syscall, as glibc's posix_madvise branches to the ret after its syscall.
 *   Once that site is patched, the branch lands inside the jump.
 * - reverie_liteinst_unlisted_getpid has no unwind-table entry, so the entry
 *   census cannot prove that nothing branches into its displaced bytes.
 * - reverie_liteinst_control_getpid has an unwind-table entry and no branch,
 *   so it shows that the census of this executable admits ordinary sites.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__asm__(
    ".text\n"
    ".p2align 4\n"
    ".global reverie_liteinst_interior_getpid\n"
    ".type reverie_liteinst_interior_getpid,@function\n"
    "reverie_liteinst_interior_getpid:\n"
    ".cfi_startproc\n"
    "mov $39, %eax\n"
    "test %rdi, %rdi\n"
    "jnz 1f\n"
    ".global reverie_liteinst_interior_site\n"
    "reverie_liteinst_interior_site:\n"
    "syscall\n"
    ".global reverie_liteinst_interior_after\n"
    "reverie_liteinst_interior_after:\n"
    "1:\n"
    ".rept 6\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size reverie_liteinst_interior_getpid, "
    ".-reverie_liteinst_interior_getpid\n"
    ".p2align 4\n"
    ".global reverie_liteinst_unlisted_getpid\n"
    ".type reverie_liteinst_unlisted_getpid,@function\n"
    "reverie_liteinst_unlisted_getpid:\n"
    "mov $39, %eax\n"
    ".global reverie_liteinst_unlisted_site\n"
    "reverie_liteinst_unlisted_site:\n"
    "syscall\n"
    ".rept 6\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".size reverie_liteinst_unlisted_getpid, "
    ".-reverie_liteinst_unlisted_getpid\n"
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

extern long reverie_liteinst_interior_getpid(long skip);
extern long reverie_liteinst_unlisted_getpid(void);
extern long reverie_liteinst_control_getpid(void);
extern unsigned char reverie_liteinst_interior_site;
extern unsigned char reverie_liteinst_unlisted_site;
extern unsigned char reverie_liteinst_control_site;

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
  long pid = reverie_liteinst_control_getpid();
  for (unsigned i = 0; i < 16; ++i) {
    if (reverie_liteinst_interior_getpid(0) != pid) {
      return 21;
    }
    /* Skips the syscall, so %rax still holds the getpid number. */
    if (reverie_liteinst_interior_getpid(1) != 39) {
      return 22;
    }
    if (reverie_liteinst_unlisted_getpid() != pid) {
      return 23;
    }
    if (reverie_liteinst_control_getpid() != pid) {
      return 24;
    }
  }

  count_fn traps = load_count("reverie_liteinst_site_trap_count");
  count_fn hooks = load_count("reverie_liteinst_site_hook_count");
  uint64_t sites[] = {
      (uint64_t)(uintptr_t)&reverie_liteinst_interior_site,
      (uint64_t)(uintptr_t)&reverie_liteinst_unlisted_site,
      (uint64_t)(uintptr_t)&reverie_liteinst_control_site,
  };
  printf(
      "interior traps=%" PRIu64 " hooks=%" PRIu64 " unlisted traps=%" PRIu64
      " hooks=%" PRIu64 " control traps=%" PRIu64 " hooks=%" PRIu64 "\n",
      traps(sites[0]),
      hooks(sites[0]),
      traps(sites[1]),
      hooks(sites[1]),
      traps(sites[2]),
      hooks(sites[2]));
  return 0;
}
