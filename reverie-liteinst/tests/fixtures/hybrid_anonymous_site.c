/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A getpid site in an anonymous executable mapping made after LiteInst
 * initialized, as a JIT writes one, and a control site in this executable's
 * text (https://github.com/rrnewton/reverie/issues/812).
 *
 * LiteInst records its trampoline arenas when it initializes, so the
 * anonymous mapping has none and its site stays on ptrace. The entry census
 * would refuse it too, since it decodes only file-backed objects. The control
 * site has an unwind-table entry and no branch, so it shows that the same
 * process still patches an ordinary site.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

typedef uint64_t (*count_fn)(uint64_t);

static count_fn load_count(const char* name) {
  count_fn function = (count_fn)dlsym(RTLD_DEFAULT, name);
  if (function == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return function;
}

/* mov $39, %eax; syscall; six nops; ret: the same bytes as the control. */
static const unsigned char anonymous_code[] = {
    0xb8,
    0x27,
    0x00,
    0x00,
    0x00,
    0x0f,
    0x05,
    0x90,
    0x90,
    0x90,
    0x90,
    0x90,
    0x90,
    0xc3,
};
enum { ANONYMOUS_OFFSET = 64, ANONYMOUS_SITE_OFFSET = 5 };

int main(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char* mapping = mmap(
      NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    return 21;
  }
  memcpy(mapping + ANONYMOUS_OFFSET, anonymous_code, sizeof anonymous_code);
  if (mprotect(mapping, page, PROT_READ | PROT_EXEC) != 0) {
    return 22;
  }
  long (*anonymous_getpid)(void) =
      (long (*)(void))(void*)(mapping + ANONYMOUS_OFFSET);
  uint64_t anonymous_site =
      (uint64_t)(uintptr_t)(mapping + ANONYMOUS_OFFSET + ANONYMOUS_SITE_OFFSET);

  long pid = reverie_liteinst_control_getpid();
  for (unsigned i = 0; i < 16; ++i) {
    if (anonymous_getpid() != pid) {
      return 23;
    }
    if (reverie_liteinst_control_getpid() != pid) {
      return 24;
    }
  }

  count_fn traps = load_count("reverie_liteinst_site_trap_count");
  count_fn hooks = load_count("reverie_liteinst_site_hook_count");
  uint64_t control_site = (uint64_t)(uintptr_t)&reverie_liteinst_control_site;
  printf(
      "anonymous traps=%" PRIu64 " hooks=%" PRIu64 " control traps=%" PRIu64
      " hooks=%" PRIu64 "\n",
      traps(anonymous_site),
      hooks(anonymous_site),
      traps(control_site),
      hooks(control_site));
  return 0;
}
