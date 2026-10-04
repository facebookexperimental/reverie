/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A getpid site in a shared object whose file this program truncates before
 * the site's first call, and a control site in this executable's text
 * (review finding F7 on https://github.com/rrnewton/reverie/pull/818).
 *
 * Usage: hybrid_truncated_object LIBRARY truncate|keep
 *
 * LIBRARY is the file of the shared object built from
 * hybrid_truncated_object_lib.c, which this executable loads at startup.
 * With `truncate`, the program cuts that file at the start of the object's
 * untouched data pages, which are then file pages past the end of the file
 * and fault when read. The object's code and unwind table come before them
 * in the file and stay in it, so a census that read those pages as zeros
 * would still find the library site patchable. The tracer builds the library
 * site's entry census at the site's first call, from every mapping of the
 * object that was readable when LiteInst reported Ready, so it reads the
 * faulting pages. With `keep`, the program leaves the file alone, as a
 * control.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
extern long reverie_liteinst_library_getpid(void);

typedef uint64_t (*count_fn)(uint64_t);

static void* load_symbol(const char* name) {
  void* symbol = dlsym(RTLD_DEFAULT, name);
  if (symbol == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return symbol;
}

struct untouched {
  const char* name;
  uint64_t address;
  uint64_t length;
  int found;
  /* The file offset of the untouched pages. */
  uint64_t offset;
};

/* Finds the file offset of the untouched pages, which must lie in the file
 * part of one of the object's loaded segments. */
static int find_untouched(struct dl_phdr_info* info, size_t size, void* data) {
  (void)size;
  struct untouched* untouched = data;
  const char* slash = strrchr(info->dlpi_name, '/');
  const char* name = slash == NULL ? info->dlpi_name : slash + 1;
  if (strcmp(name, untouched->name) != 0) {
    return 0;
  }
  for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr)* header = &info->dlpi_phdr[i];
    uint64_t start = info->dlpi_addr + header->p_vaddr;
    if (header->p_type == PT_LOAD && start <= untouched->address &&
        untouched->address + untouched->length <= start + header->p_filesz) {
      untouched->offset = header->p_offset + (untouched->address - start);
      untouched->found = 1;
    }
  }
  return 1;
}

/* Reads the first untouched page through /proc/self/mem, as the tracer's
 * census reads the object, and returns 0 if it was read, or the errno. */
static int read_untouched(uint64_t address) {
  int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
  if (memory < 0) {
    exit(29);
  }
  unsigned char byte;
  ssize_t read = pread(memory, &byte, 1, (off_t)address);
  int error = read < 0 ? errno : 0;
  close(memory);
  if (read == 1 && byte != 1) {
    exit(30);
  }
  return read == 1 ? 0 : error == 0 ? -1 : error;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    return 2;
  }
  int truncate = strcmp(argv[2], "truncate") == 0;
  if (!truncate && strcmp(argv[2], "keep") != 0) {
    return 2;
  }

  /* Everything that reads the shared object's symbol tables runs before the
   * cut. */
  count_fn traps = (count_fn)load_symbol("reverie_liteinst_site_trap_count");
  count_fn hooks = (count_fn)load_symbol("reverie_liteinst_site_hook_count");
  uint64_t library_site =
      (uint64_t)(uintptr_t)load_symbol("reverie_liteinst_library_site");
  const char* slash = strrchr(argv[1], '/');
  struct untouched untouched = {
      .name = slash == NULL ? argv[1] : slash + 1,
      .address = (uint64_t)(uintptr_t)load_symbol("reverie_liteinst_untouched"),
      .length = 3 * 4096,
  };
  dl_iterate_phdr(find_untouched, &untouched);
  if (!untouched.found || untouched.offset % 4096 != 0) {
    return 25;
  }

  if (truncate) {
    int file = open(argv[1], O_WRONLY | O_CLOEXEC);
    if (file < 0) {
      return 27;
    }
    if (ftruncate(file, (off_t)untouched.offset) != 0) {
      return 28;
    }
    close(file);
  }
  /* The census must meet exactly what this read meets: EIO after the cut,
   * the page's first byte without it. */
  if (read_untouched(untouched.address) != (truncate ? EIO : 0)) {
    return 26;
  }

  long pid = reverie_liteinst_control_getpid();
  for (unsigned i = 0; i < 16; ++i) {
    if (reverie_liteinst_library_getpid() != pid) {
      return 23;
    }
    if (reverie_liteinst_control_getpid() != pid) {
      return 24;
    }
  }

  uint64_t control_site = (uint64_t)(uintptr_t)&reverie_liteinst_control_site;
  printf(
      "library traps=%" PRIu64 " hooks=%" PRIu64 " control traps=%" PRIu64
      " hooks=%" PRIu64 "\n",
      traps(library_site),
      hooks(library_site),
      traps(control_site),
      hooks(control_site));
  fflush(stdout);
  /* Skip the shared object's destructors, which could read its cut pages. */
  _exit(0);
}
