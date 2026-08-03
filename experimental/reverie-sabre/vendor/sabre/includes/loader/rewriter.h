/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#ifndef LIBRARY_H_
#define LIBRARY_H_

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <sys/types.h>

#include "compiler.h"
#include "loader/maps.h"

struct symbol {
  const char *name;
  ElfW(Sym) sym;
  struct hlist_node symbol_hash;
};

/* Internal data structure for sections. */
struct section {
  const char *name; /* section name */
  ElfW(Shdr) shdr;  /* section header */
  struct hlist_node section_hash;
};

struct library {
  char *pathname;
  bool valid;
  bool vdso;
  char *asr_offset;
  ElfW(Ehdr) ehdr;
  struct rb_root rb_region;
  struct hlist_head *section_hash;
  struct hlist_head *symbol_hash;
  char *image;
  size_t image_size;
  struct maps *maps; // TODO(andronat): do we really need this?
  struct hlist_node library_hash;
};

struct s_code {
  char *addr;
  int len;
  unsigned short insn;
  bool is_ip_relative;
};

int which_lib_name_interesting(const char *interesting_libs[],
                               const char *pathname);
void memorymaps_rewrite_all(const char *libs[], const char *bin, bool loader);
void memorymaps_rewrite_lib(const char *libname);

#endif /* LIBRARY_H_ */
