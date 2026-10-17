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
struct intercept_tls_context;
/* Caller owns loader TLS; callback TLS is restored only during its callback. */
void memorymaps_patch_intercept(int index,
                                const struct intercept_tls_context *tls);

/* The launch setting that decides what the rewriter does with a SYSCALL at a
 * site too short for a jump rewrite: "marker" (the default) writes the UD0
 * marker the loader's SIGILL handler dispatches; "raw" leaves the instruction
 * as it is, for a runtime that traps unrewritten syscalls itself. The loader
 * consumes it; the plugin does not see it. */
#define SBR_SHORT_SYSCALL_SITES_ENV "REVERIE_SABRE_SHORT_SYSCALL_SITES"
/* Loader-internal (hidden): the loader links with -rdynamic, and a new
 * dynamic symbol would grow its first segment, moving the mappings a guest
 * sees in /proc/self/maps. */
attribute_hidden void sbr_rewriter_option_from_launch(const char *value);
/* Whether the launch chose "raw". A raw short site is monitored only by a
 * plugin whose own trap path takes every syscall the rewriter left as it is,
 * so the loader refuses "raw" unless the plugin reports post-arm routing. */
attribute_hidden bool sbr_rewriter_short_sites_raw(void);

/* Names the client's dynamic linker (its PT_INTERP, open as `fd`, which the
 * loader mapped it from) before ld.so is rewritten. From then on "ld"
 * intercepts are installed only in mappings of exactly that file, never in
 * another object that merely has a dynamic linker's name; afterwards, whether
 * every registered one was. */
attribute_hidden void sbr_rewriter_expect_dynamic_linker(int fd,
                                                         const char *path);
attribute_hidden bool sbr_rewriter_dynamic_linker_intercepted(void);

#endif /* LIBRARY_H_ */
