/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#ifndef MAPS_H_
#define MAPS_H_

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>

#include "compiler.h"
#include "hlist.h"
#include "jhash.h"
#include "list.h"
#include "rbtree.h"

/** Process memory regions */
enum region_type {
  REGION_EXECUTABLE = 0x1,
  REGION_LIBRARY = 0x2,
  REGION_HEAP = 0x4,
  REGION_STACK = 0x8,
  REGION_BSS = 0x10,
  REGION_VDSO = 0x20,
  REGION_ALL = 0x7F,
};

#define LIBS_HASHTABLE_SIZE 16
#define library_hashfn(n) jhash(n, strlen(n), 0) & (LIBS_HASHTABLE_SIZE - 1)
#define libraryhash_entry(node)                                                \
  hlist_entry_safe((node), struct library, library_hash)

#define sectionhash_size 16
#define symbolhash_size 16

struct maps {
  int fd;

  struct library *lib_vdso;

  // This is a hash table: <library_hashfn(lib_pathname), struct library>
  struct hlist_head libraries[LIBS_HASHTABLE_SIZE];
};

/** Region obtained via /proc/<pid>/maps */
struct region {
  /** Region start address */
  void *start;
  /** Region end address */
  void *end;
  /** Region size */
  size_t size;
  /** Access protection */
  int perms;
  /** Region offset */
  ElfW(Addr) offset;
  /** Device identifier */
  dev_t dev;
  /** Device inode */
  ino_t inode;
  /** Associated pathname */
  const char *pathname;
  /** Region type */
  enum region_type type;
  /** Regions tree */
  struct rb_node rb_region;
};

uintptr_t first_region(const char *);
uintptr_t end_of_stack_region();
struct maps *maps_read(const char *libname) attribute_hidden;
void *maps_alloc_near(int maps_fd, void *addr, size_t size, int prot, bool near,
                      uint64_t max_distance) attribute_hidden;
void maps_release(struct maps *maps) attribute_hidden;
void binrw_rd_init_maps(void) attribute_hidden;

/**
 * Iterate over hash table elements of given type.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos entry pointer to use as a loop cursor
 * @param table your table
 * @param member the name of the enry within the struct
 */
#define for_each_library(lib, maps)                                            \
  for (int i = 0; i < LIBS_HASHTABLE_SIZE; ++i)                                \
    for (lib = libraryhash_entry((maps)->libraries[i].first); lib;             \
         lib = libraryhash_entry(lib->library_hash.next))

#endif /* MAPS_H_ */
