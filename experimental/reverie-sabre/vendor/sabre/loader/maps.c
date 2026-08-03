/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#include "maps.h"
#include <arch/rewriter_tools.h>

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "hlist.h"
#include "list.h"
#include "rbtree.h"

#include "macros.h"

#define MAX_BUF_SIZE PATH_MAX + 1024
#define MAX_INITIAL_MAPPINGS 1024

static long initial_mappings[MAX_INITIAL_MAPPINGS];
static int initial_mapping_cnt = 0;

static void library_init(struct library *l, const char *name,
                         struct maps *maps) {
  l->pathname = strdup(name);

  l->rb_region = RB_ROOT;
  l->section_hash = malloc(sizeof(struct hlist_head) * sectionhash_size);
  for (int i = 0; i < sectionhash_size; i++)
    INIT_HLIST_HEAD(&l->section_hash[i]);
  l->symbol_hash = malloc(sizeof(struct hlist_head) * symbolhash_size);
  for (int i = 0; i < symbolhash_size; i++)
    INIT_HLIST_HEAD(&l->symbol_hash[i]);

  INIT_HLIST_NODE(&l->library_hash);

  l->valid = false;
  l->vdso = false;
  l->asr_offset = 0;
  l->image = NULL;
  l->image_size = 0;
  l->maps = maps;
}

static void library_release(struct library *lib) {
  free(lib->pathname);
  free(lib->section_hash);
  free(lib->symbol_hash);
}

static inline struct library *
library_find(struct hlist_head hashtable[LIBS_HASHTABLE_SIZE],
             const char *pathname) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct library *l;

  head = &hashtable[library_hashfn(pathname)];
  hlist_for_each_entry(l, node, head, library_hash) {
    if (strcmp(l->pathname, pathname) == 0)
      return l;
  }

  return NULL;
}

static inline void library_add(struct hlist_head hashtable[LIBS_HASHTABLE_SIZE],
                               struct library *lib) {
  struct hlist_head *head = &hashtable[library_hashfn(lib->pathname)];
  hlist_add_head(&lib->library_hash, head);
}

static inline struct region *__rb_insert_region(struct library *library,
                                                ElfW(Addr) offset,
                                                struct rb_node *node) {
  struct rb_node **p = &library->rb_region.rb_node;
  struct rb_node *parent = NULL;
  struct region *region;

  while (*p) {
    parent = *p;
    region = rb_entry(parent, struct region, rb_region);

    if (offset > region->offset)
      p = &(*p)->rb_left;
    else if (offset < region->offset)
      p = &(*p)->rb_right;
    else
      return region;
  }

  rb_link_node(node, parent, p);

  return NULL;
}

static inline struct region *rb_insert_region(struct library *library,
                                              ElfW(Addr) offset,
                                              struct rb_node *node) {
  struct region *ret;
  if ((ret = __rb_insert_region(library, offset, node)))
    goto out;
  rb_insert_color(node, &library->rb_region);
out:
  return ret;
}

static void maps_init(struct maps *maps, int fd) {
  maps->fd = fd;
  maps->lib_vdso = NULL;

  for (int i = 0; i < LIBS_HASHTABLE_SIZE; i++)
    INIT_HLIST_HEAD(&maps->libraries[i]);
}

void maps_release(struct maps *maps) {
  struct library *lib;
  for_each_library(lib, maps) { library_release(lib); }
  close(maps->fd);
}

// Returns false if segment that starts with check_addr should not be touched
static bool maps_check(unsigned long check_addr, long no_touch_addrs[],
                       int addr_cnt) {
  for (int i = 0; i < addr_cnt; ++i)
    if (check_addr == (unsigned long)no_touch_addrs[i]) {
      _nx_debug_printf("Not touching %lX\n", check_addr);
      return false;
    }
  return true;
}

uintptr_t first_region(const char *libname) {
  // The following isn't reliable:
  // struct region *first = rb_entry_region(rb_first(&lib->rb_region));

  // TODO(andronat): This won't work if we load the plugin twice (one for
  // loadtime interception and one for runtime).
  char buf[MAX_BUF_SIZE] = {'\0'};
  uintptr_t out = 0;

  FILE *fp = fopen("/proc/self/maps", "r");
  assert(fp != NULL);

  while (fgets(buf, MAX_BUF_SIZE, fp)) {
    if (strstr(buf, libname) != NULL) {
      out = strtoul(buf, NULL, 16);
      break;
    }
  }

  fclose(fp);
  return out;
}

uintptr_t end_of_stack_region() {
  char buf[MAX_BUF_SIZE] = {'\0'};
  char prev_buf[MAX_BUF_SIZE] = {'\0'};
  uintptr_t out = 0;

  FILE *fp = fopen("/proc/self/maps", "r");
  assert(fp != NULL);

  while (fgets(buf, MAX_BUF_SIZE, fp)) {
    if (strstr(buf, "[stack]") != NULL) {
      char *ptr;
      strtoul(prev_buf, &ptr, 16);
      out = strtoul(ptr + 1, NULL, 16);
      break;
    }
    strcpy(prev_buf, buf);
  }

  fclose(fp);
  return out;
}

// TODO: there is a bug there with gnu pth and pthreads. I had to change name to
// lib2pthread.
struct maps *maps_read(const char *libname) {
  int fd = open("/proc/self/maps", O_RDONLY, 0);
  if (fd < 0)
    _nx_fatal_printf("opening /proc/self/maps failed\n");

  struct maps *maps = malloc(sizeof(struct maps));
  maps_init(maps, fd);

  struct library *lib = NULL;
  if (libname != NULL) {
    lib = malloc(sizeof(struct library));
    assert(lib != NULL);
    library_init(lib, libname, maps);
    library_add(maps->libraries, lib);
  }

  char buf[MAX_BUF_SIZE] = {'\0'};
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + MAX_BUF_SIZE - 1;

  _nx_debug_printf("reading /proc/self/maps\n");
  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(from, '\n',
                          to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread = 0;
      while (to < bufend) {
        nread = read(fd, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n';                   /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0;                 /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    if (to > buf) {
      char *ptr = from;
      unsigned long start = strtoul(ptr, &ptr, 16);
      unsigned long end = strtoul(ptr + 1, &ptr, 16);
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      char *flags = ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t')
        ++ptr;
      assert(ptr - flags >= 4);
      unsigned long offset = strtoul(ptr, &ptr, 16);
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      char *id = ptr;
      unreferenced_var(id);
      while (*ptr && *ptr != ' ' && *ptr != '\t')
        ++ptr;
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t')
        ++ptr;
      assert(ptr - id > 0);
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      char *pathname = ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n')
        ++ptr;

      if (libname != NULL) {
        // If it is not the library we are looking for, there is
        // no point to continue and malloc a new region struct.
        const char *name = strstr(pathname, libname);
        if (name == NULL)
          continue;
        // Ensure the full name of the library has been matched:
        // the next character should not be a letter.
        // This prevents e.g. libc from matching libcap.
        char ch = name[strlen(libname)];
        bool is_letter = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
        if (is_letter)
          continue;
      }

      if ((flags[0] == 'r') && ((end - start) > 0) &&
          maps_check(start, initial_mappings, initial_mapping_cnt)) {
        /* allocate a new region structure */
        struct region *reg = (struct region *)malloc(sizeof(struct region));
        assert(reg != NULL);

        reg->start = (void *)start;
        reg->end = (void *)end;
        reg->size = (size_t)(end - start);

        // Setup protection permissions
        int perms = PROT_NONE;
        if (flags[0] == 'r')
          perms |= PROT_READ;
        if (flags[1] == 'w')
          perms |= PROT_WRITE;
        if (flags[2] == 'x')
          perms |= PROT_EXEC;

        if (flags[3] == 'p')
          perms |= MAP_PRIVATE;
        else if (flags[3] == 's')
          perms |= MAP_SHARED;
        reg->perms = perms;

        // Set region offset
        reg->offset = (ElfW(Addr))offset;

        if (libname != NULL) {
          reg->type = REGION_LIBRARY;

          rb_insert_region(lib, offset, &reg->rb_region);
        } else if (strncmp(pathname, "[vdso]", 6) == 0) {
          _nx_debug_printf("vdso library found\n");

          assert(maps->lib_vdso ==
                 NULL); // We currently support only 1 memory region
          assert(offset == 0);
          reg->type = REGION_VDSO;

          lib = malloc(sizeof(struct library));
          library_init(lib, pathname, maps);
          lib->vdso = true;
          maps->lib_vdso = lib;
          rb_insert_region(lib, offset, &reg->rb_region);
        } else if (pathname[0] == '/') {
          reg->type = REGION_LIBRARY;

          // TODO(andronat): library_find uses hashing. This needs benchmarking
          // as we had issues with hashing in the past.
          lib = library_find(maps->libraries, pathname);
          if (lib == NULL) {
            _nx_debug_printf("new library found: %s\n", pathname);
            lib = malloc(sizeof(struct library));
            assert(lib != NULL);
            library_init(lib, pathname, maps);
            library_add(maps->libraries, lib);
          }
          rb_insert_region(lib, offset, &reg->rb_region);
        }
      }
    }
  } while (to > buf);

  return maps;
}

#define PAGE_ALIGNMENT 4096

void *maps_alloc_near(int maps_fd, void *addr, size_t size, int prot, bool near,
                      uint64_t max_distance) {
  if (lseek(maps_fd, 0, SEEK_SET) < 0)
    return NULL;

  // We try to allocate memory within 1.5GB of a target address. This means, we
  // will be able to perform relative 32bit jumps from the target address.
  size = ALIGN(size, PAGE_ALIGNMENT);

  // Go over each line of /proc/self/maps and consider each mapped region one
  // at a time, looking for a gap between regions to allocate.
  char buf[MAX_BUF_SIZE] = {'\0'};
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + MAX_BUF_SIZE - 1;

  unsigned long gap_start = 0x10000;

  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(from, '\n',
                          to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread = 0;
      while (to < bufend) {
        nread = read(maps_fd, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n';                   /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0;                 /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    unsigned long long gap_end, map_end;
    int name;

    // Parse each line of /proc/<pid>/maps file.
    if (sscanf(from, "%llx-%llx %*4s %*d %*x:%*x %*d %n", &gap_end, &map_end,
               &name) > 1) {
      // gap_start to gap_end now covers the region of empty space before the
      // current line.
      // Now we try to see if there's a place within the gap we can use.
      if (gap_end - gap_start >= size) {
        // Is the gap before our target address?
        if (((long)addr - (long)gap_end >= 0)) {
          if (!near || ((long)addr - (gap_end - size) < max_distance)) {
            if (name == 0 || (size_t)name > strlen(from)) {
              name = strlen(from);
            }
            char *pathname = from + name;
            _nx_debug_printf("pathname %s\n", pathname);

            unsigned long pos;
            if (strncmp(pathname, "[stack]", 7) == 0) {
              // Underflow protection when we're adjacent to the stack
              if (!near || ((uintptr_t)addr < max_distance ||
                            (uintptr_t)addr - max_distance < gap_start)) {
                pos = gap_start;
              } else {
                pos = ((uintptr_t)addr - max_distance) & ~4095;
                if (pos < gap_start)
                  pos = gap_start;
              }
              //_nx_dprintf(2, "adjacent to the stack %lx\n", pos);
            } else {
              // Otherwise, take the end of the region
              pos = gap_end - size;
            }
            void *ptr = mmap((void *)pos, size, prot,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (ptr != MAP_FAILED)
              return ptr;
          }
        } else if (!near ||
                   (gap_start + size - (uintptr_t)addr < max_distance)) {
          // Gap is after the address, above checks that we can wrap around
          // through 0 to a space we'd use
          void *ptr = mmap((void *)gap_start, size, prot,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
          if (ptr != MAP_FAILED)
            return ptr;
        }
      }
      gap_start = map_end;
    }
  } while (to > buf);

  return NULL;
}

// Populates array initial_mappings with the starts of mappings of executable
// regions
void binrw_rd_init_maps(void) {
  int fd = open("/proc/self/maps", O_RDONLY, 0);
  if (fd < 0)
    _nx_fatal_printf("opening /proc/self/maps failed\n");

  char buf[MAX_BUF_SIZE] = {'\0'};
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + MAX_BUF_SIZE - 1;

  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(from, '\n',
                          to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread = 0;
      while (to < bufend) {
        nread = read(fd, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n';                   /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0;                 /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    if (to > buf) {
      char *ptr = from;
      unsigned long start = strtoul(ptr, &ptr, 16);
      unsigned long end = strtoul(ptr + 1, &ptr, 16);
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      char *flags = ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t')
        ++ptr;
      assert(ptr - flags >= 4);
      // unsigned long offset = strtoul(ptr, &ptr, 16);
      (void)strtoul(ptr, &ptr, 16);
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      char *id = ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t')
        ++ptr;
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t')
        ++ptr;
      assert(ptr - id > 0);
      unreferenced_var(id);
      while (*ptr == ' ' || *ptr == '\t')
        ++ptr;
      char *pathname = ptr;
      while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n')
        ++ptr;

      if ((flags[0] == 'r') && ((end - start) > 0) && pathname[0] == '/') {
        assert(initial_mapping_cnt < MAX_INITIAL_MAPPINGS);
        initial_mappings[initial_mapping_cnt++] = start;
      }
    }
  } while (to > buf);

  close(fd);
}

void print_maps(void) {
  char *line = NULL;
  size_t len = 0;
  FILE *maps;

  maps = fopen("/proc/self/maps", "r");

  while (getline(&line, &len, maps) != -1) {
    printf("%s", line);
  }

  free(line);
  fclose(maps);
}
