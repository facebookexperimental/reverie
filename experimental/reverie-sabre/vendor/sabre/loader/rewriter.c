/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "rewriter.h"

#include "debuginfo.h"
#include "elf_loading.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "macros.h"
#include "maps.h"
#include "stringutil.h"

#ifdef __x86_64__
#include "reverie_vdso_symbols.h"
#endif

#include "arch/rewriter_api.h"

#include <asm/unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define section_hashfn(n) jhash(n, strlen(n), 0) & (sectionhash_size - 1)

// Section and symbol records, and the name strings copied for them, are never
// freed. load() sets M_MMAP_THRESHOLD to 0 so that SaBRe's malloc never shares
// the client's brk arena, which turns each of these small allocations into a
// separate mmap: about 85% of a guest's system calls. Instead they are carved
// from anonymous chunks of METADATA_CHUNK bytes, which keep away from the brk
// arena in the same way. Anything that is freed must keep using malloc.
#define METADATA_CHUNK ((size_t)1 << 20)
#define METADATA_ALIGN ((size_t)16)

static char *metadata_next, *metadata_end;
static bool metadata_lock;

static void *metadata_mmap(size_t size) {
  void *chunk = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (chunk == MAP_FAILED)
    _nx_fatal_printf("rewriter: cannot map %zu bytes of metadata: %s\n", size,
                     strerror(errno));
  return chunk;
}

// Returns size bytes, aligned like malloc's, that live until the process ends.
static void *metadata_alloc(size_t size) {
  size = (size + METADATA_ALIGN - 1) & ~(METADATA_ALIGN - 1);
  // An object larger than a chunk gets a mapping of its own, so that the rest
  // of the current chunk stays in use.
  if (size > METADATA_CHUNK)
    return metadata_mmap(size);

  while (__atomic_test_and_set(&metadata_lock, __ATOMIC_ACQUIRE))
    ;
  if ((size_t)(metadata_end - metadata_next) < size) {
    metadata_next = metadata_mmap(METADATA_CHUNK);
    metadata_end = metadata_next + METADATA_CHUNK;
  }
  void *object = metadata_next;
  metadata_next += size;
  __atomic_clear(&metadata_lock, __ATOMIC_RELEASE);
  return object;
}

static inline void section_init(struct section *s, const char *name,
                                ElfW(Shdr) shdr) {
  s->name = name;
  s->shdr = shdr; // TODO: should we use malloc + memcpy

  INIT_HLIST_NODE(&s->section_hash);
}

static inline struct section *section_find(struct hlist_head *hash,
                                           const char *name) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct section *s;

  head = &hash[section_hashfn(name)];
  _nx_debug_printf("search: %s = %u (%zu)\n", name, section_hashfn(name),
                   strlen(name));
  hlist_for_each_entry(s, node, head, section_hash) {
    if (strcmp(name, s->name) == 0)
      return s;
  }

  return NULL;
}

static inline void section_add(struct hlist_head *hash, struct section *scn) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct section *s;

  head = &hash[section_hashfn(scn->name)];
  _nx_debug_printf("add: %s = %u (%zu)\n", scn->name, section_hashfn(scn->name),
                   strlen(scn->name));
  hlist_for_each_entry(s, node, head, section_hash) {
    if (strcmp(scn->name, s->name) == 0)
      return;
  }

  hlist_add_head(&scn->section_hash, head);
}

#define symbol_hashfn(n) jhash(n, strlen(n), 0) & (symbolhash_size - 1)

static inline void symbol_init(struct symbol *s, const char *name,
                               ElfW(Sym) sym) {
  s->name = name;
  s->sym = sym;
}

static inline struct symbol *symbol_find(struct hlist_head *hash,
                                         const char *name) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct symbol *s;

  head = &hash[symbol_hashfn(name)];
  hlist_for_each_entry(s, node, head, symbol_hash) {
    if (strcmp(name, s->name) == 0)
      return s;
  }

  return NULL;
}

static inline void symbol_add(struct hlist_head *hash, struct symbol *sym) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct symbol *s;

  head = &hash[symbol_hashfn(sym->name)];
  hlist_for_each_entry(s, node, head, symbol_hash) {
    if (strcmp(sym->name, s->name) == 0)
      return;
  }

  hlist_add_head(&sym->symbol_hash, head);
}

#define rb_entry_region(node) rb_entry((node), struct region, rb_region)

/**
 * Returns an iterator pointing to the first region whose offset does not
 * compare less than @p offset
 */
static inline struct region *rb_lower_bound_region(struct library *lib,
                                                   ElfW(Addr) offset) {
  struct rb_node *n = lib->rb_region.rb_node;
  struct rb_node *parent = NULL;
  struct region *region;

  while (n) {
    region = rb_entry_region(n);

    if (!(region->offset > offset)) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_region(parent) : NULL;
}

static char *memcpy_fromlib(void *dst, const void *src, size_t len,
                            struct library *lib) {
  // Some kernels don't allow accessing the VDSO from write()
  if (lib->vdso) {
    struct rb_node *first_node = rb_first(&lib->rb_region);
    if (first_node) {
      struct region *first_region = rb_entry_region(first_node);
      if (src >= first_region->start && src <= first_region->end) {
        ptrdiff_t max = first_region->end - src;
        memcpy(dst, src, clamp_val(len, 0, max));
        return dst;
      }
    }
  }

  // Read up to "len" bytes from "src" and copy them to "dst". Short copies
  // are possible, if we are at the end of a mapping. Returns NULL, if the
  // operation failed completely. Copy data through a socketpair, as this
  // allows us to access it without incurring a segmentation fault.
  static int socket[2];
  if (!socket[0] && !socket[1])
    socketpair(AF_UNIX, SOCK_STREAM, 0, socket);

  char *ptr = dst;
  int inc = 4096;
  while (len > 0) {
    ssize_t l = inc == 1 ? inc : 4096 - ((long)src & 0xFFF);
    if ((size_t)l > len) {
      l = len;
    }
    l = NOINTR(write(socket[0], src, l));
    if (l == -1) {
      if (errno == EFAULT) {
        if (inc == 1) {
          if (ptr == dst) {
            return NULL;
          }
          break;
        }
        inc = 1;
        continue;
      } else {
        return NULL;
      }
    }
    l = NOINTR(read(socket[1], ptr, l));
    if (l <= 0) {
      return NULL;
    }
    ptr += l;
    src += l;
    len -= l;
  }
  return dst;
}

static char *library_buf_get(struct library *lib, ElfW(Addr) offset, char *buf,
                             size_t len) {
  memset(buf, 0, len);

  if (!lib->valid)
    return NULL;

  _nx_debug_printf("library_buf_get: search for lower bound 0x%lx\n", offset);
  struct region *reg = rb_lower_bound_region(lib, offset);
  if (!reg)
    return NULL;

  _nx_debug_printf("library_buf_get: lower bound found 0x%lx (%p-%p)\n",
                   reg->offset, reg->start, reg->end);
  offset -= reg->offset;
  if (offset > reg->size - len)
    return NULL;

  char *src = (char *)(reg->start) + offset;
  _nx_debug_printf("library_buf_get: copy 0x%lx bytes from %p\n", len, src);
  if (!memcpy_fromlib(buf, src, len, lib))
    return NULL;

  return buf;
}

static char *library_buf_get_original(struct library *l, ElfW(Addr) offset,
                                      char *buf, size_t len) {
  if (!l->valid) {
    if (buf != NULL)
      memset(buf, 0, len);
    return NULL;
  }

  _nx_debug_printf("library_buf_get_original: offset 0x%lx\n", offset);

  struct region *first = rb_entry_region(rb_last(&l->rb_region));
  if (!l->image && !l->vdso && !RB_EMPTY_ROOT(&l->rb_region) &&
      first->offset == 0) {
    _nx_debug_printf("library_buf_get_original: image missing and not VDSO\n");
    // Extend the mapping of the very first page of the underlying library
    // file. This way, we can read the original file contents of the entire
    // library. We have to be careful, because doing so temporarily removes
    // the first 4096 bytes of the library from memory. And we don't want to
    // accidentally unmap code that we are executing. So, only use functions
    // that can be inlined.
    struct region *last = rb_entry_region(rb_first(&l->rb_region));

    void *start = first->start;
    l->image_size = last->offset + last->size;
    // It is possible to create a library that is only a single page in size.
    // In that case, we have to make sure that we artificially map one extra
    // page past the end of it, as our code relies on mremap() actually moving
    // the mapping.
    if (l->image_size < 8192)
      l->image_size = 8192;
    l->image = (char *)mremap(start, 4096, l->image_size, MREMAP_MAYMOVE);
    if (l->image_size == 8192 && l->image == start) {
      // We really mean it, when we say we want the memory to be moved.
      // TODO: WHY?!
      l->image = (char *)mremap(start, 4096, l->image_size, MREMAP_MAYMOVE);
      munmap((char *)start + 4096, 4096);
    }
    if (l->image == MAP_FAILED) {
      l->image = NULL;
    } else {
      void *addr = mmap(start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      if (addr != start) {
        _nx_fatal_printf("library_buf_get_original: mmap failed\n");
      }
      for (int i = 4096 / sizeof(long); --i;
           ((long *)(start))[i] = ((long *)(l->image))[i])
        ;
    }
  }

  if (l->image) {
    _nx_debug_printf("library_buf_get_original: image %p\n", l->image);
    if (offset + len > l->image_size) {
      // It is quite likely that we initially did not map the entire file as
      // we did not know how large it is. So, if necessary, try to extend the
      // mapping.
      size_t size = (offset + len + 4095) & ~4095;
      char *tmp =
          (char *)(mremap(l->image, l->image_size, size, MREMAP_MAYMOVE));
      if (tmp != MAP_FAILED)
        l->image = tmp, l->image_size = size;
    }
    if (buf && offset + len <= l->image_size) {
      return (char *)memcpy(buf, l->image + offset, len);
    }
    return NULL;
  }
  _nx_debug_printf("library_buf_get_original: buf %p\n", buf);
  return buf ? library_buf_get(l, offset, buf, len) : NULL;
}

static const char *library_copy(struct library *lib, ElfW(Addr) offset) {
  if (!lib->valid)
    return "";

  _nx_debug_printf("library_copy: offset 0x%lx\n", offset);

  struct region *reg = rb_lower_bound_region(lib, offset);
  if (reg == NULL)
    return "";

  _nx_debug_printf("library_copy: lower bound 0x%lx (%p-%p)\n", reg->offset,
                   reg->start, reg->end);

  offset -= reg->offset;
  const char *start = (char *)reg->start + offset;
  const char *stop = (char *)reg->end + offset;

  _nx_debug_printf("library_copy: range %p-%p\n", start, stop);

  char buf[4096] = {0};
  memcpy_fromlib(buf, start,
                 (uintptr_t)(stop - start) >= sizeof(buf)
                     ? sizeof(buf) - 1
                     : (uintptr_t)(stop - start),
                 lib);
  for (start = buf, stop = buf; *stop != '\0'; ++stop)
    ;

  _nx_debug_printf("library_copy: updated range %p-%p\n", start, stop);

  if (stop <= start)
    return "";

  size_t len =
      stop - start + 1; // stop == \0 thus +1 to include NULL termination
  char *string = metadata_alloc(len);
  memcpy(string, start, len);

  assert(string[len - 1] == '\0');
  return string;
}

static const char *library_copy_original(struct library *l, ElfW(Addr) offset) {
  if (!l->valid)
    goto empty;

  _nx_debug_printf("library_copy_original: offset 0x%lx\n", offset);

  // Make sure we actually have a mapping that we can access. If the string is
  // located at the end of the image, we might not yet have extended the
  // mapping sufficiently.
  if (!l->image || l->image_size <= offset)
    library_buf_get_original(l, offset, NULL, 1);

  if (l->image) {
    _nx_debug_printf("library_copy_original: image %p\n", l->image);
    if (offset < l->image_size) {
      char *start = l->image + offset;
      char *stop = start;
      while (stop < l->image + l->image_size && *stop) {
        ++stop;
        if (stop >= l->image + l->image_size)
          library_buf_get_original(l, stop - l->image, NULL, 1);
      }
      size_t len = stop - start;
      char *string = metadata_alloc(len + 1);
      _nx_debug_printf("library_copy_original: copy 0x%lx from %p to %p\n", len,
                       start, string);
      *((char *)memcpy(string, start, len) + len) = '\0';
      return string;
    }
    goto empty;
  }
  return library_copy(l, offset);

empty:
  return "";
}

#define library_get(lib, off, val)                                             \
  (typeof(val))library_buf_get(lib, off, (char *)val, sizeof(typeof(*val)))

#define library_get_original(lib, off, val)                                    \
  (typeof(val))library_buf_get_original(lib, off, (char *)val,                 \
                                        sizeof(typeof(*val)))

#define library_set(lib, off, val)                                             \
  ({                                                                           \
    struct region *__r = rb_lower_bound_region(lib, off);                      \
    if (__r) {                                                                 \
      off -= __r->offset;                                                      \
      if (off <= __r.size - sizeof(typeof(*val)))                              \
        *(typeof(val))((char *)__r->start + off) = *val;                       \
    }                                                                          \
  })

static void library_make_writable(struct library *l, bool state) {
  struct region *reg;
  struct region *n;

  rbtree_postorder_for_each_entry_safe(reg, n, &l->rb_region, rb_region) {
    mprotect(reg->start, reg->size, reg->perms | (state ? PROT_WRITE : 0));
  }
}

#ifdef __x86_64__
/* The entry point patch_vdso routes syscall `sysno` through, by detour or
 * stub, or NULL if it routes none. */
static const char *vdso_routed_entry(long sysno) {
  switch (sysno) {
  case SYS_getcpu:
    return "__vdso_getcpu";
  case SYS_time:
    return "__vdso_time";
  case SYS_gettimeofday:
    return "__vdso_gettimeofday";
  case SYS_clock_gettime:
    return "__vdso_clock_gettime";
  case SYS_clock_getres:
    return "__vdso_clock_getres";
  case SYS_getrandom:
    return "__vdso_getrandom";
  default:
    return NULL;
  }
}

/* Is `sym` an exported entry point? Mirrors `vdso_exports` in
 * reverie-ptrace/src/vdso.rs, failing closed on the type: only data and
 * bookkeeping symbols are skipped, so a symbol of any other type is code. */
static bool vdso_is_entry_point(const ElfW(Sym) * sym) {
  switch (ELF64_ST_TYPE(sym->st_info)) {
  case STT_OBJECT:
  case STT_TLS:
  case STT_COMMON:
  case STT_SECTION:
  case STT_FILE:
    return false;
  default:
    return ELF64_ST_BIND(sym->st_info) != STB_LOCAL &&
           sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS;
  }
}

/* The classification of the entry point `sym`: the reverie_vdso_symbols entry
 * of a name exported at its address, or NULL if none is listed. The x86_64
 * vDSO exports most functions twice (`clock_gettime` beside
 * `__vdso_clock_gettime`); listed names at one address that disagree are
 * fatal, as reverie-ptrace refuses such a vDSO. */
static const struct reverie_vdso_symbol *
vdso_classify(struct library *lib, const struct symbol *sym) {
  const struct reverie_vdso_symbol *known = NULL;
  for (int bucket = 0; bucket < symbolhash_size; bucket++) {
    struct hlist_node *node;
    struct symbol *other;
    hlist_for_each_entry(other, node, &lib->symbol_hash[bucket], symbol_hash) {
      if (!vdso_is_entry_point(&other->sym) ||
          other->sym.st_value != sym->sym.st_value)
        continue;
      const struct reverie_vdso_symbol *entry =
          reverie_vdso_symbol_lookup(other->name);
      if (entry == NULL)
        continue;
      if (known != NULL && (known->handling != entry->handling ||
                            known->syscall != entry->syscall))
        _nx_fatal_printf("vdso exports %s and %s at one address, but they "
                         "need different stubs\n",
                         known->name, entry->name);
      known = entry;
    }
  }
  return known;
}

/* Overwrite the vDSO entry point `sym` with `stub`, padded with NOPs. */
static char *replace_vdso_entry(struct library *lib, const struct symbol *sym,
                                const char *stub, size_t stub_len) {
  if (sym->sym.st_size < stub_len)
    _nx_fatal_printf("vdso %s is too small for its stub\n", sym->name);
  char *start = lib->asr_offset + sym->sym.st_value;
  memcpy(start, stub, stub_len);
  memset(start + stub_len, 0x90 /* NOP */, sym->sym.st_size - stub_len);
  return start;
}
#endif // __x86_64__

static void patch_vdso(struct library *lib) {
  _nx_debug_printf("patch_vdso: %s\n", lib->pathname);

  int extra_len = 0;
  char *extra_space = NULL;

  struct section *scn = section_find(lib->section_hash, ".text");
  if (!scn)
    _nx_fatal_printf("no vdso .text section");
  _nx_debug_printf("vdso .text section %p\n", scn);

  const ElfW(Shdr) *shdr = &scn->shdr;
  char *addr = (char *)(shdr->sh_addr + lib->asr_offset);
  size_t size = round_up(shdr->sh_size, 0x1000);

  if (mprotect((void *)((long)addr & ~0xFFF), size,
               PROT_READ | PROT_WRITE | PROT_EXEC)) {
    _nx_fatal_printf("mprotect failed\n");
  }
  _nx_debug_printf("mprotect done\n");

  _nx_debug_printf("detouring __vdso_getcpu\n");
  struct symbol *sym = symbol_find(lib->symbol_hash, "__vdso_getcpu");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib, lib->asr_offset + sym->sym.st_value,
                lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
                SYS_getcpu, &extra_space, &extra_len);
  }
#ifdef __x86_64__
  _nx_debug_printf("detouring __vdso_time\n");
  sym = symbol_find(lib->symbol_hash, "__vdso_time");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib, lib->asr_offset + sym->sym.st_value,
                lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
                SYS_time, &extra_space, &extra_len);
  }
#endif // __x86_64__
  _nx_debug_printf("detouring __vdso_gettimeofday\n");
  sym = symbol_find(lib->symbol_hash, "__vdso_gettimeofday");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib, lib->asr_offset + sym->sym.st_value,
                lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
                SYS_gettimeofday, &extra_space, &extra_len);
  }
  _nx_debug_printf("detouring __vdso_clock_gettime\n");
  sym = symbol_find(lib->symbol_hash, "__vdso_clock_gettime");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib, lib->asr_offset + sym->sym.st_value,
                lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
                SYS_clock_gettime, &extra_space, &extra_len);
  }

#ifdef __x86_64__
  /* The vDSO's own getrandom generates bytes from in-process ChaCha state and
   * enters the kernel only to re-key when the host crng generation changes,
   * so its syscalls depend on host time and most draws never reach the
   * router. Replace it with a stub that keeps its five-argument ABI:
   *
   * - glibc's parameter query (NULL, 0, 0, params, ~0UL) returns -ENOSYS
   *   without writing params, so glibc never sizes vDSO state and uses its
   *   own (rewritten) getrandom syscall instead;
   * - every other call forwards (buffer, len, flags) to the getrandom
   *   syscall, as the kernel's fallback does, so a caller that already holds
   *   state still reaches the router.
   *
   * The stub's syscall then enters the ordinary router. Do this once in the
   * initial rewrite, never by rewriting an already detoured library again
   * after plugin registration.
   */
  _nx_debug_printf("replacing __vdso_getrandom\n");
  sym = symbol_find(lib->symbol_hash, "__vdso_getrandom");
  if (sym != NULL && sym->sym.st_value != 0) {
    static const char getrandom_stub[] =
        "\x49\x83\xf8\xff"             // cmp $-1, %r8
        "\x75\x16"                     // jne syscall
        "\x48\x85\xff"                 // test %rdi, %rdi
        "\x75\x11"                     // jne syscall
        "\x48\x85\xf6"                 // test %rsi, %rsi
        "\x75\x0c"                     // jne syscall
        "\x85\xd2"                     // test %edx, %edx
        "\x75\x08"                     // jne syscall
        "\x48\xc7\xc0\xda\xff\xff\xff" // mov $-ENOSYS, %rax
        "\xc3"                         // ret
        "\xb8\x3e\x01\x00\x00"         // syscall: mov $SYS_getrandom, %eax
        "\x0f\x05"                     // syscall
        "\xc3";                        // ret
    char *start =
        replace_vdso_entry(lib, sym, getrandom_stub, sizeof(getrandom_stub) - 1);
    patch_syscalls_in_range(lib, start, start + sym->sym.st_size, &extra_space,
                            &extra_len, false);
  }

  /* clock_getres has no detour; issue its syscall, which then enters the
   * router like the getrandom stub's. */
  _nx_debug_printf("replacing __vdso_clock_getres\n");
  sym = symbol_find(lib->symbol_hash, "__vdso_clock_getres");
  if (sym != NULL && sym->sym.st_value != 0) {
    static const char clock_getres_stub[] =
        "\xb8\xe5\x00\x00\x00" // mov $SYS_clock_getres, %eax
        "\x0f\x05"             // syscall
        "\xc3";                // ret
    char *start = replace_vdso_entry(lib, sym, clock_getres_stub,
                                     sizeof(clock_getres_stub) - 1);
    patch_syscalls_in_range(lib, start, start + sym->sym.st_size, &extra_space,
                            &extra_len, false);
  }

  /* Every other entry point is handled as reverie-core classifies it
   * (reverie_vdso_symbols.h, generated from `VdsoSymbol::class`): a syscall
   * fast path must be one routed above, a function the classification leaves
   * native keeps the kernel's code, and any other function, or a name the
   * table does not list, returns -ENOSYS, so none keeps running the kernel's
   * code outside the router; reverie/src/vdso.rs documents which glibc
   * callers tolerate -ENOSYS. */
  static const char enosys_stub[] =
      "\x48\xc7\xc0\xda\xff\xff\xff" // mov $-ENOSYS, %rax
      "\xc3";                         // ret
  for (int bucket = 0; bucket < symbolhash_size; bucket++) {
    struct hlist_node *node;
    struct symbol *other;
    hlist_for_each_entry(other, node, &lib->symbol_hash[bucket], symbol_hash) {
      if (!vdso_is_entry_point(&other->sym))
        continue;
      const struct reverie_vdso_symbol *known = vdso_classify(lib, other);
      if (known == NULL) {
        _nx_debug_printf("replacing unknown vdso %s with -ENOSYS\n",
                         other->name);
        replace_vdso_entry(lib, other, enosys_stub, sizeof(enosys_stub) - 1);
        continue;
      }
      switch (known->handling) {
      case REVERIE_VDSO_SYSCALL: {
        /* Routed above under its `__vdso_` name, which this one aliases. */
        const char *routed_name = vdso_routed_entry(known->syscall);
        struct symbol *routed =
            routed_name == NULL ? NULL
                                : symbol_find(lib->symbol_hash, routed_name);
        if (routed == NULL || routed->sym.st_value != other->sym.st_value)
          _nx_fatal_printf("vdso %s needs syscall %ld, which patch_vdso does "
                           "not route\n",
                           other->name, known->syscall);
        break;
      }
      case REVERIE_VDSO_ENOSYS:
        _nx_debug_printf("replacing vdso %s with -ENOSYS\n", other->name);
        replace_vdso_entry(lib, other, enosys_stub, sizeof(enosys_stub) - 1);
        break;
      case REVERIE_VDSO_NATIVE:
        break;
      }
    }
  }
#endif // __x86_64__

  if (extra_space != NULL) {
    // Mark our scratch space as write-protected and executable.
    mprotect(extra_space, 0x1000, PROT_READ | PROT_EXEC);
  }
}

// Returns a pointer to a stripped version of pathname that corresponds
// to the library
static const char *strip_pathname(const char *pathname) {
  const char *real = pathname;

  for (const char *delim = " /"; *delim; ++delim) {
    const char *skip = strrchr(real, *delim);
    if (skip) {
      real = skip + 1;
    }
  }

  return real;
}

bool starts_with(const char *a, const char *b) {
  if (strncmp(a, b, strlen(b)) == 0)
    return true;
  return false;
}

// TODO: This needs refactoring to use only SONAMEs.
// Returns true if real library filename corresponds to bare library name
static bool lib_name_match(const char *bare, const char *pathname) {
  const char *real = strip_pathname(pathname);

  // The dynamic loader intercept uses the historical bare name "ld". Do not
  // confuse linker executables such as ld, ld.bfd, or ld-new with the
  // ld-linux/ld.so loader family.
  if (!strcmp(bare, "ld")) {
    const char *so = strstr(real, ".so");
    const bool has_so_boundary =
        so != NULL && (so[3] == '\0' || so[3] == '.');
    return has_so_boundary &&
           (starts_with(real, "ld-linux-") || starts_with(real, "ld.so") ||
            (starts_with(real, "ld-") && real[3] >= '0' && real[3] <= '9'));
  }

  if (starts_with(real, bare)) {
    return true;
  }
  return false;
}

// Returns true if library defined by pathname has functions that we want to
// intercept
static bool lib_is_icepted(const char *pathname) {
  for (int i = 0; i < registered_icept_cnt; ++i) {
    if (lib_name_match(intercept_records[i].lib_name, pathname))
      return true;
  }

  return false;
}

static void patch_syscalls(struct library *lib, bool loader) {
  if (!lib->valid)
    return;

  _nx_debug_printf("rewriter: patching syscalls in -> (%s)\n", lib->pathname);

  int extra_len = 0;
  char *extra_space = NULL;

  struct section *scn = section_find(lib->section_hash, ".text");
  // TODO if the section table has been stripped, we should look at executable
  // segments instead
  if (!scn)
    return;

  _nx_debug_printf(".text section %p\n", scn);
  const ElfW(Shdr) *shdr = &scn->shdr;
  char *start = (char *)(shdr->sh_addr + lib->asr_offset);
  char *stop = start + shdr->sh_size;
  // dprintf(1, "Tas (%s) start: %p stop: %p\n", lib->pathname, start, stop);
  patch_syscalls_in_range(lib, start, stop, &extra_space, &extra_len, loader);

  _nx_debug_printf("mprotect extra space %p\n", extra_space);
  if (extra_space != NULL) {
    // Mark our scratch space as write-protected and executable.
    mprotect(extra_space, 0x1000, PROT_READ | PROT_EXEC);
  }
  _nx_debug_printf("mprotected\n");
}

// Try to find ld symbol in a given .so file
bool find_ld_symbol_in(const char *ld_path, const char *fn_name,
                       GElf_Sym *result) {
  if (access(ld_path, F_OK) == -1)
    return false;

  bool valid = false;
  *result = find_elf_symbol(ld_path, fn_name, &valid);
  return valid;
}

// Under some OSes (e.g. Ubuntu 18.04), ld comes without debug symbols. This
// wrapper function firstly checks if ld has debug symbols and then just looks
// over various other places to find the symbols.
static GElf_Sym find_ld_symbol(const char *ld_path, const char *fn_name) {
  GElf_Sym gsym;

  // Try ld_path itself
  if (find_ld_symbol_in(ld_path, fn_name, &gsym)) {
    return gsym;
  }

  // Cache the lookup result to avoid doing full search every time
  static char *ld_orig_path = NULL;
  static char *ld_debug_path = NULL;
  if (ld_orig_path == NULL || strcmp(ld_orig_path, ld_path)) {
    // Save new ld_path
    free(ld_orig_path);
    free(ld_debug_path);
    ld_orig_path = copy_string(ld_path);
    _nx_debug_printf("searching for external debug info for %s\n", ld_path);
    ld_debug_path = debuginfo_lookup_external(ld_orig_path);
    if (ld_debug_path == NULL)
      _nx_fatal_printf("refused: SaBRe cannot find %s in the dynamic linker "
                       "%s: it is not in its symbol table, and it has no "
                       "external debug information\n",
                       fn_name, ld_path);
  }

  if (find_ld_symbol_in(ld_debug_path, fn_name, &gsym)) {
    return gsym;
  }
  _nx_fatal_printf("refused: SaBRe cannot find %s in the dynamic linker %s or "
                   "its debug information %s\n",
                   fn_name, ld_path, ld_debug_path);
}

static bool find_intercept_target(struct library *lib, int record,
                                  GElf_Sym *target) {
  struct symbol *sym =
      symbol_find(lib->symbol_hash, intercept_records[record].fn_name);
  if (sym != NULL && sym->sym.st_value != 0) {
    *target = sym->sym;
    return true;
  }
  if (sym == NULL && !strcmp(intercept_records[record].lib_name, "ld")) {
    *target = find_ld_symbol(lib->pathname, intercept_records[record].fn_name);
    return true;
  }
  return false;
}

/* The file of the client's dynamic linker (device and inode), and how many
 * "ld" intercepts were installed once it was known. Kept small on purpose:
 * the loader's own mappings are visible to the guest in /proc/self/maps, and
 * a path buffer here grew its bss by a page. */
static bool dynamic_linker_known;
static dev_t dynamic_linker_dev;
static ino_t dynamic_linker_ino;
static int dynamic_linker_intercepts;

void sbr_rewriter_expect_dynamic_linker(int fd, const char *path) {
  /* The open descriptor, not the path: the file the loader actually mapped,
   * whatever the path names by now. Each mapping is then matched by stat()
   * of its /proc/self/maps path, not by the device and inode that file
   * prints, which on an overlay filesystem can be the underlying layer's. */
  struct stat file;
  if (fstat(fd, &file) != 0)
    _nx_fatal_printf("refused: SaBRe cannot stat the dynamic linker %s\n",
                     path);
  dynamic_linker_dev = file.st_dev;
  dynamic_linker_ino = file.st_ino;
  dynamic_linker_known = true;
  dynamic_linker_intercepts = 0;
}

/* Whether `lib` is a mapping of the client's dynamic linker. A mapping whose
 * path cannot be checked is not. */
static bool is_dynamic_linker(const struct library *lib) {
  struct stat file;
  return stat(lib->pathname, &file) == 0 && file.st_dev == dynamic_linker_dev &&
         file.st_ino == dynamic_linker_ino;
}

bool sbr_rewriter_dynamic_linker_intercepted(void) {
  int expected = 0;
  for (int i = 0; i < registered_icept_cnt; ++i)
    if (!strcmp(intercept_records[i].lib_name, "ld"))
      ++expected;
  return expected > 0 && dynamic_linker_intercepts == expected;
}

/* Whether intercept record `i` applies to `lib`. Once the client's dynamic
 * linker is known, "ld" records apply to that file only: another object named
 * like a dynamic linker that defines the same functions would otherwise
 * overwrite the saved real functions. */
static bool record_applies(int i, const struct library *lib) {
  if (!lib_name_match(intercept_records[i].lib_name, lib->pathname))
    return false;
  return strcmp(intercept_records[i].lib_name, "ld") != 0 ||
         !dynamic_linker_known || is_dynamic_linker(lib);
}

static void reject_overlapping_intercepts(struct library *lib) {
  // Different declared names can resolve to one entry in this object. Reject
  // that ambiguity before rewriting detour entry bytes or invoking a callback.
  // Resolve from this object's original symbols each time; a persistent address
  // set would incorrectly suppress a new mapping that reused an old address.
  for (int i = 0; i < registered_icept_cnt; ++i) {
    GElf_Sym target;
    if (!record_applies(i, lib) || !find_intercept_target(lib, i, &target))
      continue;
    for (int j = 0; j < i; ++j) {
      GElf_Sym earlier;
      if (record_applies(j, lib) &&
          find_intercept_target(lib, j, &earlier) &&
          earlier.st_value == target.st_value)
        _nx_fatal_printf("overlapping function intercept target\n");
    }
  }
}

static void patch_funcs(struct library *lib, int first, int end,
                        const struct intercept_tls_context *tls) {
  if (!lib->valid)
    return;

  reject_overlapping_intercepts(lib);

  int extra_len = 0;
  char *extra_space = NULL;

  for (int i = first; i < end; ++i) {
    if (record_applies(i, lib)) {
      _nx_debug_printf("patching intercepts: %s\n", lib->pathname);
      struct section *scn = section_find(lib->section_hash, ".text");
      _nx_debug_printf(".text section %p\n", scn);
      if (!scn)
        return;

      const ElfW(Shdr) *shdr = &scn->shdr;
      char *addr = (char *)(shdr->sh_addr + lib->asr_offset);
      size_t size = round_up(shdr->sh_size, 0x1000);

      if (mprotect((void *)((long)addr & ~0xFFF), size,
                   PROT_READ | PROT_WRITE | PROT_EXEC)) {
        _nx_debug_printf("mprotect failed\n");
        return;
      }
      _nx_debug_printf("mprotect done\n");

      GElf_Sym target;
      if (find_intercept_target(lib, i, &target)) {
        _nx_debug_printf("patching at address %lx\n",
                         (long)lib->asr_offset + target.st_value);
        api_detour_func(lib, lib->asr_offset + target.st_value,
                        lib->asr_offset + target.st_value + target.st_size,
                        intercept_records[i].callback,
                        intercept_records[i].copy_first_stack_arg, &extra_space,
                        &extra_len, tls);
        if (!strcmp(intercept_records[i].lib_name, "ld") &&
            dynamic_linker_known)
          ++dynamic_linker_intercepts;
      }
    }
  }
}

static bool parse_symbols(struct library *lib) {
  if (!lib->valid)
    return false;

  ElfW(Shdr) str_shdr;
  ignore_result(library_get_original(
      lib, lib->ehdr.e_shoff + lib->ehdr.e_shstrndx * lib->ehdr.e_shentsize,
      &str_shdr));

  // Find symbol table
  struct section *scn = section_find(lib->section_hash, ".dynsym");
  const ElfW(Shdr) *symtab = scn ? &scn->shdr : NULL;
  ElfW(Shdr) strtab = {0};
  if (symtab) {
    if (symtab->sh_link >= lib->ehdr.e_shnum ||
        !library_get_original(
            lib, lib->ehdr.e_shoff + symtab->sh_link * lib->ehdr.e_shentsize,
            &strtab)) {
      _nx_debug_printf("WARN: cannot find valid symbol table\n");
      goto error;
    }

    // Parse symbol table and add its entries
    for (ElfW(Addr) addr = 0; addr < symtab->sh_size;
         addr += sizeof(ElfW(Sym))) {
      ElfW(Sym) sym;
      if (!library_get_original(lib, symtab->sh_offset + addr, &sym) ||
          (sym.st_shndx >= lib->ehdr.e_shnum && sym.st_shndx < SHN_LORESERVE)) {
        _nx_debug_printf("WARN: encountered invalid symbol\n");
        goto error;
      }
      const char *name =
          library_copy_original(lib, strtab.sh_offset + sym.st_name);
      _nx_debug_printf("parse_symbols: name copied\n");
      if (!strlen(name))
        continue;

      struct symbol *ls = metadata_alloc(sizeof(*ls));
      symbol_init(ls, name, sym);
      symbol_add(lib->symbol_hash, ls);
      _nx_debug_printf("parse_symbols: symbol %s (%p)\n", name, (void *)addr);
    }
  }

  return true;

error:
  _nx_debug_printf("shit!\n");
  lib->valid = false;
  return false;
}

static bool parse_elf(struct library *lib, const char *prog_name) {
  lib->valid = true;

  // Verify ELF header
  ElfW(Shdr) str_shdr;
  if (!library_get_original(lib, 0, &lib->ehdr) ||
      lib->ehdr.e_ehsize < sizeof(ElfW(Ehdr)) ||
      lib->ehdr.e_phentsize < sizeof(ElfW(Phdr)) ||
      lib->ehdr.e_shentsize < sizeof(ElfW(Shdr)) ||
      !library_get_original(
          lib, lib->ehdr.e_shoff + lib->ehdr.e_shstrndx * lib->ehdr.e_shentsize,
          &str_shdr)) {
    _nx_debug_printf("parse_elf: header invalid\n");
    goto error;
  }

  // Parse section table and find all sections in this ELF file
  for (int i = 0; i < lib->ehdr.e_shnum; i++) {
    ElfW(Shdr) shdr;
    if (!library_get_original(
            lib, lib->ehdr.e_shoff + i * lib->ehdr.e_shentsize, &shdr))
      continue;

    struct section *scn = metadata_alloc(sizeof(*scn));
    section_init(scn,
                 library_copy_original(lib, str_shdr.sh_offset + shdr.sh_name),
                 shdr);
    section_add(lib->section_hash, scn);
    _nx_debug_printf("[%u] section %s\n", i, scn->name);
  }

  // Compute the offset of entries in the .text segment
  struct section *scn = section_find(lib->section_hash, ".text");
  const ElfW(Shdr) *text = scn ? &scn->shdr : NULL;
  if (!text) {
    _nx_debug_printf("parse_elf: failed to find .text\n");
    goto error;
  }

  // Now that we know where the .text segment is located, we can compute the
  // asr_offset_
  struct region *rgn = rb_lower_bound_region(lib, text->sh_offset);
  if (!rgn) {
    _nx_debug_printf("parse_elf: failed to find .text region\n");
    goto error;
  }

  _nx_debug_printf("region %lu\n", rgn->offset);
  lib->asr_offset =
      (char *)rgn->start - (text->sh_addr - (text->sh_offset - rgn->offset));
  _nx_debug_printf("asr offset %p\n", lib->asr_offset);

  if (prog_name && !strcmp(lib->pathname, prog_name))
    return parse_symbols(lib);

  const char *libnames[] = {"[vdso]", "libc", "libpthread", NULL};
  if (which_lib_name_interesting(libnames, lib->pathname) >= 0)
    return parse_symbols(lib);
  else
    return true;

error:
  _nx_debug_printf("rewriter: failed to parse\n");
  lib->valid = false;
  return false;
}

int which_lib_name_interesting(const char *interesting_libs[],
                               const char *pathname) {
  const char *mapping = pathname;
  for (const char *delim = " /"; *delim; ++delim) {
    // Find the actual base name of the mapped library by skipping past
    // any SPC and forward-slashes. We don't want to accidentally find
    // matches, because the directory name included part of our well-known
    // lib names.
    //
    // Typically, prior to pruning, entries would look something like
    // this: 08:01 2289011 /lib/libc-2.7.so
    const char *skip = strrchr(mapping, *delim); // TODO: do this at maps_read?
    if (skip) {
      mapping = skip + 1;
    }
  }

  for (const char **lib = interesting_libs; *lib; lib++) {
    const char *name = strstr(mapping, *lib);
    if (name != NULL) {
      char ch = name[strlen(*lib)];
      if (ch < 'A' || (ch > 'Z' && ch < 'a') || ch > 'z') {
        return lib - interesting_libs;
      }
    }
  }

  return -1;
}

void memorymaps_patch_intercept(int index,
                                const struct intercept_tls_context *tls) {
  assert(index >= 0 && index < registered_icept_cnt && tls != NULL);
  struct maps *maps = maps_read(NULL);
  if (maps == NULL)
    _nx_fatal_printf("could not inspect mappings for function intercept\n");

  struct library *lib;
  for_each_library(lib, maps) {
    if (!lib_name_match(intercept_records[index].lib_name, lib->pathname))
      continue;
    // Only the new record is applied. Loader allocations and protection work
    // use loader TLS; api_detour_func temporarily restores the callback's TLS.
    if (parse_elf(lib, lib->pathname)) {
      library_make_writable(lib, true);
      patch_funcs(lib, index, index + 1, tls);
      library_make_writable(lib, false);
    }
  }
  maps_release(maps);
}

void memorymaps_rewrite_lib(const char *libname) {
  struct maps *maps = maps_read(libname);
  if (maps == NULL)
    _nx_fatal_printf(
        "memrewrite: couldn't find library %s, when we should had\n", libname);

  struct library *l;
  int guard = 0; // Test that we always find exactly 1 library
  for_each_library(l, maps) {
    if (parse_elf(l, libname)) {
      _nx_debug_printf("memrewrite: patching syscalls in library %s\n",
                       l->pathname);
      library_make_writable(l, true);
      patch_syscalls(l, false);
      if (lib_is_icepted(l->pathname))
        patch_funcs(l, 0, registered_icept_cnt, NULL);
      library_make_writable(l, false);
    }
    guard++;
  }
  assert(guard == 1);

  maps_release(maps);
  _nx_debug_printf("memrewrite: done processing libraries\n");
}

void memorymaps_rewrite_all(const char *libs[], const char *bin, bool loader) {
  // We find all libraries that have system calls and redirect the system
  // calls to the sandbox. If we miss any system calls, the application will
  // be terminated by the kernel's seccomp code. So, from a security point of
  // view, if this code fails to identify system calls, we are still behaving
  // correctly.
  struct maps *maps = maps_read(NULL);

  // Intercept system calls in the VDSO segment (if any). This has to happen
  // before intercepting system calls in any of the other libraries, as the
  // main kernel entry point might be inside of the VDSO and we need to
  // determine its address before we can compare it to jumps from inside
  // other libraries.

  // TODO(andronat): I think this is wrong. We are in the loader and vdso will
  // be redirected in the plugin without switching the TLS.
  if (maps->lib_vdso != NULL && parse_elf(maps->lib_vdso, bin)) {
    _nx_debug_printf("memrewrite: patching vdso\n");
    library_make_writable(maps->lib_vdso, true);
    patch_vdso(maps->lib_vdso);
    library_make_writable(maps->lib_vdso, false);
    _nx_debug_printf("memrewrite: vdso done\n");
  }

  // Intercept system calls in libraries that are known to have them.
  struct library *l;
  for_each_library(l, maps) {
    _nx_debug_printf("memrewrite: processing library %s\n", l->pathname);
    bool is_bin = false;
    if ((which_lib_name_interesting(libs, l->pathname) >= 0 ||
         (bin &&
          (is_bin = !strcmp(l->pathname,
                            bin)))) // FIXME here bin should be the full path
        && parse_elf(l, bin)) {
      _nx_debug_printf("memrewrite: patching syscalls in library %s\n",
                       l->pathname);
      library_make_writable(l, true);
      patch_syscalls(l, is_bin ? false : loader);
      if (lib_is_icepted(l->pathname))
        patch_funcs(l, 0, registered_icept_cnt, NULL);
      library_make_writable(l, false);
    }
  }

  maps_release(maps);
  _nx_debug_printf("memrewrite: done processing libraries\n");
}
