#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Linux/glibc only. Bootstrap forwarding cannot itself call dlsym from malloc.
 * After setup, every mandatory public route forwards to its warmed RTLD_NEXT
 * symbol. Hidden/direct libc allocation is explicitly outside this observer. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);
extern void *__libc_memalign(size_t, size_t);

static void *(*next_malloc)(size_t) = __libc_malloc;
static void *(*next_calloc)(size_t, size_t) = __libc_calloc;
static void *(*next_realloc)(void *, size_t) = __libc_realloc;
static void (*next_free)(void *) = __libc_free;
static void *(*next_aligned)(size_t, size_t);
static int (*next_posix)(void **, size_t, size_t);
static volatile unsigned watching;
enum { MALLOC, CALLOC, REALLOC, FREE, ALIGNED, POSIX, ROUTES };
static const char *const route_names[ROUTES] = {
    "malloc", "calloc", "realloc", "free", "aligned_alloc", "posix_memalign"};
static uint64_t counts[ROUTES];

void *malloc(size_t n) {
  if (watching)
    ++counts[MALLOC];
  return next_malloc(n);
}
void *calloc(size_t n, size_t size) {
  if (watching)
    ++counts[CALLOC];
  return next_calloc(n, size);
}
void *realloc(void *p, size_t n) {
  if (watching)
    ++counts[REALLOC];
  return next_realloc(p, n);
}
void free(void *p) {
  if (watching)
    ++counts[FREE];
  next_free(p);
}
void *aligned_alloc(size_t alignment, size_t n) {
  if (watching)
    ++counts[ALIGNED];
  return next_aligned ? next_aligned(alignment, n)
                      : __libc_memalign(alignment, n);
}
int posix_memalign(void **p, size_t alignment, size_t n) {
  if (watching)
    ++counts[POSIX];
  if (next_posix)
    return next_posix(p, alignment, n);
  if (alignment < sizeof(void *) || alignment % sizeof(void *) ||
      (alignment & (alignment - 1)))
    return EINVAL;
  void *q = __libc_memalign(alignment, n);
  if (!q)
    return ENOMEM;
  *p = q;
  return 0;
}

/* Separate diagnostic ABI. The frozen M1 guest and records are unchanged. */
struct m1_result {
  uint64_t abi_version, status, pointer, size, align;
  uint64_t installation_before, dispatch_before, installation_after,
      dispatch_after;
  uint64_t private_member;
};
struct snapshot {
  uint64_t version, status, backing_kind, region_published, backing_ready;
  uint64_t installation_depth, dispatch_depth;
  uint64_t tool_base, tool_end, patch_base, patch_end;
  uint64_t tool_next_address, tool_next_size, tool_next_align, tool_next;
  uint64_t tool_free_head_address, tool_free_head_size, tool_free_head_align,
      tool_free_head;
  uint64_t tool_lock_address, tool_lock_size, tool_lock_align,
      tool_lock_sample_held;
  uint64_t patch_next_address, patch_next_size, patch_next_align, patch_next;
  uint64_t head_address, head_span, head_next, reserved;
};
_Static_assert(sizeof(struct m1_result) == 80, "unchanged M1 result ABI");
_Static_assert(sizeof(struct snapshot) == 248, "separate snapshot ABI");
static uint64_t (*snapshot)(struct snapshot *, size_t);
static uint64_t (*operation)(uint64_t, uint64_t, void *, size_t, size_t, size_t,
                             struct m1_result *);
static int64_t (*read_maps)(unsigned char *, size_t);
static void (*initialize)(void);
static int (*constructor_query)(uint64_t *), (*generic_query)(uint64_t *);
static Dl_info plugin_owner;
static unsigned failures, placement_failures, operations;
static unsigned reusable_metadata_changed;
static uint64_t self_counts[ROUTES];
static unsigned char maps[1024 * 1024];
static int64_t maps_length;
struct row {
  const char *name;
  uint64_t op, scope, old_pointer, old_size, size, align, return_status;
  uint64_t before_break, after_break, calls[ROUTES];
  struct snapshot before, after;
  struct m1_result result;
};
static struct row rows[32];
static void check(int condition) {
  if (!condition)
    ++failures;
}
static uint64_t raw_break(void) {
  uint64_t value;
  __asm__ volatile("syscall"
                   : "=a"(value)
                   : "a"(12UL), "D"(0UL)
                   : "rcx", "r11", "memory", "cc");
  return value;
}
static unsigned char pattern(size_t i, unsigned seed) {
  return (unsigned char)((i * 29U + seed * 17U + 3U) & 255U);
}
static void fill(void *p, size_t n, unsigned seed) {
  for (size_t i = 0; i < n; ++i)
    ((unsigned char *)p)[i] = pattern(i, seed);
}
static void contents(const void *p, size_t n, unsigned seed) {
  for (size_t i = 0; i < n; ++i)
    check(((const unsigned char *)p)[i] == pattern(i, seed));
}
static void *owned(void *handle, const char *name, const char *runtime) {
  void *fn = dlsym(handle, name);
  Dl_info owner;
  if (!fn || !dladdr(fn, &owner) || !owner.dli_fname ||
      strcmp(owner.dli_fname, runtime))
    return NULL;
  if (!plugin_owner.dli_fbase)
    plugin_owner = owner;
  return owner.dli_fbase == plugin_owner.dli_fbase ? fn : NULL;
}
static int bind_symbols(const char *runtime) {
  void *handle = dlopen(runtime, RTLD_NOW | RTLD_NOLOAD);
  if (!handle)
    return 0;
  const char *names[] = {"m1_alloc",
                         "m1_realloc",
                         "m1_dealloc",
                         "m1_probe_private",
                         "m1_query",
                         "m5_allocator_snapshot",
                         "m5_allocator_operation",
                         "m5_allocator_maps",
                         "reverie_liteinst_initialize",
                         "reverie_inguest_constructor_stack_query",
                         "reverie_inguest_generic_stack_query"};
  void *symbols[11];
  for (unsigned i = 0; i < 11; ++i)
    if (!(symbols[i] = owned(handle, names[i], runtime)))
      return 0;
  memcpy(&snapshot, &symbols[5], sizeof snapshot);
  memcpy(&operation, &symbols[6], sizeof operation);
  memcpy(&read_maps, &symbols[7], sizeof read_maps);
  memcpy(&initialize, &symbols[8], sizeof initialize);
  memcpy(&constructor_query, &symbols[9], sizeof constructor_query);
  memcpy(&generic_query, &symbols[10], sizeof generic_query);
  void *pub[ROUTES];
  for (unsigned i = 0; i < ROUTES; ++i)
    if (!(pub[i] = dlsym(RTLD_NEXT, route_names[i])))
      return 0;
  memcpy(&next_malloc, &pub[MALLOC], sizeof next_malloc);
  memcpy(&next_calloc, &pub[CALLOC], sizeof next_calloc);
  memcpy(&next_realloc, &pub[REALLOC], sizeof next_realloc);
  memcpy(&next_free, &pub[FREE], sizeof next_free);
  memcpy(&next_aligned, &pub[ALIGNED], sizeof next_aligned);
  memcpy(&next_posix, &pub[POSIX], sizeof next_posix);
  return 1;
}
static int in_span(uint64_t p, uint64_t n, uint64_t base, uint64_t end) {
  return p && p >= base && p < end && n <= end - p;
}
static int disjoint(const void *a, size_t an, const void *b, size_t bn) {
  uint64_t ap = (uintptr_t)a, bp = (uintptr_t)b;
  return a && b && an <= UINT64_MAX - ap && bn <= UINT64_MAX - bp &&
         (ap + an <= bp || bp + bn <= ap);
}
static void take_snapshot(struct snapshot *s) {
  memset(s, 0, sizeof *s);
  check(snapshot(s, sizeof *s) == 0 && s->version == 1 && s->status == 0 &&
        s->backing_ready == 1 && s->region_published == 1 &&
        s->backing_kind <= 1);
  check(!s->installation_depth && !s->dispatch_depth &&
        s->tool_lock_sample_held == 1 && !s->reserved);
  check(s->tool_base < s->tool_end && s->patch_base < s->patch_end);
  check(s->tool_end - s->tool_base == 32ULL * 1024 * 1024 &&
        s->patch_end - s->patch_base == 32ULL * 1024 * 1024);
  check(s->tool_next <= 32ULL * 1024 * 1024 &&
        s->patch_next <= 32ULL * 1024 * 1024);
  check(s->tool_next_size == 8 && s->tool_next_align == 8 &&
        s->tool_next_address % 8 == 0);
  check(s->tool_free_head_size == 8 && s->tool_free_head_align == 8 &&
        s->tool_free_head_address % 8 == 0);
  check(s->tool_lock_size == 1 && s->tool_lock_align == 1);
  check(s->patch_next_size == 8 && s->patch_next_align == 8 &&
        s->patch_next_address % 8 == 0);
  if (s->tool_free_head) {
    check(s->head_address == s->tool_base + s->tool_free_head);
    check(s->head_address % 8 == 0 && s->head_span >= 32 &&
          s->head_span % 8 == 0);
    check(in_span(s->head_address, s->head_span, s->tool_base, s->tool_end));
    check(!s->head_next ||
          (s->head_next >= s->tool_free_head + s->head_span &&
           s->head_next % 8 == 0 && s->head_next <= 32ULL * 1024 * 1024 - 16));
  } else
    check(!s->head_address && !s->head_span && !s->head_next);
}
static int watcher_controls(void) {
  /* Volatile function pointers plus -fno-builtin prevent removal/substitution.
   * No symbol lookup, formatting or allocation in the observer itself. */
  void *(*volatile gm)(size_t) = malloc;
  void *(*volatile gc)(size_t, size_t) = calloc;
  void *(*volatile gr)(void *, size_t) = realloc;
  void (*volatile gf)(void *) = free;
  void *(*volatile ga)(size_t, size_t) = aligned_alloc;
  int (*volatile gp)(void **, size_t, size_t) = posix_memalign;
  memset(counts, 0, sizeof(counts));
  watching = 1;
  void *m = gm(64), *z = gc(17, 3), *a = ga(64, 128), *p = NULL;
  int pe = gp(&p, 4096, 4096);
  int ok = m && z && a && !pe && p;
  if (m) {
    fill(m, 64, 11);
    void *grown = gr(m, 128);
    if (grown) {
      m = grown;
      contents(m, 64, 11);
    } else
      ok = 0;
  }
  if (z)
    for (size_t i = 0; i < 51; ++i)
      if (((unsigned char *)z)[i])
        ok = 0;
  gf(m);
  gf(z);
  gf(a);
  gf(p);
  watching = 0;
  memcpy(self_counts, counts, sizeof(counts));
  for (unsigned i = 0; i < ROUTES; ++i)
    if (!counts[i])
      ok = 0;
  return ok;
}

static struct row *run(const char *name, uint64_t op, uint64_t scope, void *p,
                       size_t old, size_t n, size_t align, uint64_t expected) {
  if (operations == 32) {
    ++failures;
    return NULL;
  }
  struct row *r = &rows[operations++];
  r->name = name;
  r->op = op;
  r->scope = scope;
  r->old_pointer = (uintptr_t)p;
  r->old_size = old;
  r->size = n;
  r->align = align;
  r->before_break = raw_break();
  take_snapshot(&r->before);
  memset(counts, 0, sizeof counts);
  watching = 1;
  r->return_status = operation(op, scope, p, old, n, align, &r->result);
  watching = 0;
  memcpy(r->calls, counts, sizeof counts);
  take_snapshot(&r->after);
  r->after_break = raw_break();
  /* Derived from actual retained scalar/header observations, never a shadow
   * mutation counter or a requirement that every middle free moves the head. */
  reusable_metadata_changed |=
      r->before.tool_next != r->after.tool_next ||
      r->before.tool_free_head != r->after.tool_free_head ||
      r->before.head_address != r->after.head_address ||
      r->before.head_span != r->after.head_span ||
      r->before.head_next != r->after.head_next;
  check(r->return_status == expected && r->result.status == expected &&
        r->result.abi_version == 1);
  check(r->before_break == r->after_break);
  check(r->before.backing_kind == r->after.backing_kind &&
        r->before.tool_base == r->after.tool_base &&
        r->before.tool_end == r->after.tool_end &&
        r->before.patch_base == r->after.patch_base &&
        r->before.patch_end == r->after.patch_end &&
        r->before.tool_next_address == r->after.tool_next_address &&
        r->before.tool_free_head_address == r->after.tool_free_head_address &&
        r->before.tool_lock_address == r->after.tool_lock_address &&
        r->before.patch_next_address == r->after.patch_next_address);
  check(r->result.align == align);
  check(r->result.installation_before == (scope >> 1) &&
        r->result.installation_after == (scope >> 1));
  check(r->result.dispatch_before == (scope & 1) &&
        r->result.dispatch_after == (scope & 1));
  for (unsigned i = 0; i < ROUTES; ++i)
    check(!r->calls[i]);
  if (!expected) {
    check(r->result.size == (op == 3 ? old : n));
    uint64_t pointer = r->result.pointer;
    check(pointer && r->result.private_member == 1 && pointer % align == 0);
    int tool = in_span(pointer, r->result.size, r->before.tool_base,
                       r->before.tool_end);
    int patch = in_span(pointer, r->result.size, r->before.patch_base,
                        r->before.patch_end);
    check(tool || patch);
    /* Ownership of an old pointer, not current scope, decides resize/free. */
    int old_patch = p && in_span((uintptr_t)p, old, r->before.patch_base,
                                 r->before.patch_end);
    if (op < 2 ? !!(scope & 2) : old_patch) {
      check(patch);
      if (op == 3)
        check(r->before.patch_next == r->after.patch_next);
      else {
        uint64_t start = r->before.patch_base + r->before.patch_next;
        check(start >= r->before.patch_base &&
              start <= UINT64_MAX - (align - 1));
        uint64_t aligned = (start + align - 1) & ~(uint64_t)(align - 1);
        check(pointer == aligned && n <= r->before.patch_end - pointer);
        check(r->after.patch_next == pointer - r->before.patch_base + n);
      }
    } else
      check(tool);
  } else if (op < 2)
    check(!r->result.pointer);
  else
    check(r->result.pointer == (uint64_t)(uintptr_t)p && r->result.size == old);
  return r;
}
static void *allocate(const char *name, uint64_t scope, size_t n, size_t align,
                      int zero, unsigned seed) {
  struct row *r = run(name, zero ? 1 : 0, scope, NULL, 0, n, align, 0);
  if (!r || r->result.status || !r->result.pointer)
    return NULL;
  void *p = (void *)(uintptr_t)r->result.pointer;
  if (zero)
    for (size_t i = 0; i < n; ++i)
      check(!((unsigned char *)p)[i]);
  fill(p, n, seed);
  contents(p, n, seed);
  return p;
}
static void release(const char *name, uint64_t scope, void *p, size_t n,
                    size_t align) {
  if (p)
    run(name, 3, scope, p, n, 0, align, 0);
  else
    ++failures;
}
static int maps_cover(uint64_t base, uint64_t end, const char *wanted) {
  uint64_t cursor = base;
  const char *line = (const char *)maps;
  while (*line && cursor < end) {
    unsigned long long lo, hi, offset, inode;
    unsigned major, minor;
    char perms[5];
    int consumed = 0;
    if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu%n", &lo, &hi, perms,
               &offset, &major, &minor, &inode, &consumed) == 7 &&
        lo <= cursor && cursor < hi) {
      if (strcmp(perms, wanted) || offset || major || minor || inode)
        return 0;
      const char *path = line + consumed;
      while (*path == ' ')
        ++path;
      /* Require actual anonymous coverage, not a file/shared substitute. */
      if (*path && *path != '\n' && strncmp(path, "[anon:", 6))
        return 0;
      cursor = hi < end ? hi : end;
    }
    const char *next = strchr(line, '\n');
    if (!next)
      break;
    line = next + 1;
  }
  return cursor == end;
}
static void placement(const struct snapshot *s) {
  const uint64_t tool = 0x600010000000ULL, patch = 0x600014000000ULL,
                 bytes = 32ULL * 1024 * 1024;
  placement_failures += !(s->tool_base == tool && s->tool_end == tool + bytes);
  placement_failures +=
      !(s->patch_base == patch && s->patch_end == patch + bytes);
  const uint64_t addresses[] = {s->tool_next_address, s->tool_free_head_address,
                                s->tool_lock_address, s->patch_next_address};
  const uint64_t sizes[] = {s->tool_next_size, s->tool_free_head_size,
                            s->tool_lock_size, s->patch_next_size};
  const uint64_t aligns[] = {s->tool_next_align, s->tool_free_head_align,
                             s->tool_lock_align, s->patch_next_align};
  for (unsigned i = 0; i < 4; ++i)
    placement_failures += !(
        in_span(addresses[i], sizes[i], 0x600000023000ULL, 0x600000024000ULL) &&
        aligns[i] && addresses[i] % aligns[i] == 0);
  placement_failures += !maps_cover(tool, tool + bytes, "rw-p");
  placement_failures += !maps_cover(patch, patch + bytes, "rw-p");
  placement_failures +=
      !maps_cover(0x600000023000ULL, 0x600000024000ULL, "rw-p");
  for (unsigned i = 0; i < 2; ++i) {
    uint64_t base = i ? patch : tool;
    placement_failures += !maps_cover(base - 4096, base, "---p");
    placement_failures +=
        !maps_cover(base + bytes, base + bytes + 4096, "---p");
  }
  for (unsigned i = 0; i < operations; ++i) {
    const struct row *r = &rows[i];
    if (r->result.status || r->op == 3)
      continue;
    int patch_pointer = in_span(r->result.pointer, r->result.size,
                                r->before.patch_base, r->before.patch_end);
    placement_failures += !in_span(r->result.pointer, r->result.size,
                                   patch_pointer ? patch : tool,
                                   (patch_pointer ? patch : tool) + bytes);
  }
}
static void print_snapshot(const char *name, unsigned index,
                           const struct snapshot *s) {
  printf("fixed snapshot row=%u edge=%s", index, name);
  uint64_t words[31];
  memcpy(words, s, sizeof words);
  for (unsigned i = 0; i < 31; ++i)
    printf(" w%u=0x%" PRIx64, i, words[i]);
  putchar('\n');
}
int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "inert") && strcmp(argv[1], "active"))) {
    fputs("fixed infrastructure: inert|active EXACT_RUNTIME required\n",
          stderr);
    return 20;
  }
  if (!bind_symbols(argv[2])) {
    fputs("fixed infrastructure: missing/wrong-owner actual exports\n", stderr);
    return 21;
  }
  struct snapshot initial;
  memset(&initial, 0, sizeof initial);
  uint64_t query_status = snapshot(&initial, sizeof initial);
  if (initial.version != 1 || query_status != initial.status ||
      (query_status != 0 && query_status != 1)) {
    fputs("fixed infrastructure: initial actual snapshot failed\n", stderr);
    return 22;
  }
  uint64_t constructor[16] = {0}, generic[16] = {0};
  if (!strcmp(argv[1], "inert")) {
    if (getenv("REVERIE_LITEINST_TOOL") || getenv("REVERIE_INGUEST_TOOL") ||
        initial.region_published || constructor_query(constructor) != -1 ||
        generic_query(generic) != -1) {
      fputs("fixed infrastructure: standalone not genuinely inert\n", stderr);
      return 23;
    }
    initialize(); /* Genuine public None once; no second initialization. */
    if (constructor_query(constructor) != -1 || generic_query(generic) != 0) {
      fputs("fixed infrastructure: genuine None did not return generic owner\n",
            stderr);
      return 23;
    }
  } else if (!initial.region_published || constructor_query(constructor) != 0 ||
             generic_query(generic) != -1) {
    fputs("fixed infrastructure: active constructor owner absent\n", stderr);
    return 23;
  }
  const uint64_t *owner = !strcmp(argv[1], "inert") ? generic : constructor;
  check(owner[0] == 1 && owner[1] == 4 && owner[2] == (uint64_t)gettid());
  check(owner[12] == 0x600000001000ULL && owner[14] == 0x600000000000ULL &&
        owner[15] == 0x600100000000ULL);
  if (!watcher_controls() || failures) {
    fputs("fixed infrastructure: six watcher controls failed\n", stderr);
    return 24;
  }
  /* Warm the real guest brk site outside metadata mutation brackets. */
  (void)raw_break();
  void *a = allocate("outside-alloc", 0, 64, 16, 0, 7);
  void *z = allocate("outside-zero", 0, 257, 16, 1, 8);
  void *aligned = allocate("outside-overaligned", 0, 4096, 4096, 0, 9);
  check(disjoint(a, 64, z, 257) && disjoint(a, 64, aligned, 4096) &&
        disjoint(z, 257, aligned, 4096));
  if (a) {
    struct row *r = run("outside-grow", 2, 0, a, 64, 4096, 16, 0);
    if (r && !r->result.status && r->result.pointer) {
      a = (void *)(uintptr_t)r->result.pointer;
      contents(a, 64, 7);
      fill(a, 4096, 7);
      check(disjoint(a, 4096, z, 257) && disjoint(a, 4096, aligned, 4096));
      r = run("outside-shrink-in-both-scopes", 2, 3, a, 4096, 32, 16, 0);
      if (r && !r->result.status && r->result.pointer) {
        a = (void *)(uintptr_t)r->result.pointer;
        contents(a, 32, 7);
        release("outside-free-in-install", 2, a, 32, 16);
      } else
        release("grow-cleanup", 0, a, 4096, 16);
    } else
      release("allocation-cleanup", 0, a, 64, 16);
  } else
    ++failures;
  if (z)
    contents(z, 257, 8);
  if (aligned)
    contents(aligned, 4096, 9);
  release("outside-zero-free", 0, z, 257, 16);
  release("outside-aligned-free", 0, aligned, 4096, 4096);
  void *dispatch = allocate("dispatch-alloc", 1, 96, 16, 0, 10);
  release("dispatch-free", 1, dispatch, 96, 16);
  void *patch = allocate("install-alloc", 2, 73, 4096, 0, 11);
  void *patch_zero = allocate("install-zero", 2, 257, 16, 1, 12);
  check(disjoint(patch, 73, patch_zero, 257));
  if (patch) {
    struct row *r = run("patch-grow-outside", 2, 0, patch, 73, 8192, 4096, 0);
    if (r && !r->result.status && r->result.pointer) {
      void *grown = (void *)(uintptr_t)r->result.pointer;
      check(disjoint(grown, 8192, patch, 73) &&
            disjoint(grown, 8192, patch_zero, 257));
      contents(grown, 73, 11);
      contents(patch, 73, 11);
      fill(grown, 8192, 11);
      release("patch-free-in-dispatch", 1, grown, 8192, 4096);
    } else
      release("patch-cleanup", 0, patch, 73, 4096);
  } else
    ++failures;
  if (patch_zero)
    contents(patch_zero, 257, 12);
  release("patch-zero-free", 0, patch_zero, 257, 16);
  void *retained = allocate("failed-realloc-source", 0, 128, 16, 0, 13);
  if (retained) {
    run("failed-realloc", 2, 0, retained, 128, 64U * 1024U * 1024U + 4096U, 16,
        2);
    contents(retained, 128, 13);
    release("failed-realloc-source-free", 0, retained, 128, 16);
  } else
    ++failures;
  run("install-oversized", 0, 2, NULL, 0, 64U * 1024U * 1024U + 4096U, 16, 2);
  run("install-zero-oversized", 1, 2, NULL, 0, 64U * 1024U * 1024U + 4096U, 16,
      2);
  check(operations == 20 && reusable_metadata_changed);
  for (unsigned i = 1; i < operations; ++i) {
    const struct snapshot *first = &rows[0].before, *s = &rows[i].before;
    check(first->backing_kind == s->backing_kind &&
          first->tool_base == s->tool_base && first->tool_end == s->tool_end &&
          first->patch_base == s->patch_base &&
          first->patch_end == s->patch_end &&
          first->tool_next_address == s->tool_next_address &&
          first->tool_free_head_address == s->tool_free_head_address &&
          first->tool_lock_address == s->tool_lock_address &&
          first->patch_next_address == s->patch_next_address);
  }
  maps_length = read_maps(maps, sizeof maps - 1);
  if (maps_length < 0 || maps_length >= (int64_t)sizeof maps) {
    fputs("fixed infrastructure: actual maps read failed\n", stderr);
    return 25;
  }
  maps[maps_length] = 0;
  printf("fixed fixture abi=1 setup=%s owner=%s base=0x%" PRIxPTR
         " operations=%u operation_failures=%u reusable_metadata_changed=%u\n",
         argv[1], plugin_owner.dli_fname, (uintptr_t)plugin_owner.dli_fbase,
         operations, failures, reusable_metadata_changed);
  print_snapshot("initial", 0, &initial);
  printf("fixed origin");
  for (unsigned i = 0; i < 16; ++i) {
    printf(" w%u=0x%" PRIx64, i, owner[i]);
  }
  putchar('\n');
  for (unsigned i = 0; i < ROUTES; ++i)
    printf("fixed watcher route=%s self=%" PRIu64 "\n", route_names[i],
           self_counts[i]);
  for (unsigned i = 0; i < operations; ++i) {
    struct row *r = &rows[i];
    printf("fixed operation row=%u name=%s op=%" PRIu64 " scope=%" PRIu64
           " old=0x%" PRIx64 " oldsize=%" PRIu64 " size=%" PRIu64
           " align=%" PRIu64 " rc=%" PRIu64 " pointer=0x%" PRIx64
           " result_size=%" PRIu64 " status=%" PRIu64 " depths=%" PRIu64
           ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 " brk=0x%" PRIx64 ",0x%" PRIx64,
           i, r->name, r->op, r->scope, r->old_pointer, r->old_size, r->size,
           r->align, r->return_status, r->result.pointer, r->result.size,
           r->result.status, r->result.installation_before,
           r->result.dispatch_before, r->result.installation_after,
           r->result.dispatch_after, r->before_break, r->after_break);
    for (unsigned j = 0; j < ROUTES; ++j) {
      printf(" call%u=%" PRIu64, j, r->calls[j]);
    }
    putchar('\n');
    print_snapshot("before", i, &r->before);
    print_snapshot("after", i, &r->after);
  }
  printf("fixed raw_maps_begin bytes=%" PRId64 "\n", maps_length);
  fwrite(maps, 1, (size_t)maps_length, stdout);
  puts("fixed raw_maps_end");
  if (failures) {
    puts("fixed result workload_failed placement_unmeasured");
    return 26;
  }
  /* Only now evaluate Fixed placement: Legacy must reach the same live work. */
  placement(&rows[0].before);
  printf("fixed result operations_complete=1 placement_failures=%u "
         "fixed_pass=%u\n",
         placement_failures, !placement_failures);
  return placement_failures ? 1 : 0;
}
