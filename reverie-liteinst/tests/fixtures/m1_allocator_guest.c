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
    "malloc", "calloc", "realloc", "free", "aligned_alloc", "posix_memalign"
};
static uint64_t counts[ROUTES];

void *malloc(size_t n) {
    if (watching) ++counts[MALLOC];
    return next_malloc(n);
}
void *calloc(size_t n, size_t size) {
    if (watching) ++counts[CALLOC];
    return next_calloc(n, size);
}
void *realloc(void *p, size_t n) {
    if (watching) ++counts[REALLOC];
    return next_realloc(p, n);
}
void free(void *p) {
    if (watching) ++counts[FREE];
    next_free(p);
}
void *aligned_alloc(size_t alignment, size_t n) {
    if (watching) ++counts[ALIGNED];
    return next_aligned ? next_aligned(alignment, n) : __libc_memalign(alignment, n);
}
int posix_memalign(void **p, size_t alignment, size_t n) {
    if (watching) ++counts[POSIX];
    if (next_posix) return next_posix(p, alignment, n);
    if (alignment < sizeof(void *) || alignment % sizeof(void *) ||
        (alignment & (alignment - 1))) return EINVAL;
    void *q = __libc_memalign(alignment, n);
    if (!q) return ENOMEM;
    *p = q;
    return 0;
}

struct m1_result {
    uint64_t abi_version, status, pointer, size, align;
    uint64_t installation_before, dispatch_before, installation_after, dispatch_after;
    uint64_t private_member;
};
struct m1_query {
    uint64_t abi_version, status, installation_depth, dispatch_depth;
    uint64_t tool_base, tool_end, patch_base, patch_end, live_allocations;
};
_Static_assert(sizeof(struct m1_result) == 80, "Rust/C result ABI");
_Static_assert(sizeof(struct m1_query) == 72, "Rust/C query ABI");
_Static_assert(sizeof(void *) == 8, "Linux x86-64 fixture");

static uint64_t (*plugin_alloc)(size_t, size_t, uint64_t, struct m1_result *);
static uint64_t (*plugin_realloc)(void *, size_t, size_t, size_t, struct m1_result *);
static uint64_t (*plugin_dealloc)(void *, size_t, size_t, struct m1_result *);
static uint64_t (*plugin_private)(const void *);
static uint64_t (*plugin_query)(struct m1_query *);
static struct m1_query regions;
static Dl_info plugin_owner;
static unsigned failures;
static unsigned operations;
static uint64_t export_counts[ROUTES];
static uint64_t self_counts[ROUTES];
static unsigned case_selected[6], case_executed[6], case_complete[6];
static const char *const case_names[6] = { "small", "zeroed", "grow_shrink", "overaligned", "retained", "exhaustion" };

struct observation {
    const char *operation;
    struct m1_result result;
    uint64_t return_status, before_break, after_break, calls[ROUTES];
};
static struct observation observations[64];

static uint64_t raw_break(void) {
    uint64_t result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(12UL), "D"(0UL)
                     : "rcx", "r11", "memory", "cc");
    return result;
}
static void check(int condition) { if (!condition) ++failures; }
static int numeric_private(uint64_t p, uint64_t n) {
    if (!p || p + n < p) return 0;
    return (p >= regions.tool_base && p < regions.tool_end && p + n <= regions.tool_end) ||
           (p >= regions.patch_base && p < regions.patch_end && p + n <= regions.patch_end);
}
static unsigned char pattern(size_t index, unsigned seed) {
    return (unsigned char)((index * 29U + seed * 17U + 3U) & 255U);
}
static void fill(void *p, size_t n, unsigned seed) {
    for (size_t i = 0; i < n; ++i) ((unsigned char *)p)[i] = pattern(i, seed);
}
static void contents(const void *p, size_t n, unsigned seed) {
    for (size_t i = 0; i < n; ++i) check(((const unsigned char *)p)[i] == pattern(i, seed));
}

static int bind_symbols(void) {
    const char *const public_names[ROUTES] = { "malloc", "calloc", "realloc", "free", "aligned_alloc", "posix_memalign" };
    void *public_symbols[ROUTES];
    for (unsigned i = 0; i < ROUTES; ++i) {
        public_symbols[i] = dlsym(RTLD_NEXT, public_names[i]);
        if (!public_symbols[i]) return 0;
    }
    /* POSIX defines dlsym function-pointer conversion on this target. */
    memcpy(&next_malloc, &public_symbols[MALLOC], sizeof(next_malloc));
    memcpy(&next_calloc, &public_symbols[CALLOC], sizeof(next_calloc));
    memcpy(&next_realloc, &public_symbols[REALLOC], sizeof(next_realloc));
    memcpy(&next_free, &public_symbols[FREE], sizeof(next_free));
    memcpy(&next_aligned, &public_symbols[ALIGNED], sizeof(next_aligned));
    memcpy(&next_posix, &public_symbols[POSIX], sizeof(next_posix));
    const char *const names[5] = { "m1_alloc", "m1_realloc", "m1_dealloc", "m1_probe_private", "m1_query" };
    void *symbols[5];
    for (unsigned i = 0; i < 5; ++i) {
        symbols[i] = dlsym(RTLD_DEFAULT, names[i]);
        if (!symbols[i]) return 0;
        Dl_info owner;
        if (!dladdr(symbols[i], &owner) || !owner.dli_fname || !owner.dli_fbase) return 0;
        if (i == 0) plugin_owner = owner;
        else if (owner.dli_fbase != plugin_owner.dli_fbase ||
                 strcmp(owner.dli_fname, plugin_owner.dli_fname)) return 0;
    }
    const char *leaf = strrchr(plugin_owner.dli_fname, '/');
    leaf = leaf ? leaf + 1 : plugin_owner.dli_fname;
    if (strcmp(leaf, "libdetcore_liteinst.so") && strcmp(leaf, "libreverie_liteinst.so") &&
        strcmp(leaf, "libreverie_liteinst_preload.so")) return 0;
    memcpy(&plugin_alloc, &symbols[0], sizeof(plugin_alloc));
    memcpy(&plugin_realloc, &symbols[1], sizeof(plugin_realloc));
    memcpy(&plugin_dealloc, &symbols[2], sizeof(plugin_dealloc));
    memcpy(&plugin_private, &symbols[3], sizeof(plugin_private));
    memcpy(&plugin_query, &symbols[4], sizeof(plugin_query));
    return 1;
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
        if (grown) { m = grown; contents(m, 64, 11); }
        else ok = 0;
    }
    if (z) for (size_t i = 0; i < 51; ++i) if (((unsigned char *)z)[i]) ok = 0;
    gf(m); gf(z); gf(a); gf(p);
    watching = 0;
    memcpy(self_counts, counts, sizeof(counts));
    for (unsigned i = 0; i < ROUTES; ++i) if (!counts[i]) ok = 0;
    return ok;
}

static int warm_plugin(void) {
    struct m1_result a, r, d;
    if (plugin_query(&regions) || regions.abi_version != 1 || regions.status ||
        regions.installation_depth || regions.dispatch_depth || regions.live_allocations ||
        regions.tool_end <= regions.tool_base || regions.patch_end <= regions.patch_base ||
        regions.tool_end - regions.tool_base != 32U * 1024U * 1024U ||
        regions.patch_end - regions.patch_base != 32U * 1024U * 1024U ||
        !(regions.tool_end <= regions.patch_base || regions.patch_end <= regions.tool_base)) return 0;
    void *guest = malloc(96);
    if (!guest || plugin_private(guest) || numeric_private((uintptr_t)guest, 96)) {
        free(guest); return 0;
    }
    free(guest);
    /* Identical warmup on quiet/work, exercising every actual std shim. */
    if (plugin_alloc(64, 16, 1, &a) || !a.pointer) return 0;
    if (plugin_realloc((void *)(uintptr_t)a.pointer, 64, 16, 128, &r) || !r.pointer) {
        plugin_dealloc((void *)(uintptr_t)a.pointer, 64, 16, &d); return 0;
    }
    if (plugin_dealloc((void *)(uintptr_t)r.pointer, 128, 16, &d)) return 0;
    if (plugin_alloc(64, 16, 0, &a) || !a.pointer) return 0;
    if (plugin_dealloc((void *)(uintptr_t)a.pointer, 64, 16, &d)) return 0;
    if (plugin_alloc(4096, 4096, 0, &a) || !a.pointer) return 0;
    if (plugin_dealloc((void *)(uintptr_t)a.pointer, 4096, 4096, &d)) return 0;
    if (plugin_query(&regions) || regions.live_allocations ||
        regions.installation_depth || regions.dispatch_depth) return 0;
    return 1;
}

static struct observation *begin(const char *name) {
    if (operations >= sizeof(observations) / sizeof(observations[0])) return NULL;
    struct observation *o = &observations[operations++];
    o->operation = name;
    o->before_break = raw_break();
    memset(counts, 0, sizeof(counts));
    watching = 1;
    return o;
}
static void end(struct observation *o, uint64_t expected_status, int needs_live) {
    watching = 0;
    memcpy(o->calls, counts, sizeof(counts));
    o->after_break = raw_break();
    for (unsigned i = 0; i < ROUTES; ++i) {
        export_counts[i] += counts[i];
        check(counts[i] == 0);
    }
    check(o->before_break == o->after_break);
    check(o->result.abi_version == 1 && o->return_status == o->result.status);
    check(o->result.status == expected_status);
    check(!o->result.installation_before && !o->result.dispatch_before &&
          !o->result.installation_after && !o->result.dispatch_after);
    if (needs_live && o->result.status == 0 && o->result.pointer) {
        int own = numeric_private(o->result.pointer, o->result.size);
        check(own && o->result.private_member == 1);
        check(o->result.align && !(o->result.pointer % o->result.align));
    }
}
static void *allocate(size_t n, size_t align, int zero, int exhaustion) {
    struct observation *o = begin(exhaustion ? "exhaustion_alloc" : zero ? "alloc_zeroed" : "alloc");
    if (!o) { ++failures; return NULL; }
    o->return_status = plugin_alloc(n, align, (uint64_t)zero, &o->result);
    end(o, exhaustion ? 2 : 0, !exhaustion);
    if (exhaustion) check(o->result.pointer == 0);
    if (o->result.status || !o->result.pointer) return NULL;
    return (void *)(uintptr_t)o->result.pointer;
}
static void release(void *p, size_t n, size_t align) {
    if (!p) return;
    struct observation *o = begin("dealloc");
    if (!o) { ++failures; return; }
    o->return_status = plugin_dealloc(p, n, align, &o->result);
    end(o, 0, 0);
    check(o->result.pointer == (uint64_t)(uintptr_t)p && o->result.private_member == 1);
}
static int resize(void **p, size_t *old, size_t n) {
    struct observation *o = begin("realloc");
    if (!o) { ++failures; return 0; }
    o->return_status = plugin_realloc(*p, *old, 16, n, &o->result);
    end(o, 0, 1);
    if (o->result.status) return 0; /* Original remains live on failure. */
    *p = (void *)(uintptr_t)o->result.pointer;
    *old = n;
    return *p != NULL;
}

static void run_case(unsigned index) {
    case_executed[index] = 1;
    unsigned before = operations;
    if (index == 0 || index == 1 || index == 3) {
        size_t n = index == 0 ? 64 : index == 1 ? 257 : 4096;
        size_t align = index == 3 ? 4096 : 16;
        void *p = allocate(n, align, index == 1, 0);
        if (p) {
            if (index == 1) for (size_t i = 0; i < n; ++i) check(!((unsigned char *)p)[i]);
            fill(p, n, index + 1); contents(p, n, index + 1);
            release(p, n, align); case_complete[index] = 1;
        }
    } else if (index == 2) {
        size_t n = 64;
        void *p = allocate(n, 16, 0, 0);
        if (p) {
            fill(p, 64, 7);
            if (resize(&p, &n, 4096)) {
                contents(p, 64, 7); fill(p, 4096, 7);
                if (resize(&p, &n, 32)) { contents(p, 32, 7); case_complete[index] = 1; }
            }
            release(p, n, 16);
        }
    } else if (index == 4) {
        unsigned completed_cycles = 0;
        for (unsigned cycle = 0; cycle < 2; ++cycle) {
        void *p[8] = {0};
        static const unsigned order[8] = {3, 0, 7, 2, 5, 1, 6, 4};
        unsigned acquired = 0;
        for (unsigned i = 0; i < 8; ++i) {
            p[i] = allocate(31 + i * 37, 16, 0, 0);
            if (!p[i]) break;
            ++acquired; fill(p[i], 31 + i * 37, i + 20);
            for (unsigned j = 0; j < i; ++j) {
                uintptr_t a = (uintptr_t)p[i], b = (uintptr_t)p[j];
                check(a + 31 + i * 37 <= b || b + 31 + j * 37 <= a);
                contents(p[j], 31 + j * 37, j + 20);
            }
        }
        for (unsigned k = 0; k < 8; ++k) {
            unsigned i = order[k];
            if (p[i]) { contents(p[i], 31 + i * 37, i + 20); release(p[i], 31 + i * 37, 16); }
        }
        completed_cycles += acquired == 8;
        }
        case_complete[index] = completed_cycles == 2;
    } else {
        /* Beyond either frozen reserve; fallible raw alloc, not Vec/abort. */
        void *p = allocate(64U * 1024U * 1024U + 4096U, 16, 0, 1);
        if (p) release(p, 64U * 1024U * 1024U + 4096U, 16); /* Baseline cleanup. */
        case_complete[index] = 1; /* Allocation attempt observed, including failure. */
    }
    check(operations > before && case_complete[index]);
}

int main(void) {
    unsigned char input[2];
    size_t got = 0;
    while (got < sizeof(input)) {
        ssize_t n = read(STDIN_FILENO, input + got, sizeof(input) - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { fprintf(stderr, "m1 infrastructure: fixed stdin mode/case missing\n"); return 20; }
        got += (size_t)n;
    }
    if ((input[0] != 'Q' && input[0] != 'W') || !input[1] || !strchr("ASZGORE", input[1])) {
        fprintf(stderr, "m1 infrastructure: invalid fixed stdin mode/case\n"); return 20;
    }
    if (!bind_symbols()) {
        fprintf(stderr, "m1 infrastructure: missing fixture export/public forwarder or wrong loaded export owner\n"); return 21;
    }
    if (!watcher_controls() || failures) {
        fprintf(stderr, "m1 infrastructure: mandatory watcher/guest allocator positive control failed\n"); return 22;
    }
    if (!warm_plugin()) {
        fprintf(stderr, "m1 infrastructure: ABI/ranges/scopes/warmup/guest-pointer negative control failed\n"); return 23;
    }
    /* Same setup and guest allocation sequence in quiet/work, before output. */
    void *guest = malloc(333), *prior = malloc(111);
    if (!guest || !prior) { free(guest); free(prior); return 24; }
    fill(guest, 333, 77); free(prior);
    uint64_t guest_break_before = raw_break();
    for (unsigned i = 0; i < 6; ++i) {
        static const char selectors[6] = {'S', 'Z', 'G', 'O', 'R', 'E'};
        case_selected[i] = input[1] == 'A' || input[1] == selectors[i];
        if (case_selected[i]) {
            /* Identical allocation-free query/bookkeeping calls in Q/W.
             * Live membership comes from each export plus independently checked
             * frozen raw ranges, not a work-only membership export call. */
            struct m1_query checkpoint;
            check(plugin_query(&checkpoint) == 0 && !checkpoint.status &&
                  !checkpoint.installation_depth && !checkpoint.dispatch_depth &&
                  !checkpoint.live_allocations);
            check(plugin_private(guest) == 0);
            if (input[0] == 'W') run_case(i);
            check(plugin_query(&checkpoint) == 0 && !checkpoint.status &&
                  !checkpoint.installation_depth && !checkpoint.dispatch_depth &&
                  !checkpoint.live_allocations);
            check(plugin_private(guest) == 0);
        }
    }
    if (input[0] == 'W') {
        for (unsigned i = 0; i < 6; ++i)
            check(!case_selected[i] || (case_executed[i] && case_complete[i]));
    }
    uint64_t guest_break_after = raw_break();
    check(guest_break_before == guest_break_after);
    contents(guest, 333, 77);
    void *next = malloc(777);
    if (!next) { free(guest); return 24; }
    fill(next, 777, 88); contents(next, 777, 88);
    check(!plugin_private(guest) && !plugin_private(next));
    struct m1_query final;
    check(plugin_query(&final) == 0 && final.abi_version == 1 && !final.status &&
          !final.installation_depth && !final.dispatch_depth && !final.live_allocations);
    check(final.tool_base == regions.tool_base && final.tool_end == regions.tool_end &&
          final.patch_base == regions.patch_base && final.patch_end == regions.patch_end);
    uint64_t hash_guest = 14695981039346656037ULL, hash_next = hash_guest;
    for (size_t i = 0; i < 333; ++i) hash_guest = (hash_guest ^ ((unsigned char *)guest)[i]) * 1099511628211ULL;
    for (size_t i = 0; i < 777; ++i) hash_next = (hash_next ^ ((unsigned char *)next)[i]) * 1099511628211ULL;
    /* Formatting begins only after all address/byte observations are retained. */
    printf("m1 fixture abi=1 mode=%c case=%c owner=%s owner_base=0x%" PRIxPTR " operations=%u failures=%u\n",
           input[0], input[1], plugin_owner.dli_fname, (uintptr_t)plugin_owner.dli_fbase, operations, failures);
    printf("m1 ranges tool=[0x%" PRIx64 ",0x%" PRIx64 ") patch=[0x%" PRIx64 ",0x%" PRIx64 ")\n",
           regions.tool_base, regions.tool_end, regions.patch_base, regions.patch_end);
    for (unsigned i = 0; i < ROUTES; ++i)
        printf("m1 watcher route=%s self=%" PRIu64 " export=%" PRIu64 "\n", route_names[i], self_counts[i], export_counts[i]);
    for (unsigned i = 0; i < 6; ++i)
        printf("m1 case name=%s selected=%u executed=%u complete=%u\n", case_names[i], case_selected[i], case_executed[i], case_complete[i]);
    for (unsigned i = 0; i < operations; ++i) {
        const struct observation *o = &observations[i];
        printf("m1 op index=%u name=%s rc=%" PRIu64 " status=%" PRIu64 " pointer=0x%" PRIx64
               " size=%" PRIu64 " align=%" PRIu64 " private=%" PRIu64
               " depths=%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
               " brk=0x%" PRIx64 ",0x%" PRIx64 " calls=%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
               i, o->operation, o->return_status, o->result.status, o->result.pointer, o->result.size,
               o->result.align, o->result.private_member, o->result.installation_before, o->result.dispatch_before,
               o->result.installation_after, o->result.dispatch_after, o->before_break, o->after_break,
               o->calls[0], o->calls[1], o->calls[2], o->calls[3], o->calls[4], o->calls[5]);
    }
    printf("m1 addresses guest=0x%" PRIxPTR " next=0x%" PRIxPTR " brk=0x%" PRIx64 ",0x%" PRIx64
           " payload_hash=0x%" PRIx64 ",0x%" PRIx64 " exact_address_comparison=pending_external full_M1_pass=unclaimed\n",
           (uintptr_t)guest, (uintptr_t)next, guest_break_before, guest_break_after, hash_guest, hash_next);
    /* Retain literal initialized bytes, not only hashes, for the exact comparator. */
    printf("m1 guest_bytes=");
    for (size_t i = 0; i < 333; ++i) printf("%02x", ((unsigned char *)guest)[i]);
    printf("\nm1 next_bytes=");
    for (size_t i = 0; i < 777; ++i) printf("%02x", ((unsigned char *)next)[i]);
    printf("\n");
    free(next); free(guest);
    return failures ? 1 : 0;
}
