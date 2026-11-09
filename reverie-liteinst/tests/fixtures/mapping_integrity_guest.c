#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define PAGE 4096ULL
#define OWNER_BASE 0x600000000000ULL
#define OWNER_END 0x600100000000ULL

struct snapshot {
  uint64_t version, owner, control, state, current_pid, current_tid;
  uint64_t alt_bottom, alt_top;
  uint64_t live_base, live_bytes, live_guard_low, live_guard_high, live_owned;
  uint64_t free_base, free_bytes, free_guard_low, free_guard_high, free_unowned;
  uint64_t sentinel_expected, reuse_base, reuse_count;
};
_Static_assert(sizeof(struct snapshot) == 21 * sizeof(uint64_t), "snapshot ABI");
typedef int32_t (*action_fn)(struct snapshot *, size_t);
typedef int32_t (*finish_fn)(void);
typedef int64_t (*maps_fn)(unsigned char *, size_t);
typedef uint64_t (*counter_fn)(uint64_t);
typedef uint64_t (*allocator_fn)(uint64_t *, size_t);
extern long m6_guest_syscall(long, const uint64_t *);
extern unsigned char m6_guest_syscall_site[];
static unsigned char maps[65536];
static char owner_before[16384], owner_after[16384];
static maps_fn actual_maps;

static void *owned(const char *name, const char *runtime) {
  void *symbol = dlsym(RTLD_DEFAULT, name);
  Dl_info info;
  if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
      strcmp(info.dli_fname, runtime)) {
    fprintf(stderr, "mapping setup: actual runtime export %s missing/wrong provider\n", name);
    return NULL;
  }
  return symbol;
}

static long call(long number, uint64_t a0, uint64_t a1, uint64_t a2,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
  const uint64_t args[6] = {a0, a1, a2, a3, a4, a5};
  return m6_guest_syscall(number, args);
}

/* Compare actual owner VMAs, including coverage, permissions and map identity. */
static int owner_maps(char *signature, size_t capacity, uint64_t probe,
                      char permissions[5]) {
  long count = actual_maps(maps, sizeof maps - 1);
  if (count <= 0 || (size_t)count == sizeof maps - 1)
    return -1;
  maps[count] = 0;
  size_t used = 0;
  permissions[0] = 0;
  for (char *line = (char *)maps; *line;) {
    char *end = strchr(line, '\n');
    if (!end)
      return -1;
    unsigned long start, stop;
    char access[5];
    if (sscanf(line, "%lx-%lx %4s", &start, &stop, access) != 3)
      return -1;
    if (start <= probe && probe < stop)
      memcpy(permissions, access, 5);
    if (start < OWNER_END && stop > OWNER_BASE) {
      size_t bytes = (size_t)(end + 1 - line);
      if (bytes >= capacity - used)
        return -1;
      memcpy(signature + used, line, bytes);
      used += bytes;
    }
    line = end + 1;
  }
  signature[used] = 0;
  return used ? 0 : -1;
}

static int identity(const struct snapshot *a, const struct snapshot *b) {
  return a->version == 1 && b->version == 1 && a->owner == b->owner &&
         a->control == b->control && a->state == b->state &&
         a->alt_bottom == b->alt_bottom && a->alt_top == b->alt_top &&
         a->live_base == b->live_base && a->live_bytes == b->live_bytes &&
         a->live_guard_low == b->live_guard_low &&
         a->live_guard_high == b->live_guard_high &&
         a->free_base == b->free_base && a->free_bytes == b->free_bytes &&
         a->free_guard_low == b->free_guard_low &&
         a->free_guard_high == b->free_guard_high;
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[2], "mprotect") && strcmp(argv[2], "munmap")))
    return 90;
  const char *runtime = argv[1], *operation = argv[2];
  action_fn prepare = (action_fn)owned("m6_mapping_fixture_prepare", runtime);
  action_fn observe = (action_fn)owned("m6_mapping_fixture_observe", runtime);
  action_fn reuse = (action_fn)owned("m6_mapping_fixture_reuse", runtime);
  finish_fn finish = (finish_fn)owned("m6_mapping_fixture_finish", runtime);
  actual_maps = (maps_fn)owned("m5_allocator_maps", runtime);
  allocator_fn allocator = (allocator_fn)owned("m5_allocator_snapshot", runtime);
  counter_fn traps = (counter_fn)owned("reverie_liteinst_site_trap_count", runtime);
  counter_fn hooks = (counter_fn)owned("reverie_liteinst_site_hook_count", runtime);
  if (!prepare || !observe || !reuse || !finish || !actual_maps ||
      !allocator || !traps || !hooks)
    return 91;

  /* Warm the genuine dispatcher before choosing any spare/free extent. */
  long pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
  if (pid <= 0 || call(SYS_getpid, 0, 0, 0, 0, 0, 0) != pid)
    return 92;
  struct snapshot before = {0}, after = {0}, reused = {0};
  int setup = prepare(&before, sizeof before);
  printf("MAPPING_SETUP operation=%s result=%d\n", operation, setup);
  if (setup || before.current_pid != (uint64_t)pid ||
      before.current_tid != before.current_pid || !before.live_owned ||
      !before.free_unowned || before.live_bytes != PAGE ||
      before.free_bytes != PAGE || before.alt_top <= before.alt_bottom)
    return 93;
  uint64_t allocation[31] = {0};
  if (allocator(allocation, sizeof allocation) || allocation[2] != 1 ||
      before.state < allocation[7] || before.state >= allocation[8])
    return 94; /* Actual retained state must be in the qualified Fixed Tool heap. */
  char free_before[5] = {0}, free_after[5] = {0};
  if (owner_maps(owner_before, sizeof owner_before, before.free_base, free_before) ||
      strcmp(free_before, "---p"))
    return 95;
  unsigned char sentinel_before = *(volatile unsigned char *)(uintptr_t)before.live_base;
  if (sentinel_before != before.sentinel_expected)
    return 96;

  long number = !strcmp(operation, "mprotect") ? SYS_mprotect : SYS_munmap;
  uint64_t site = (uintptr_t)m6_guest_syscall_site;
  uint64_t trap_before = traps(site), hook_before = hooks(site);
  long raw = call(number, before.free_base, PAGE,
                  number == SYS_mprotect ? PROT_READ | PROT_WRITE : 0, 0, 0, 0);
  uint64_t trap_after = traps(site), hook_after = hooks(site);
  int maps_result = owner_maps(owner_after, sizeof owner_after, before.free_base, free_after);
  int maps_equal = !maps_result && !strcmp(owner_before, owner_after);
  int observed = observe(&after, sizeof after);
  unsigned char sentinel_after = *(volatile unsigned char *)(uintptr_t)before.live_base;
  int reuse_result = reuse(&reused, sizeof reused);
  int second_reuse = reuse_result ? reuse_result : reuse(&reused, sizeof reused);

  /* Outside Guest mappings remain usable with the same real forwarded calls. */
  long outside = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, UINT64_MAX, 0);
  int outside_separate = outside > 0 &&
      (uint64_t)outside <= UINT64_MAX - PAGE &&
      !((uint64_t)outside < OWNER_END && OWNER_BASE < (uint64_t)outside + PAGE);
  long outside_result = outside < 0 ? outside :
      call(number, (uint64_t)outside, PAGE,
           number == SYS_mprotect ? PROT_READ : 0, 0, 0, 0);
  long outside_cleanup = outside < 0 || number == SYS_munmap ? 0 :
      call(SYS_munmap, (uint64_t)outside, PAGE, 0, 0, 0, 0);
  int identity_equal = !observed && identity(&before, &after) &&
                       !reuse_result && !second_reuse && identity(&before, &reused);
  printf("MAPPING_LITERAL operation=%s raw=%ld expected=%d maps_equal=%d "
         "before_permissions=%s after_permissions=%s observe=%d identity_equal=%d "
         "sentinel_before=%u sentinel_after=%u reuse=%d second_reuse=%d "
         "reuse_same=%d reuse_count=%" PRIu64 " outside_separate=%d outside=%ld cleanup=%ld "
         "trap_delta=%" PRIu64 " hook_delta=%" PRIu64 "\n",
         operation, raw, -EPERM, maps_equal, free_before,
         free_after[0] ? free_after : "absent", observed, identity_equal,
         sentinel_before, sentinel_after, reuse_result, second_reuse,
         reused.reuse_base == before.free_base, reused.reuse_count,
         outside_separate, outside_result, outside_cleanup, trap_after - trap_before, hook_after - hook_before);
  fflush(stdout);
  int passed = raw == -EPERM && maps_equal && !strcmp(free_after, "---p") &&
               identity_equal && sentinel_before == sentinel_after &&
               after.live_owned && after.free_unowned && reused.live_owned &&
               reused.free_unowned && reused.reuse_base == before.free_base &&
               reused.reuse_count == 2 && outside_separate && outside_result == 0 &&
               outside_cleanup == 0 &&
               (trap_after > trap_before || hook_after > hook_before);
  if (!passed)
    return 1; /* Literal old-source mutations remain failures, never relabelled. */
  return finish() ? 97 : 0;
}
