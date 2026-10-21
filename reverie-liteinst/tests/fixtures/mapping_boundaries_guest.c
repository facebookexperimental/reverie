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


#include <unistd.h>
#include <sys/wait.h>

/* Kept separate from the frozen minimal forwarding oracle. */
#define RAW_MSEAL 462
static action_fn prepare_action, observe_action, reuse_action;
static finish_fn finish_action;
static counter_fn trap_count, hook_count;

static int prepare_owned(const char *runtime, struct snapshot *before) {
  prepare_action = (action_fn)owned("m6_mapping_fixture_prepare", runtime);
  observe_action = (action_fn)owned("m6_mapping_fixture_observe", runtime);
  reuse_action = (action_fn)owned("m6_mapping_fixture_reuse", runtime);
  finish_action = (finish_fn)owned("m6_mapping_fixture_finish", runtime);
  actual_maps = (maps_fn)owned("m5_allocator_maps", runtime);
  allocator_fn allocator = (allocator_fn)owned("m5_allocator_snapshot", runtime);
  trap_count = (counter_fn)owned("reverie_liteinst_site_trap_count", runtime);
  hook_count = (counter_fn)owned("reverie_liteinst_site_hook_count", runtime);
  if (!prepare_action || !observe_action || !reuse_action || !finish_action ||
      !actual_maps || !allocator || !trap_count || !hook_count)
    return 91;
  long pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
  if (pid <= 0 || call(SYS_getpid, 0, 0, 0, 0, 0, 0) != pid)
    return 92;
  if (prepare_action(before, sizeof *before) || before->version != 1 ||
      before->current_pid != (uint64_t)pid || before->current_tid != (uint64_t)pid ||
      !before->live_owned || !before->free_unowned ||
      before->live_bytes != PAGE || before->free_bytes != PAGE ||
      before->alt_top <= before->alt_bottom)
    return 93;
  uint64_t allocation[31] = {0};
  if (allocator(allocation, sizeof allocation) || allocation[2] != 1 ||
      before->state < allocation[7] || before->state >= allocation[8])
    return 94;
  return *(volatile unsigned char *)(uintptr_t)before->live_base ==
         before->sentinel_expected ? 0 : 95;
}

static int owner_usable(const struct snapshot *before, uint64_t probe,
                        const char *expected_permissions) {
  struct snapshot after = {0}, reused = {0};
  char permissions[5] = {0};
  int observed = observe_action(&after, sizeof after);
  int mapped = owner_maps(owner_after, sizeof owner_after, probe, permissions);
  int same = !mapped && !strcmp(owner_before, owner_after) &&
             !strcmp(permissions, expected_permissions);
  int sentinel = *(volatile unsigned char *)(uintptr_t)before->live_base ==
                 before->sentinel_expected;
  int lease = reuse_action(&reused, sizeof reused);
  int second = lease ? lease : reuse_action(&reused, sizeof reused);
  int retained = !observed && identity(before, &after) && after.live_owned &&
                 after.free_unowned && !lease && !second &&
                 identity(before, &reused) && reused.live_owned &&
                 reused.free_unowned && reused.reuse_base == before->free_base &&
                 reused.reuse_count == 2;
  printf("BOUNDARY_OWNER maps_equal=%d sentinel=%d identity_lease=%d "
         "observe=%d lease=%d second=%d\n", same, sentinel, retained,
         observed, lease, second);
  return same && sentinel && retained;
}

static int protection_case(const char *mode, const struct snapshot *before) {
  int guard = !strcmp(mode, "guard");
  uint64_t address = guard ? before->live_guard_low : before->live_base;
  const char *expected = guard ? "---p" : "rw-p";
  char permissions[5] = {0};
  if (owner_maps(owner_before, sizeof owner_before, address, permissions) ||
      strcmp(permissions, expected))
    return 96;
  uint64_t site = (uintptr_t)m6_guest_syscall_site;
  uint64_t traps = trap_count(site), hooks = hook_count(site);
  long result = call(SYS_mprotect, address, PAGE,
                     guard ? PROT_READ | PROT_WRITE : PROT_READ, 0, 0, 0);
  int routed = trap_count(site) > traps || hook_count(site) > hooks;
  int retained = owner_usable(before, address, expected);
  long outside = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, UINT64_MAX, 0);
  int separate = outside > 0 &&
      ((uint64_t)outside + PAGE <= OWNER_BASE || (uint64_t)outside >= OWNER_END);
  long changed = outside < 0 ? outside :
      call(SYS_mprotect, (uint64_t)outside, PAGE, PROT_READ, 0, 0, 0);
  long released = outside < 0 ? outside :
      call(SYS_munmap, (uint64_t)outside, PAGE, 0, 0, 0, 0);
  int passed = result == -EPERM && routed && retained && separate &&
               changed == 0 && released == 0;
  printf("MAPPING_BOUNDARY mode=%s raw=%ld routed=%d retained=%d "
         "outside=%d changed=%ld released=%ld passed=%d\n",
         mode, result, routed, retained, separate, changed, released, passed);
  return passed ? 0 : 1;
}

static int break_case(const struct snapshot *before) {
  char permissions[5] = {0};
  if (owner_maps(owner_before, sizeof owner_before, before->free_base, permissions) ||
      strcmp(permissions, "---p"))
    return 96;
  long initial = call(SYS_brk, 0, 0, 0, 0, 0, 0);
  void *saved = sbrk(0);
  /* This non-PIE fixture's heap is below the fixed reservation. */
  if (initial <= 0 || (uint64_t)initial >= OWNER_BASE ||
      (uintptr_t)saved != (uint64_t)initial)
    return 97;
  uint64_t target = OWNER_BASE + PAGE;
  long raw = call(SYS_brk, target, 0, 0, 0, 0, 0);
  errno = 0;
  int denied = brk((void *)(uintptr_t)target);
  int denied_errno = errno;
  int unchanged = raw == initial && denied == -1 && denied_errno == ENOMEM &&
                  call(SYS_brk, 0, 0, 0, 0, 0, 0) == initial &&
                  (uintptr_t)sbrk(0) == (uint64_t)initial;
  long invalid = call(SYS_brk, UINT64_MAX, 0, 0, 0, 0, 0);
  errno = 0;
  int invalid_libc = brk((void *)UINTPTR_MAX);
  int invalid_errno = errno;
  int invalid_unchanged = invalid == initial && invalid_libc == -1 &&
      invalid_errno == ENOMEM && call(SYS_brk, 0, 0, 0, 0, 0, 0) == initial &&
      (uintptr_t)sbrk(0) == (uint64_t)initial;

  /* Actually forward byte changes in both directions within a single page,
     then restore the initial heap break before any later guest allocation. */
  uint64_t next_page = ((uint64_t)initial + PAGE - 1) & ~(PAGE - 1);
  uint64_t positions[] = {next_page + 1, next_page + 2, next_page + 1,
                          (uint64_t)initial};
  int byte_changes = 1;
  for (size_t i = 0; i < sizeof positions / sizeof positions[0]; ++i) {
    int changed = brk((void *)(uintptr_t)positions[i]);
    long actual = call(SYS_brk, 0, 0, 0, 0, 0, 0);
    uintptr_t cached = (uintptr_t)sbrk(0);
    byte_changes &= changed == 0 && (uint64_t)actual == positions[i] &&
                    cached == positions[i];
  }
  int retained = owner_usable(before, before->free_base, "---p");
  int passed = unchanged && invalid_unchanged && byte_changes && retained;
  printf("MAPPING_BOUNDARY mode=brk raw=%ld initial=%ld libc=%d errno=%d "
         "unchanged=%d invalid=%d byte_changes=%d retained=%d passed=%d\n",
         raw, initial, denied, denied_errno, unchanged, invalid_unchanged,
         byte_changes, retained, passed);
  return passed ? 0 : 1;
}

static int seal_case(const struct snapshot *before) {
  long outside = call(SYS_mmap, 0, PAGE, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, UINT64_MAX, 0);
  if (outside <= 0 || ((uint64_t)outside < OWNER_END &&
                      OWNER_BASE < (uint64_t)outside + PAGE))
    return 98;
  long support = call(RAW_MSEAL, (uint64_t)outside, PAGE, 0, 0, 0, 0);
  if (support != 0 && support != -ENOSYS) {
    fprintf(stderr, "mseal support probe unexpected result=%ld\n", support);
    return 99;
  }
  /* Successful mseal forbids later unmap. This separate page lives until exit. */
  char permissions[5] = {0};
  if (owner_maps(owner_before, sizeof owner_before, before->free_base, permissions) ||
      strcmp(permissions, "---p"))
    return 96;
  uint64_t site = (uintptr_t)m6_guest_syscall_site;
  uint64_t traps = trap_count(site), hooks = hook_count(site);
  long result = call(RAW_MSEAL, before->free_base, PAGE, 0, 0, 0, 0);
  int routed = trap_count(site) > traps || hook_count(site) > hooks;
  int retained = owner_usable(before, before->free_base, "---p");
  int passed = result == -EPERM && routed && retained;
  printf("MAPPING_BOUNDARY mode=mseal raw=%ld support=%ld facility=%s "
         "routed=%d retained=%d passed=%d\n", result, support,
         support == 0 ? "supported" : "unavailable-live-mutation-unmeasured",
         routed, retained, passed);
  return passed ? 0 : 1;
}

static int fork_case(const struct snapshot *before) {
  char permissions[5] = {0};
  if (owner_maps(owner_before, sizeof owner_before, before->free_base, permissions) ||
      strcmp(permissions, "---p"))
    return 96;
  long child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
  if (child < 0)
    return 100;
  if (child == 0) {
    struct snapshot inherited = {0};
    int observed = observe_action(&inherited, sizeof inherited);
    long pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int inherited_identity = !observed && identity(before, &inherited) &&
        inherited.current_pid == (uint64_t)pid &&
        inherited.current_tid == (uint64_t)pid &&
        inherited.current_pid != before->current_pid;
    uint64_t site = (uintptr_t)m6_guest_syscall_site;
    uint64_t traps = trap_count(site), hooks = hook_count(site);
    long result = call(SYS_mprotect, before->free_base, PAGE,
                       PROT_READ | PROT_WRITE, 0, 0, 0);
    int routed = trap_count(site) > traps || hook_count(site) > hooks;
    int retained = owner_usable(before, before->free_base, "---p");
    int passed = inherited_identity && result == -EPERM && routed && retained;
    printf("MAPPING_FORK_CHILD inherited=%d raw=%ld routed=%d retained=%d passed=%d\n",
           inherited_identity, result, routed, retained, passed);
    (void)call(SYS_exit_group, passed ? 0 : 1, 0, 0, 0, 0, 0);
    __builtin_trap();
  }
  int status = -1;
  long waited;
  do {
    waited = call(SYS_wait4, (uint64_t)child, (uintptr_t)&status, 0, 0, 0, 0);
  } while (waited == -EINTR);
  int retained = owner_usable(before, before->free_base, "---p");
  int passed = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 && retained;
  printf("MAPPING_BOUNDARY mode=fork waited=%ld child=%ld status=%d retained=%d passed=%d\n",
         waited, child, status, retained, passed);
  return passed ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc != 3)
    return 90;
  setvbuf(stdout, NULL, _IONBF, 0);
  struct snapshot before = {0};
  int setup = prepare_owned(argv[1], &before);
  if (setup) {
    fprintf(stderr, "mapping boundary setup=%d\n", setup);
    return setup;
  }
  int result;
  if (!strcmp(argv[2], "guard") || !strcmp(argv[2], "live"))
    result = protection_case(argv[2], &before);
  else if (!strcmp(argv[2], "brk"))
    result = break_case(&before);
  else if (!strcmp(argv[2], "mseal"))
    result = seal_case(&before);
  else if (!strcmp(argv[2], "fork"))
    result = fork_case(&before);
  else
    return 90;
  return result ? result : (finish_action() ? 101 : 0);
}
