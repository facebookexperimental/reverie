#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef long (*guest_fn)(void);
typedef uint64_t (*count_fn)(uint64_t);

static const unsigned char guest_code[] = {
    0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
};

static void write_guest(void *mapping) {
  memcpy(mapping, guest_code, sizeof(guest_code));
  __builtin___clear_cache(mapping, (char *)mapping + sizeof(guest_code));
}

static count_fn load_count(const char *name) {
  count_fn function = (count_fn)dlsym(RTLD_DEFAULT, name);
  if (function == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return function;
}

int main(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  void *requested = (void *)(uintptr_t)UINT64_C(0x20000000);
  void *mapping = mmap(requested, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (mapping == MAP_FAILED) {
    return 10;
  }
  write_guest(mapping);
  guest_fn function = (guest_fn)mapping;
  long expected = function();
  if (function() != expected) {
    return 11;
  }

  uint64_t old_site = (uint64_t)(uintptr_t)((unsigned char *)mapping + 5);
  if (munmap(mapping, page) != 0) {
    return 15;
  }
  mapping = mmap(mapping, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapping == MAP_FAILED) {
    return 16;
  }
  write_guest(mapping);
  function = (guest_fn)mapping;
  if (function() != expected || function() != expected) {
    return 17;
  }

  uint64_t traps = load_count("reverie_liteinst_site_trap_count")(old_site);
  uint64_t hooks = load_count("reverie_liteinst_site_hook_count")(old_site);
  printf("reuse traps=%" PRIu64 " hooks=%" PRIu64 "\n", traps, hooks);
  return 0;
}
