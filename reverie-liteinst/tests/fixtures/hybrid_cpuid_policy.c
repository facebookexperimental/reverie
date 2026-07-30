#define _GNU_SOURCE
#include <asm/prctl.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

__asm__(".text\n"
        ".p2align 4\n"
        ".global reverie_liteinst_cpuid_getpid\n"
        ".type reverie_liteinst_cpuid_getpid,@function\n"
        "reverie_liteinst_cpuid_getpid:\n"
        "mov $39, %eax\n"
        ".global reverie_liteinst_cpuid_getpid_site\n"
        "reverie_liteinst_cpuid_getpid_site:\n"
        "syscall\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "ret\n"
        ".size reverie_liteinst_cpuid_getpid, "
        ".-reverie_liteinst_cpuid_getpid\n");

extern long reverie_liteinst_cpuid_getpid(void);
extern unsigned char reverie_liteinst_cpuid_getpid_site;

typedef long (*guest_fn)(void);
typedef uint64_t (*count_fn)(uint64_t);

static long cpuid_state(void) {
  return syscall(SYS_arch_prctl, ARCH_GET_CPUID, 0);
}

static int set_cpuid(long state) {
  return (int)syscall(SYS_arch_prctl, ARCH_SET_CPUID, state);
}

static count_fn load_count(const char *name) {
  count_fn function = (count_fn)dlsym(RTLD_DEFAULT, name);
  if (function == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return function;
}

static guest_fn fallback_guest(size_t page, void **mapping_out,
                               uint64_t *site_out) {
  unsigned char *mapping = mmap(NULL, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    return NULL;
  }
  unsigned char *site = mapping + page - 7;
  const unsigned char code[] = {0xb8, 0x27, 0x00, 0x00, 0x00,
                                0x0f, 0x05, 0xc3};
  unsigned char *entry = site - 5;
  memcpy(entry, code, sizeof(code));
  __builtin___clear_cache((char *)entry, (char *)entry + sizeof(code));
  *mapping_out = mapping;
  *site_out = (uint64_t)(uintptr_t)site;
  return (guest_fn)entry;
}

int main(int argc, char **argv) {
  int fallback = argc == 2 && strcmp(argv[1], "fallback") == 0;
  count_fn trap_count = load_count("reverie_liteinst_site_trap_count");
  count_fn hook_count = load_count("reverie_liteinst_site_hook_count");
  void *mapping = NULL;
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  uint64_t site =
      (uint64_t)(uintptr_t)&reverie_liteinst_cpuid_getpid_site;
  guest_fn function = reverie_liteinst_cpuid_getpid;
  unsigned calls = 32;
  if (fallback) {
    function = fallback_guest(page, &mapping, &site);
    calls = 2;
    if (function == NULL) {
      return 21;
    }
  }

  errno = 0;
  long initial = cpuid_state();
  if (initial == -1 && errno == ENODEV) {
    return 77;
  }
  if (initial != 1) {
    return 22;
  }
  errno = 0;
  if (set_cpuid(0) != 0) {
    if (errno == ENODEV) {
      return 77;
    }
    return 22;
  }
  if (cpuid_state() != 0) {
    return 22;
  }

  long expected = -1;
  for (unsigned i = 0; i < calls; ++i) {
    long observed = function();
    if (expected == -1) {
      expected = observed;
    } else if (observed != expected) {
      return 23;
    }
  }
  long restored = cpuid_state();
  if (restored != 0) {
    return 24;
  }
  if (set_cpuid(1) != 0) {
    return 25;
  }

  uint64_t traps = trap_count(site);
  uint64_t hooks = hook_count(site);
  printf("mode=%s calls=%u traps=%" PRIu64 " hooks=%" PRIu64
         " cpuid=%ld\n",
         fallback ? "fallback" : "active", calls, traps, hooks, restored);
  if (mapping != NULL && munmap(mapping, page) != 0) {
    return 26;
  }
  return 0;
}
