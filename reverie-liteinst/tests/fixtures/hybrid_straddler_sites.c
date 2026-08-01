#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__asm__(".text\n"
        ".macro STRADDLER offset, padding\n"
        ".p2align 6\n"
        ".global reverie_liteinst_straddler_\\offset\n"
        ".type reverie_liteinst_straddler_\\offset,@function\n"
        "reverie_liteinst_straddler_\\offset:\n"
        "mov $39, %eax\n"
        ".fill \\padding, 1, 0x90\n"
        ".global reverie_liteinst_straddler_site_\\offset\n"
        "reverie_liteinst_straddler_site_\\offset:\n"
        "syscall\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "ret\n"
        ".size reverie_liteinst_straddler_\\offset, "
        ".-reverie_liteinst_straddler_\\offset\n"
        ".endm\n"
        "STRADDLER 57, 52\n"
        "STRADDLER 58, 53\n"
        "STRADDLER 59, 54\n"
        "STRADDLER 60, 55\n"
        "STRADDLER 61, 56\n"
        "STRADDLER 62, 57\n"
        "STRADDLER 63, 58\n");

typedef long (*site_fn)(void);
typedef uint64_t (*count_fn)(uint64_t);

#define DECLARE_STRADDLER(offset)                                              \
  extern long reverie_liteinst_straddler_##offset(void);                      \
  extern unsigned char reverie_liteinst_straddler_site_##offset

DECLARE_STRADDLER(57);
DECLARE_STRADDLER(58);
DECLARE_STRADDLER(59);
DECLARE_STRADDLER(60);
DECLARE_STRADDLER(61);
DECLARE_STRADDLER(62);
DECLARE_STRADDLER(63);

static count_fn load_count(const char *name) {
  count_fn function = (count_fn)dlsym(RTLD_DEFAULT, name);
  if (function == NULL) {
    fprintf(stderr, "missing %s: %s\n", name, dlerror());
    exit(20);
  }
  return function;
}

int main(void) {
  site_fn functions[] = {
      reverie_liteinst_straddler_57, reverie_liteinst_straddler_58,
      reverie_liteinst_straddler_59, reverie_liteinst_straddler_60,
      reverie_liteinst_straddler_61, reverie_liteinst_straddler_62,
      reverie_liteinst_straddler_63,
  };
  unsigned char *sites[] = {
      &reverie_liteinst_straddler_site_57,
      &reverie_liteinst_straddler_site_58,
      &reverie_liteinst_straddler_site_59,
      &reverie_liteinst_straddler_site_60,
      &reverie_liteinst_straddler_site_61,
      &reverie_liteinst_straddler_site_62,
      &reverie_liteinst_straddler_site_63,
  };

  for (unsigned i = 0; i < 7; ++i) {
    if (((uintptr_t)sites[i] & 63) != 57 + i) {
      fprintf(stderr, "site %u has cache-line offset %" PRIuPTR "\n", 57 + i,
              (uintptr_t)sites[i] & 63);
      return 21;
    }
  }

  long expected = -1;
  for (unsigned round = 0; round < 2; ++round) {
    for (unsigned i = 0; i < 7; ++i) {
      long observed = functions[i]();
      if (expected == -1) {
        expected = observed;
      } else if (observed != expected) {
        return 22;
      }
    }
  }

  count_fn trap_count = load_count("reverie_liteinst_site_trap_count");
  count_fn hook_count = load_count("reverie_liteinst_site_hook_count");
  uint64_t traps = 0;
  uint64_t hooks = 0;
  for (unsigned i = 0; i < 7; ++i) {
    traps += trap_count((uint64_t)(uintptr_t)sites[i]);
    hooks += hook_count((uint64_t)(uintptr_t)sites[i]);
  }

  printf("offsets=57..63 calls=14 traps=%" PRIu64 " hooks=%" PRIu64 "\n",
         traps, hooks);
  return 0;
}
