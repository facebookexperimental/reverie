#include <stdint.h>

#ifndef FOOTPRINT_ITEMS
#error FOOTPRINT_ITEMS must name the functional working-set size
#endif

/* Every word is used below. These are input values and a transformation workspace,
 * not linker padding or an attempt to equalize two production image sizes. */
static const volatile uint64_t values[FOOTPRINT_ITEMS] = {
    [0 ... FOOTPRINT_ITEMS - 1] = UINT64_C(0x9e3779b97f4a7c15),
};
static volatile uint64_t workspace[FOOTPRINT_ITEMS];
extern const unsigned char __ehdr_start[];

static uint64_t transform(uint64_t seed) {
  for (uint64_t index = 0; index < FOOTPRINT_ITEMS; ++index)
    workspace[index] = values[index] + seed + index;
  uint64_t checksum = 0;
  for (uint64_t index = 0; index < FOOTPRINT_ITEMS; ++index)
    checksum += workspace[index];
  return checksum;
}

#ifdef FOOTPRINT_CLIENT
#include "dr_api.h"

extern uint64_t footprint_runtime_transform(uint64_t seed);
extern uint64_t footprint_runtime_items(void);
extern uintptr_t footprint_runtime_base(void);

static char* append_text(char* output, const char* text) {
  while (*text != 0)
    *output++ = *text++;
  return output;
}

static char* append_hex(char* output, uint64_t value) {
  static const char digits[] = "0123456789abcdef";
  output = append_text(output, "0x");
  for (int shift = 60; shift >= 0; shift -= 4)
    *output++ = digits[(value >> shift) & 15];
  return output;
}

static char* append_field(char* output, const char* name, uint64_t value) {
  output = append_text(output, name);
  output = append_hex(output, value);
  *output++ = ' ';
  return output;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  (void)id;
  (void)argc;
  (void)argv;
  uint64_t client_sum = transform(17);
  uint64_t runtime_sum = footprint_runtime_transform(31);
  char output[256];
  char* end = append_text(output, "FOOTPRINT ");
  end = append_field(end, "client_items=", FOOTPRINT_ITEMS);
  end = append_field(end, "runtime_items=", footprint_runtime_items());
  end = append_field(end, "client_sum=", client_sum);
  end = append_field(end, "runtime_sum=", runtime_sum);
  end = append_field(end, "client_base=", (uintptr_t)__ehdr_start);
  end = append_field(end, "runtime_base=", footprint_runtime_base());
  end[-1] = '\n';
  long result;
  __asm__ volatile("syscall"
                   : "=a"(result)
                   : "0"(1L), "D"(2L), "S"(output), "d"((long)(end - output))
                   : "rcx", "r11", "memory");
  if (result != end - output) {
    __asm__ volatile("syscall" : : "a"(231L), "D"(91L) : "rcx", "r11", "memory");
    __builtin_trap();
  }
}
#else
uint64_t footprint_runtime_transform(uint64_t seed) {
  return transform(seed);
}

uint64_t footprint_runtime_items(void) {
  return FOOTPRINT_ITEMS;
}

uintptr_t footprint_runtime_base(void) {
  return (uintptr_t)__ehdr_start;
}
#endif
