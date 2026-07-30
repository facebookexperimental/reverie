#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>

static volatile uint64_t cpu_witness;

static int activation_probe_impl(void) { return cpu_witness != 0; }

static void *resolve_activation_probe(void) {
  uint32_t eax = 0;
  uint32_t ebx;
  uint32_t ecx = 0;
  uint32_t edx;
  uint32_t tsc_low;
  uint32_t tsc_high;

  __asm__ volatile("cpuid"
                   : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx)
                   :
                   : "memory");
  __asm__ volatile("rdtsc" : "=a"(tsc_low), "=d"(tsc_high) : : "memory");
  cpu_witness = ((uint64_t)eax << 32) ^ ebx ^ ecx ^ edx ^ tsc_low ^
                ((uint64_t)tsc_high << 32);
  if (cpu_witness == 0) {
    cpu_witness = 1;
  }
  return activation_probe_impl;
}

static int activation_probe(void)
    __attribute__((ifunc("resolve_activation_probe")));

int main(void) {
  const unsigned char *entry = (const unsigned char *)getauxval(AT_ENTRY);
  int still_guarded = entry == NULL || *entry == 0xcc;
  printf("entry-int3=%d probe=%d\n", still_guarded, activation_probe());
  return still_guarded || !activation_probe() ? 20 : 0;
}
