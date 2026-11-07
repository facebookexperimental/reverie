/* A shared library whose constructor runs CPUID and RDTSC while dlopen maps
 * it, after the LiteInst runtime recorded its trampoline arenas. This is the
 * shape of libcrypto's OPENSSL_cpuid_setup, which runs from its initializer
 * during dlopen and first exposed an in-guest runtime crash: no arena covers
 * the library, so the instruction can never be patched. */
#include <cpuid.h>
#include <stdint.h>
#include <x86intrin.h>

static unsigned int constructor_words[4];
static uint64_t constructor_tsc;

__attribute__((constructor)) static void late_code_constructor(void) {
  __cpuid_count(0, 0, constructor_words[0], constructor_words[1],
                constructor_words[2], constructor_words[3]);
  constructor_tsc = __rdtsc();
}

void late_code_constructor_cpuid(unsigned int out[4]) {
  for (int index = 0; index < 4; index++) {
    out[index] = constructor_words[index];
  }
}

uint64_t late_code_constructor_tsc(void) { return constructor_tsc; }
