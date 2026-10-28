#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct snapshot {
  uint64_t gpr[16], flags, expected_sp, xmm[16][2];
};
extern void clean_call_probe_inline(uint64_t, uint64_t, struct snapshot*);
extern void clean_call_probe_rcx(uint64_t, uint64_t, struct snapshot*);
extern void clean_call_probe_flags(uint64_t, uint64_t, struct snapshot*);
extern void clean_call_probe_combined(uint64_t, uint64_t, struct snapshot*);
const uint64_t vector_pattern[16][2] = {
    {0x1020304050607080, 0x9080706050403020},
    {0x1122334455667788, 0x8877665544332211},
    {0x2233445566778899, 0x9988776655443322},
    {0x33445566778899aa, 0xaa99887766554433},
    {0x445566778899aabb, 0xbbaa998877665544},
    {0x5566778899aabbcc, 0xccbbaa9988776655},
    {0x66778899aabbccdd, 0xddccbbaa99887766},
    {0x778899aabbccddee, 0xeeddccbbaa998877},
    {0x8899aabbccddeeff, 0xffeeddccbbaa9988},
    {0x99aabbccddeeff00, 0x00ffeeddccbbaa99},
    {0xaabbccddeeff0011, 0x1100ffeeddccbbaa},
    {0xbbccddeeff001122, 0x221100ffeeddccbb},
    {0xccddeeff00112233, 0x33221100ffeeddcc},
    {0xddeeff0011223344, 0x4433221100ffeedd},
    {0xeeff001122334455, 0x554433221100ffee},
    {0xff00112233445566, 0x66554433221100ff}};
__attribute__((noinline)) void clean_call_prepare(
    unsigned mode,
    unsigned variant) {
  __asm__ volatile("" : : "r"(mode), "r"(variant) : "memory");
}
__attribute__((noinline)) void clean_call_finish(void) {
  __asm__ volatile("" ::: "memory");
}
static void (*const probes[])(uint64_t, uint64_t, struct snapshot*) = {
    clean_call_probe_inline,
    clean_call_probe_rcx,
    clean_call_probe_flags,
    clean_call_probe_combined};
static pthread_barrier_t barrier;
static void
check(unsigned id, unsigned repetition, unsigned variant, unsigned mode) {
  struct snapshot actual;
  memset(&actual, 0, sizeof(actual));
  uint64_t rcx =
      UINT64_C(0xfedcba9876543210) ^ ((uint64_t)id << 32) ^ repetition;
  uint64_t flags = repetition % 2 ? 0xad7 : 0x246;
  clean_call_prepare(mode, variant);
  probes[variant](rcx, flags, &actual);
  uint64_t expected[] = {
      0xa0a0a0a0a0a0a0a0,
      rcx,
      0xd2d2d2d2d2d2d2d2,
      0xb3b3b3b3b3b3b3b3,
      actual.expected_sp,
      0xb5b5b5b5b5b5b5b5,
      0x5151515151515151,
      0xd1d1d1d1d1d1d1d1,
      0x0808080808080808,
      0x0909090909090909,
      (uint64_t)&actual,
      0x1111111111111111,
      0x1212121212121212,
      0x1313131313131313,
      0x1414141414141414,
      0x1515151515151515};
  if (mode == 2) {
    expected[1] ^= UINT64_C(0xdeadbeef13579bdf);
    flags ^= 1;
    if (variant == 3)
      expected[2] ^= UINT64_C(0x123456789abcdef0);
  }
  for (unsigned i = 0; i < 16; ++i) {
    if (actual.gpr[i] != expected[i]) {
      fprintf(
          stderr,
          "gpr mismatch thread=%u repeat=%u variant=%u mode=%u reg=%u actual=%016lx expected=%016lx\n",
          id,
          repetition,
          variant,
          mode,
          i,
          actual.gpr[i],
          expected[i]);
      exit(51);
    }
  }
  if ((actual.flags & 0xcd5) != (flags & 0xcd5)) {
    fprintf(
        stderr,
        "flags mismatch thread=%u repeat=%u variant=%u mode=%u actual=%lx expected=%lx\n",
        id,
        repetition,
        variant,
        mode,
        actual.flags,
        flags);
    exit(52);
  }
  if (memcmp(actual.xmm, vector_pattern, sizeof(actual.xmm)) != 0) {
    fprintf(
        stderr,
        "SIMD mismatch thread=%u repeat=%u variant=%u mode=%u\n",
        id,
        repetition,
        variant,
        mode);
    exit(53);
  }
  clean_call_finish();
}
static void* worker(void* opaque) {
  unsigned id = (uintptr_t)opaque;
  int status = pthread_barrier_wait(&barrier);
  if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD)
    abort();
  for (unsigned r = 0; r < 100; ++r)
    for (unsigned variant = 0; variant < 4; ++variant)
      for (unsigned mode = 0; mode < 3; ++mode)
        check(id, r, variant, mode);
  return NULL;
}
int main(void) {
  /* Compile and execute every branch in the original thread before any
   * additional thread uses those same application basic blocks. */
  for (unsigned variant = 0; variant < 4; ++variant)
    for (unsigned mode = 0; mode < 3; ++mode)
      check(0, 0, variant, mode);
  pthread_t threads[8];
  if (pthread_barrier_init(&barrier, NULL, 8))
    return 54;
  for (uintptr_t i = 0; i < 8; ++i)
    if (pthread_create(&threads[i], NULL, worker, (void*)(i + 1)))
      return 55;
  for (unsigned i = 0; i < 8; ++i)
    if (pthread_join(threads[i], NULL))
      return 56;
  if (pthread_barrier_destroy(&barrier))
    return 57;
  puts(
      "application completed cases=9612 general_registers=16 xmm_registers=16 flags_mask=0xcd5 threads=9");
  return 0;
}
