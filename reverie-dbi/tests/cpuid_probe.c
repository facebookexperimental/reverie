/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} cpuid_result_t;

#define BIT32(bit) (UINT32_C(1) << (bit))
#define LEAF7_EBX_TSX (BIT32(4) | BIT32(11))
#define LEAF7_EBX_AVX512                                                       \
  (BIT32(16) | BIT32(17) | BIT32(21) | BIT32(26) | BIT32(27) | BIT32(28) |     \
   BIT32(30) | BIT32(31))
#define LEAF7_ECX_AVX512                                                       \
  (BIT32(1) | BIT32(6) | BIT32(11) | BIT32(12) | BIT32(14))
#define LEAF7_EDX_AVX512 (BIT32(2) | BIT32(3) | BIT32(8) | BIT32(23))

static cpuid_result_t cpuid(uint32_t leaf, uint32_t subleaf) {
  cpuid_result_t result;
  __cpuid_count(leaf, subleaf, result.eax, result.ebx, result.ecx, result.edx);
  return result;
}

static void check(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "cpuid probe failed: %s\n", message);
    exit(1);
  }
}

static int equal(cpuid_result_t left, cpuid_result_t right) {
  return left.eax == right.eax && left.ebx == right.ebx &&
         left.ecx == right.ecx && left.edx == right.edx;
}

int main(void) {
  const uint32_t leaf7_ebx_mask = LEAF7_EBX_TSX | BIT32(18) | LEAF7_EBX_AVX512;
  cpuid_result_t leaf0 = cpuid(0, 0);
  cpuid_result_t leaf1 = cpuid(1, 0);
  cpuid_result_t leaf7 = cpuid(7, 0);
  cpuid_result_t leaf7_subleaf1 = cpuid(7, 1);
  cpuid_result_t unsupported = cpuid(UINT32_C(0x40000000), 0);
  char vendor[13] = {0};
  int iteration;

  memcpy(vendor, &leaf0.ebx, sizeof(leaf0.ebx));
  memcpy(vendor + 4, &leaf0.edx, sizeof(leaf0.edx));
  memcpy(vendor + 8, &leaf0.ecx, sizeof(leaf0.ecx));

  check(leaf0.eax == UINT32_C(0x0000000D), "unexpected maximum leaf");
  check(strcmp(vendor, "GenuineIntel") == 0, "unexpected vendor");
  check(equal(leaf1,
              (cpuid_result_t){0x00000663, 0x00000800, 0x90B82201, 0x078BFBFD}),
        "unexpected deterministic leaf 1");
  check(equal(leaf7,
              (cpuid_result_t){0x00000000, 0x001807A9, 0x00000000, 0x00000000}),
        "unexpected deterministic leaf 7");
  check((leaf1.ecx & BIT32(30)) == 0, "RDRAND remains advertised");
  check((leaf7.ebx & leaf7_ebx_mask) == 0,
        "TSX, RDSEED, or AVX-512 remains advertised in leaf 7 EBX");
  check((leaf7.ecx & LEAF7_ECX_AVX512) == 0,
        "AVX-512 remains advertised in leaf 7 ECX");
  check((leaf7.edx & LEAF7_EDX_AVX512) == 0,
        "AVX-512 remains advertised in leaf 7 EDX");
  check(equal(leaf7_subleaf1, (cpuid_result_t){0}),
        "unsupported leaf 7 subleaf is nonzero");
  check(equal(unsupported, (cpuid_result_t){0}),
        "unsupported CPUID leaf is nonzero");

  for (iteration = 0; iteration != 32; ++iteration) {
    check(equal(leaf0, cpuid(0, 0)), "vendor result changed");
    check(equal(leaf1, cpuid(1, 0)), "signature result changed");
    check(equal(leaf7, cpuid(7, 0)), "feature result changed");
  }

  printf("CPUID-SUCCESS vendor=%s signature=%08x\n", vendor, leaf1.eax);
  return 0;
}
