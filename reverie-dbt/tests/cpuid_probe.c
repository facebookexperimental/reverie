/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Prints every CPUID row a program can ask for: each basic leaf up to the
 * advertised maximum for subleaves 0 to 2, and each extended leaf up to its
 * maximum for subleaf 0. The native client has no CPUID table of its own; it
 * asks the runtime's tool, and the prototype runtime's answer is the host's, so
 * under DynamoRIO this prints what it prints natively.
 */

#include <cpuid.h>
#include <stdio.h>

static void row(unsigned leaf, unsigned subleaf) {
  unsigned eax, ebx, ecx, edx;
  __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
  printf(
      "%08x.%u: %08x %08x %08x %08x\n", leaf, subleaf, eax, ebx, ecx, edx);
}

int main(void) {
  unsigned max_basic, max_extended, ebx, ecx, edx;
  __cpuid_count(0, 0, max_basic, ebx, ecx, edx);
  for (unsigned leaf = 0; leaf <= max_basic; leaf++) {
    for (unsigned subleaf = 0; subleaf < 3; subleaf++) {
      row(leaf, subleaf);
    }
  }
  __cpuid_count(0x80000000u, 0, max_extended, ebx, ecx, edx);
  for (unsigned leaf = 0x80000000u; leaf <= max_extended; leaf++) {
    row(leaf, 0);
  }
  return 0;
}
