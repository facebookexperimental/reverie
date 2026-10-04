/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdio.h>
#include <sys/auxv.h>

int main(void) {
  const unsigned char* entry = (const unsigned char*)getauxval(AT_ENTRY);
  int still_guarded = entry == NULL || *entry == 0xcc;
  printf("entry-int3=%d\n", still_guarded);
  return still_guarded ? 20 : 0;
}
