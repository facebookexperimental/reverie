/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <stdio.h>

int main(int argc, char* argv[]) {
  long* invalid_ptr = (long*)0x123;

  *invalid_ptr = 0x12345678l;

  return 0;
}
