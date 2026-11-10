/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* A guest that replaces itself with /bin/true. */

#include <unistd.h>

int main(void) {
  execl("/bin/true", "true", (char*)0);
  return 1;
}
