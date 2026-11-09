/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * A guest that blocks in the kernel and never stops on its own: it waits in
 * pause() for a signal that never comes.
 */

#include <unistd.h>

int main(void) {
  pause();
  return 0;
}
