/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
extern ssize_t late_probe(unsigned char*, size_t, unsigned);
extern bool late_guest_ran;
int main(void) {
  late_guest_ran = true;
  unsigned char b[4] = {0, 1, 2, 3};
  errno = 0;
  assert(late_probe(b, 4, 0x1357) == 137);
  assert(b[0] == 0xea && b[1] == 1 && b[2] == 2 && b[3] == 3);
  assert(errno == EDOM);
  assert(write(1, "CLIENT_OK\n", 10) == 10);
  return 0;
}

/* These belong to the guest and its ordinary dependency, not the plugin. */
extern bool calling_from_plugin(void) __attribute__((weak));
__attribute__((destructor)) static void guest_finalizer(void) {
  if (!late_guest_ran)
    return;
  assert(calling_from_plugin != NULL);
  assert(!calling_from_plugin());
}
