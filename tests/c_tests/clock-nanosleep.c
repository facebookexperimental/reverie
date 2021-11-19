/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

int main(int argc, char* argv[]) {
  struct timespec req = {
      .tv_sec = 0,
      .tv_nsec = 100000000,
  };
  struct timespec rem;
  int ret;

  do {
    ret = clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);
    memcpy(&req, &rem, sizeof(req));
  } while (ret != 0 && errno == EINTR);

  return 0;
}
