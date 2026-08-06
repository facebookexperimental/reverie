/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Guest fixture for the DBT `chaos` example-tool E2E test.
 *
 * Opens the file named by argv[1] and reads it into a buffer, correctly
 * handling short reads (POSIX permits read(2) to return fewer bytes than
 * requested) and retrying on EINTR. It then writes the assembled contents to
 * stdout. Under the chaos tool every read is truncated to one byte (and,
 * optionally, interrupted with EINTR first), so a correct program must still
 * reconstruct the full file. Any divergence in the emitted bytes means the
 * intervention corrupted the read rather than merely perturbing it.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0)
    return 3;

  char buf[256];
  size_t total = 0;
  for (;;) {
    if (total >= sizeof(buf))
      break;
    ssize_t n = read(fd, buf + total, sizeof(buf) - total);
    if (n < 0) {
      if (errno == EINTR)
        continue; /* tolerate an injected interruption and retry */
      return 4;
    }
    if (n == 0)
      break; /* EOF */
    total += (size_t)n;
  }
  close(fd);

  size_t written = 0;
  while (written < total) {
    ssize_t n = write(1, buf + written, total - written);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return 5;
    }
    written += (size_t)n;
  }
  return 0;
}
