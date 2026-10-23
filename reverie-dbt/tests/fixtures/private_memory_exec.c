/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "exec") == 0) {
    execl(argv[0], argv[0], "after", (char *)NULL);
    return 21;
  }
  puts("private memory guest completed");
  return 0;
}
