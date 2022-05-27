/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  write(STDOUT_FILENO, "0", 1);
  write(STDOUT_FILENO, "1", 1);
  write(STDOUT_FILENO, "2", 1);
  write(STDOUT_FILENO, "3", 1);
  write(STDOUT_FILENO, "4", 1);
  write(STDOUT_FILENO, "5", 1);
  write(STDOUT_FILENO, "6", 1);
  write(STDOUT_FILENO, "7", 1);
  write(STDOUT_FILENO, "8", 1);
  write(STDOUT_FILENO, "9", 1);
  write(STDOUT_FILENO, "\n", 1);
}
