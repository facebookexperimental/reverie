/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

// RUN: %{cc} %s -o %t1
// RUN: touch %t3
// RUN: %{sbr} %{sbr-id} -- %t1 %t3 2>&1

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>

int main(int argc, char **argv) {

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0)
    return 1;

  if (fchown(fd, getuid(), getgid()) < 0)
    return 2;

  close(fd);

  return 0;
}
