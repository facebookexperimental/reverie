/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

// RUN: %{cc} %s -o %t1
// RUN: touch %t3
// RUN: ln -sf %t3 %t3.link
// RUN: %t1 %t3 %t3.link || RC_ORIG=$(echo $?)
// RUN: %{sbr} %{sbr-id} -- %t1 %t3 %t3.link 2>&1 || RC_SABRE=$(echo $?)
// RUN: test ${RC_ORIG} -eq ${RC_SABRE}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

// TODO(andronat): By default ext4 doesn't mount with user_xattr and thus
// most of the bellow code fails due to ENOTSUP. We just invoke the
// below syscalls to test if Varan can intercept them, and not that
// they properly work. Ideally a new mount should be created with
// user_xattr enabled and this code should be tested inside it.

int main(int argc, char **argv) {
  const char test_key[] = "user.test-key";
  const char test_val[] = "test val";
  char buf[1024];
  size_t s;

  setxattr(argv[1], test_key, test_val, sizeof(test_val), XATTR_CREATE);
  // if (setxattr(argv[1], test_key, test_val, sizeof(test_val), XATTR_CREATE) < 0)
  //   return 1;

  if ((s = getxattr(argv[1], test_key, buf, sizeof(test_val))) < 0)
    return 2;
  // if (s != sizeof(test_val) || strcmp(buf, test_val))
  //   return 3;

  if ((s = listxattr(argv[1], buf, sizeof buf)) == -1)
    return 4;
  // if (s != sizeof(test_key) || strcmp(buf, test_key))
  //   return 5;

  removexattr(argv[1], test_key);
  // if (removexattr(argv[1], test_key) == -1)
  //   return 6;

  /* link variants */

  // this should fail as user extended attributes are not allowed on non-regular files
  if (lsetxattr(argv[2], test_key, test_val, sizeof(test_val), XATTR_CREATE) !=
      -1)
    return 7;

  // hence the attribute list should be empty
  if (lgetxattr(argv[2], test_key, buf, sizeof(test_val)) != -1)
    return 8;

  if (llistxattr(argv[2], buf, sizeof buf) != 0)
    return 10;

  if (lremovexattr(argv[2], test_key) != -1)
    return 12;

  /* file descriptor variants */

  int fd = open(argv[1], O_RDWR);

  fsetxattr(fd, test_key, test_val, sizeof(test_val), XATTR_CREATE);
  // if (fsetxattr(fd, test_key, test_val, sizeof(test_val), XATTR_CREATE) < 0)
  //   return 13;

  if ((s = fgetxattr(fd, test_key, buf, sizeof(test_val))) < 0)
    return 14;
  // if (s != sizeof(test_val) || strcmp(buf, test_val))
  //   return 15;

  if ((s = flistxattr(fd, buf, sizeof buf)) == -1)
    return 16;
  // if (s != sizeof(test_key) || strcmp(buf, test_key))
  //   return 17;

  fremovexattr(fd, test_key);
  // if (fremovexattr(fd, test_key) == -1)
  //   return 18;

  close(fd);
  return 0;
}
