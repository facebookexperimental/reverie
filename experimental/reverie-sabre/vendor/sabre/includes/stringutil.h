/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef STRINGUTIL_H
#define STRINGUTIL_H

#include <stdlib.h>
#include <string.h>

static inline char *copy_string(const char *str) {
  size_t len = strlen(str);
  char *result = malloc(len);
  if (result == NULL) {
    return NULL;
  }
  memcpy(result, str, len);
  result[len] = '\0';
  return result;
}

static inline void hexdump(size_t bytes, const void *in, char *out) {
  const unsigned char *cin = in;
  for (size_t i = 0; i < bytes; ++i) {
    static const char digits[] = "0123456789abcdef";
    out[2 * i] = digits[cin[i] / 16];
    out[2 * i + 1] = digits[cin[i] % 16];
  }
}

#endif
