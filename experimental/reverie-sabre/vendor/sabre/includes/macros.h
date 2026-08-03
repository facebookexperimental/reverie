/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MACROS_H
#define MACROS_H

#include <stdio.h>
#include <stdlib.h>

#define _nx_fatal_printf(fmt, args...)                                         \
  do {                                                                         \
    dprintf(2, "Fatal error in %s:%u\n", __FILE__, __LINE__);                  \
    dprintf(2, fmt, ##args);                                                   \
    exit(127);                                                                 \
  } while (0)

#if SBR_DEBUG
#define _nx_debug_printf(fmt, args...)                                         \
  do {                                                                         \
    dprintf(2, "Debug in %s at %s:%u\n\t", __func__, __FILE__, __LINE__);      \
    dprintf(2, fmt, ##args);                                                   \
  } while (0)
#else
#define _nx_debug_printf(fmt, args...)                                         \
  do {                                                                         \
    ;                                                                          \
  } while (0)
#endif

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

// This works for syscalls made through libc which sets errno when fail.  This
// does not work for syscalls made directly to the kernel, which signals errors
// by returning a negative value
#define NOINTR(x)                                                              \
  ({                                                                           \
    typeof(x) __i;                                                             \
    while ((__i = (x)) < 0 && errno == EINTR)                                  \
      ;                                                                        \
    __i;                                                                       \
  })

#endif /* !MACROS_H */
