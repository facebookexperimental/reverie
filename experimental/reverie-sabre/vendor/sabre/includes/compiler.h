/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef COMPILER_H_
#define COMPILER_H_

#define __packed __attribute__((packed))

#define __unused __attribute__((unused))

#define attribute_hidden __attribute__((visibility("hidden")))

#define __hidden __attribute__((visibility("hidden")))
#define __internal __attribute__((visibility("internal")))

#define unreferenced_var(x)                                                    \
  do {                                                                         \
    (void)x;                                                                   \
  } while (0)
#define ignore_result(x)                                                       \
  do {                                                                         \
    __typeof__(x) z = x;                                                       \
    (void)sizeof z;                                                            \
  } while (0)

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define unreachable() __builtin_unreachable()

#endif /* COMPILER_H_ */
