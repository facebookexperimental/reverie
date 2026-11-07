/* SPDX-License-Identifier: GPL-2.0 */

#ifndef KERNEL_H_
#define KERNEL_H_

#include "compiler.h"

#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((unsigned long)(p), (a)))
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a)-1)) == 0)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#endif

#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define DIV_ROUND_UP_ULL(ll, d)                                                \
  ({                                                                           \
    unsigned long long _tmp = (ll) + (d)-1;                                    \
    do_div(_tmp, d);                                                           \
    _tmp;                                                                      \
  })

#if BITS_PER_LONG == 32
#define DIV_ROUND_UP_SECTOR_T(ll, d) DIV_ROUND_UP_ULL(ll, d)
#else
#define DIV_ROUND_UP_SECTOR_T(ll, d) DIV_ROUND_UP(ll, d)
#endif

#ifndef roundup
#define roundup(x, y)                                                          \
  ({                                                                           \
    const typeof(y) __y = y;                                                   \
    (((x) + (__y - 1)) / __y) * __y;                                           \
  })
#endif

#ifndef rounddown
#define rounddown(x, y)                                                        \
  ({                                                                           \
    typeof(x) __x = (x);                                                       \
    __x - (__x % (y));                                                         \
  })
#endif

#define DIV_ROUND_CLOSEST(x, divisor)                                          \
  ({                                                                           \
    typeof(divisor) __divisor = divisor;                                       \
    (((x) + ((__divisor) / 2)) / (__divisor));                                 \
  })

/**
 * Return bits 32-63 of a number.
 * @param n the number we're accessing
 */
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

/**
 * Return bits 0-31 of a number.
 * @param n the number we're accessing
 */
#define lower_32_bits(n) ((u32)(n))

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#ifndef max
#define max(x, y)                                                              \
  ({                                                                           \
    typeof(x) _max1 = (x);                                                     \
    typeof(y) _max2 = (y);                                                     \
    (void)(&_max1 == &_max2);                                                  \
    _max1 > _max2 ? _max1 : _max2;                                             \
  })
#endif

#ifndef min
#define min(x, y)                                                              \
  ({                                                                           \
    typeof(x) _min1 = (x);                                                     \
    typeof(y) _min2 = (y);                                                     \
    (void)(&_min1 == &_min2);                                                  \
    _min1 < _min2 ? _min1 : _min2;                                             \
  })
#endif

#define min3(x, y, z)                                                          \
  ({                                                                           \
    typeof(x) _min1 = (x);                                                     \
    typeof(y) _min2 = (y);                                                     \
    typeof(z) _min3 = (z);                                                     \
    (void)(&_min1 == &_min2);                                                  \
    (void)(&_min1 == &_min3);                                                  \
    _min1 < _min2 ? (_min1 < _min3 ? _min1 : _min3)                            \
                  : (_min2 < _min3 ? _min2 : _min3);                           \
  })

#define max3(x, y, z)                                                          \
  ({                                                                           \
    typeof(x) _max1 = (x);                                                     \
    typeof(y) _max2 = (y);                                                     \
    typeof(z) _max3 = (z);                                                     \
    (void)(&_max1 == &_max2);                                                  \
    (void)(&_max1 == &_max3);                                                  \
    _max1 > _max2 ? (_max1 > _max3 ? _max1 : _max3)                            \
                  : (_max2 > _max3 ? _max2 : _max3);                           \
  })

/**
 * Return the minimum that is _not_ zero, unless both are zero.
 *
 * @param x first value
 * @param y second value
 */
#define min_not_zero(x, y)                                                     \
  ({                                                                           \
    typeof(x) __x = (x);                                                       \
    typeof(y) __y = (y);                                                       \
    __x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y));                       \
  })

/**
 * Return a value clamped to a given range with strict typechecking.
 *
 * @param val current value
 * @param min minimum allowable value
 * @param max maximum allowable value
 */
#define clamp(val, min, max)                                                   \
  ({                                                                           \
    typeof(val) __val = (val);                                                 \
    typeof(min) __min = (min);                                                 \
    typeof(max) __max = (max);                                                 \
    (void)(&__val == &__min);                                                  \
    (void)(&__val == &__max);                                                  \
    __val = __val < __min ? __min : __val;                                     \
    __val > __max ? __max : __val;                                             \
  })

#define min_t(type, x, y)                                                      \
  ({                                                                           \
    type __min1 = (x);                                                         \
    type __min2 = (y);                                                         \
    __min1 < __min2 ? __min1 : __min2;                                         \
  })

#define max_t(type, x, y)                                                      \
  ({                                                                           \
    type __max1 = (x);                                                         \
    type __max2 = (y);                                                         \
    __max1 > __max2 ? __max1 : __max2;                                         \
  })

/**
 * Return a value clamped to a given range using a given type.
 *
 * @param type type of variable to use
 * @param val current value
 * @param min minimum allowable value
 * @param max maximum allowable value
 */
#define clamp_t(type, val, min, max)                                           \
  ({                                                                           \
    type __val = (val);                                                        \
    type __min = (min);                                                        \
    type __max = (max);                                                        \
    __val = __val < __min ? __min : __val;                                     \
    __val > __max ? __max : __val;                                             \
  })

/**
 * Return a value clamped to a given range using @val's type.
 *
 * @param val current value
 * @param min minimum allowable value
 * @param max maximum allowable value
 */
#define clamp_val(val, min, max)                                               \
  ({                                                                           \
    typeof(val) __val = (val);                                                 \
    typeof(val) __min = (min);                                                 \
    typeof(val) __max = (max);                                                 \
    __val = __val < __min ? __min : __val;                                     \
    __val > __max ? __max : __val;                                             \
  })

/**
 * Swap value of @p a and @p b.
 */
#define swap(a, b)                                                             \
  do {                                                                         \
    typeof(a) __tmp = (a);                                                     \
    (a) = (b);                                                                 \
    (b) = __tmp;                                                               \
  } while (0)

#ifndef container_of
/**
 * Cast a member of a structure out to the containing structure.
 *
 * @param ptr pointer to the member
 * @param type type of the container struct this is embedded in
 * @param member name of the member within the struct
 */
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
#endif

#endif /* KERNEL_H_ */
