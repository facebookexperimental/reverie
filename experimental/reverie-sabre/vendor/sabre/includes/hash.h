/* SPDX-License-Identifier: GPL-2.0 */

#ifndef HASH_H_
#define HASH_H_

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __AVX2__
#include <x86intrin.h>
#endif

/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative _hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on them can
 * use shifts and additions instead of multiplications for machines where
 * multiplications are slow.
 */

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if __WORDSIZE == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define hash_long(val, bits) hash_32(val, bits)
#elif __WORDSIZE == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#endif

static inline uint64_t hash_64(uint64_t val, unsigned int bits) {
  uint64_t hash = val;

  uint64_t n = hash;
  n <<= 18;
  hash -= n;
  n <<= 33;
  hash -= n;
  n <<= 3;
  hash += n;
  n <<= 3;
  hash -= n;
  n <<= 4;
  hash += n;
  n <<= 2;
  hash += n;

  // High bits are more random, so use them
  return hash >> (64 - bits);
}

static inline uint32_t hash_32(uint32_t val, unsigned int bits) {
  uint32_t hash = val * GOLDEN_RATIO_PRIME_32;

  // High bits are more random, so use them
  return hash >> (32 - bits);
}

static inline unsigned long hash_ptr(const void *ptr, unsigned int bits) {
  return hash_long((unsigned long)ptr, bits);
}

static inline unsigned long hash_internal(const void *data, unsigned int len) {
  unsigned char *p = (unsigned char *)data;
  unsigned char *e = p + len;
  uint64_t h = 0xfeedbeeffeedbeef;

#ifdef __AVX2__
  // Proceed in 8x32 bit steps

  __m256i pack_h = _mm256_set1_epi32(0xfeedbeef);
  __m256i pack_golden = _mm256_set1_epi32(0x9e3779b9);
  // 32 bit golden number
  // From http://burtleburtle.net/bob/hash/evahash.html

  while (true) {
    unsigned char *aux = p + sizeof(pack_h);
    if (aux > e)
      break;

    __m256i pack_p = _mm256_loadu_si256((void *)p);

    pack_h = _mm256_xor_si256(pack_h, pack_p);
    pack_h = _mm256_mullo_epi32(pack_h, pack_golden);

    p = aux;
  }

  uint64_t result[4];
  _mm256_storeu_si256((void *)result, pack_h);

  h = result[0];
  h ^= result[1];
  h ^= result[2];
  h ^= result[3];

#else
  // Proceed in 64 bit steps
  while (true) {
    unsigned char *aux = p + sizeof(h);
    if (aux > e)
      break;

    h ^= *(uint64_t *)(p);
    h *= 0x9e3779b97f4a7c13LL;
    // 64 bit golden number
    // From http://burtleburtle.net/bob/hash/evahash.html

    p = aux;
  }
#endif

  // Finish
  while (p < e) {
    h ^= (uint64_t)(*p++);
    h *= 0x9e3779b97f4a7c13LL;
  }

  return h;
}

#endif /* HASH_H */
