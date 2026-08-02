/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#ifndef SHOOTOUT_FREESTANDING
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#endif

#if !defined(__linux__) || !defined(__x86_64__)
#error "counter2-shootout workload requires Linux x86-64"
#endif

#define SYS_WRITE 1
#define SYS_GETPID 39
#define SYS_EXIT_GROUP 231

static long raw_syscall0(long number) {
  register long rax __asm__("rax") = number;
  __asm__ volatile("syscall" : "+a"(rax) : : "rcx", "r11", "memory");
  return rax;
}

static long raw_syscall1(long number, long arg0) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg0;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"(rdi)
                   : "rcx", "r11", "memory");
  return rax;
}

static long raw_syscall3(long number, long arg0, long arg1, long arg2) {
  register long rax __asm__("rax") = number;
  register long rdi __asm__("rdi") = arg0;
  register long rsi __asm__("rsi") = arg1;
  register long rdx __asm__("rdx") = arg2;
  __asm__ volatile("syscall"
                   : "+a"(rax)
                   : "D"(rdi), "S"(rsi), "d"(rdx)
                   : "rcx", "r11", "memory");
  return rax;
}

__attribute__((noreturn)) static void raw_exit(int status) {
  (void)raw_syscall1(SYS_EXIT_GROUP, status);
  __builtin_unreachable();
}

static int text_equal(const char *left, const char *right) {
  while (*left != '\0' && *left == *right) {
    ++left;
    ++right;
  }
  return *left == *right;
}

#ifdef SHOOTOUT_FREESTANDING
static uint64_t parse_digits(const char *text) {
  uint64_t value = 0;
  if (*text == '\0') {
    return 0;
  }
  for (; *text != '\0'; ++text) {
    if (*text < '0' || *text > '9') {
      return 0;
    }
    value = value * 10 + (uint64_t)(*text - '0');
  }
  return value;
}
#endif

#ifndef SHOOTOUT_FREESTANDING
static uint64_t parse_u64(const char *text, const char *name) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0) {
    fprintf(stderr, "invalid %s: %s\n", name, text);
    exit(2);
  }
  return (uint64_t)value;
}
#endif

static uint64_t execute(uint64_t iterations, uint64_t syscall_stride) {
  uint64_t state = UINT64_C(0x6a09e667f3bcc909);
  uint64_t until_syscall = syscall_stride;
  for (uint64_t index = 0; index < iterations; ++index) {
    state ^= state << 7;
    state ^= state >> 9;
    state *= UINT64_C(0x9e3779b185ebca87);
    state += index ^ UINT64_C(0xd1b54a32d192ed03);
    if (--until_syscall == 0) {
      (void)raw_syscall0(SYS_GETPID);
      until_syscall = syscall_stride;
    }
  }
  return state;
}

#ifndef SHOOTOUT_FREESTANDING
static double elapsed_ms(const struct timespec *start,
                         const struct timespec *end) {
  return (double)(end->tv_sec - start->tv_sec) * 1000.0 +
         (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
}

static int calibrate(uint64_t target_ms, uint64_t syscall_stride) {
  uint64_t iterations = UINT64_C(1000000);
  double duration = 0.0;
  uint64_t checksum = 0;
  do {
    struct timespec start;
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
      perror("clock_gettime");
      return 2;
    }
    checksum ^= execute(iterations, syscall_stride);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
      perror("clock_gettime");
      return 2;
    }
    duration = elapsed_ms(&start, &end);
    if (duration < 100.0) {
      iterations *= 2;
    }
  } while (duration < 100.0);

  long double scaled = (long double)iterations * (long double)target_ms /
                       (long double)duration;
  uint64_t recommendation = (uint64_t)scaled;
  if (recommendation == 0) {
    recommendation = 1;
  }
  fprintf(stderr, "pilot_ms=%.3f pilot_iterations=%" PRIu64
                  " checksum=%" PRIu64 "\n",
          duration, iterations, checksum);
  printf("iterations=%" PRIu64 "\n", recommendation);
  return 0;
}
#endif

static size_t append_text(char *output, size_t offset, const char *text) {
  while (*text != '\0') {
    output[offset++] = *text++;
  }
  return offset;
}

static size_t append_u64(char *output, size_t offset, uint64_t value) {
  char reversed[32];
  size_t length = 0;
  do {
    reversed[length++] = (char)('0' + value % 10);
    value /= 10;
  } while (value != 0);
  while (length != 0) {
    output[offset++] = reversed[--length];
  }
  return offset;
}

__attribute__((noreturn)) static void run_measured(uint64_t iterations,
                                                   uint64_t syscall_stride) {
  uint64_t checksum = execute(iterations, syscall_stride);
  char output[192];
  size_t length = append_text(output, 0, "checksum=");
  length = append_u64(output, length, checksum);
  length = append_text(output, length, " iterations=");
  length = append_u64(output, length, iterations);
  length = append_text(output, length, " stride=");
  length = append_u64(output, length, syscall_stride);
  output[length++] = '\n';
  if (raw_syscall3(SYS_WRITE, 1, (long)output, (long)length) != (long)length) {
    raw_exit(2);
  }
  raw_exit(0);
}

#ifndef SHOOTOUT_FREESTANDING
static void usage(const char *program) {
  fprintf(stderr,
          "usage: %s --calibrate-ms MS --stride N\n"
          "       %s --iterations N --stride N\n",
          program, program);
}

int main(int argc, char **argv) {
  uint64_t calibration_ms = 0;
  uint64_t iterations = 0;
  uint64_t syscall_stride = 0;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc) {
      usage(argv[0]);
      return 2;
    }
    if (text_equal(argv[index], "--calibrate-ms")) {
      calibration_ms = parse_u64(argv[index + 1], "calibration milliseconds");
    } else if (text_equal(argv[index], "--iterations")) {
      iterations = parse_u64(argv[index + 1], "iterations");
    } else if (text_equal(argv[index], "--stride")) {
      syscall_stride = parse_u64(argv[index + 1], "syscall stride");
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  if (syscall_stride == 0 || (calibration_ms == 0) == (iterations == 0)) {
    usage(argv[0]);
    return 2;
  }
  if (calibration_ms != 0) {
    return calibrate(calibration_ms, syscall_stride);
  }

  run_measured(iterations, syscall_stride);
}
#else
__attribute__((used, noreturn)) static void freestanding_main(long argc,
                                                               char **argv) {
  uint64_t iterations = 0;
  uint64_t syscall_stride = 0;
  for (long index = 1; index + 1 < argc; index += 2) {
    if (text_equal(argv[index], "--iterations")) {
      iterations = parse_digits(argv[index + 1]);
    } else if (text_equal(argv[index], "--stride")) {
      syscall_stride = parse_digits(argv[index + 1]);
    } else {
      raw_exit(2);
    }
  }
  if (iterations == 0 || syscall_stride == 0) {
    raw_exit(2);
  }
  run_measured(iterations, syscall_stride);
}

__asm__(".global _start\n"
        "_start:\n"
        "mov (%rsp), %rdi\n"
        "lea 8(%rsp), %rsi\n"
        "andq $-16, %rsp\n"
        "call freestanding_main\n");
#endif
