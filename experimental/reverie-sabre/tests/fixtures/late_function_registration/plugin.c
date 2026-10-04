/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <asm/prctl.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "real_syscall.h"
#include "sbr_api_defs.h"
extern bool calling_from_plugin(void);
extern ssize_t late_probe(unsigned char*, size_t, unsigned);
extern long late_raw_getpid(void);
extern ssize_t late_probe_two(unsigned char*, size_t, unsigned);
typedef ssize_t (*operation)(unsigned char*, size_t, unsigned);
static operation original, original_two;
static unsigned calls, calls_two;
static unsigned long expected_fs;
static __thread unsigned tls_marker __attribute__((tls_model("initial-exec")));
static unsigned char* expected_buffer;
static bool is_static;
static bool initialized;
static unsigned finalizer_phase;
__attribute__((destructor(201))) static void finalize_second(void) {
  if (!initialized)
    return;
  assert(calling_from_plugin());
  assert(finalizer_phase++ == 0);
}
__attribute__((destructor(200))) static void finalize_first(void) {
  if (!initialized)
    return;
  assert(calling_from_plugin());
  assert(finalizer_phase++ == 1);
}
void finalizer_last(void) {
  if (!initialized)
    return;
  assert(calling_from_plugin());
  assert(finalizer_phase++ == 2);
}

static unsigned long fs(void) {
  unsigned long address = 0;
  assert(
      real_syscall(SYS_arch_prctl, ARCH_GET_FS, (long)&address, 0, 0, 0, 0) ==
      0);
  return address;
}
static void check_tls(void) {
  assert(fs() == expected_fs);
  assert(tls_marker == 0x12345678);
}
static ssize_t stub(unsigned char* buf, size_t len, unsigned flags) {
  check_tls();
  assert(calls == 1 && original != NULL);
  assert(len == 4 && flags == 0x1357);
  if (expected_buffer != NULL)
    assert(buf == expected_buffer);
  ssize_t result = original(buf, len, flags);
  assert(result == 37 && buf[0] == 0x6a);
  if (!is_static)
    assert(errno == EDOM);
  buf[0] ^= 0x80;
  return result + 100;
}
static ssize_t stub_two(unsigned char* buf, size_t len, unsigned flags) {
  check_tls();
  assert(calls_two == 1 && original_two != NULL);
  return original_two(buf, len, flags);
}
static void_void_fn capture(void_void_fn real) {
  check_tls();
  assert(calling_from_plugin() == !is_static);
  assert(calls++ == 0);
  original = (operation)real;
  return (void_void_fn)stub;
}
static void_void_fn capture_two(void_void_fn real) {
  check_tls();
  assert(calling_from_plugin() == !is_static);
  assert(calls_two++ == 0);
  original_two = (operation)real;
  return (void_void_fn)stub_two;
}
static int protections(const void* address) {
  static char buffer[65536];
  long fd =
      real_syscall(SYS_openat, AT_FDCWD, (long)"/proc/self/maps", 0, 0, 0, 0);
  assert(fd >= 0);
  size_t used = 0;
  for (;;) {
    assert(used < sizeof(buffer) - 1);
    long n = real_syscall(
        SYS_read,
        fd,
        (long)(buffer + used),
        sizeof(buffer) - 1 - used,
        0,
        0,
        0);
    assert(n >= 0);
    if (n == 0)
      break;
    used += n;
  }
  assert(used > 0);
  assert(real_syscall(SYS_close, fd, 0, 0, 0, 0, 0) == 0);
  buffer[used] = 0;
  for (char* line = buffer; line != NULL && *line;) {
    unsigned long lo, hi;
    char mode[5] = {0};
    assert(sscanf(line, "%lx-%lx %4s", &lo, &hi, mode) == 3);
    if ((uintptr_t)address >= lo && (uintptr_t)address < hi)
      return (mode[0] == 'r' ? PROT_READ : 0) |
          (mode[1] == 'w' ? PROT_WRITE : 0) | (mode[2] == 'x' ? PROT_EXEC : 0);
    line = strchr(line, '\n');
    if (line != NULL)
      ++line;
  }
  assert(!"mapping not found");
  return -1;
}
static long
passthrough(long nr, long a, long b, long c, long d, long e, long f, void* sp) {
  (void)sp;
  return real_syscall(nr, a, b, c, d, e, f);
}
#ifdef __NX_INTERCEPT_RDTSC
static long rdtsc(void) {
  unsigned a, d;
  __asm__ volatile("rdtsc" : "=a"(a), "=d"(d));
  return ((long)d << 32) | a;
}
#endif
static void post_load(bool value) {
  assert(value == is_static);
  check_tls();
  assert(is_static ? calls == 0 : calls == 1);
}
void sbr_init(
    int* argc,
    char*** argv,
    sbr_icept_reg_fn reg,
    sbr_icept_vdso_callback_fn* vdso,
    sbr_sc_handler_fn* syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
    sbr_rdtsc_handler_fn* rdtsc_handler,
#endif
    sbr_post_load_fn* post,
    char* loader,
    char* client) {
  (void)loader;
  (void)client;
  assert(*argc == 2);
  const char* mode = (*argv)[1];
  is_static = strncmp(mode, "static", 6) == 0;
  expected_fs = fs();
  tls_marker = 0x12345678;
  *vdso = NULL;
  *syscall_handler = passthrough;
  *post = post_load;
#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = rdtsc;
#endif
  sbr_fn_icept_struct one = {
      is_static ? "client-static" : "liblate", "late_probe", capture};
  if (is_static) {
    reg(&one);
    check_tls();
    assert(calls == 0);
    if (strcmp(mode, "static-alias") == 0) {
      sbr_fn_icept_struct alias = {"client", "late_probe", capture};
      reg(&alias);
      check_tls();
      assert(calls == 0);
    }
  } else {
    unsigned char code[32], vdso_bytes[65536];
    memcpy(code, (void*)late_raw_getpid, sizeof(code));
    ElfW(Ehdr)* ehdr = (void*)getauxval(AT_SYSINFO_EHDR);
    assert(ehdr != NULL && ehdr->e_phnum < 32);
    ElfW(Phdr)* ph = (void*)((char*)ehdr + ehdr->e_phoff);
    size_t extent = 0;
    for (unsigned i = 0; i < ehdr->e_phnum; ++i)
      if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr + ph[i].p_memsz > extent)
        extent = ph[i].p_vaddr + ph[i].p_memsz;
    assert(extent > 0 && extent <= sizeof(vdso_bytes));
    memcpy(vdso_bytes, ehdr, extent);
    int before = protections((void*)late_probe);
    assert(before == (PROT_READ | PROT_EXEC));
    reg(&one);
    check_tls();
    assert(calls == 1 && "late registration did not install callback");
    assert(protections((void*)late_probe) == before);
    assert(memcmp(code, (void*)late_raw_getpid, sizeof(code)) == 0);
    assert(memcmp(vdso_bytes, ehdr, extent) == 0);
    unsigned char buf[4] = {0, 1, 2, 3};
    expected_buffer = buf;
    errno = 0;
    assert(original(buf, 4, 0x1357) == 37 && errno == EDOM);
    assert(buf[0] == 0x6a && buf[1] == 1 && buf[2] == 2 && buf[3] == 3);
    errno = 0;
    assert(late_probe(buf, 4, 0x1357) == 137 && errno == EDOM);
    assert(buf[0] == 0xea && buf[1] == 1 && buf[2] == 2 && buf[3] == 3);
    operation saved = original;
    reg(&one);
    check_tls();
    assert(calls == 1 && original == saved);
    sbr_fn_icept_struct two = {"liblate_probe", "late_probe_two", capture_two};
    reg(&two);
    check_tls();
    assert(calls_two == 1 && calls == 1 && original == saved);
    errno = 0;
    assert(late_probe_two(buf, 4, 0x1357) == 137 && errno == EDOM);
    sbr_fn_icept_struct absent = {
        "lib_unrelated_absent", "no_function", capture_two};
    reg(&absent);
    check_tls();
    assert(calls_two == 1 && calls == 1);
    assert(protections((void*)late_probe) == before);
    if (strcmp(mode, "conflict") == 0) {
      one.icept_callback = capture_two;
      reg(&one);
      assert(!"conflict accepted");
    }
    if (strcmp(mode, "capacity") == 0) {
      for (unsigned i = 0; i < 64; i++) {
        char name[32];
        snprintf(name, sizeof(name), "absent_%u", i);
        absent.fn_name = name;
        reg(&absent);
      }
      assert(!"capacity accepted");
    }
    if (strncmp(mode, "alias-", 6) == 0) {
      sbr_fn_icept_struct alias = {"liblate_probe", "late_probe", capture};
      if (strcmp(mode, "alias-elf") == 0)
        alias.fn_name = "late_probe_alias";
      if (strcmp(mode, "alias-conflict") == 0)
        alias.icept_callback = capture_two;
      reg(&alias);
      assert(!"resolved-target alias accepted");
    }
    expected_buffer = NULL;
  }
  initialized = true;
  (*argc) -= 2;
  (*argv) += 2;
}
