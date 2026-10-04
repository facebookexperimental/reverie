/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct iterate_context {
  dev_t device;
  ino_t inode;
  uintptr_t address;
  unsigned int matches;
};

struct mapping_identity {
  unsigned int major;
  unsigned int minor;
  unsigned long inode;
};

static void fail(const char* operation) {
  int saved = errno;
  const char* loader = dlerror();
  if (loader != NULL)
    dprintf(STDERR_FILENO, "%s: %s\n", operation, loader);
  else
    dprintf(STDERR_FILENO, "%s: %s\n", operation, strerror(saved));
  _exit(125);
}

static int
identify_loaded_object(struct dl_phdr_info* info, size_t size, void* opaque) {
  (void)size;
  struct iterate_context* context = opaque;
  if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0')
    return 0;
  struct stat metadata;
  if (stat(info->dlpi_name, &metadata) != 0)
    return 0;
  if (metadata.st_dev == context->device && metadata.st_ino == context->inode) {
    context->address = (uintptr_t)info->dlpi_addr;
    ++context->matches;
  }
  return 0;
}

static void write_all(const char* bytes, size_t length) {
  while (length != 0) {
    ssize_t written = write(STDOUT_FILENO, bytes, length);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      fail("write report");
    bytes += written;
    length -= (size_t)written;
  }
}

static struct mapping_identity mapping_for(uintptr_t address) {
  FILE* maps = fopen("/proc/self/maps", "r");
  if (maps == NULL)
    fail("open maps");
  char line[4096];
  while (fgets(line, sizeof(line), maps) != NULL) {
    unsigned long start, end, offset, inode;
    unsigned int device_major, device_minor;
    char permissions[5];
    if (sscanf(
            line,
            "%lx-%lx %4s %lx %x:%x %lu",
            &start,
            &end,
            permissions,
            &offset,
            &device_major,
            &device_minor,
            &inode) != 7)
      continue;
    if (address < start || address >= end)
      continue;
    if (permissions[0] != 'r' || permissions[1] != '-' ||
        permissions[2] != 'x' || permissions[3] != 'p' || inode == 0) {
      fclose(maps);
      errno = EINVAL;
      fail("initializer mapping permissions");
    }
    fclose(maps);
    return (struct mapping_identity){
        .major = device_major,
        .minor = device_minor,
        .inode = inode,
    };
  }
  fclose(maps);
  errno = ENOENT;
  fail("initializer mapping");
  __builtin_unreachable();
}

int main(int argc, char** argv) {
  if (argc != 3 || (strcmp(argv[1], "base") && strcmp(argv[1], "new"))) {
    errno = EINVAL;
    fail("usage: fixture {base|new} /canonical/runtime.so");
  }

  struct stat metadata;
  if (stat(argv[2], &metadata) != 0 || !S_ISREG(metadata.st_mode))
    fail("stat runtime");

  dlerror();
  void* handle = !strcmp(argv[1], "base")
      ? dlopen(argv[2], RTLD_NOW | RTLD_LOCAL)
      : dlmopen(LM_ID_NEWLM, argv[2], RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL)
    fail("load runtime");

  dlerror();
  void* symbol = dlsym(handle, "reverie_liteinst_initialize_host");
  if (symbol == NULL || dlerror() != NULL)
    fail("dlsym initializer");

  struct link_map* by_handle = NULL;
  if (dlinfo(handle, RTLD_DI_LINKMAP, &by_handle) != 0 || by_handle == NULL)
    fail("dlinfo link map");
  Lmid_t namespace_id = LM_ID_BASE;
  if (dlinfo(handle, RTLD_DI_LMID, &namespace_id) != 0)
    fail("dlinfo namespace");

  Dl_info symbol_info;
  void* extra = NULL;
  memset(&symbol_info, 0, sizeof(symbol_info));
  if (dladdr1(symbol, &symbol_info, &extra, RTLD_DL_LINKMAP) == 0 ||
      extra == NULL || symbol_info.dli_fbase == NULL ||
      symbol_info.dli_saddr == NULL || symbol_info.dli_sname == NULL ||
      strcmp(symbol_info.dli_sname, "reverie_liteinst_initialize_host"))
    fail("dladdr1 initializer");
  struct link_map* by_symbol = extra;

  struct iterate_context iteration = {
      .device = metadata.st_dev,
      .inode = metadata.st_ino,
  };
  if (dl_iterate_phdr(identify_loaded_object, &iteration) != 0)
    fail("dl_iterate_phdr");
  struct mapping_identity mapping = mapping_for((uintptr_t)symbol);

  unsigned long auxiliary_phdr = getauxval(AT_PHDR);
  if (auxiliary_phdr == 0)
    fail("getauxval AT_PHDR");

  char report[1024];
  int length = snprintf(
      report,
      sizeof(report),
      "symbol=%lx dlinfo_map=%lx dlinfo_addr=%lx dlinfo_ld=%lx "
      "iterate_addr=%lx iterate_matches=%x dladdr_map=%lx "
      "dladdr_addr=%lx dladdr_ld=%lx dladdr_fbase=%lx "
      "dladdr_symbol=%lx at_phdr=%lx dev_major=%x dev_minor=%x "
      "stat_inode=%lx map_major=%x map_minor=%x map_inode=%lx "
      "namespace=%lx\n",
      (unsigned long)(uintptr_t)symbol,
      (unsigned long)(uintptr_t)by_handle,
      (unsigned long)(uintptr_t)by_handle->l_addr,
      (unsigned long)(uintptr_t)by_handle->l_ld,
      (unsigned long)iteration.address,
      iteration.matches,
      (unsigned long)(uintptr_t)by_symbol,
      (unsigned long)(uintptr_t)by_symbol->l_addr,
      (unsigned long)(uintptr_t)by_symbol->l_ld,
      (unsigned long)(uintptr_t)symbol_info.dli_fbase,
      (unsigned long)(uintptr_t)symbol_info.dli_saddr,
      auxiliary_phdr,
      major(metadata.st_dev),
      minor(metadata.st_dev),
      (unsigned long)metadata.st_ino,
      mapping.major,
      mapping.minor,
      mapping.inode,
      (unsigned long)namespace_id);
  if (length <= 0 || (size_t)length >= sizeof(report))
    fail("format report");
  write_all(report, (size_t)length);

  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
    fail("PTRACE_TRACEME");
  if (raise(SIGSTOP) != 0)
    fail("raise SIGSTOP");

  write_all("resumed\n", sizeof("resumed\n") - 1);
  return 0;
}
