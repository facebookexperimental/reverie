/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Exercise the actual maps parser and static rewrite protection helper on
 * owned native mappings. This does not execute a SaBRe or Hermit guest. */
#define _GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

struct protection_call {
  void* address;
  size_t length;
  int protection;
  int result;
  int error;
};
static struct protection_call calls[4];
static size_t call_count;

/* Observe the real libc/kernel return, without replacing it. Only the
 * included helper uses this wrapper; setup/probes call mprotect directly. */
static int observed_mprotect(void* address, size_t length, int protection) {
  assert(call_count < sizeof(calls) / sizeof(calls[0]));
  int result = mprotect(address, length, protection);
  int error = result == -1 ? errno : 0;
  calls[call_count++] =
      (struct protection_call){address, length, protection, result, error};
  return result;
}

#define mprotect observed_mprotect
#include "../vendor/sabre/loader/rewriter.c"
#undef mprotect
#include "../vendor/sabre/loader/maps.c"

static char owned_path[4096];

static void remove_owned_file(void) {
  if (owned_path[0] != '\0')
    unlink(owned_path);
}

static void permissions_at(void* address, size_t length, char permissions[5]) {
  FILE* maps = fopen("/proc/self/maps", "r");
  assert(maps != NULL);
  char line[8192];
  int found = 0;
  while (fgets(line, sizeof(line), maps) != NULL) {
    unsigned long start, end;
    char value[5];
    if (sscanf(line, "%lx-%lx %4s", &start, &end, value) == 3 &&
        start <= (uintptr_t)address && (uintptr_t)address + length <= end) {
      assert(found++ == 0);
      memcpy(permissions, value, 5);
    }
  }
  assert(fclose(maps) == 0);
  assert(found == 1);
}

static int probe_write(volatile unsigned char* address) {
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    struct rlimit no_core = {0, 0};
    assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
    assert(signal(SIGSEGV, SIG_DFL) != SIG_ERR);
    *address = 0x5a;
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  printf(
      "write_probe wait_status=%d exited=%d signal=%d\n",
      status,
      WIFEXITED(status) ? WEXITSTATUS(status) : -1,
      WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  return status;
}

static void require_call(void* address, size_t length, int index) {
  assert((size_t)index < call_count);
  struct protection_call call = calls[index];
  printf(
      "mprotect index=%d address=%p length=%zu protection=%d result=%d "
      "errno=%d\n",
      index,
      call.address,
      call.length,
      call.protection,
      call.result,
      call.error);
  assert(call.address == address && call.length == length);
}

int main(int argc, char** argv) {
  assert(argc == 3);
  assert(setvbuf(stdout, NULL, _IONBF, 0) == 0);
  alarm(10);
  const char* name = argv[1];
  bool unmapped = strcmp(name, "unmapped") == 0;
  bool shared = strncmp(name, "shared-", 7) == 0;
  int original = PROT_READ;
  if (strstr(name, "-rx") != NULL)
    original |= PROT_EXEC;
  else if (strstr(name, "-rw") != NULL || unmapped)
    original |= PROT_WRITE;
  else
    assert(strcmp(name, "private-r") == 0 || strcmp(name, "shared-r") == 0);
  assert(shared || strncmp(name, "private-", 8) == 0 || unmapped);
  long page = sysconf(_SC_PAGESIZE);
  assert(page > 0);
  size_t length = (size_t)page * 3;
  int n = snprintf(owned_path, sizeof(owned_path), "%s/maps-XXXXXX", argv[2]);
  assert(n > 0 && (size_t)n < sizeof(owned_path));
  int fd = mkstemp(owned_path);
  assert(fd >= 0);
  assert(atexit(remove_owned_file) == 0);
  assert(ftruncate(fd, (off_t)length) == 0);
  void* address =
      mmap(NULL, length, original, shared ? MAP_SHARED : MAP_PRIVATE, fd, 0);
  assert(address != MAP_FAILED);
  assert(close(fd) == 0);

  char before[5], during[5], after[5];
  permissions_at(address, length, before);
  struct maps* parsed = maps_read(owned_path);
  struct library* library = library_find(parsed->libraries, owned_path);
  assert(library != NULL);
  struct rb_node* node = rb_first(&library->rb_region);
  assert(node != NULL && rb_next(node) == NULL);
  struct region* region = rb_entry(node, struct region, rb_region);
  assert(
      region->start == address && region->size == length &&
      region->offset == 0);
  printf(
      "case=%s before=%s original=%d parser=%d address=%p length=%zu\n",
      name,
      before,
      original,
      region->perms,
      address,
      length);

  if (unmapped) {
    assert(munmap(address, length) == 0);
    library_make_writable(library, true);
    assert(call_count == 1);
    require_call(address, length, 0);
    assert(calls[0].result == -1 && calls[0].error == ENOMEM);
    printf("PASS %s\n", name);
    return 0;
  }

  library_make_writable(library, true);
  assert(call_count == 1);
  require_call(address, length, 0);
  assert(
      calls[0].result == 0 && calls[0].protection == (original | PROT_WRITE));
  permissions_at(address, length, during);
  assert(during[1] == 'w');
  /* The vDSO path also applies a page-aligned mprotect inside its writable
   * region. Keep that real intermediate operation in this native control. */
  void* middle = (char*)address + page;
  int patch_result = mprotect(middle, (size_t)page, original | PROT_WRITE);
  int patch_error = patch_result == -1 ? errno : 0;
  printf(
      "patch_mprotect address=%p length=%ld protection=%d result=%d errno=%d\n",
      middle,
      page,
      original | PROT_WRITE,
      patch_result,
      patch_error);
  assert(patch_result == 0);
  *(volatile unsigned char*)middle = 0xa5;
  assert(*(volatile unsigned char*)middle == 0xa5);
  library_make_writable(library, false);
  assert(call_count == 2);
  require_call(address, length, 1);
  assert(calls[1].result == 0);
  permissions_at(address, length, after);
  printf("case=%s before=%s during=%s after=%s\n", name, before, during, after);
  int status = probe_write(middle);
  bool writable = (original & PROT_WRITE) != 0;
  bool correct_probe = writable
      ? WIFEXITED(status) && WEXITSTATUS(status) == 0
      : WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;
  if (region->perms != original || calls[1].protection != original ||
      strcmp(before, after) != 0 || !correct_probe) {
    fprintf(
        stderr,
        "original protections were not restored: case=%s "
        "expected=%d parsed=%d after=%s probe_ok=%d\n",
        name,
        original,
        region->perms,
        after,
        correct_probe);
    return 1;
  }
  assert(munmap(address, length) == 0);
  printf("PASS %s\n", name);
  return 0;
}
