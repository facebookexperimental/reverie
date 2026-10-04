/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Drives the vDSO getrandom entry point the way glibc 2.41+ does: a parameter
 * query, then draws with caller-owned state. Under SaBRe the query must be
 * refused with -ENOSYS without writing params, and every draw must reach the
 * plugin as a getrandom syscall. */
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#define DRAW_LEN 37
#define DRAWS 5
#define PATTERN 0xa5

struct opaque_params {
  uint32_t size_of_opaque_state;
  uint32_t mmap_prot;
  uint32_t mmap_flags;
  uint32_t reserved[13];
};

typedef ssize_t (*vdso_getrandom)(void*, size_t, unsigned, void*, size_t);

int main(void) {
  void* vdso = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_NOLOAD);
  vdso_getrandom getrandom =
      vdso ? (vdso_getrandom)dlsym(vdso, "__vdso_getrandom") : NULL;
  if (getrandom == NULL) {
    printf("VDSO_GETRANDOM_ABSENT\n");
    return 0;
  }

  struct opaque_params sentinel, params;
  memset(&sentinel, 0xff, sizeof(sentinel));
  params = sentinel;
  ssize_t ret = getrandom(NULL, 0, 0, &params, ~0UL);
  if (ret != -ENOSYS) {
    fprintf(stderr, "query returned %zd, want %d\n", ret, -ENOSYS);
    return 1;
  }
  assert(memcmp(&params, &sentinel, sizeof(params)) == 0);

  /* Any state a caller held from before the rewrite; the stub ignores it. */
  void* state = mmap(
      NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(state != MAP_FAILED);
  for (int draw = 0; draw < DRAWS; draw++) {
    unsigned char buf[DRAW_LEN] = {0};
    ret = getrandom(buf, DRAW_LEN, 0, state, 144);
    assert(ret == DRAW_LEN);
    for (int i = 0; i < DRAW_LEN; i++)
      assert(buf[i] == PATTERN);
  }
  printf("VDSO_GETRANDOM_OK draws=%d\n", DRAWS);
  return 0;
}
