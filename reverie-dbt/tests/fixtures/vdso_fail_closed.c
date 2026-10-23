/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Calls the vDSO SGX enclave entry, which has no syscall equivalent, with leaf
 * 0 (neither EENTER nor ERESUME). The kernel's code returns -EINVAL; under the
 * DBT client, which replaces every vDSO entry point it does not route to a
 * syscall, it must return -ENOSYS.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

typedef int (*sgx_enter_enclave)(
    unsigned long,
    unsigned long,
    unsigned long,
    unsigned int,
    unsigned long,
    unsigned long,
    void*);

int main(void) {
  void* vdso = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_NOLOAD);
  sgx_enter_enclave sgx = vdso
      ? (sgx_enter_enclave)dlsym(vdso, "__vdso_sgx_enter_enclave")
      : NULL;
  if (sgx == NULL) {
    puts("vdso-sgx=absent");
    return 0;
  }
  printf("vdso-sgx=%d\n", sgx(0, 0, 0, 0, 0, 0, NULL));
  return 0;
}
