/* Every vDSO entry point must be routed to the plugin or stubbed. Under SaBRe
 * the vDSO's clock_getres, which the loader used to leave native, must reach
 * the plugin as a syscall, and the SGX enclave entry, which has no syscall
 * equivalent, must return -ENOSYS rather than the kernel's -EINVAL for an
 * invalid leaf. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#define MARKER_NSEC 12345

typedef int (*vdso_clock_getres)(clockid_t, struct timespec*);
typedef int (*sgx_enter_enclave)(
    unsigned long,
    unsigned long,
    unsigned long,
    unsigned int,
    unsigned long,
    unsigned long,
    void*);

int main(void) {
  int failed = 0;
  void* vdso = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_NOLOAD);
  if (vdso == NULL) {
    printf("VDSO_ABSENT\n");
    return 0;
  }

  vdso_clock_getres clock_getres =
      (vdso_clock_getres)dlsym(vdso, "__vdso_clock_getres");
  if (clock_getres != NULL) {
    struct timespec res = {0};
    int ret = clock_getres(CLOCK_MONOTONIC, &res);
    if (ret != 0 || res.tv_sec != 0 || res.tv_nsec != MARKER_NSEC) {
      fprintf(
          stderr,
          "clock_getres returned %d {%ld, %ld}, want 0 {0, %d}\n",
          ret,
          (long)res.tv_sec,
          (long)res.tv_nsec,
          MARKER_NSEC);
      failed = 1;
    }
  }

  sgx_enter_enclave sgx =
      (sgx_enter_enclave)dlsym(vdso, "__vdso_sgx_enter_enclave");
  if (sgx != NULL) {
    int ret = sgx(0, 0, 0, 0, 0, 0, NULL);
    if (ret != -ENOSYS) {
      fprintf(stderr, "sgx returned %d, want %d\n", ret, -ENOSYS);
      failed = 1;
    }
  }
  if (failed) {
    return 1;
  }
  printf(
      "VDSO_FAIL_CLOSED_OK clock_getres=%s sgx=%s\n",
      clock_getres != NULL ? "routed" : "absent",
      sgx != NULL ? "stubbed" : "absent");
  return 0;
}
