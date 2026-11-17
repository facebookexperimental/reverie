/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/time.h>
#include <time.h>

#ifdef NDEBUG
#error "vDSO conformance requires assertions"
#endif

// Each kernel's vDSO linker script names the entry points and their version:
// x86_64 exports __vdso_* under LINUX_2.6 (arch/x86/entry/vdso/vdso.lds.S);
// arm64 exports __kernel_* under LINUX_2.6.39 and has no getcpu
// (arch/arm64/kernel/vdso/vdso.lds.S).
#if defined(__x86_64__)
#define VDSO_VERSION "LINUX_2.6"
#define VDSO_CLOCK_GETTIME "__vdso_clock_gettime"
#define VDSO_GETTIMEOFDAY "__vdso_gettimeofday"
#define VDSO_GETCPU "__vdso_getcpu"
#define VDSO_CLOCK_GETRES "__vdso_clock_getres"
#elif defined(__aarch64__)
#define VDSO_VERSION "LINUX_2.6.39"
#define VDSO_CLOCK_GETTIME "__kernel_clock_gettime"
#define VDSO_GETTIMEOFDAY "__kernel_gettimeofday"
#define VDSO_CLOCK_GETRES "__kernel_clock_getres"
#else
#error "no vDSO entry point names for this architecture"
#endif

static void *entry(void *handle, const void *base, const char *name) {
    dlerror();
    void *symbol = dlvsym(handle, name, VDSO_VERSION);
    assert(dlerror() == NULL);
    assert(symbol != NULL);
    Dl_info info = {0};
    assert(dladdr(symbol, &info) != 0);
    assert(info.dli_fbase == base);
    return symbol;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    bool native = strcmp(argv[1], "native") == 0;
    assert(native || strcmp(argv[1], "tool") == 0);

    const void *base = (const void *)(uintptr_t)getauxval(AT_SYSINFO_EHDR);
    assert(base != NULL);
    void *handle = dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_LOCAL);
    assert(handle != NULL);
    int (*clock_gettime_entry)(clockid_t, struct timespec *) =
        (int (*)(clockid_t, struct timespec *))
            entry(handle, base, VDSO_CLOCK_GETTIME);
    int (*gettimeofday_entry)(struct timeval *, struct timezone *) =
        (int (*)(struct timeval *, struct timezone *))
            entry(handle, base, VDSO_GETTIMEOFDAY);
#ifdef VDSO_GETCPU
    long (*getcpu_entry)(unsigned *, unsigned *, void *) =
        (long (*)(unsigned *, unsigned *, void *))
            entry(handle, base, VDSO_GETCPU);
#endif
    int (*clock_getres_entry)(clockid_t, struct timespec *) =
        (int (*)(clockid_t, struct timespec *))
            entry(handle, base, VDSO_CLOCK_GETRES);

    struct timespec now = {0};
    struct timeval tod = {0};
    struct timezone tz = {0};
#ifdef VDSO_GETCPU
    unsigned cpu = UINT_MAX;
#endif
    struct timespec resolution = {.tv_sec = 1, .tv_nsec = 0};
    int time_result = clock_gettime_entry(CLOCK_MONOTONIC, &now);
    int tod_result = gettimeofday_entry(&tod, &tz);
#ifdef VDSO_GETCPU
    long cpu_result = getcpu_entry(&cpu, NULL, NULL);
#endif
    int resolution_result = clock_getres_entry(CLOCK_MONOTONIC, &resolution);

    if (native) {
        assert(time_result == 0);
        assert(now.tv_sec >= 0);
        assert(now.tv_nsec >= 0 && now.tv_nsec < 1000000000);
        assert(tod_result == 0);
        assert(tod.tv_sec >= 0);
        assert(tod.tv_usec >= 0 && tod.tv_usec < 1000000);
#ifdef VDSO_GETCPU
        assert(cpu_result == 0);
        assert(cpu != UINT_MAX);
#endif
        assert(resolution_result == 0);
        assert(resolution.tv_sec >= 0);
        assert(resolution.tv_nsec >= 0 && resolution.tv_nsec < 1000000000);
        assert(resolution.tv_sec > 0 || resolution.tv_nsec > 0);
    } else {
        // Direct vDSO calls return negative errno, without libc translation.
        assert(time_result == -EINVAL);
        assert(tod_result == 0);
        assert(tod.tv_usec % 1000 == 345);
#ifdef VDSO_GETCPU
        assert(cpu_result == 0);
        assert(cpu == 0);
#endif
        assert(resolution_result == 0);
        assert(resolution.tv_sec == 0);
        assert(resolution.tv_nsec == 42);
    }
    return 0;
}
