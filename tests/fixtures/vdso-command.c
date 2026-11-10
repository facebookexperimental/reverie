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

static void *entry(void *handle, const void *base, const char *name) {
    dlerror();
    void *symbol = dlvsym(handle, name, "LINUX_2.6");
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
            entry(handle, base, "__vdso_clock_gettime");
    int (*gettimeofday_entry)(struct timeval *, struct timezone *) =
        (int (*)(struct timeval *, struct timezone *))
            entry(handle, base, "__vdso_gettimeofday");
    long (*getcpu_entry)(unsigned *, unsigned *, void *) =
        (long (*)(unsigned *, unsigned *, void *))
            entry(handle, base, "__vdso_getcpu");
    int (*clock_getres_entry)(clockid_t, struct timespec *) =
        (int (*)(clockid_t, struct timespec *))
            entry(handle, base, "__vdso_clock_getres");

    struct timespec now = {0};
    struct timeval tod = {0};
    struct timezone tz = {0};
    unsigned cpu = UINT_MAX;
    struct timespec resolution = {.tv_sec = 1, .tv_nsec = 0};
    int time_result = clock_gettime_entry(CLOCK_MONOTONIC, &now);
    int tod_result = gettimeofday_entry(&tod, &tz);
    long cpu_result = getcpu_entry(&cpu, NULL, NULL);
    int resolution_result = clock_getres_entry(CLOCK_MONOTONIC, &resolution);

    if (native) {
        assert(time_result == 0);
        assert(now.tv_sec >= 0);
        assert(now.tv_nsec >= 0 && now.tv_nsec < 1000000000);
        assert(tod_result == 0);
        assert(tod.tv_sec >= 0);
        assert(tod.tv_usec >= 0 && tod.tv_usec < 1000000);
        assert(cpu_result == 0);
        assert(cpu != UINT_MAX);
        assert(resolution_result == 0);
        assert(resolution.tv_sec >= 0);
        assert(resolution.tv_nsec >= 0 && resolution.tv_nsec < 1000000000);
        assert(resolution.tv_sec > 0 || resolution.tv_nsec > 0);
    } else {
        // Direct vDSO calls return negative errno, without libc translation.
        assert(time_result == -EINVAL);
        assert(tod_result == 0);
        assert(tod.tv_usec % 1000 == 345);
        assert(cpu_result == 0);
        assert(cpu == 0);
        assert(resolution_result == 0);
        assert(resolution.tv_sec == 0);
        assert(resolution.tv_nsec == 42);
    }
    return 0;
}
