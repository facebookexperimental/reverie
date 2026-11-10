/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef NDEBUG
#error "stat conformance requires assertions"
#endif

int main(void) {
    const char *path = "/proc/self/exe";
    int fd = open(path, O_RDONLY);
    assert(fd > 0);

    struct stat stat_result;
    struct stat lstat_result;
    struct stat fstat_result;
    assert(stat(path, &stat_result) == 0);
    assert(lstat(path, &lstat_result) == 0);
    assert(fstat(fd, &fstat_result) == 0);
    assert(stat_result.st_ino == fstat_result.st_ino);
    assert(stat_result.st_ino != lstat_result.st_ino);
    return 0;
}
