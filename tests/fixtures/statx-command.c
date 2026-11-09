/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef NDEBUG
#error "statx conformance requires assertions"
#endif

int main(void) {
    const char *path = "/proc/self/exe";
    int dirfd = AT_FDCWD;
    struct stat fstatat_result;
    struct statx statx_result;
    assert(fstatat(dirfd, path, &fstatat_result, AT_SYMLINK_NOFOLLOW) == 0);
    assert(syscall(SYS_statx, dirfd, path, AT_SYMLINK_NOFOLLOW, STATX_INO,
                   &statx_result) == 0);
    assert(fstatat_result.st_ino == statx_result.stx_ino);
    return 0;
}
