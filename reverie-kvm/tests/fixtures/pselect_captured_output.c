/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    /* These are guest-only duplicates, not changes to the test runner's fds. */
    int fds[] = {STDOUT_FILENO, STDERR_FILENO, dup(STDOUT_FILENO), dup(STDERR_FILENO)};
    if (fds[2] < 3 || fds[2] >= 64 || fds[3] < 3 || fds[3] >= 64) return 80;
    for (unsigned i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) {
        uint64_t sets[] = {UINT64_C(1) << fds[i], UINT64_C(1) << fds[i], UINT64_C(1) << fds[i]};
        uint64_t before[3];
        memcpy(before, sets, sizeof(sets));
        struct timespec timeout = {0, 0};
        errno = 0;
        long result = syscall(SYS_pselect6, fds[i] + 1, &sets[0], &sets[1], &sets[2], &timeout, NULL);
        int error = errno;
        if (result != -1 || error != ENOSYS || memcmp(sets, before, sizeof(sets)) != 0 ||
            timeout.tv_sec != 0 || timeout.tv_nsec != 0) {
            dprintf(STDERR_FILENO, "captured pselect fd=%d result=%ld errno=%d\n", fds[i], result, error);
            return 81;
        }
    }
    if (close(fds[2]) != 0 || close(fds[3]) != 0) return 82;
    static const char success[] = "captured pselect refused 4\n";
    return write(STDOUT_FILENO, success, sizeof(success) - 1) == sizeof(success) - 1 ? 0 : 83;
}
