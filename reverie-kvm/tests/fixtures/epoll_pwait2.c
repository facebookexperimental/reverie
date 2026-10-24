/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

#define PAGE 4096
#define ARENA (2 * PAGE)
#define EPOLL_FD 20
#define EVENT_FD 21
#define SECOND_FD 22
#define NULL_OFFSET UINT32_MAX
#define DATA_A UINT64_C(0x0123456789abcdef)
#define DATA_B UINT64_C(0xfedcba9876543210)
#define NOISE UINT64_C(0x8000000100000000)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        dprintf(2, "epoll_pwait2: line %d, errno %d\n", __LINE__, errno); \
        return 80; \
    } \
} while (0)

_Static_assert(sizeof(struct epoll_event) == 12, "x86-64 packed epoll event");
_Static_assert(sizeof(struct timespec) == 16, "x86-64 timespec");

static long wait_zero(uint64_t fd, void *out, uint64_t count,
                      const struct timespec *zero, uint64_t mask_size) {
    return syscall(SYS_epoll_pwait2, fd, out, count, zero, NULL, mask_size);
}

/* Keep all seven checks and the exact success line of Hermit's original cell:
 * https://github.com/rrnewton/hermit/blob/0f028322361f7357203ed4ef841dc63a770a2180/tests/c/epoll_pwait2_readiness.c
 */
static int seven_check_contract(void) {
    enum { EXPECTED_CHECKS = 7 };
    int ok = 0;
    struct timespec zero = {0, 0};
    int efd = eventfd(0, EFD_NONBLOCK);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0 || ep < 0) {
        printf("epoll_pwait2 SETUP_FAIL\n");
        return 1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = efd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev) == 0) ok++;
    uint64_t one = 1;
    if (write(efd, &one, sizeof(one)) == (ssize_t)sizeof(one)) ok++;
    struct epoll_event out[4];
    memset(out, 0, sizeof(out));
    int n = (int)wait_zero(ep, out, 4, &zero, 0);
    if (n == 1) ok++;
    if (n == 1 && out[0].data.fd == efd) ok++;
    if (n == 1 && (out[0].events & EPOLLIN)) ok++;
    if (epoll_ctl(ep, EPOLL_CTL_DEL, efd, &ev) == 0) ok++;
    int n2 = (int)wait_zero(ep, out, 4, &zero, 0);
    if (n2 == 0) ok++;
    close(efd);
    close(ep);
    printf("epoll_pwait2 ok=%d\n", ok);
    return ok == EXPECTED_CHECKS ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int pin_descriptor(int fd, int destination) {
    REQUIRE(fd >= 0);
    if (fd != destination) {
        REQUIRE(dup2(fd, destination) == destination);
        REQUIRE(close(fd) == 0);
    }
    return 0;
}

static int register_event(int ep, int fd, uint64_t data) {
    struct epoll_event event = {.events = EPOLLIN | EPOLLONESHOT};
    event.data.u64 = data;
    REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    return 0;
}

static int arm_event(int fd) {
    uint64_t one = 1;
    REQUIRE(write(fd, &one, sizeof(one)) == sizeof(one));
    return 0;
}

static void expected_event(unsigned char *arena, unsigned offset, uint64_t data) {
    uint32_t events = EPOLLIN;
    memcpy(arena + offset, &events, sizeof(events));
    memcpy(arena + offset + sizeof(events), &data, sizeof(data));
}

static int write_all(const void *data, size_t length) {
    const unsigned char *bytes = data;
    while (length) {
        ssize_t count = write(STDOUT_FILENO, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

struct report {
    int64_t result;
    int32_t error;
    uint32_t mode;
    uint64_t raw_fd;
    uint64_t raw_count;
    uint32_t offset;
    uint32_t calls;
    int64_t retry_result;
    int64_t after_result;
    uint64_t mask_size;
};
_Static_assert(sizeof(struct report) == 64, "complete report layout");

static int parity_case(unsigned mode, int expected_bad_fd_errno) {
    REQUIRE(mode < 16);
    REQUIRE(pin_descriptor(epoll_create1(EPOLL_CLOEXEC), EPOLL_FD) == 0);
    REQUIRE(pin_descriptor(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC), EVENT_FD) == 0);
    REQUIRE(register_event(EPOLL_FD, EVENT_FD, DATA_A) == 0);
    unsigned char *arena = mmap(NULL, ARENA, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct timespec *zero = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(arena != MAP_FAILED && zero != MAP_FAILED);
    memset(arena, 0xa5, ARENA);
    memset(zero, 0xa5, PAGE);
    zero->tv_sec = zero->tv_nsec = 0;
    unsigned char expected_timeout[PAGE];
    memcpy(expected_timeout, zero, PAGE);
    REQUIRE(mprotect(zero, PAGE, PROT_READ) == 0);

    struct report output = {0};
    output.mode = mode;
    output.raw_fd = EPOLL_FD;
    output.raw_count = 4;
    output.offset = 128;
    output.calls = 1;
    long expected_result = 0;
    int expected_error = 0;
    int ready = 0;
    int protection = -1;
    int retry = 0;
    switch (mode) {
    case 0: /* A registered but empty eventfd produces no output. */
        break;
    case 1: /* The ready event is copied exactly once. */
    case 2: /* epfd and maxevents use signed low 32-bit words. */
    case 3: /* NULL sigmask ignores even an absurd sigsetsize. */
        ready = 1;
        expected_result = 1;
        if (mode == 2) {
            output.raw_fd |= NOISE;
            output.raw_count |= NOISE;
        }
        if (mode == 3) output.mask_size = UINT64_MAX;
        break;
    case 4: /* Empty epoll does not write a numerically valid NULL output. */
    case 5: /* Ready epoll faults at NULL and keeps its one-shot event armed. */
        output.offset = NULL_OFFSET;
        ready = retry = mode == 5;
        break;
    case 6: /* Empty epoll does not require writable output pages. */
    case 7: /* Ready epoll faults on read-only output. */
        output.offset = PAGE + 128;
        protection = PROT_READ;
        ready = retry = mode == 7;
        break;
    case 8: /* Empty epoll does not even require mapped/readable output. */
    case 9: /* Ready epoll faults on PROT_NONE output. */
        output.offset = PAGE + 128;
        protection = PROT_NONE;
        ready = retry = mode == 9;
        break;
    case 10: /* Mask store succeeds; the following eight-byte data store faults. */
        output.offset = PAGE - 4;
        protection = PROT_NONE;
        ready = retry = 1;
        break;
    case 11: /* A complete first event survives the second event's data fault. */
        REQUIRE(pin_descriptor(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC), SECOND_FD) == 0);
        REQUIRE(register_event(EPOLL_FD, SECOND_FD, DATA_B) == 0);
        output.offset = PAGE - 16;
        protection = PROT_NONE;
        expected_result = 1;
        ready = retry = 1;
        break;
    case 12: /* Zero low count wins over an inaccessible output. */
        output.raw_count = NOISE;
        output.offset = NULL_OFFSET;
        expected_result = -1;
        expected_error = EINVAL;
        break;
    case 13: /* Negative low count wins over an inaccessible output. */
        output.raw_count = NOISE | UINT32_MAX;
        output.offset = NULL_OFFSET;
        expected_result = -1;
        expected_error = EINVAL;
        break;
    case 14: /* Require the exact host-ABI errno supplied by the native harness. */
        REQUIRE(expected_bad_fd_errno > 0);
        output.raw_fd = UINT64_MAX;
        output.raw_count = 0;
        expected_result = -1;
        expected_error = expected_bad_fd_errno;
        break;
    case 15: /* A proven eventfd is not an epoll instance. */
        output.raw_fd = EVENT_FD;
        expected_result = -1;
        expected_error = EINVAL;
        break;
    }
    if (retry && mode != 11) {
        expected_result = -1;
        expected_error = EFAULT;
    }
    if (ready) REQUIRE(arm_event(EVENT_FD) == 0);
    /* Kernel ready-list order comes from these two sequential writes, with no
     * other writer or asynchronous source. No sorting can hide a lost event. */
    if (mode == 11) REQUIRE(arm_event(SECOND_FD) == 0);
    unsigned char expected[ARENA];
    memcpy(expected, arena, ARENA);
    if (expected_result == 1) expected_event(expected, output.offset, DATA_A);
    if (mode == 10 || mode == 11) {
        uint32_t events = EPOLLIN;
        memcpy(expected + PAGE - 4, &events, sizeof(events));
    }
    if (protection >= 0) REQUIRE(mprotect(arena + PAGE, PAGE, protection) == 0);
    void *events = output.offset == NULL_OFFSET ? NULL : arena + output.offset;
    errno = 0;
    output.result = wait_zero(output.raw_fd, events, output.raw_count, zero, output.mask_size);
    output.error = output.result == -1 ? errno : 0;
    REQUIRE(output.result == expected_result && output.error == expected_error);
    if (retry) {
        /* The failed event must still be deliverable. Its one-shot state is
         * disabled only by this successful copy, not the earlier EFAULT. */
        output.calls = 3;
        errno = 0;
        output.retry_result = wait_zero(EPOLL_FD, arena + 512, 4, zero, 0);
        REQUIRE(output.retry_result == 1 && errno == 0);
        expected_event(expected, 512, mode == 11 ? DATA_B : DATA_A);
        errno = 0;
        output.after_result = wait_zero(EPOLL_FD, arena + 544, 4, zero, 0);
        REQUIRE(output.after_result == 0 && errno == 0);
    }
    REQUIRE(memcmp(zero, expected_timeout, PAGE) == 0);
    /* Inspect protected bytes only after the tested calls: the complete arena,
     * including untouched suffixes, must equal the explicit expected bytes. */
    REQUIRE(mprotect(arena, ARENA, PROT_READ) == 0);
    REQUIRE(memcmp(arena, expected, ARENA) == 0);
    REQUIRE(write_all(&output, sizeof(output)) == 0);
    REQUIRE(write_all(arena, ARENA) == 0);
    REQUIRE(write_all(zero, PAGE) == 0);
    REQUIRE(munmap(arena, ARENA) == 0 && munmap(zero, PAGE) == 0);
    REQUIRE(close(EVENT_FD) == 0 && close(EPOLL_FD) == 0);
    if (mode == 11) REQUIRE(close(SECOND_FD) == 0);
    return 0;
}

static int captured_case(void) {
    struct timespec zero = {0, 0};
    /* Prove that capture alone is allowed before selecting a captured carrier. */
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    REQUIRE(efd >= 0 && ep >= 0);
    REQUIRE(register_event(ep, efd, DATA_A) == 0 && arm_event(efd) == 0);
    unsigned char events[64], expected[64];
    memset(events, 0xa5, sizeof(events));
    memcpy(expected, events, sizeof(events));
    expected_event(expected, 0, DATA_A);
    REQUIRE(wait_zero(ep, events, 4, &zero, 0) == 1);
    REQUIRE(memcmp(events, expected, sizeof(events)) == 0);
    REQUIRE(close(ep) == 0 && close(efd) == 0);

    int alias = dup(STDOUT_FILENO);
    REQUIRE(alias >= 3);
    int targets[] = {STDOUT_FILENO, alias};
    for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        ep = epoll_create1(EPOLL_CLOEXEC);
        REQUIRE(ep >= 0);
        struct epoll_event interest = {.events = EPOLLOUT};
        interest.data.u64 = DATA_B;
        /* The bounded libtest child has a pipe at host stdout. Require a real
         * registration; EPERM on a regular-file carrier is not this test. */
        REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, targets[i], &interest) == 0);
        memset(events, 0xa5, sizeof(events));
        memcpy(expected, events, sizeof(events));
        errno = 0;
        REQUIRE(wait_zero(ep, events, 4, &zero, 0) == -1 && errno == ENOSYS);
        REQUIRE(memcmp(events, expected, sizeof(events)) == 0);
        REQUIRE(zero.tv_sec == 0 && zero.tv_nsec == 0);
        REQUIRE(close(ep) == 0);
    }
    REQUIRE(close(alias) == 0);
    static const char success[] = "captured epoll_pwait2 refused 2\n";
    REQUIRE(write_all(success, sizeof(success) - 1) == 0);
    return 0;
}

int main(int argc, char **argv) {
    REQUIRE(argc == 2);
    if (strcmp(argv[1], "contract") == 0) return seven_check_contract();
    if (strcmp(argv[1], "captured") == 0) return captured_case();
    char *end = NULL;
    unsigned long mode = strtoul(argv[1], &end, 10);
    REQUIRE(end != argv[1] && mode < 16);
    int expected_bad_fd_errno = 0;
    if (mode == 14) {
        /* This input is identical for native and every KVM path. Never probe
         * inside the guest: that would let the tested implementation choose
         * its own expected errno. No alternative errno is accepted here. */
        REQUIRE(*end == ':');
        char *error_end = NULL;
        unsigned long error = strtoul(end + 1, &error_end, 10);
        REQUIRE(error_end != end + 1 && *error_end == '\0' && error > 0 && error <= INT_MAX);
        expected_bad_fd_errno = (int)error;
    } else {
        REQUIRE(*end == '\0');
    }
    return parity_case((unsigned)mode, expected_bad_fd_errno);
}
