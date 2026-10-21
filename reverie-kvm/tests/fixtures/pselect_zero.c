/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define ARENA (2 * PAGE)
#define READ_FD 20
#define WRITE_FD 21
#define SOCKET_FD 22
#define PEER_FD 23
#define PATH_FD 24
#define ABSENT_FD 30
#define LAST_FD 63
#define NONE UINT32_MAX
#define BAD (UINT32_MAX - 1)
#define BIT(fd) (UINT64_C(1) << (fd))
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        dprintf(2, "pselect zero: line %d, errno %d\n", __LINE__, errno); \
        return 80; \
    } \
} while (0)

struct mask_argument {
    const void *mask;
    uint64_t size;
};

struct report {
    int64_t result;
    int32_t error;
    uint32_t mode;
    uint64_t raw_nfds;
    uint32_t offsets[3];
    uint32_t reserved;
    int64_t timeout[2];
    uint64_t mask_size;
};
_Static_assert(sizeof(struct mask_argument) == 16, "x86-64 mask wrapper");
_Static_assert(sizeof(struct timespec) == 16, "x86-64 timespec");
_Static_assert(sizeof(struct report) == 64, "complete report layout");

static int pin_pair(int pair[2], int first, int second) {
    /* Retain both originals before replacing either destination. All changes
     * affect only this fixture process, never the Rust test's descriptor table. */
    int a = fcntl(pair[0], F_DUPFD_CLOEXEC, 80);
    int b = fcntl(pair[1], F_DUPFD_CLOEXEC, 80);
    REQUIRE(a >= 80 && b >= 80);
    REQUIRE(close(pair[0]) == 0 && close(pair[1]) == 0);
    REQUIRE(dup2(a, first) == first && dup2(b, second) == second);
    REQUIRE(close(a) == 0 && close(b) == 0);
    return 0;
}

static int fixed_descriptors(void) {
    int numbers[] = {READ_FD, WRITE_FD, SOCKET_FD, PEER_FD,
                     PATH_FD, ABSENT_FD, LAST_FD};
    for (unsigned i = 0; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        errno = 0;
        REQUIRE(close(numbers[i]) == 0 || errno == EBADF);
    }
    int pair[2];
    REQUIRE(pipe(pair) == 0);
    REQUIRE(pin_pair(pair, READ_FD, WRITE_FD) == 0);
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    REQUIRE(pin_pair(pair, SOCKET_FD, PEER_FD) == 0);
    int path = open(".", O_PATH | O_CLOEXEC);
    REQUIRE(path >= 0);
    REQUIRE(dup2(path, PATH_FD) == PATH_FD);
    if (path != PATH_FD) REQUIRE(close(path) == 0);
    REQUIRE(dup2(READ_FD, LAST_FD) == LAST_FD);
    errno = 0;
    REQUIRE(fcntl(ABSENT_FD, F_GETFD) == -1 && errno == EBADF);
    return 0;
}

static void put_word(unsigned char *arena, uint32_t offset, uint64_t word) {
    memcpy(arena + offset, &word, sizeof(word));
}

static void *set_pointer(unsigned char *arena, uint32_t offset) {
    if (offset == NONE) return NULL;
    if (offset == BAD) return (void *)(uintptr_t)-1;
    return arena + offset;
}

static int write_all(const void *data, size_t length) {
    const unsigned char *bytes = data;
    while (length) {
        ssize_t n = write(STDOUT_FILENO, bytes, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += n;
        length -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    REQUIRE(argc == 2);
    int mode = atoi(argv[1]);
    REQUIRE(mode >= 0 && mode < 18);
    REQUIRE(fixed_descriptors() == 0);
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
    output.mode = (uint32_t)mode;
    output.raw_nfds = WRITE_FD + 1;
    output.offsets[0] = 128;
    output.offsets[1] = output.offsets[2] = NONE;
    uint64_t inputs[3] = {BIT(READ_FD) | BIT(63), 0, 0};
    uint64_t results[3] = {0, 0, 0};
    long expected_result = 0;
    int expected_error = 0;
    int write_open = 1;
    int protected_page = -1;
    int protection = PROT_READ;

    /* Every mode makes exactly one raw pselect6 call. Preparation is causal:
     * no worker, timer, signal, retry, or observed clock affects readiness. */
    switch (mode) {
    case 0: /* Empty read end. */
        break;
    case 1: /* Buffered read end. */
    case 7: /* Dirty high nfds bits must be ignored. */
    case 9: /* NULL inner mask ignores even an absurd sigsetsize. */
        REQUIRE(write(WRITE_FD, "r", 1) == 1);
        results[0] = BIT(READ_FD);
        expected_result = 1;
        if (mode == 7) output.raw_nfds |= BIT(32) | BIT(63);
        if (mode == 9) output.mask_size = UINT64_MAX;
        break;
    case 2: { /* A drained pipe with a live writer is not readable. */
        char byte = 0;
        REQUIRE(write(WRITE_FD, "r", 1) == 1);
        REQUIRE(read(READ_FD, &byte, 1) == 1 && byte == 'r');
        break;
    }
    case 3: /* EOF is readable without buffered data. */
        REQUIRE(close(WRITE_FD) == 0);
        write_open = 0;
        results[0] = BIT(READ_FD);
        expected_result = 1;
        break;
    case 4: /* The pipe write end is writable. */
        output.offsets[0] = NONE;
        output.offsets[1] = 256;
        inputs[1] = BIT(WRITE_FD) | BIT(63);
        results[1] = BIT(WRITE_FD);
        expected_result = 1;
        break;
    case 5: /* One socket ready in two sets counts twice. */
    case 15: /* All three output pointers alias; except is copied last. */
        REQUIRE(write(PEER_FD, "s", 1) == 1);
        output.raw_nfds = SOCKET_FD + 1;
        output.offsets[1] = mode == 15 ? 128 : 256;
        if (mode == 15) output.offsets[2] = 128;
        inputs[0] = inputs[1] = inputs[2] = BIT(SOCKET_FD) | BIT(63);
        results[0] = results[1] = BIT(SOCKET_FD);
        expected_result = 2;
        break;
    case 6: /* Linux's open-fd check precedes fdget's O_PATH exclusion.
             * Its POLLNVAL then contributes to all three select masks. */
        output.raw_nfds = PATH_FD + 1;
        output.offsets[1] = 256;
        output.offsets[2] = 384;
        inputs[0] = inputs[1] = inputs[2] = BIT(PATH_FD) | BIT(63);
        results[0] = results[1] = results[2] = BIT(PATH_FD);
        expected_result = 3;
        break;
    case 8: /* Low-word zero ignores every inaccessible fd-set pointer. */
    case 17: /* A negative low word is EINVAL before fd-set access. */
        output.raw_nfds = BIT(32) | (mode == 17 ? UINT32_MAX : 0);
        output.offsets[0] = output.offsets[1] = output.offsets[2] = BAD;
        if (mode == 17) {
            expected_result = -1;
            expected_error = EINVAL;
        }
        break;
    case 10: /* Exactly one word at the readable mapping boundary. */
        REQUIRE(write(WRITE_FD, "r", 1) == 1);
        output.raw_nfds = 64;
        output.offsets[0] = PAGE - 8;
        inputs[0] = results[0] = BIT(LAST_FD);
        expected_result = 1;
        protected_page = 1;
        protection = PROT_NONE;
        break;
    case 11: /* Readable input, entirely read-only output. */
    case 12: /* An eight-byte fd set crosses writable -> read-only. */
        output.offsets[0] = mode == 11 ? PAGE + 128 : PAGE - 4;
        expected_result = -1;
        expected_error = EFAULT;
        protected_page = 1;
        break;
    case 13: /* Read output survives the second set's copyout fault. */
    case 14: /* Read and write outputs survive the third set's fault. */
        REQUIRE(write(WRITE_FD, "r", 1) == 1);
        output.offsets[1] = mode == 13 ? PAGE + 128 : 256;
        output.offsets[2] = mode == 14 ? PAGE + 128 : 384;
        inputs[1] = BIT(WRITE_FD) | BIT(63);
        inputs[2] = BIT(READ_FD) | BIT(63);
        results[0] = BIT(READ_FD);
        results[1] = BIT(WRITE_FD);
        expected_result = -1;
        expected_error = EFAULT;
        protected_page = 1;
        break;
    case 16: /* A selected absent fd beats read-set copyout EFAULT. */
        REQUIRE(write(WRITE_FD, "r", 1) == 1);
        output.raw_nfds = ABSENT_FD + 1;
        output.offsets[0] = PAGE + 128;
        output.offsets[1] = 256;
        inputs[1] = BIT(ABSENT_FD) | BIT(63);
        expected_result = -1;
        expected_error = EBADF;
        protected_page = 1;
        break;
    }
    for (unsigned i = 0; i < 3; ++i) {
        if (output.offsets[i] < ARENA) put_word(arena, output.offsets[i], inputs[i]);
    }
    unsigned char expected[ARENA];
    memcpy(expected, arena, ARENA);
    if (expected_error == 0) {
        /* This order is observable when all three pointers alias. */
        for (unsigned i = 0; i < 3; ++i) {
            if (output.offsets[i] < ARENA)
                put_word(expected, output.offsets[i], results[i]);
        }
    } else if (mode == 12) {
        /* The high half keeps its input sentinel; only the writable prefix clears. */
        memset(expected + PAGE - 4, 0, 4);
    } else if (mode == 13 || mode == 14) {
        put_word(expected, output.offsets[0], results[0]);
        if (mode == 14) put_word(expected, output.offsets[1], results[1]);
    }
    if (protected_page >= 0)
        REQUIRE(mprotect(arena + protected_page * PAGE, PAGE, protection) == 0);

    struct mask_argument mask = {.mask = NULL, .size = output.mask_size};
    errno = 0;
    output.result = syscall(SYS_pselect6, output.raw_nfds,
                            set_pointer(arena, output.offsets[0]),
                            set_pointer(arena, output.offsets[1]),
                            set_pointer(arena, output.offsets[2]),
                            zero, mode == 9 ? &mask : NULL);
    output.error = output.result == -1 ? errno : 0;
    memcpy(output.timeout, zero, sizeof(output.timeout));
    REQUIRE(output.result == expected_result && output.error == expected_error);
    REQUIRE(memcmp(zero, expected_timeout, PAGE) == 0);
    REQUIRE(mask.mask == NULL && mask.size == output.mask_size);
    /* Read inaccessible bytes only after the syscall so their preservation is
     * compared too. This never grants the syscall extra write permission. */
    REQUIRE(mprotect(arena, ARENA, PROT_READ) == 0);
    REQUIRE(memcmp(arena, expected, ARENA) == 0);
    REQUIRE(write_all(&output, sizeof(output)) == 0);
    REQUIRE(write_all(arena, ARENA) == 0);
    REQUIRE(munmap(arena, ARENA) == 0 && munmap(zero, PAGE) == 0);
    REQUIRE(close(READ_FD) == 0 && close(LAST_FD) == 0);
    if (write_open) REQUIRE(close(WRITE_FD) == 0);
    REQUIRE(close(SOCKET_FD) == 0 && close(PEER_FD) == 0 && close(PATH_FD) == 0);
    return 0;
}
