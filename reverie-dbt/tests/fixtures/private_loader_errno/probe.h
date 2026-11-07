#ifndef PRIVATE_LOADER_ERRNO_PROBE_H
#define PRIVATE_LOADER_ERRNO_PROBE_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define PROBE_MARKER 0x4552524eL
#define PROBE_THREADS 2
#define PROBE_PHASES 2
#define PROBE_OPERATIONS 11

typedef struct {
    long result;
    int error;
    int sentinel;
    long expected;
    int expected_error;
    int payload_ok;
} observation_t;

/* Setup and evidence do not use the imported functions under test. */
static inline long raw_call(long number, long a, long b, long c, long d) {
    register long fourth __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c), "r"(fourth)
                     : "rcx", "r11", "memory");
    return result;
}

static inline int private_cookie(int slot) { return 1200 + slot; }
static inline int application_cookie(int slot, int phase) { return 1400 + slot * 2 + phase; }

static inline void begin_observation(observation_t *o, int slot, int index,
                              long expected, int error) {
    o->sentinel = 800 + slot * 32 + index;
    o->expected = expected;
    o->expected_error = error == 0 ? o->sentinel : error;
    o->payload_ok = 1;
    errno = o->sentinel;
}

static inline void end_observation(observation_t *o, long result) {
    /* Copy errno before reporting or performing any other libc operation. */
    o->error = errno;
    o->result = result;
}

static inline int observation_ok(const observation_t *o) {
    return o->result == o->expected && o->error == o->expected_error && o->payload_ok;
}

/* All operations are ordinary libc imports, with independent raw pipe setup. */
static inline int run_operations(int slot, observation_t out[PROBE_OPERATIONS]) {
    char buffer[4096];
    struct iovec bad = {buffer, 1};
    int pipefd[2] = {-1, -1};
    begin_observation(&out[0], slot, 0, -1, EBADF);
    end_observation(&out[0], read(-1, buffer, 1));
    begin_observation(&out[1], slot, 1, -1, EBADF);
    end_observation(&out[1], write(-1, "x", 1));
    begin_observation(&out[2], slot, 2, -1, EBADF);
    end_observation(&out[2], writev(-1, &bad, 1));

    if (raw_call(SYS_pipe2, (long)pipefd, O_NONBLOCK | O_CLOEXEC, 0, 0) != 0)
        return 1;
    int setup_error = 0;
    begin_observation(&out[3], slot, 3, 0, 0);
    end_observation(&out[3], write(pipefd[1], "", 0));
    begin_observation(&out[4], slot, 4, 3, 0);
    end_observation(&out[4], write(pipefd[1], "abc", 3));
    begin_observation(&out[5], slot, 5, 3, 0);
    end_observation(&out[5], read(pipefd[0], buffer, 8));
    out[5].payload_ok = out[5].result == 3 && memcmp(buffer, "abc", 3) == 0;
    begin_observation(&out[6], slot, 6, -1, EAGAIN);
    end_observation(&out[6], read(pipefd[0], buffer, 1));

    long capacity = raw_call(SYS_fcntl, pipefd[1], F_GETPIPE_SZ, 0, 0);
    if (capacity <= 0 || capacity > 4 * 1024 * 1024) {
        setup_error = 2;
        goto done;
    }
    memset(buffer, 'f', sizeof(buffer));
    long filled = 0;
    for (;;) {
        long n = raw_call(SYS_write, pipefd[1], (long)buffer, sizeof(buffer), 0);
        if (n == -EAGAIN)
            break;
        if (n <= 0 || filled + n > capacity) {
            setup_error = 3;
            goto done;
        }
        filled += n;
    }
    if (filled != capacity) {
        setup_error = 4;
        goto done;
    }
    begin_observation(&out[7], slot, 7, -1, EAGAIN);
    end_observation(&out[7], write(pipefd[1], "x", 1));
    long drained = 0;
    for (;;) {
        long n = raw_call(SYS_read, pipefd[0], (long)buffer, sizeof(buffer), 0);
        if (n == -EAGAIN)
            break;
        if (n <= 0 || drained + n > filled) {
            setup_error = 5;
            goto done;
        }
        drained += n;
    }
    if (drained != filled) {
        setup_error = 6;
        goto done;
    }
    struct iovec good[2] = {{(void *)"xy", 2}, {(void *)"z", 1}};
    begin_observation(&out[8], slot, 8, 3, 0);
    end_observation(&out[8], writev(pipefd[1], good, 2));
    begin_observation(&out[9], slot, 9, 3, 0);
    end_observation(&out[9], read(pipefd[0], buffer, 8));
    out[9].payload_ok = out[9].result == 3 && memcmp(buffer, "xyz", 3) == 0;
    if (raw_call(SYS_close, pipefd[1], 0, 0, 0) != 0) {
        setup_error = 7;
        goto done;
    }
    pipefd[1] = -1;
    begin_observation(&out[10], slot, 10, 0, 0);
    end_observation(&out[10], read(pipefd[0], buffer, 1));
done:
    if (pipefd[1] >= 0 && raw_call(SYS_close, pipefd[1], 0, 0, 0) != 0)
        setup_error = 8;
    if (raw_call(SYS_close, pipefd[0], 0, 0, 0) != 0)
        setup_error = 9;
    return setup_error;
}
#endif
