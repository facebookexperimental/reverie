#define _GNU_SOURCE
#include "probe.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static int report_fd;
static int native_mode;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static unsigned failures, setup_errors, calls;

static void emit(const char *line, int length) {
    if (length <= 0 || length >= 384 ||
        raw_call(SYS_write, report_fd, (long)line, length, 0) != length)
        _exit(93);
}

static void *worker(void *argument) {
    int slot = (int)(intptr_t)argument;
    int *location = __errno_location();
    for (int phase = 0; phase < PROBE_PHASES; ++phase) {
        int prior_ok = phase == 0 || !native_mode || *location == private_cookie(slot);
        int sentinel = application_cookie(slot, phase);
        observation_t observations[PROBE_OPERATIONS] = {{0}};
        int setup = 0;
        *location = sentinel;
        long result;
        if (native_mode) {
            setup = run_operations(slot, observations);
            result = raw_call(SYS_getpid, 0, 0, 0, 0);
        } else {
            result = syscall(SYS_getpid, PROBE_MARKER, phase, slot,
                             (uintptr_t)location, sentinel);
        }
        int after = *location;
        pthread_mutex_lock(&output_lock);
        char line[384];
        int n = snprintf(line, sizeof(line),
            "GUEST slot=%d phase=%d tid=%ld ptr=%llx accessor=%llx before=%d after=%d result=%ld prior_ok=%d setup=%d\n",
            slot, phase, raw_call(SYS_gettid, 0, 0, 0, 0),
            (unsigned long long)(uintptr_t)location,
            (unsigned long long)(uintptr_t)&__errno_location, sentinel, after, result,
            prior_ok, setup);
        emit(line, n);
        calls++;
        if (result <= 0 || !prior_ok || (!native_mode && after != sentinel))
            failures++;
        if (setup != 0)
            setup_errors++;
        else if (native_mode) {
            for (int i = 0; i < PROBE_OPERATIONS; ++i) {
                observation_t *o = &observations[i];
                n = snprintf(line, sizeof(line),
                    "OP slot=%d phase=%d op=%d result=%ld errno=%d expected=%ld expected_errno=%d payload=%d\n",
                    slot, phase, i, o->result, o->error, o->expected,
                    o->expected_error, o->payload_ok);
                emit(line, n);
                if (!observation_ok(o))
                    failures++;
            }
        }
        pthread_mutex_unlock(&output_lock);
        *location = private_cookie(slot);
        /* Both threads remain alive until the other's phase is complete. */
        int rc = pthread_barrier_wait(&barrier);
        if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD)
            _exit(93);
    }
    return NULL;
}

int main(int argc, char **argv) {
    native_mode = argc == 3 && strcmp(argv[1], "--native") == 0;
    if ((!native_mode && argc != 2) || (native_mode && argc != 3))
        return 93;
    const char *path = argv[native_mode ? 2 : 1];
    report_fd = (int)raw_call(SYS_openat, AT_FDCWD, (long)path,
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (report_fd < 0 || pthread_barrier_init(&barrier, NULL, PROBE_THREADS) != 0)
        return 93;
    pthread_t threads[PROBE_THREADS];
    for (int i = 0; i < PROBE_THREADS; ++i)
        if (pthread_create(&threads[i], NULL, worker, (void *)(intptr_t)i) != 0)
            return 93;
    for (int i = 0; i < PROBE_THREADS; ++i)
        if (pthread_join(threads[i], NULL) != 0)
            return 93;
    char line[384];
    int n = snprintf(line, sizeof(line),
        "SUMMARY calls=%u threads=%d failures=%u setup_errors=%u\n",
        calls, PROBE_THREADS, failures, setup_errors);
    emit(line, n);
    if (raw_call(SYS_close, report_fd, 0, 0, 0) != 0 ||
        pthread_barrier_destroy(&barrier) != 0)
        return 93;
    const char output[] = "private-errno-guest-complete\n";
    if (raw_call(SYS_write, 1, (long)output, sizeof(output) - 1, 0) != (long)(sizeof(output) - 1))
        return 93;
    return setup_errors != 0 ? 93 : (failures != 0 ? 1 : 0);
}
