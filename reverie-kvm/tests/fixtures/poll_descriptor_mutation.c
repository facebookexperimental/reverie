#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EVENT_FD 198
static int ready_pipe[2];
static struct pollfd descriptor;

struct report {
    int64_t before, ready, after;
    uint64_t counter;
    int32_t error;
    int16_t before_revents, ready_revents, after_revents;
    uint16_t reserved;
    uint32_t sentinel;
    int32_t ready_fd;
    int16_t ready_events;
    uint16_t reserved2;
};
_Static_assert(sizeof(struct report) == 56, "complete report layout");

static void *worker(void *argument) {
    int event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event < 0 || dup2(event, EVENT_FD) != EVENT_FD) _exit(90);
    if (event != EVENT_FD && close(event)) _exit(91);
    int gate = open(argument, O_RDONLY | O_CLOEXEC);
    if (gate < 0 || write(ready_pipe[1], "r", 1) != 1) _exit(92);
    char release = 0;
    if (read(gate, &release, 1) != 1 || release != 'g') _exit(93);
    /* The observer released us only after the root entered the real wait. */
    __atomic_store_n(&descriptor.fd, -17, __ATOMIC_RELEASE);
    __atomic_store_n(&descriptor.events, POLLOUT, __ATOMIC_RELEASE);
    uint64_t counter = 7;
    if (write(EVENT_FD, &counter, sizeof(counter)) != sizeof(counter)) _exit(94);
    if (close(gate)) _exit(95);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || pipe(ready_pipe)) return 80;
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, argv[1])) return 81;
    char ready = 0;
    if (read(ready_pipe[0], &ready, 1) != 1 || ready != 'r') return 82;
    struct report output;
    memset(&output, 0, sizeof(output));
    output.sentinel = 0xa1b2c3d4;
    descriptor = (struct pollfd){.fd = EVENT_FD, .events = POLLIN};
    /* Zero probes use poll, so they cannot satisfy the blocked ppoll witness. */
    output.before = syscall(SYS_poll, &descriptor, 1, 0);
    output.before_revents = descriptor.revents;
    if (output.before != 0 || descriptor.revents != 0) return 83;
    struct timespec timeout = {.tv_sec = 2, .tv_nsec = 0};
    errno = 0;
    output.ready = syscall(SYS_ppoll, &descriptor, 1, &timeout, 0, 8);
    output.error = output.ready == -1 ? errno : 0;
    output.ready_revents = descriptor.revents;
    output.ready_fd = __atomic_load_n(&descriptor.fd, __ATOMIC_ACQUIRE);
    output.ready_events = __atomic_load_n(&descriptor.events, __ATOMIC_ACQUIRE);
    if (output.ready_fd != -17 || output.ready_events != POLLOUT) return 84;
    if (output.ready != 1 || output.error || descriptor.revents != POLLIN) return 85;
    if (read(EVENT_FD, &output.counter, sizeof(output.counter)) != sizeof(output.counter)
        || output.counter != 7) return 86;
    output.after = syscall(SYS_poll, &descriptor, 1, 0);
    output.after_revents = descriptor.revents;
    if (output.after != 0 || descriptor.revents != 0) return 87;
    void *result = 0;
    if (pthread_join(thread, &result) || result) return 88;
    if (close(EVENT_FD) || close(ready_pipe[0]) || close(ready_pipe[1])) return 89;
    if (write(1, &output, sizeof(output)) != sizeof(output)) return 96;
    return write(1, &descriptor, sizeof(descriptor)) == sizeof(descriptor) ? 0 : 97;
}
