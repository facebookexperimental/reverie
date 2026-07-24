#define _GNU_SOURCE

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { THREAD_COUNT = 8, WAVE_COUNT = 16 };

struct worker_arg {
    unsigned wave;
    unsigned index;
};

static atomic_uint completed;

static void *worker(void *opaque)
{
    struct worker_arg *arg = opaque;
    long tid = syscall(SYS_gettid);

    assert(tid > 0);
    atomic_fetch_add_explicit(&completed, 1, memory_order_relaxed);
    return (void *)(uintptr_t)(1 + arg->wave * THREAD_COUNT + arg->index);
}

int main(void)
{
    pthread_t threads[THREAD_COUNT];
    struct worker_arg args[THREAD_COUNT];

    for (unsigned wave = 0; wave < WAVE_COUNT; ++wave) {
        for (unsigned index = 0; index < THREAD_COUNT; ++index) {
            args[index] = (struct worker_arg){ .wave = wave, .index = index };
            assert(pthread_create(&threads[index], NULL, worker, &args[index]) == 0);
        }

        for (unsigned index = 0; index < THREAD_COUNT; ++index) {
            void *result = NULL;
            uintptr_t expected = 1 + wave * THREAD_COUNT + index;

            assert(pthread_join(threads[index], &result) == 0);
            assert((uintptr_t)result == expected);
        }
    }

    assert(atomic_load_explicit(&completed, memory_order_relaxed) ==
           THREAD_COUNT * WAVE_COUNT);
    puts("thread-lifecycle: ok");
    return 0;
}
