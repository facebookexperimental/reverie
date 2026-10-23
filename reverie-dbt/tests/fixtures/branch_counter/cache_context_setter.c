/* Isolated Linux/x86-64 release-build decision control.  This does not call
 * DynamoRIO or install a kernel context.  decision.inc is an exact source
 * extraction; the setter and notification below are test doubles. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char byte;
typedef byte *app_pc;
typedef struct { app_pc pc; } priv_mcontext_t;
typedef struct dcontext_t dcontext_t;
typedef struct { dcontext_t *dcontext; } thread_record_t;
struct dcontext_t { thread_record_t *thread_record; };
typedef int thread_synch_state_t;

/* Match the extracted code's Linux/x86-64 Release configuration. */
#define _IF_X64(...) , __VA_ARGS__
#define _IF_WINDOWS(...)
#define IF_ARM(...)
#define ASSERT(...) ((void)0)
#define LOG(...) ((void)0)

enum mode { DIRECT_SUCCESS, QUEUED_SUCCESS, DIRECT_FAILURE };
static const char *const names[] = { "direct-success", "queued-success", "failure" };
static enum mode active_mode;
static unsigned setter_calls, notifications;
static bool setter_completed;
static size_t allocation_size;
static priv_mcontext_t *queued_context;
static dcontext_t *expected_target;
static byte raw_location, app_location, reset_location;

static void
check(bool ok, const char *reason)
{
    if (!ok) {
        fprintf(stderr, "FAIL %s: %s\n", names[active_mode], reason);
        exit(1);
    }
}

static app_pc
get_reset_exit_stub(dcontext_t *target)
{
    check(target == expected_target, "wrong reset target");
    return &reset_location;
}

static void
release_context(priv_mcontext_t *mc)
{
    /* A post-setter dereference cannot rely on freed heap storage surviving.
     * No allocation occurs between this unmap and the notification. */
    check(munmap(mc, allocation_size) == 0, "mock context release failed");
}

static bool
set_synched_thread_context(thread_record_t *trec, priv_mcontext_t *mc,
                           void *cxt, size_t cxt_size,
                           thread_synch_state_t desired_state, void *cxt_alloc)
{
    check(trec == expected_target->thread_record, "wrong setter target");
    check(cxt == NULL && cxt_size == 0 && desired_state == 7,
          "wrong setter arguments");
    check(cxt_alloc == mc, "wrong allocation owner");
    check(mc->pc == &reset_location, "setter did not receive reset continuation");
    check(setter_calls == 0 && notifications == 0, "setter/notification order");
    ++setter_calls;
    if (active_mode == QUEUED_SUCCESS)
        queued_context = mc; /* Ownership passes to the simulated target. */
    else
        release_context(mc); /* Direct success AND failure consume mc. */
    setter_completed = true;
    return active_mode != DIRECT_FAILURE;
}

static void
instrument_cache_context_invalidated(dcontext_t *target, app_pc source_pc,
                                     app_pc target_pc)
{
    check(active_mode != DIRECT_FAILURE, "unexpected notification");
    check(setter_completed && setter_calls == 1, "notification before setter return");
    check(notifications == 0, "duplicate notification");
    check(target == expected_target, "wrong notification target");
    check(source_pc == &raw_location, "raw PC was not preserved");
    check(target_pc == &app_location, "application PC was not copied before reset");
    if (active_mode == QUEUED_SUCCESS)
        check(queued_context != NULL && queued_context->pc == &reset_location,
              "queued context ownership was not retained");
    ++notifications;
}

#ifndef SETTER_DECISION_INCLUDE
#define SETTER_DECISION_INCLUDE "decision.inc"
#endif

static void
exercise(enum mode mode)
{
    active_mode = mode;
    setter_calls = notifications = 0;
    setter_completed = false;
    queued_context = NULL;
    thread_record_t thread;
    dcontext_t target = { .thread_record = &thread };
    thread.dcontext = &target;
    expected_target = &target;
    dcontext_t *dcontext = &target;
    priv_mcontext_t *mc = mmap(NULL, allocation_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(mc != MAP_FAILED, "context allocation failed");
    mc->pc = &app_location;
    app_pc pre_translation = &raw_location;
    thread_synch_state_t synch_state = 7;
    bool free_cxt = true;
    bool res = false;

#include SETTER_DECISION_INCLUDE

    check(setter_calls == 1 && setter_completed, "setter missing");
    check(res == (mode != DIRECT_FAILURE), "release result was discarded");
    check(!free_cxt, "caller retained a consumed context");
    check(notifications == (mode == DIRECT_FAILURE ? 0u : 1u),
          "wrong notification count");
    if (mode == QUEUED_SUCCESS) {
        check(queued_context == mc, "queued target lost its context");
        release_context(queued_context);
        queued_context = NULL;
    }
    printf("PASS %s\n", names[mode]);
}

int
main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (size_t)page_size < sizeof(priv_mcontext_t)) {
        fputs("SETUP: invalid page size\n", stderr);
        return 2;
    }
    allocation_size = (size_t)page_size;
    exercise(DIRECT_SUCCESS);
    exercise(QUEUED_SUCCESS);
    exercise(DIRECT_FAILURE);
    puts("PASS component-notification-decision");
    return 0;
}
