#ifdef PRIVATE_ERRNO_NO_LIBC
#include "dr_api.h"

/* Separate libc-free compatibility image: read/write remain actual imports.
 * All setup and reporting use raw Linux or DR-owned operations. */
extern ssize_t read(int fd, void *buffer, size_t count);
extern ssize_t write(int fd, const void *buffer, size_t count);
static long raw3(long number, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}
static bool same(const char *a, const char *b) {
    while (*a != 0 && *a == *b) { ++a; ++b; }
    return *a == *b;
}
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    (void)id;
    if (argc != 3)
        dr_exit_process(94);
    bool success = same(argv[2], "success");
    bool error_read = same(argv[2], "error-read");
    bool error_write = same(argv[2], "error-write");
    if (!success && !error_read && !error_write)
        dr_exit_process(94);
    file_t report = dr_open_file(argv[1], DR_FILE_WRITE_REQUIRE_NEW);
    int pipes[2];
    char buffer[8];
    if (report == INVALID_FILE || raw3(293, (long)pipes, 0, 0) != 0 ||
        write(pipes[1], "", 0) != 0 || write(pipes[1], "abc", 3) != 3 ||
        read(pipes[0], buffer, sizeof(buffer)) != 3 ||
        buffer[0] != 'a' || buffer[1] != 'b' || buffer[2] != 'c' ||
        raw3(3, pipes[1], 0, 0) != 0 || read(pipes[0], buffer, 1) != 0 ||
        raw3(3, pipes[0], 0, 0) != 0)
        dr_exit_process(94);
    const char done[] = "NO_LIBC success=1 operations=4 payload=1\n";
    if (dr_write_file(report, done, sizeof(done) - 1) != (ssize_t)(sizeof(done) - 1))
        dr_exit_process(94);
    dr_close_file(report);
    if (success)
        return;
    if (error_read)
        (void)read(-1, buffer, 1);
    else
        (void)write(-1, buffer, 1);
    /* An old raw result or silent -1 cannot satisfy a named unsupported error. */
    dr_exit_process(94);
}

#else
#define _GNU_SOURCE
#include "probe.h"
#include "dr_api.h"
#include <asm/prctl.h>

#ifdef PRIVATE_ERRNO_WRONG_PROVIDER
/* Deliberately separate test-only provider: real libc import fixtures above
 * must never be replaced by this refusal control. */
static _Thread_local int wrong_provider_errno;
int *__errno_location(void) {
    return &wrong_provider_errno;
}
#endif

/* Malformed accessor images are separate negative clients, never the real
 * libc-import witness.  Their exact symbol types/segments are checked first. */
#if defined(PRIVATE_ERRNO_OBJECT)
__asm__(".pushsection .data\n.globl __errno_location\n"
        ".type __errno_location,@object\n__errno_location: .quad 0\n"
        ".size __errno_location,8\n.popsection\n");
#elif defined(PRIVATE_ERRNO_NOTYPE)
__asm__(".pushsection .text\n.globl __errno_location\n"
        ".type __errno_location,@notype\n__errno_location: ret\n"
        ".size __errno_location,1\n.popsection\n");
#elif defined(PRIVATE_ERRNO_NONEXEC)
__asm__(".pushsection .data\n.globl __errno_location\n"
        ".type __errno_location,@function\n__errno_location: .byte 0xc3\n"
        ".size __errno_location,1\n.popsection\n");
#endif

typedef struct {
    int phase;
    int slot;
    int *location;
} thread_state_t;
static file_t report = INVALID_FILE;
static void *report_lock;
static unsigned calls, failures, setup_errors, observed_threads;

static void emit(const char *data, size_t length) {
    if (dr_write_file(report, data, length) != (ssize_t)length)
        dr_exit_process(94);
}


extern long invoke_with_wrong_fs(void *wrong, void *saved,
                                ssize_t (*operation)(int, void *, size_t));
__asm__(".text\n.type invoke_with_wrong_fs,@function\n"
        "invoke_with_wrong_fs:\n"
        "push %r12\npush %r13\npush %r14\n"
        "mov %rsi,%r12\nmov %rdx,%r13\nmov %rdi,%r14\n"
        "mov $158,%rax\nmov $0x1002,%rdi\nmov %r14,%rsi\nsyscall\n"
        "test %rax,%rax\njnz 1f\n"
        "mov $-1,%edi\nmov %rsp,%rsi\nmov $1,%edx\ncall *%r13\n"
        "mov $158,%rax\nmov $0x1002,%rdi\nmov %r12,%rsi\nsyscall\n"
        "test %rax,%rax\njz 1f\n"
        "mov $231,%rax\nmov $94,%edi\nsyscall\nud2\n"
        "1: mov $-94,%rax\npop %r14\npop %r13\npop %r12\nret\n"
        ".size invoke_with_wrong_fs,.-invoke_with_wrong_fs\n");

static void wrong_private_tls(void) {
    void *dc = dr_get_current_drcontext();
    uintptr_t saved = 0, app = 0, restored = 0;
    if (dc == NULL || raw_call(SYS_arch_prctl, ARCH_GET_FS, (long)&saved, 0, 0) != 0)
        dr_exit_process(94);
    dr_switch_to_app_state(dc);
    long app_result = raw_call(SYS_arch_prctl, ARCH_GET_FS, (long)&app, 0, 0);
    dr_switch_to_dr_state(dc);
    if (app_result != 0 || raw_call(SYS_arch_prctl, ARCH_GET_FS, (long)&restored, 0, 0) != 0 ||
        restored != saved || saved == 0 || saved == app)
        dr_exit_process(94);
    void *wrong = dr_global_alloc(4096);
    if (wrong == NULL || (uintptr_t)wrong == saved || (uintptr_t)wrong == app)
        dr_exit_process(94);
    char line[192];
    int n = dr_snprintf(line, sizeof(line),
        "TLS prepared=1 saved=%llx app=%llx wrong=%llx\n",
        (unsigned long long)saved, (unsigned long long)app,
        (unsigned long long)(uintptr_t)wrong);
    if (n <= 0 || (size_t)n >= sizeof(line))
        dr_exit_process(94);
    emit(line, (size_t)n);
    dr_close_file(report);
    invoke_with_wrong_fs(wrong, (void *)saved, read);
    /* A setup failure or unexpected adapter return is not the named refusal. */
    dr_global_free(wrong, 4096);
    dr_exit_process(94);
}

static void thread_init(void *dc) {
    thread_state_t *state = dr_thread_alloc(dc, sizeof(*state));
    if (state == NULL)
        dr_exit_process(94);
    memset(state, 0, sizeof(*state));
    state->slot = -1;
    dr_set_tls_field(dc, state);
}

static void thread_exit(void *dc) {
    thread_state_t *state = dr_get_tls_field(dc);
    if (state != NULL)
        dr_thread_free(dc, state, sizeof(*state));
}

static bool filter(void *dc, int number) {
    (void)dc;
    return number == SYS_getpid;
}

static bool before(void *dc, int number) {
    if (number != SYS_getpid || (long)dr_syscall_get_param(dc, 0) != PROBE_MARKER)
        return true;
    int phase = (int)dr_syscall_get_param(dc, 1);
    int slot = (int)dr_syscall_get_param(dc, 2);
    uintptr_t app_pointer = (uintptr_t)dr_syscall_get_param(dc, 3);
    thread_state_t *state = dr_get_tls_field(dc);
    int *location = __errno_location();
    int prior = *location;
    observation_t observations[PROBE_OPERATIONS] = {{0}};
    int invalid = state == NULL || slot < 0 || slot >= PROBE_THREADS ||
        phase < 0 || phase >= PROBE_PHASES ||
        (state != NULL && state->phase != phase);
    int prior_ok = phase == 0 || (state != NULL && state->slot == slot &&
        state->location == location && prior == private_cookie(slot));
    int setup = invalid ? 10 : run_operations(slot, observations);
    if (!invalid) {
        if (phase == 0) {
            state->slot = slot;
            state->location = location;
        }
        state->phase++;
    }
    *location = private_cookie(slot);
    dr_mutex_lock(report_lock);
    char line[384];
    int n = dr_snprintf(line, sizeof(line),
        "THREAD slot=%d phase=%d tid=%d ptr=%llx accessor=%llx app=%llx prior=%d prior_ok=%d setup=%d\n",
        slot, phase, dr_get_thread_id(dc), (unsigned long long)(uintptr_t)location,
        (unsigned long long)(uintptr_t)&__errno_location,
        (unsigned long long)app_pointer, prior, prior_ok, setup);
    if (n <= 0 || (size_t)n >= sizeof(line))
        dr_exit_process(94);
    emit(line, (size_t)n);
    calls++;
    if (phase == 0)
        observed_threads++;
    if (!prior_ok || (uintptr_t)location == app_pointer)
        failures++;
    if (setup != 0)
        setup_errors++;
    else {
        for (int i = 0; i < PROBE_OPERATIONS; ++i) {
            observation_t *o = &observations[i];
            n = dr_snprintf(line, sizeof(line),
                "OP slot=%d phase=%d op=%d result=%ld errno=%d expected=%ld expected_errno=%d payload=%d\n",
                slot, phase, i, o->result, o->error, o->expected, o->expected_error,
                o->payload_ok);
            if (n <= 0 || (size_t)n >= sizeof(line))
                dr_exit_process(94);
            emit(line, (size_t)n);
            if (!observation_ok(o))
                failures++;
        }
    }
    dr_mutex_unlock(report_lock);
    /* Reporting is independent; leave a private sentinel for the next phase. */
    *location = private_cookie(slot);
    return true;
}

static void finished(void) {
    char line[160];
    int n = dr_snprintf(line, sizeof(line),
        "SUMMARY calls=%u threads=%u failures=%u setup_errors=%u\n",
        calls, observed_threads, failures, setup_errors);
    if (n <= 0 || (size_t)n >= sizeof(line))
        dr_exit_process(94);
    emit(line, (size_t)n);
    dr_close_file(report);
    dr_mutex_destroy(report_lock);
}

static void release_provider_handles(void) {
    for (int cycle = 0; cycle < 2; ++cycle) {
        byte *start = NULL, *end = NULL;
        dr_auxlib_handle_t owner = dr_load_aux_library("libc.so.6", &start, &end);
        if (owner == NULL || start == NULL || end <= start)
            dr_exit_process(94);
        int *(*accessor)(void) = (int *(*)(void))
            dr_lookup_aux_library_routine(owner, "__errno_location");
        if (accessor == NULL || accessor() != __errno_location())
            dr_exit_process(94);
        if (!dr_unload_aux_library(owner))
            dr_exit_process(94);
        byte *mapping = NULL;
        size_t size = 0;
        uint protection = 0;
        if (!dr_query_memory((byte *)accessor, &mapping, &size, &protection) ||
            (protection & DR_MEMPROT_EXEC) == 0 || accessor() != __errno_location())
            dr_exit_process(94);
        char line[160];
        int n = dr_snprintf(line, sizeof(line),
            "AUX_RELEASE cycle=%d released=1 mapped=1 same_errno=1\n", cycle);
        if (n <= 0 || (size_t)n >= sizeof(line))
            dr_exit_process(94);
        emit(line, (size_t)n);
    }
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    (void)id;
    bool release_owner = argc == 3 && strcmp(argv[2], "--release-provider") == 0;
    bool wrong_tls = argc == 3 && strcmp(argv[2], "--wrong-private-tls") == 0;
    if (argc != 2 && !release_owner && !wrong_tls)
        dr_exit_process(94);
    report = dr_open_file(argv[1], DR_FILE_WRITE_REQUIRE_NEW);
    if (report == INVALID_FILE)
        dr_exit_process(94);
    report_lock = dr_mutex_create();
    if (report_lock == NULL)
        dr_exit_process(94);
    if (wrong_tls)
        wrong_private_tls();
    if (release_owner)
        release_provider_handles();
    dr_register_thread_init_event(thread_init);
    dr_register_thread_exit_event(thread_exit);
    dr_register_filter_syscall_event(filter);
    dr_register_pre_syscall_event(before);
    dr_register_exit_event(finished);
}


#endif
