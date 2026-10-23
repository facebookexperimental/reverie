#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* Only this selector is interposed. All other getters keep current environ. */
extern char **environ;
static int generic_enabled;
static char *raw_value(const char *name) {
    size_t n = strlen(name);
    for (char **p = environ; p && *p; ++p)
        if (!strncmp(*p, name, n) && (*p)[n] == '=') return *p + n + 1;
    return NULL;
}
char *getenv(const char *name) {
    if (!strcmp(name, "REVERIE_LITEINST_TOOL")) {
        const char *policy = raw_value("STANDALONE_CONSTRUCTOR_GETENV");
        if (policy && !strcmp(policy, "hide")) return NULL;
        if (policy && !strcmp(policy, "strace")) return (char *)"strace";
        if (policy && !strcmp(policy, "invalid")) return (char *)"unsupported-provider";
        if (policy && !strcmp(policy, "generic"))
            return generic_enabled ? (char *)"strace" : NULL;
    }
    return raw_value(name);
}

static long raw(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}
static stack_t original_alternate;
static long original_alternate_result;
static void before_ctors(void) {
    original_alternate_result = raw(SYS_sigaltstack, 0, (long)&original_alternate, 0, 0, 0, 0);
}
__attribute__((used, section(".preinit_array")))
static void (*const preinit)(void) = before_ctors;

/* The existing sixteen-word fixture ABI; no nominal address substitutes for it. */
struct record {
    uint64_t version, phase, tid, extent_start, extent_end, bottom, top, caller_rsp;
    uint64_t adoption_entry, body_entry, adoption_sample, body_sample;
    uint64_t control, record, region_base, region_end;
};
_Static_assert(sizeof(struct record) == 128, "constructor record ABI");
typedef int (*query_fn)(struct record *);
struct kernel_query {
    uint64_t version;
    int64_t status, tid, pid, alt_result;
    uint64_t alt_sp, alt_size, alt_flags;
    int64_t mincore_result, constructor_result;
    struct record constructor;
    uint64_t probe_mask;
    int64_t interior, lower, upper, bitmap_result;
    uint64_t bitmap[33];
};
_Static_assert(sizeof(struct kernel_query) == 512, "actual kernel query ABI");
typedef int (*kernel_fn)(struct kernel_query *, size_t);
static void json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static void json_record(const struct record *record) {
    uint64_t words[16];
    memcpy(words, record, sizeof words);
    putchar('[');
    for (size_t i = 0; i < 16; ++i) printf("%s%llu", i ? "," : "", (unsigned long long)words[i]);
    putchar(']');
}
static int setup_error(const char *text) {
    fprintf(stderr, "standalone constructor probe setup: %s\n", text);
    return 2;
}
static int drop_entry(const char *entry) {
    static const char *const names[] = {
        "LD_PRELOAD=", "REVERIE_LITEINST_TOOL=", "STANDALONE_CONSTRUCTOR_GETENV=",
        "REVERIE_LITEINST_TOOL_EXTRA=", "XREVERIE_LITEINST_TOOL="
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i)
        if (!strncmp(entry, names[i], strlen(names[i]))) return 1;
    return 0;
}
static int prepare(int argc, char **argv) {
    if (argc != 5) return setup_error("prepare CASE RUNTIME ROOT_OR_DASH");
    const char *which = argv[2];
    char *env[512]; size_t used = 0;
    for (char **p = environ; p && *p; ++p) {
        if (drop_entry(*p)) continue;
        if (used >= 500) return setup_error("environment exceeds finite fixture capacity");
        env[used++] = *p;
    }
    char preload[8192];
    int length = !strcmp(argv[4], "-")
        ? snprintf(preload, sizeof preload, "LD_PRELOAD=%s", argv[3])
        : snprintf(preload, sizeof preload, "LD_PRELOAD=%s:%s", argv[4], argv[3]);
    if (length < 0 || (size_t)length >= sizeof preload) return setup_error("preload path capacity");
    env[used++] = preload;
    char non_utf8[] = "REVERIE_LITEINST_TOOL=\xff";
    if (!strcmp(which, "strace") || !strcmp(which, "root") || !strcmp(which, "hide"))
        env[used++] = (char *)"REVERIE_LITEINST_TOOL=strace";
    else if (!strcmp(which, "compat") || !strcmp(which, "replace"))
        env[used++] = (char *)"REVERIE_LITEINST_TOOL=compat";
    else if (!strcmp(which, "passthrough")) env[used++] = (char *)"REVERIE_LITEINST_TOOL=passthrough";
    else if (!strcmp(which, "spoof-getpid")) env[used++] = (char *)"REVERIE_LITEINST_TOOL=spoof-getpid";
    else if (!strcmp(which, "empty")) env[used++] = (char *)"REVERIE_LITEINST_TOOL=";
    else if (!strcmp(which, "invalid")) env[used++] = (char *)"REVERIE_LITEINST_TOOL=unsupported-raw";
    else if (!strcmp(which, "non-utf8")) env[used++] = non_utf8;
    else if (!strcmp(which, "first-valid")) {
        env[used++] = (char *)"REVERIE_LITEINST_TOOL=strace";
        env[used++] = (char *)"REVERIE_LITEINST_TOOL=unsupported-second";
    } else if (!strcmp(which, "first-invalid")) {
        env[used++] = (char *)"REVERIE_LITEINST_TOOL=unsupported-first";
        env[used++] = (char *)"REVERIE_LITEINST_TOOL=strace";
    } else if (!strcmp(which, "lookalikes")) {
        env[used++] = (char *)"REVERIE_LITEINST_TOOL_EXTRA=strace";
        env[used++] = (char *)"XREVERIE_LITEINST_TOOL=strace";
    } else if (strcmp(which, "absent") && strcmp(which, "synthesize") && strcmp(which, "generic"))
        return setup_error("unknown finite selector case");
    if (!strcmp(which, "hide")) env[used++] = (char *)"STANDALONE_CONSTRUCTOR_GETENV=hide";
    else if (!strcmp(which, "replace")) env[used++] = (char *)"STANDALONE_CONSTRUCTOR_GETENV=invalid";
    else if (!strcmp(which, "synthesize")) env[used++] = (char *)"STANDALONE_CONSTRUCTOR_GETENV=strace";
    else if (!strcmp(which, "generic")) env[used++] = (char *)"STANDALONE_CONSTRUCTOR_GETENV=generic";
    env[used] = NULL;
    char *child[] = {argv[0], (char *)"child", argv[2], argv[3], argv[4], NULL};
    execve(argv[0], child, env);
    return setup_error("execve real prepared leaf");
}
int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "prepare")) return prepare(argc, argv);
    if (argc != 5 || strcmp(argv[1], "child")) return setup_error("child arguments");
    void *query_address = dlsym(RTLD_DEFAULT, "reverie_inguest_constructor_stack_query");
    Dl_info owner;
    if (!query_address || !dladdr(query_address, &owner) || strcmp(owner.dli_fname, argv[3]))
        return setup_error("query export must belong to exact real runtime");
    query_fn query = (query_fn)query_address;
    void *kernel_address = dlsym(RTLD_DEFAULT, "m3_standalone_query");
    Dl_info kernel_owner;
    if (!kernel_address || !dladdr(kernel_address, &kernel_owner) ||
        kernel_owner.dli_fbase != owner.dli_fbase || strcmp(kernel_owner.dli_fname, argv[3]))
        return setup_error("actual kernel query must belong to exact real runtime");
    kernel_fn kernel = (kernel_fn)kernel_address;
    struct record before = {0}, after = {0};
    int query_before = query(&before), query_after;
    struct kernel_query kernel_before = {0}, kernel_after = {0};
    int kernel_before_result = kernel(&kernel_before, sizeof kernel_before);
    if (!strcmp(argv[2], "generic")) {
        void *handle = dlopen(argv[3], RTLD_NOW | RTLD_NOLOAD);
        void *entry = handle ? dlsym(handle, "reverie_liteinst_initialize") : NULL;
        Dl_info generic_owner;
        if (!entry || !dladdr(entry, &generic_owner) || generic_owner.dli_fbase != owner.dli_fbase)
            return setup_error("direct generic call must use actual leaf export");
        generic_enabled = 1;
        ((void (*)(void))entry)();
    }
    query_after = query(&after);
    int kernel_after_result = kernel(&kernel_after, sizeof kernel_after);
    int record_crosscheck = kernel_before.constructor_result == query_before &&
        kernel_after.constructor_result == query_after &&
        !memcmp(&before, &kernel_before.constructor, sizeof before) &&
        !memcmp(&after, &kernel_after.constructor, sizeof after);
    long tid = kernel_after.tid;
    /* Retain the actual inline guest operation, including native -EOPNOTSUPP.
     * The trusted diagnostic's physical PID never substitutes for this value. */
    long pid_result = raw(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int bootstrap_held = 0;
    if (query_after == 0) {
        bootstrap_held = kernel_after.bitmap_result == (long)sizeof kernel_after.bitmap;
        for (size_t i = 0; i < 32; ++i) if (kernel_after.bitmap[i] != UINT64_MAX) bootstrap_held = 0;
        if ((kernel_after.bitmap[32] & 3) != 3) bootstrap_held = 0;
    }
    long root_calls = -1;
    if (strcmp(argv[4], "-")) {
        void *address = dlsym(RTLD_DEFAULT, "standalone_root_interposer_calls");
        Dl_info root_owner;
        if (!address || !dladdr(address, &root_owner) || strcmp(root_owner.dli_fname, argv[4]))
            return setup_error("root control export must belong to exact interposer");
        root_calls = ((long (*)(void))address)();
    }
    printf("{\"schema\":1,\"case\":"); json_string(argv[2]);
    printf(",\"owner\":"); json_string(owner.dli_fname);
    printf(",\"owner_base\":%llu,\"query_before\":%d,\"query_after\":%d,\"record\":",
           (unsigned long long)(uintptr_t)owner.dli_fbase, query_before, query_after);
    json_record(&after);
    printf(",\"record_before\":"); json_record(&before);
    printf(",\"kernel_constructor_before\":"); json_record(&kernel_before.constructor);
    printf(",\"kernel_constructor_after\":"); json_record(&kernel_after.constructor);
    printf(",\"tid\":%ld,\"kernel_pid\":%ld,\"getpid\":%ld,\"kernel_before_result\":%d,\"kernel_after_result\":%d,\"kernel_before_version\":%llu,\"kernel_after_version\":%llu,\"kernel_before_status\":%ld,\"kernel_after_status\":%ld,\"kernel_before_tid\":%ld,\"kernel_before_pid\":%ld,\"kernel_constructor_before_result\":%ld,\"kernel_constructor_after_result\":%ld,\"record_crosscheck\":%d",
           tid, (long)kernel_after.pid, pid_result, kernel_before_result, kernel_after_result,
           (unsigned long long)kernel_before.version, (unsigned long long)kernel_after.version,
           (long)kernel_before.status, (long)kernel_after.status,
           (long)kernel_before.tid, (long)kernel_before.pid,
           (long)kernel_before.constructor_result, (long)kernel_after.constructor_result, record_crosscheck);
    printf(",\"original_alt_result\":%ld,\"original_alt_sp\":%llu,\"original_alt_flags\":%d,\"original_alt_size\":%llu",
           original_alternate_result, (unsigned long long)(uintptr_t)original_alternate.ss_sp,
           original_alternate.ss_flags, (unsigned long long)original_alternate.ss_size);
    printf(",\"alt_before_result\":%ld,\"alt_before_sp\":%llu,\"alt_before_flags\":%d,\"alt_before_size\":%llu",
           (long)kernel_before.alt_result, (unsigned long long)kernel_before.alt_sp,
           (int)kernel_before.alt_flags, (unsigned long long)kernel_before.alt_size);
    printf(",\"alt_after_result\":%ld,\"alt_after_sp\":%llu,\"alt_after_flags\":%d,\"alt_after_size\":%llu",
           (long)kernel_after.alt_result, (unsigned long long)kernel_after.alt_sp,
           (int)kernel_after.alt_flags, (unsigned long long)kernel_after.alt_size);
    printf(",\"mapping_before\":%ld,\"mapping_after\":%ld,\"probe_mask\":%llu,\"interior\":%ld,\"lower_guard\":%ld,\"upper_guard\":%ld,\"bitmap_read\":%ld,\"bitmap\":[",
           (long)kernel_before.mincore_result, (long)kernel_after.mincore_result,
           (unsigned long long)kernel_after.probe_mask, (long)kernel_after.interior,
           (long)kernel_after.lower, (long)kernel_after.upper, (long)kernel_after.bitmap_result);
    for (size_t i = 0; i < 33; ++i)
        printf("%s%llu", i ? "," : "", (unsigned long long)kernel_after.bitmap[i]);
    printf("],\"bootstrap_held\":%d,\"root_calls\":%ld}\n", bootstrap_held, root_calls);
    return 0;
}
