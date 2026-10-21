#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

/* Separate M2 observer. The fixed M1 workload and compiler recipe are unchanged.
 * Both queries read the runtime's actual kernel registration; neither query
 * prepares or enters a callback. All placement/permission assertions belong to
 * the consumer, so old backing still produces a complete raw observation. */
struct m2_stack_query {
    uint64_t abi_version, status, current_tid;
    int64_t alt_result;
    uint64_t alt_sp, alt_size, alt_flags;
    uint64_t continuation_prepared, continuation_bottom, continuation_top;
    uint64_t continuation_owner_tid;
    uint64_t marker_number, marker_guest_ip, marker_arm_tid, marker_armed;
    uint64_t marker_hits, reached_rsp, reached_tid, reached_guest_ip;
    uint64_t owned_entries, owned_callbacks, owned_completions;
    uint64_t alt_probe_mask;
    int64_t alt_read_result, alt_lower_result, alt_upper_result;
    uint64_t continuation_probe_mask;
    int64_t continuation_read_result, continuation_lower_result;
    int64_t continuation_upper_result;
};

_Static_assert(sizeof(struct m2_stack_query) == 240, "Rust/C M2 stack ABI");
_Static_assert(sizeof(void *) == 8, "Linux x86-64 fixture");
_Static_assert(SYS_write == 1, "literal x86-64 marker number");

static int (*query)(struct m2_stack_query *, size_t);
static int (*arm)(size_t, size_t);
static Dl_info owner;

extern int64_t m2_stack_marker(void);
extern const unsigned char m2_stack_marker_ip[];

__asm__(
    ".text\n"
    ".p2align 4\n"
    ".globl m2_stack_marker\n"
    ".type m2_stack_marker,@function\n"
    "m2_stack_marker:\n"
    ".cfi_startproc\n"
    /* Existing native Strace admits read/write without publishing this site.
     * A zero-length write has literal result zero and adds no stdout bytes. */
    "mov $1,%eax\n"
    "mov $1,%edi\n"
    "xor %esi,%esi\n"
    "xor %edx,%edx\n"
    /* Match the existing native read/write adapter admission: a complete
     * scan window at offset 60, no interior entry, no calibration. */
    ".p2align 6,0x90\n"
    ".fill 60,1,0x90\n"
    ".globl m2_stack_marker_ip\n"
    "m2_stack_marker_ip:\n"
    ".byte 0x0f,0x05,0x31,0xc9,0x31,0xd2,0x90,0x90\n"
    "ret\n"
    ".fill 16,1,0x90\n"
    ".cfi_endproc\n"
    ".size m2_stack_marker,.-m2_stack_marker\n"
);

static int bind_exports(const char *expected_owner) {
    void *symbols[2];
    const char *names[2] = { "m2_stack_query", "m2_stack_arm" };
    for (unsigned i = 0; i < 2; ++i) {
        symbols[i] = dlsym(RTLD_DEFAULT, names[i]);
        Dl_info found;
        if (!symbols[i] || !dladdr(symbols[i], &found) ||
            !found.dli_fname || !found.dli_fbase ||
            strcmp(found.dli_fname, expected_owner)) return 0;
        if (i == 0) owner = found;
        else if (owner.dli_fbase != found.dli_fbase ||
                 strcmp(owner.dli_fname, found.dli_fname)) return 0;
    }
    /* POSIX defines this function-pointer conversion on this platform. */
    memcpy(&query, &symbols[0], sizeof(query));
    memcpy(&arm, &symbols[1], sizeof(arm));
    return 1;
}

static void print_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            putchar('\\');
            putchar(*p);
        } else if (*p < 32) {
            printf("\\u%04x", (unsigned)*p);
        } else {
            putchar(*p);
        }
    }
    putchar('"');
}

static void print_query(const struct m2_stack_query *q) {
    putchar('{');
#define U(field) printf("\"" #field "\":%" PRIu64 ",", q->field)
#define S(field) printf("\"" #field "\":%" PRId64 ",", q->field)
    U(abi_version); U(status); U(current_tid); S(alt_result);
    U(alt_sp); U(alt_size); U(alt_flags);
    U(continuation_prepared); U(continuation_bottom); U(continuation_top);
    U(continuation_owner_tid);
    U(marker_number); U(marker_guest_ip); U(marker_arm_tid); U(marker_armed);
    U(marker_hits); U(reached_rsp); U(reached_tid); U(reached_guest_ip);
    U(owned_entries); U(owned_callbacks); U(owned_completions);
    U(alt_probe_mask); S(alt_read_result); S(alt_lower_result); S(alt_upper_result);
    U(continuation_probe_mask); S(continuation_read_result);
    S(continuation_lower_result);
    printf("\"continuation_upper_result\":%" PRId64 "}",
           q->continuation_upper_result);
#undef U
#undef S
}

static int64_t probe_fixed_range(void) {
    unsigned char residency = 0;
    int64_t result;
    /* Genuine full-page mincore: distinguishes the inert unmapped range from
     * a mapping. No read/write or reservation of the range is performed. */
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"((uint64_t)SYS_mincore), "D"(UINT64_C(0x600000000000)),
                       "S"(UINT64_C(4096)), "d"(&residency)
                     : "rcx", "r11", "memory", "cc");
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "observe") && strcmp(argv[1], "inert"))) {
        fprintf(stderr, "usage: m2_stack_guest <observe|inert> <exact runtime owner>\n");
        return 2;
    }
    if (!bind_exports(argv[2])) {
        fprintf(stderr, "M2 real query/arm exports or exact runtime owner absent\n");
        return 2;
    }
    struct m2_stack_query before = {0}, after = {0};
    unsigned char bytes_before[2], bytes_after[2];
    int before_result = query(&before, sizeof(before));
    memcpy(bytes_before, m2_stack_marker_ip, sizeof(bytes_before));
    int arm_result = arm(SYS_write, (size_t)m2_stack_marker_ip);
    int64_t marker_result = m2_stack_marker();
    int after_result = query(&after, sizeof(after));
    memcpy(bytes_after, m2_stack_marker_ip, sizeof(bytes_after));
    int region_probe_executed = !strcmp(argv[1], "inert");
    int64_t region_probe_result = region_probe_executed ? probe_fixed_range() : 0;

    printf("{\"schema\":1,\"mode\":"); print_string(argv[1]);
    printf(",\"owner\":"); print_string(owner.dli_fname);
    printf(",\"marker_ip\":%" PRIu64 ",\"marker_result\":%" PRId64,
           (uint64_t)(uintptr_t)m2_stack_marker_ip, marker_result);
    printf(",\"before_result\":%d,\"arm_result\":%d,\"after_result\":%d",
           before_result, arm_result, after_result);
    printf(",\"marker_bytes_before\":[%u,%u],\"marker_bytes_after\":[%u,%u]",
           (unsigned)bytes_before[0], (unsigned)bytes_before[1],
           (unsigned)bytes_after[0], (unsigned)bytes_after[1]);
    printf(",\"region_probe_executed\":%d,\"region_probe_result\":%" PRId64,
           region_probe_executed, region_probe_result);
    printf(",\"before\":"); print_query(&before);
    printf(",\"after\":"); print_query(&after);
    puts("}");
    /* An out-of-region baseline is still a valid successful observation. */
    return before_result || arm_result || after_result || marker_result != 0 ? 2 : 0;
}
