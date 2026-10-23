/* Real exec/kernel-state component. Link the actual production capture/restore.
 * The syscall primitive is a direct raw-syscall stand-in for the fixed gate;
 * private Tool/admission/loader ownership is not established by this fixture.
 * The selected mode is an explicit C-boundary input, NOT another production
 * subscription selector. Rust owner/selection tests must cover that seam.
 * This fixture links the actual kernel_tsc/guest_tsc control layout.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include "private-control.h"

static struct ExecPrivateControl control;
static unsigned inherited, selected, installed, denial;
struct Action { uint64_t handler, flags, restorer, mask; };
struct Witness {
    uint64_t magic, stage, inherited, observed;
    int64_t query_rc;
    uint64_t captured, selected, native_state, tid;
};
_Static_assert(sizeof(struct Witness) == 72, "parent witness wire extent");

static long call(long nr, uint64_t a, uint64_t b, uint64_t c,
                 uint64_t d, uint64_t e, uint64_t f) {
    return private_native_syscall(nr, a, b, c, d, e, f);
}
static unsigned decimal(const char *p) {
    unsigned value = 0;
    if (!p || !*p) private_native_terminal(73);
    for (; *p; ++p) {
        if (*p < '0' || *p > '9' || value > 10000)
            private_native_terminal(73);
        value = 10 * value + (unsigned)(*p - '0');
    }
    return value;
}
static int get_mode(void) {
    int mode = 0;
    if (call(SYS_prctl, PR_GET_TSC, (uint64_t)&mode, 0, 0, 0, 0) ||
        (mode != PR_TSC_ENABLE && mode != PR_TSC_SIGSEGV))
        private_native_terminal(74);
    return mode;
}
static void witness(unsigned stage) {
    int mode = 0;
    long rc = call(SYS_prctl, PR_GET_TSC, (uint64_t)&mode, 0, 0, 0, 0);
    struct Witness record = {
        UINT64_C(0x3153435454455354), stage, inherited, (uint64_t)mode, rc,
        control.kernel_tsc, control.guest_tsc, control.native_state,
        control.native_tid
    };
    if (call(SYS_write, 1, (uint64_t)&record, sizeof(record), 0, 0, 0) !=
        (long)sizeof(record)) private_native_terminal(75);
}
static void prior_handler(void) { private_native_terminal(91); }
static void deny_prctl(unsigned operation) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, operation, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        instructions
    };
    if (call(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) ||
        call(SYS_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
             (uint64_t)&program, 0, 0, 0)) private_native_terminal(76);
}
static void rdtsc_witness(unsigned stage) {
    unsigned low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    __asm__ volatile("" : : "r"(low), "r"(high) : "memory");
    witness(stage);
}
struct RobustHead { uint64_t next, futex_offset, pending; };
static struct RobustHead tool_robust;
static uint32_t tool_clear_tid;
static uint64_t tool_tls[8];
static void prepare_actual_private_state(void) {
    control.phase = EXEC_PRIVATE_TOOL_INIT; /* Explicitly modeled owner phase. */
    tool_robust.next = (uint64_t)&tool_robust;
    uint64_t robust_args[6] = {(uint64_t)&tool_robust, sizeof(tool_robust)};
    if (private_registration_call(&control, SYS_set_robust_list, robust_args))
        private_native_terminal(84);
    uint64_t tid_args[6] = {(uint64_t)&tool_clear_tid};
    if (private_registration_call(&control, SYS_set_tid_address, tid_args) !=
        (long)control.native_tid) private_native_terminal(85);
    /* This really changes FS; the executable has no libc/TLS consumers. */
    if (call(SYS_arch_prctl, 0x1002, (uint64_t)tool_tls, 0, 0, 0, 0))
        private_native_terminal(86);
    control.tool_fs = private_native_get_fs();
    if (control.tool_fs != (uint64_t)tool_tls) private_native_terminal(87);
}
static void verify_actual_restored_state(void) {
    uint64_t head = UINT64_MAX, length = 0;
    if (call(SYS_get_robust_list, 0, (uint64_t)&head, (uint64_t)&length, 0, 0, 0) ||
        head != control.kernel_robust_head || length != control.kernel_robust_len ||
        call(SYS_gettid, 0, 0, 0, 0, 0, 0) != (long)control.native_tid ||
        call(SYS_brk, 0, 0, 0, 0, 0, 0) != (long)control.kernel_brk ||
        private_native_get_fs() != control.tool_fs || control.private_clear_tid != 0 ||
        control.native_state != (EXEC_PRIVATE_NATIVE_CAPTURED | EXEC_PRIVATE_NATIVE_RESTORED))
        private_native_terminal(88);
}
int fixture_main(uint64_t *stack) {
    if (stack[0] != 6) return 70;
    char **argv = (void *)(stack + 1);
    inherited = decimal(argv[2]); selected = decimal(argv[3]);
    installed = decimal(argv[4]); denial = decimal(argv[5]);
    if ((inherited != 1 && inherited != 2) || selected > 2 ||
        (installed != 0 && installed != 2) || denial > 8 ||
        (denial >= 3 && !selected)) return 71;
    if (argv[1][0] == 'p') {
        struct Action action = {(uint64_t)prior_handler, 0, 0, 0};
        if (call(SYS_rt_sigaction, SIGSEGV, (uint64_t)&action, 0, 8, 0, 0) ||
            call(SYS_prctl, PR_SET_TSC, inherited, 0, 0, 0, 0) ||
            get_mode() != (int)inherited) return 77;
        witness('P');
        char *next[] = {argv[0], "child", argv[2], argv[3], argv[4], argv[5], 0};
        char *environment[] = {0};
        (void)call(SYS_execve, (uint64_t)argv[0], (uint64_t)next,
                   (uint64_t)environment, 0, 0, 0);
        return 78;
    }
    if (argv[1][0] != 'c' || get_mode() != (int)inherited) return 79;
    struct Action action = {0};
    if (call(SYS_rt_sigaction, SIGSEGV, 0, (uint64_t)&action, 8, 0, 0) ||
        action.handler != 0) return 80;
    witness('E');
    if (denial == 1 || denial == 2)
        deny_prctl(denial == 1 ? PR_GET_TSC : PR_SET_TSC);
    int captured = private_capture_kernel_state(&control);
    if (denial == 1 || denial == 2) {
        if (!captured) return 81;
        witness('D'); /* Actual kernel denial, no private-loader handoff. */
        return 0;
    }
    if (captured || control.native_state != EXEC_PRIVATE_NATIVE_CAPTURED ||
        control.native_tid != (uint64_t)call(SYS_gettid, 0, 0, 0, 0, 0, 0) ||
        control.kernel_tsc != inherited || control.guest_tsc != 0 ||
        get_mode() != PR_TSC_ENABLE) return 82;
    witness('C');
    rdtsc_witness('L'); /* Stand-in private-loader opcode, before an installer. */
    if (!selected) return 0;
    prepare_actual_private_state();
    control.guest_tsc = selected; /* Manually selected C boundary, not admission. */
    /* Model the real installer's subscribed-mode effect using its actual setter. */
    if (installed && call(SYS_prctl, PR_SET_TSC, installed, 0, 0, 0, 0)) return 83;
    witness('I');
    if (denial == 3 || denial == 4)
        deny_prctl(denial == 3 ? PR_GET_TSC : PR_SET_TSC);
    /* Explicit invalid-state mutations, separate from real inheritance. */
    if (denial == 5) control.kernel_tsc = 0;
    if (denial == 6) control.kernel_tsc = 3;
    if (denial == 7) control.guest_tsc = 0;
    if (denial == 8) control.guest_tsc = 3;
    int restored = private_restore_kernel_state(&control);
    if (denial >= 3) {
        if (!restored) return 89;
        witness('D'); /* No final RDTSC/guest handoff after refused restore. */
        return 0;
    }
    if (restored || get_mode() != (int)selected) return 90;
    verify_actual_restored_state();
    witness('F');
    /* Raw syscalls only after final mode2; no libc/allocator/clock/formatting. */
    rdtsc_witness('R');
    return 0;
}
