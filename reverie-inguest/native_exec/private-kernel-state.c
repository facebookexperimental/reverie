/* Freestanding native state ownership for the source-only InitialImage proof.
 * No libc calls, errno TLS, allocation, fabricated registrations, or threads.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include "private-control.h"

#define PAGE UINT64_C(4096)
#define ROBUST_HEAD_BYTES UINT64_C(24)
#define SIGSYS_BIT (UINT64_C(1) << (SIGSYS - 1))
_Static_assert(sizeof(int) == 4, "PR_GET_TSC writes a Linux 32-bit int");

static int failed(long value) {
    return (uint64_t)value >= (uint64_t)-4095;
}
static long call(long nr, uint64_t a, uint64_t b, uint64_t c,
                 uint64_t d, uint64_t e, uint64_t f) {
    return private_native_syscall(nr, a, b, c, d, e, f);
}
static uint64_t up(uint64_t value) {
    return (value + PAGE - 1) & ~(PAGE - 1);
}
static int current_robust_registration(uint64_t *head, uint64_t *len) {
    return call(SYS_get_robust_list, 0, (uint64_t)head, (uint64_t)len, 0, 0, 0) ? -1 : 0;
}
static void append_text(char *out, size_t *used, const char *text) {
    while (*text && *used < 511) out[(*used)++] = *text++;
}
static void append_hex(char *out, size_t *used, const char *name, uint64_t value) {
    append_text(out, used, name);
    append_text(out, used, "=0x");
    for (unsigned i = 0; i < 16 && *used < 511; ++i)
        out[(*used)++] = "0123456789abcdef"[(value >> (60 - 4 * i)) & 15];
    append_text(out, used, " ");
}
static void capture_refused(unsigned reason, long tid, long brk, long fs_rc, uint64_t fs,
                            long mask_rc, uint64_t mask, long robust_rc, uint64_t head,
                            uint64_t len, long clear_set_rc, uint64_t clear_requested,
                            long operation_rc) {
    char out[512];
    size_t used = 0;
    append_text(out, &used, "exec-private capture refused ");
    append_hex(out, &used, "reason", reason);
    append_hex(out, &used, "gettid_rc", tid);
    append_hex(out, &used, "brk_rc", brk);
    append_hex(out, &used, "fs_rc", fs_rc);
    append_hex(out, &used, "fs", fs);
    append_hex(out, &used, "mask_rc", mask_rc);
    append_hex(out, &used, "mask", mask);
    append_hex(out, &used, "robust_rc", robust_rc);
    append_hex(out, &used, "head", head);
    append_hex(out, &used, "len", len);
    append_hex(out, &used, "clear_set_rc", clear_set_rc);
    append_hex(out, &used, "clear_requested", clear_requested);
    append_hex(out, &used, "operation_rc", operation_rc);
    if (used < sizeof(out)) out[used++] = '\n';
    /* One bounded native write, no libc/TLS/allocator. A short/error write is
     * not reclassified as a complete diagnostic or a successful capture.
     */
    (void)call(SYS_write, 2, (uint64_t)out, used, 0, 0, 0);
}
uint64_t private_native_get_fs(void) {
    uint64_t fs = 0;
    if (call(SYS_arch_prctl, 0x1003, (uint64_t)&fs, 0, 0, 0, 0))
        private_native_terminal(71);
    return fs;
}

int private_capture_kernel_state(struct ExecPrivateControl *ctl) {
    uint64_t head = 0, len = 0, mask = 0, fs = 0;
    const uint64_t clear_requested = 0;
    long tid = call(SYS_gettid, 0, 0, 0, 0, 0, 0);
    long brk = call(SYS_brk, 0, 0, 0, 0, 0, 0);
    long fs_rc = call(SYS_arch_prctl, 0x1003, (uint64_t)&fs, 0, 0, 0, 0);
    long mask_rc = call(SYS_rt_sigprocmask, SIG_SETMASK, 0, (uint64_t)&mask, 8, 0, 0);
    long robust_rc = call(SYS_get_robust_list, 0, (uint64_t)&head, (uint64_t)&len, 0, 0, 0);
    /* This entry is before either loader runs after a fresh native exec.
     * Linux fs/exec.c:854 -> fork.c:1453-1457,1426-1436 clears the old
     * clear_child_tid. Establish the same null baseline with the actual setter;
     * fork.c:1733-1738 assigns the pointer and returns the calling task's TID.
     * These are local Linux 6.17 citations, not running-custom-kernel identity.
     */
    long clear_set_rc = call(SYS_set_tid_address, clear_requested, 0, 0, 0, 0, 0);
    if (tid <= 0 || failed(brk) || brk == 0 ||
        fs_rc || mask_rc || robust_rc || clear_set_rc != tid) {
        capture_refused(1, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, 0);
        return -1;
    }
    /* Robust-list state remains a genuine query. The clear-tid baseline above
     * is setter-established state, not a fabricated PR_GET_TID_ADDRESS result.
     */
    if (head != 0 || len != ROBUST_HEAD_BYTES) {
        capture_refused(2, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, 0);
        return -1;
    }
    /* TSC faulting survives exec, while a caught SIGSEGV disposition does not.
     * Normalize only this fresh image's private loader interval. The admitted
     * Rust owner selects guest_tsc once; final restore applies it before Guest.
     */
    int tsc = 0;
    long tsc_rc = call(SYS_prctl, PR_GET_TSC, (uint64_t)&tsc, 0, 0, 0, 0);
    if (tsc_rc || (tsc != PR_TSC_ENABLE && tsc != PR_TSC_SIGSEGV)) {
        capture_refused(5, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, tsc_rc);
        return -1;
    }
    ctl->kernel_tsc = (uint64_t)tsc;
    ctl->guest_tsc = 0;
    tsc_rc = call(SYS_prctl, PR_SET_TSC, PR_TSC_ENABLE, 0, 0, 0, 0);
    if (tsc_rc) {
        capture_refused(6, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, tsc_rc);
        return -1;
    }
    tsc = 0;
    tsc_rc = call(SYS_prctl, PR_GET_TSC, (uint64_t)&tsc, 0, 0, 0, 0);
    if (tsc_rc || tsc != PR_TSC_ENABLE) {
        capture_refused(7, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, tsc_rc);
        return -1;
    }
    ctl->guest_fs = fs;
    ctl->kernel_mask = mask;
    ctl->guest_resume_mask = mask & ~SIGSYS_BIT;
    ctl->kernel_robust_head = head;
    ctl->kernel_robust_len = len;
    ctl->kernel_clear_tid = clear_requested;
    ctl->kernel_brk = (uint64_t)brk;
    ctl->native_tid = (uint64_t)tid;
    ctl->private_robust_head = head;
    ctl->private_robust_len = len;
    ctl->private_clear_tid = clear_requested;

    /* Block ordinary asynchronous signals; SIGSYS must remain deliverable
     * before the owned frontend is installed and throughout real init.
     */
    uint64_t startup_mask = UINT64_MAX & ~SIGSYS_BIT;
    long setmask_rc = call(SYS_rt_sigprocmask, SIG_SETMASK, (uint64_t)&startup_mask, 0, 8, 0, 0);
    if (setmask_rc) {
        capture_refused(3, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, setmask_rc);
        return -1;
    }
    long base = call(SYS_mmap, EXEC_PRIVATE_BRK_BASE, EXEC_PRIVATE_BRK_BYTES,
                     PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                     (uint64_t)-1, 0);
    if (base != (long)EXEC_PRIVATE_BRK_BASE) {
        capture_refused(4, tid, brk, fs_rc, fs, mask_rc, mask, robust_rc,
                         head, len, clear_set_rc, clear_requested, base);
        return -1;
    }
    ctl->private_brk_base = (uint64_t)base;
    ctl->private_brk_current = (uint64_t)base;
    ctl->private_brk_end = (uint64_t)base + EXEC_PRIVATE_BRK_BYTES;
    ctl->native_state = EXEC_PRIVATE_NATIVE_CAPTURED;
    return 0;
}

long private_owned_brk(struct ExecPrivateControl *ctl, uint64_t requested) {
    uint64_t previous = ctl->private_brk_current;
    if (!(ctl->native_state & EXEC_PRIVATE_NATIVE_CAPTURED) ||
        ctl->private_brk_base != EXEC_PRIVATE_BRK_BASE ||
        ctl->private_brk_end != EXEC_PRIVATE_BRK_BASE + EXEC_PRIVATE_BRK_BYTES ||
        previous < ctl->private_brk_base || previous > ctl->private_brk_end)
        private_native_terminal(72);
    if (requested == 0)
        return (long)previous;
    if (requested < ctl->private_brk_base || requested > ctl->private_brk_end ||
        requested > UINT64_MAX - (PAGE - 1))
        return (long)previous;
    uint64_t before = up(previous), after = up(requested);
    if (after > before) {
        if (call(SYS_mprotect, before, after - before, PROT_READ | PROT_WRITE, 0, 0, 0))
            private_native_terminal(73); /* no claim about partial mprotect failure */
        if (private_track_map(ctl, before, after - before, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS))
            private_native_terminal(73);
    } else if (after < before) {
        if (call(SYS_mprotect, after, before - after, PROT_NONE, 0, 0, 0))
            private_native_terminal(73);
        if (private_track_map(ctl, after, before - after, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS))
            private_native_terminal(73);
        /* Never claim old contents survived a failed/partial discard. A
         * disposal failure after changing permissions is terminal, not a
         * fabricated successful shrink or successful rollback.
         */
        if (call(SYS_madvise, after, before - after, MADV_DONTNEED, 0, 0, 0))
            private_native_terminal(73);
    }
    ctl->private_brk_current = requested;
    return (long)requested;
}

long private_registration_call(struct ExecPrivateControl *ctl, long nr,
                               const uint64_t args[6]) {
    if (nr != SYS_set_tid_address && nr != SYS_set_robust_list)
        private_native_terminal(74); /* rseq/threads/exec are never simulated */
    uint64_t phase = __atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE);
    if (phase != EXEC_PRIVATE_TOOL_LOADING && phase != EXEC_PRIVATE_TOOL_INIT)
        private_native_terminal(76); /* no registration changes after Guest starts */
    long result = call(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
    if (!failed(result)) {
        uint64_t head = 0, len = 0;
        if (current_robust_registration(&head, &len))
            private_native_terminal(75);
        if (nr == SYS_set_tid_address &&
            (result != (long)ctl->native_tid ||
             call(SYS_gettid, 0, 0, 0, 0, 0, 0) != result))
            private_native_terminal(75);
        if (nr == SYS_set_robust_list &&
            (result != 0 || head != args[0] || len != args[1]))
            private_native_terminal(75);
        ctl->private_robust_head = head;
        ctl->private_robust_len = len;
        /* Only the successful actual setter changes this accepted-pointer
         * witness. A robust-list operation does not synthesize a tid query.
         */
        if (nr == SYS_set_tid_address) ctl->private_clear_tid = args[0];
    }
    return result;
}

int private_restore_kernel_state(struct ExecPrivateControl *ctl) {
    if (!(ctl->native_state & EXEC_PRIVATE_NATIVE_CAPTURED) ||
        (ctl->native_state & EXEC_PRIVATE_NATIVE_RESTORED) || ctl->kernel_clear_tid != 0 ||
        (ctl->kernel_tsc != PR_TSC_ENABLE && ctl->kernel_tsc != PR_TSC_SIGSEGV) ||
        (ctl->guest_tsc != PR_TSC_ENABLE && ctl->guest_tsc != PR_TSC_SIGSEGV))
        return -1;
    uint64_t head = 0, len = 0;
    long tid = call(SYS_set_tid_address, ctl->kernel_clear_tid, 0, 0, 0, 0, 0);
    if (tid != (long)ctl->native_tid ||
        call(SYS_set_robust_list, ctl->kernel_robust_head,
             ctl->kernel_robust_len, 0, 0, 0, 0) ||
        current_robust_registration(&head, &len) ||
        head != ctl->kernel_robust_head || len != ctl->kernel_robust_len ||
        call(SYS_gettid, 0, 0, 0, 0, 0, 0) != (long)ctl->native_tid ||
        call(SYS_brk, 0, 0, 0, 0, 0, 0) != (long)ctl->kernel_brk)
        return -1;
    /* C returns on Tool FS. Only the final assembly leaf may change it. */
    if (private_native_get_fs() != ctl->tool_fs)
        return -1;
    ctl->private_clear_tid = ctl->kernel_clear_tid;
    ctl->private_robust_head = head;
    ctl->private_robust_len = len;
    /* Last physical policy change, after every registration/FS/brk check.
     * Only raw C/assembly remains before guest handoff; no libc or clock call
     * may run after restoring a possibly faulting TSC mode.
     */
    int tsc = 0;
    if (call(SYS_prctl, PR_SET_TSC, ctl->guest_tsc, 0, 0, 0, 0) ||
        call(SYS_prctl, PR_GET_TSC, (uint64_t)&tsc, 0, 0, 0, 0) ||
        (uint64_t)tsc != ctl->guest_tsc)
        return -1;
    ctl->native_state |= EXEC_PRIVATE_NATIVE_RESTORED;
    return 0;
}
