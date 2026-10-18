/* SOURCE-ONLY InitialImage bootstrap. No libc/TLS/allocator, no fake Detcore.
 * PT_LOAD logic is lifted from frozen delegate-bootstrap-padzero.c:207-274
 * (08b393777472b54ceca129d61fb52af090793c3830dc003e026256d161f42d6b):
 * reserve span; map actual file pages; full-page padzero; anonymous BSS; W^X.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include "private-control.h"
#include "bootstrap-image.h"
#define Image BootstrapImage
#define equal bootstrap_equal

#define PAGE UINT64_C(4096)
#define MAX_IMAGE UINT64_C(16777216)
#define MAX_AUX 64u
#define SIGSYS_BIT (UINT64_C(1) << (SIGSYS - 1))
#define DROP_MAP UINT64_MAX
/* Version-one ToolRegion contract, guest/tool_region.rs::BASE/BYTES.
 * The generic mmap bound remains independent of this exact reservation.
 */
#define TOOL_REGION_BASE UINT64_C(0x600000000000)
#define TOOL_REGION_BYTES UINT64_C(0x100000000)
extern struct ExecPrivateControl *exec_private_control;
extern void private_bootstrap_sigsys_entry(void);
extern unsigned char private_boot_code_start[], private_boot_code_end[];
extern unsigned char private_boot_data_start[], private_boot_data_end[];
static uint64_t guest_aux[MAX_AUX * 2], guest_aux_count;

struct KernelAction {
    uint64_t handler, flags, restorer, mask;
};

static long call(long nr, uint64_t a, uint64_t b, uint64_t c,
                 uint64_t d, uint64_t e, uint64_t f) {
    return private_native_syscall(nr, a, b, c, d, e, f);
}
static int failed(long value) {
    return (uint64_t)value >= (uint64_t)-4095;
}
static uint64_t down(uint64_t value) { return value & ~(PAGE - 1); }
static uint64_t up(uint64_t value) { return (value + PAGE - 1) & ~(PAGE - 1); }
__attribute__((noreturn)) static void fail(unsigned code) {
    struct ExecPrivateControl *ctl = exec_private_control;
    if ((uint64_t)ctl == EXEC_PRIVATE_CONTROL_ADDR) ctl->failure_code = code;
    private_native_terminal(code);
}
static int overlaps(uint64_t lo, uint64_t hi, uint64_t a, uint64_t b) {
    return lo < b && a < hi;
}
static int extent(uint64_t addr, uint64_t bytes, uint64_t *lo, uint64_t *hi) {
    if (!bytes || addr > UINT64_MAX - bytes ||
        addr + bytes > UINT64_MAX - (PAGE - 1)) return 0;
    *lo = down(addr);
    *hi = up(addr + bytes);
    return *hi > *lo;
}
static int forbidden(struct ExecPrivateControl *ctl, uint64_t lo, uint64_t hi) {
    return overlaps(lo, hi, EXEC_PRIVATE_GATE_BASE, EXEC_PRIVATE_BOOTSTRAP_END) ||
        overlaps(lo, hi, EXEC_PRIVATE_CONTROL_ADDR, EXEC_NATIVE_RESUME_ADDR + PAGE) ||
        overlaps(lo, hi, EXEC_PRIVATE_SIGNAL_BASE, EXEC_PRIVATE_SIGNAL_BASE + EXEC_PRIVATE_SIGNAL_BYTES) ||
        overlaps(lo, hi, EXEC_PRIVATE_STACK_BASE, EXEC_PRIVATE_STACK_BASE + EXEC_PRIVATE_STACK_BYTES) ||
        overlaps(lo, hi, EXEC_PRIVATE_BRK_BASE, EXEC_PRIVATE_BRK_BASE + EXEC_PRIVATE_BRK_BYTES) ||
        overlaps(lo, hi, ctl->guest_ld_lo, ctl->guest_ld_hi);
}
static int covered(struct ExecPrivateControl *ctl, uint64_t lo, uint64_t hi) {
    if (ctl->private_map_count > EXEC_PRIVATE_EXTENT_CAPACITY) fail(91);
    uint64_t cursor = lo;
    for (uint64_t i = 0; i < ctl->private_map_count; ++i) {
        const struct ExecPrivateMap *m = &ctl->maps[i];
        if (m->hi <= cursor) continue;
        if (m->lo > cursor) return 0;
        cursor = m->hi;
        if (cursor >= hi) return 1;
    }
    return 0;
}

static void track(struct ExecPrivateControl *ctl, uint64_t lo, uint64_t bytes,
                  uint64_t prot, uint64_t flags) {
    if (private_track_map(ctl, lo, bytes, prot, flags)) fail(92);
}
static void reserve(struct ExecPrivateControl *ctl, uint64_t addr, uint64_t bytes,
                    uint64_t prot) {
    long got = call(SYS_mmap, addr, bytes, prot,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                    (uint64_t)-1, 0);
    if (got != (long)addr) fail(93);
    track(ctl, addr, bytes, prot, MAP_PRIVATE | MAP_ANONYMOUS);
}
static uint64_t sealed_packet(int fd, uint64_t addr, uint64_t max) {
    struct stat st;
    long seals = call(SYS_fcntl, fd, F_GET_SEALS, 0, 0, 0, 0);
    if (call(SYS_fstat, fd, (uint64_t)&st, 0, 0, 0, 0) ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 || (uint64_t)st.st_size > max ||
        failed(seals) || (seals & 15) != 15)
        fail(94);
    long mapped = call(SYS_mmap, addr, PAGE, PROT_READ,
                      MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    if (mapped != (long)addr) fail(94);
    return (uint64_t)st.st_size;
}
static int absolute_path(const char *s, uint64_t size) {
    if (!size || s[0] != '/') return 0;
    for (uint64_t i = 0; i < size; ++i) {
        if (!s[i]) return i > 1;
        if (s[i] == ':' || s[i] == '$') return 0;
    }
    return 0;
}

/* Role private=0 is exclusively the genuine GUEST loader: no ownership/code
 * records, no private-origin admission, no misclassified guest mprotect.
 */
static void image_track(void *context, uint64_t lo, uint64_t bytes,
                        uint64_t prot, uint64_t flags) {
    track(context, lo, bytes, prot, flags);
}
static struct Image map_image(struct ExecPrivateControl *ctl, int fd, int private) {
    const struct BootstrapImageOps ops = {call, fail, private ? image_track : 0, ctl};
    return bootstrap_map_image(fd, &ops, 0);
}

static void capture_aux(uint64_t *stack) {
    uint64_t argc = stack[0];
    if (argc > 256) fail(107);
    uint64_t *env = stack + argc + 2;
    unsigned n = 0;
    while (*env) { if (++n > 4096) fail(107); ++env; }
    uint64_t *aux = env + 1;
    for (unsigned i = 0; i < MAX_AUX; ++i) {
        guest_aux[i * 2] = aux[i * 2];
        guest_aux[i * 2 + 1] = aux[i * 2 + 1];
        if (aux[i * 2] == AT_NULL) { guest_aux_count = i + 1; return; }
    }
    fail(107);
}
static uint64_t aux_value(uint64_t kind) {
    unsigned hits = 0;
    uint64_t value = 0;
    for (uint64_t i = 0; i < guest_aux_count; ++i)
        if (guest_aux[i * 2] == kind) { ++hits; value = guest_aux[i * 2 + 1]; }
    if (hits != 1) fail(108);
    return value;
}
static uint64_t push_bytes(uint64_t *cursor, const void *source, uint64_t bytes) {
    if (bytes > *cursor - (EXEC_PRIVATE_STACK_BASE + PAGE)) fail(109);
    *cursor -= bytes;
    memcpy((void *)(uintptr_t)*cursor, source, bytes);
    return *cursor;
}
static uint64_t push_string(uint64_t *cursor, const char *source, uint64_t limit) {
    uint64_t n = 0;
    while (n < limit && source[n]) ++n;
    if (n == limit) fail(109);
    return push_bytes(cursor, source, n + 1);
}
static void make_private_stack(struct ExecPrivateControl *ctl,
                               const struct ExecPrivateNativeConfig *config) {
    uint64_t cursor = ctl->private_stack_end;
    uint64_t argv0 = push_string(&cursor, config->runner_path, sizeof(config->runner_path));
    char control_string[19];
    control_string[0] = '0'; control_string[1] = 'x';
    for (unsigned i = 0; i < 16; ++i)
        control_string[i + 2] = "0123456789abcdef"[(EXEC_PRIVATE_CONTROL_ADDR >> (60 - 4 * i)) & 15];
    control_string[18] = 0;
    uint64_t argv1 = push_string(&cursor, control_string, sizeof(control_string));
    char library[sizeof(config->tool_library_path) + 17];
    const char prefix[] = "LD_LIBRARY_PATH=";
    unsigned used = 0;
    for (unsigned i = 0; i < sizeof(prefix) - 1; ++i) library[used++] = prefix[i];
    for (unsigned i = 0; config->tool_library_path[i]; ++i) library[used++] = config->tool_library_path[i];
    library[used++] = 0;
    uint64_t env0 = push_bytes(&cursor, library, used);
    uint64_t env1 = push_string(&cursor, "GLIBC_TUNABLES=glibc.pthread.rseq=0", 64);
    uint64_t random = push_bytes(&cursor, (void *)(uintptr_t)aux_value(AT_RANDOM), 16);
    uint64_t private_aux[MAX_AUX * 2], count = 0;
    for (uint64_t i = 0; i < guest_aux_count; ++i) {
        uint64_t kind = guest_aux[i * 2], value = guest_aux[i * 2 + 1];
        if (kind == AT_SYSINFO_EHDR) continue; /* private libc uses its own syscall sites */
        if (kind == AT_PHDR) value = ctl->runner_phdr;
        else if (kind == AT_PHNUM) value = ctl->runner_phnum;
        else if (kind == AT_PHENT) value = ctl->runner_phent;
        else if (kind == AT_ENTRY) value = ctl->runner_entry;
        else if (kind == AT_BASE) value = ctl->tool_ld_bias;
        else if (kind == AT_EXECFN) value = argv0;
        else if (kind == AT_RANDOM) value = random;
        else if (kind == AT_PLATFORM || kind == AT_BASE_PLATFORM) {
            if (value) value = push_string(&cursor, (void *)(uintptr_t)value, 256);
        }
        private_aux[count * 2] = kind; private_aux[count * 2 + 1] = value;
        ++count;
    }
    /* Mandatory kernel keys are present exactly once before their substitution. */
    (void)aux_value(AT_PHDR); (void)aux_value(AT_PHNUM); (void)aux_value(AT_PHENT);
    (void)aux_value(AT_ENTRY); (void)aux_value(AT_BASE); (void)aux_value(AT_EXECFN);
    uint64_t words = 7 + count * 2; /* argc, argv[2], NULL, env[2], NULL, aux */
    if (cursor < EXEC_PRIVATE_STACK_BASE + PAGE + words * 8 + 16) fail(110);
    uint64_t sp = (cursor - words * 8) & ~UINT64_C(15);
    uint64_t *out = (void *)(uintptr_t)sp;
    out[0] = 2; out[1] = argv0; out[2] = argv1; out[3] = 0;
    out[4] = env0; out[5] = env1; out[6] = 0;
    for (uint64_t i = 0; i < count * 2; ++i) out[7 + i] = private_aux[i];
    *(uint64_t *)(uintptr_t)ctl->private_stack_base = sp; /* native entry metadata */
}

/* Only real private executable mappings may issue relayed syscalls. */
static int private_syscall_ip(struct ExecPrivateControl *ctl, uint64_t ip) {
    if (ctl->private_code_count > EXEC_PRIVATE_EXTENT_CAPACITY || ip < 2) return 0;
    for (uint64_t i = 0; i < ctl->private_code_count; ++i)
        if (ip - 2 >= ctl->code[i].lo && ip < ctl->code[i].hi) {
            const unsigned char *instruction = (void *)(uintptr_t)(ip - 2);
            return instruction[0] == 0x0f && instruction[1] == 0x05;
        }
    return 0;
}
static int initial_tool_reservation(struct ExecPrivateControl *ctl, const uint64_t a[6]) {
    return __atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE) == EXEC_PRIVATE_TOOL_INIT &&
        a[0] == TOOL_REGION_BASE && a[1] == TOOL_REGION_BYTES && a[2] == PROT_NONE &&
        a[3] == (uint64_t)(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE) &&
        a[4] == UINT64_MAX && a[5] == 0;
}
static void mmap_refused(struct ExecPrivateControl *ctl, long nr, const uint64_t a[6]) {
    char out[320];
    size_t used = 0;
    const char *prefix = "exec-private mapping refused ";
    while (*prefix && used < sizeof(out) - 1) out[used++] = *prefix++;
    const char *const names[8] = {"phase", "nr", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"};
    uint64_t values[8] = {__atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE), (uint64_t)nr,
                          a[0], a[1], a[2], a[3], a[4], a[5]};
    for (unsigned i = 0; i < 8; ++i) {
        const char *name = names[i];
        while (*name && used < sizeof(out) - 1) out[used++] = *name++;
        if (used + 19 >= sizeof(out)) break;
        out[used++] = '='; out[used++] = '0'; out[used++] = 'x';
        for (unsigned digit = 0; digit < 16; ++digit)
            out[used++] = "0123456789abcdef"[(values[i] >> (60 - 4 * digit)) & 15];
        if (used < sizeof(out) - 1) out[used++] = ' ';
    }
    if (used < sizeof(out)) out[used++] = '\n';
    /* One nonblocking diagnostic on the coordinator-owned stderr socket.
     * Short/error output never delays refusal or changes a mapping predicate.
     */
    (void)call(SYS_sendto, 2, (uint64_t)out, used, 0x4040, 0, 0);
}
static long relay_mapping(struct ExecPrivateControl *ctl, long nr, const uint64_t a[6]) {
    uint64_t lo, hi;
    if (nr == SYS_mmap) {
        if (!a[1] || (a[1] > (1u << 30) && !initial_tool_reservation(ctl, a)) ||
            (a[2] & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) ||
            ((a[2] & PROT_EXEC) && (a[3] & MAP_ANONYMOUS))) {
            mmap_refused(ctl, nr, a);
            fail(111);
        }
        if ((a[3] & (MAP_FIXED | MAP_FIXED_NOREPLACE)) &&
            (!extent(a[0], a[1], &lo, &hi) || forbidden(ctl, lo, hi) ||
             ((a[3] & MAP_FIXED) && !covered(ctl, lo, hi))))
            fail(112);
        long result = call(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (!failed(result)) {
            if (!extent(result, a[1], &lo, &hi) || lo != (uint64_t)result ||
                forbidden(ctl, lo, hi)) fail(113);
            track(ctl, lo, hi - lo, a[2], a[3] & ~(uint64_t)(MAP_FIXED | MAP_FIXED_NOREPLACE));
        }
        return result;
    }
    if (nr == SYS_mremap) {
        /* First private allocator slice supports ordinary MAYMOVE data remap.
         * FIXED/DONTUNMAP, executable remap and aliases remain explicit refusals.
         */
        if (!extent(a[0], a[1], &lo, &hi) || forbidden(ctl, lo, hi) ||
            !covered(ctl, lo, hi) || !a[2] || a[2] > (1u << 30) || (a[3] & ~UINT64_C(1)))
            fail(114);
        uint64_t prot = UINT64_MAX, flags = 0;
        for (uint64_t i = 0; i < ctl->private_map_count; ++i)
            if (ctl->maps[i].lo <= lo && ctl->maps[i].hi >= hi) {
                prot = ctl->maps[i].prot; flags = ctl->maps[i].flags; break;
            }
        if (prot == UINT64_MAX || (prot & PROT_EXEC) || !(flags & MAP_ANONYMOUS)) fail(114);
        long result = call(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (!failed(result)) {
            track(ctl, lo, hi - lo, DROP_MAP, 0);
            if (!extent(result, a[2], &lo, &hi) || forbidden(ctl, lo, hi)) fail(114);
            track(ctl, lo, hi - lo, prot, flags);
        }
        return result;
    }
    if (!extent(a[0], a[1], &lo, &hi) || forbidden(ctl, lo, hi) ||
        !covered(ctl, lo, hi)) {
        mmap_refused(ctl, nr, a);
        fail(115);
    }
    if (nr == SYS_mprotect || nr == SYS_pkey_mprotect) {
        if ((a[2] & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) ||
            (nr == SYS_pkey_mprotect && a[3] != 0))
            fail(116);
        if (a[2] & PROT_EXEC)
            for (uint64_t i = 0; i < ctl->private_map_count; ++i)
                if (overlaps(lo, hi, ctl->maps[i].lo, ctl->maps[i].hi) &&
                    (ctl->maps[i].flags & MAP_ANONYMOUS)) fail(116);
    }
    long result = call(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (result == 0 && nr == SYS_munmap) track(ctl, lo, hi - lo, DROP_MAP, 0);
    if (result == 0 && (nr == SYS_mprotect || nr == SYS_pkey_mprotect)) {
        /* Keep existing file/anonymous provenance while updating permissions. */
        struct ExecPrivateMap before[EXEC_PRIVATE_EXTENT_CAPACITY];
        uint64_t count = ctl->private_map_count;
        for (uint64_t i = 0; i < count; ++i) before[i] = ctl->maps[i];
        for (uint64_t i = 0; i < count; ++i)
            if (overlaps(lo, hi, before[i].lo, before[i].hi)) {
                uint64_t start = lo > before[i].lo ? lo : before[i].lo;
                uint64_t end = hi < before[i].hi ? hi : before[i].hi;
                track(ctl, start, end - start, a[2], before[i].flags);
            }
    }
    return result;
}

void private_bootstrap_sigsys(int signal, siginfo_t *info, void *context) {
    struct ExecPrivateControl *ctl = exec_private_control;
    if ((uint64_t)ctl != EXEC_PRIVATE_CONTROL_ADDR ||
        ctl->abi_version != EXEC_PRIVATE_ABI_VERSION || ctl->byte_len != sizeof(*ctl))
        fail(117);
    uint64_t phase = __atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE);
    if (phase != EXEC_PRIVATE_TOOL_LOADING && phase != EXEC_PRIVATE_TOOL_INIT &&
        phase != EXEC_PRIVATE_TOOL_CALLBACK && phase != EXEC_PRIVATE_TOOL_LIFECYCLE) fail(118); /* never guest relay */
    ucontext_t *uc = context;
    greg_t *g = uc->uc_mcontext.gregs;
    uint64_t ip = (uint64_t)g[REG_RIP];
    if (signal != SIGSYS || !info || info->si_code != 1 ||
        info->si_arch != 0xc000003e || info->si_syscall < 0 ||
        (info->si_syscall & 0x40000000) ||
        (uint64_t)info->si_call_addr != ip || !private_syscall_ip(ctl, ip))
        fail(119);
    long nr = info->si_syscall;
    uint64_t a[6] = {(uint64_t)g[REG_RDI], (uint64_t)g[REG_RSI], (uint64_t)g[REG_RDX],
                     (uint64_t)g[REG_R10], (uint64_t)g[REG_R8], (uint64_t)g[REG_R9]};
    if (phase != EXEC_PRIVATE_TOOL_LOADING && private_native_get_fs() != ctl->tool_fs)
        fail(120);
    if (nr == SYS_clone || nr == SYS_clone3 || nr == SYS_fork || nr == SYS_vfork ||
        nr == SYS_execve || nr == SYS_execveat || nr == SYS_rseq ||
        nr == SYS_seccomp || nr == SYS_pkey_alloc || nr == SYS_pkey_free ||
        (nr == SYS_prctl && a[0] == 22)) fail(121);
    if (nr == SYS_rt_sigaction && a[0] == SIGSYS && a[1]) fail(122);
    if (nr == SYS_rt_sigprocmask && a[1] &&
        (a[0] == SIG_BLOCK || a[0] == SIG_SETMASK) &&
        (*(const uint64_t *)(uintptr_t)a[1] & SIGSYS_BIT)) fail(123);
    if (nr == SYS_arch_prctl && (a[0] == 0x1001 ||
        (a[0] == 0x1002 && phase != EXEC_PRIVATE_TOOL_LOADING && a[1] != ctl->tool_fs)))
        fail(124);
    ++ctl->native_traps; /* PRIVATE Tool traffic; never Detcore guest evidence */
    long result;
    if (nr == SYS_brk) result = private_owned_brk(ctl, a[0]);
    else if (nr == SYS_set_tid_address || nr == SYS_set_robust_list)
        result = private_registration_call(ctl, nr, a);
    else if (nr == SYS_mmap || nr == SYS_mprotect || nr == SYS_munmap ||
             nr == SYS_mremap || nr == SYS_madvise || nr == SYS_pkey_mprotect)
        result = relay_mapping(ctl, nr, a);
    else result = call(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    uint64_t actual_fs = private_native_get_fs();
    if (phase == EXEC_PRIVATE_TOOL_LOADING) ctl->tool_fs = actual_fs;
    else if (actual_fs != ctl->tool_fs) fail(125);
    if (__atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE) != phase) fail(125);
    /* Kernel skipped the original syscall. Preserve every other saved GPR/RIP
     * and signal/XSTATE field; only supply the actual native return value.
     */
    g[REG_RAX] = (greg_t)result;
}
__attribute__((unused)) static void install_handler(struct ExecPrivateControl *ctl) {
    stack_t stack = {(void *)(uintptr_t)ctl->bootstrap_stack_base, 0,
                     ctl->bootstrap_stack_end - ctl->bootstrap_stack_base};
    struct KernelAction action = {(uint64_t)private_bootstrap_sigsys_entry,
        UINT64_C(0x04000000) | SA_SIGINFO | SA_ONSTACK, EXEC_PRIVATE_RESTORER_ENTRY, 0};
    if (call(SYS_sigaltstack, (uint64_t)&stack, 0, 0, 0, 0, 0) ||
        call(SYS_rt_sigaction, SIGSYS, (uint64_t)&action, 0, 8, 0, 0)) fail(126);
    struct KernelAction verify = {0};
    uint64_t mask = 0;
    if (call(SYS_rt_sigaction, SIGSYS, 0, (uint64_t)&verify, 8, 0, 0) ||
        !equal(&action, &verify, sizeof(action)) ||
        call(SYS_rt_sigprocmask, SIG_SETMASK, 0, (uint64_t)&mask, 8, 0, 0) ||
        (mask & SIGSYS_BIT)) fail(126);
}

/* Version one defines the loader's actual controlled entry GPRs. The old
 * InitialImage resume path does not read or map this record. Kernel original
 * argc/argv/env/auxv bytes remain untouched, including the genuine AT_BASE=0.
 */
static void prepare_native_resume(struct ExecPrivateControl *ctl) {
    const unsigned char *input = (void *)(uintptr_t)ctl->init_input;
    if (ctl->init_input_len < 8 || !equal(input, "HLNEXEC1", 8)) return;
    reserve(ctl, EXEC_NATIVE_RESUME_ADDR, PAGE, PROT_READ | PROT_WRITE);
    struct ExecNativeResume *resume = (void *)(uintptr_t)EXEC_NATIVE_RESUME_ADDR;
    resume->magic = EXEC_NATIVE_RESUME_MAGIC;
    resume->abi_version = 1;
    resume->byte_len = sizeof(*resume);
    resume->native_tid = ctl->native_tid;
    /* General registers are intentionally zero at this defined native loader
     * entry. Assembly really loads every field; no syscall frame is fabricated.
     */
    resume->regs[15] = UINT64_MAX; /* orig_rax: no active syscall */
    resume->regs[16] = ctl->guest_ld_entry;
    uint16_t cs, ss, ds, es;
    __asm__ volatile("mov %%cs,%0; mov %%ss,%1; mov %%ds,%2; mov %%es,%3"
        : "=r"(cs), "=r"(ss), "=r"(ds), "=r"(es));
    resume->regs[17] = cs;
    resume->regs[18] = 0x202; /* final assembly installs these exact flags */
    resume->regs[19] = ctl->guest_rsp;
    resume->regs[20] = ss;
    resume->regs[21] = ctl->guest_fs;
    if (call(SYS_arch_prctl, 0x1004, (uint64_t)&resume->regs[22], 0, 0, 0, 0)) fail(134);
    resume->regs[23] = ds;
    resume->regs[24] = es;
    /* FS and GS selectors are queried, never guessed from their bases. */
    uint16_t fs, gs;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1" : "=r"(fs), "=r"(gs));
    resume->regs[25] = fs;
    resume->regs[26] = gs;
    resume->pkru = ctl->guest_pkru;
    if (call(SYS_mprotect, EXEC_NATIVE_RESUME_ADDR, PAGE, PROT_READ, 0, 0, 0)) fail(134);
    track(ctl, EXEC_NATIVE_RESUME_ADDR, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS);
}

struct ExecPrivateControl *private_bootstrap_prepare(uint64_t *guest_stack,
                                                     uint64_t guest_pkru) {
    /* First native syscall still uses the exact selected gate and no handler.
     * The wrong-page negative must die here rather than being relayed.
     */
    if (call(SYS_getpid, 0, 0, 0, 0, 0, 0) <= 0) fail(127);
    long mapped = call(SYS_mmap, EXEC_PRIVATE_CONTROL_ADDR, PAGE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, (uint64_t)-1, 0);
    if (mapped != (long)EXEC_PRIVATE_CONTROL_ADDR) fail(128);
    struct ExecPrivateControl *ctl = (void *)(uintptr_t)mapped;
    ctl->abi_version = EXEC_PRIVATE_ABI_VERSION;
    ctl->byte_len = sizeof(*ctl);
    ctl->phase = EXEC_PRIVATE_TOOL_LOADING;
    ctl->guest_rsp = (uint64_t)guest_stack;
    ctl->guest_pkru = guest_pkru;
    exec_private_control = ctl;
    track(ctl, EXEC_PRIVATE_CONTROL_ADDR, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    track(ctl, down((uint64_t)private_boot_code_start),
          up((uint64_t)private_boot_code_end) - down((uint64_t)private_boot_code_start),
          PROT_READ | PROT_EXEC, MAP_PRIVATE);
    track(ctl, down((uint64_t)private_boot_data_start),
          up((uint64_t)private_boot_data_end) - down((uint64_t)private_boot_data_start),
          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    if (private_capture_kernel_state(ctl)) fail(129);
    track(ctl, EXEC_PRIVATE_BRK_BASE, EXEC_PRIVATE_BRK_BYTES, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS);
    capture_aux(guest_stack);
    if (aux_value(AT_PAGESZ) != PAGE || aux_value(AT_BASE) != 0) fail(130);

    ctl->init_input_len = sealed_packet(EXEC_PRIVATE_INIT_INPUT_FD,
                                        EXEC_PRIVATE_INPUT_ADDR, EXEC_PRIVATE_PACKET_LIMIT);
    ctl->init_input = EXEC_PRIVATE_INPUT_ADDR;
    ctl->init_input_fd = EXEC_PRIVATE_INIT_INPUT_FD;
    ctl->input_mapping_base = EXEC_PRIVATE_INPUT_ADDR;
    ctl->input_mapping_end = EXEC_PRIVATE_INPUT_ADDR + PAGE;
    track(ctl, EXEC_PRIVATE_INPUT_ADDR, PAGE, PROT_READ, MAP_PRIVATE);
    if (sealed_packet(EXEC_PRIVATE_NATIVE_CONFIG_FD, EXEC_PRIVATE_CONFIG_ADDR,
                      EXEC_PRIVATE_PACKET_LIMIT) != sizeof(struct ExecPrivateNativeConfig))
        fail(131);
    const struct ExecPrivateNativeConfig *config = (void *)(uintptr_t)EXEC_PRIVATE_CONFIG_ADDR;
    if (config->abi_version != EXEC_PRIVATE_ABI_VERSION || config->byte_len != sizeof(*config) ||
        !absolute_path(config->runner_path, sizeof(config->runner_path)) ||
        !absolute_path(config->tool_library_path, sizeof(config->tool_library_path)))
        fail(131);
    ctl->native_config = EXEC_PRIVATE_CONFIG_ADDR;
    track(ctl, EXEC_PRIVATE_CONFIG_ADDR, PAGE, PROT_READ, MAP_PRIVATE);
    if (call(SYS_close, EXEC_PRIVATE_NATIVE_CONFIG_FD, 0, 0, 0, 0, 0)) fail(131);
    reserve(ctl, EXEC_PRIVATE_SIGNAL_BASE, EXEC_PRIVATE_SIGNAL_BYTES, PROT_READ | PROT_WRITE);
    reserve(ctl, EXEC_PRIVATE_STACK_BASE, EXEC_PRIVATE_STACK_BYTES, PROT_READ | PROT_WRITE);
    ctl->bootstrap_handler = (uint64_t)private_bootstrap_sigsys_entry;
    ctl->bootstrap_restorer = EXEC_PRIVATE_RESTORER_ENTRY;
    ctl->bootstrap_stack_base = EXEC_PRIVATE_SIGNAL_BASE;
    ctl->bootstrap_stack_end = EXEC_PRIVATE_SIGNAL_BASE + EXEC_PRIVATE_SIGNAL_BYTES;
    ctl->private_stack_base = EXEC_PRIVATE_STACK_BASE;
    ctl->private_stack_end = EXEC_PRIVATE_STACK_BASE + EXEC_PRIVATE_STACK_BYTES;
    struct Image guest = map_image(ctl, EXEC_PRIVATE_GUEST_LOADER_FD, 0);
    ctl->guest_ld_lo = guest.lo; ctl->guest_ld_hi = guest.hi; ctl->guest_ld_entry = guest.entry;
    prepare_native_resume(ctl);
    struct Image runner = map_image(ctl, EXEC_PRIVATE_RUNNER_FD, 1);
    ctl->runner_entry = runner.entry; ctl->runner_bias = runner.bias;
    ctl->runner_phdr = runner.phdr; ctl->runner_phnum = runner.phnum; ctl->runner_phent = runner.phent;
    struct Image loader = map_image(ctl, EXEC_PRIVATE_TOOL_LOADER_FD, 1);
    ctl->tool_ld_entry = loader.entry; ctl->tool_ld_bias = loader.bias;
    make_private_stack(ctl, config);
    /* Never edit any byte of the guest's original argc/argv/env/auxv table. */
    uint64_t *env = guest_stack + guest_stack[0] + 2;
    while (*env) ++env;
    if (!equal(env + 1, guest_aux, guest_aux_count * 16)) fail(132);
#ifndef EXEC_PRIVATE_NO_HANDLER
    install_handler(ctl);
#endif
    /* The locator is write-once. Native private callbacks use the same pointer
     * after the genuine Rust handover; no legacy DelegateState occupies it.
     */
    if (call(SYS_mprotect, EXEC_PRIVATE_LOCATOR_ADDR, PAGE, PROT_READ, 0, 0, 0)) fail(133);
    return ctl;
}
