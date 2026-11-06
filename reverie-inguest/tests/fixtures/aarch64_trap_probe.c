/*
 * aarch64 seccomp-trap kernel-semantics probe (maintained test fixture).
 *
 * Pins every kernel-visible constant the aarch64 trap runtime relies on:
 * filter-visible svc IP, SIGSYS siginfo vs ucontext relations, arg
 * integrity, restorer return IP, fixed gate geometry, BTI landing pads,
 * SVE signal records, page/altstack sizing, trap cost, filter stacking,
 * and syscall-user-dispatch availability. Driven by
 * tests/aarch64_trap_probe.rs, which asserts on the KEY=VALUE lines.
 *
 * Manual build (the test builds it the same way):
 *   cc -O1 -g -Wall -o aarch64-trap-probe aarch64_trap_probe.c -pthread
 * Also build with -mbranch-protection=standard: P1/P3/P4 must behave
 * identically when the whole binary is BTI-guarded; P6 covers page BTI.
 *
 * Output: one KEY=VALUE line per measurement; parent prints per-child status.
 * Every filter installs in a forked child only (filters are irreversible).
 * Escape hatch: every filter allowlists exit_group(94) at the escape svc
 * site under BOTH ip candidates (site, site+4), so handlers can always die
 * loudly before P1 pins which candidate the kernel reports.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef PROT_BTI
#define PROT_BTI 0x10
#endif
#ifndef PR_SVE_GET_VL
#define PR_SVE_GET_VL 51
#endif
#ifndef SYS_rt_sigreturn
#define SYS_rt_sigreturn 139
#endif
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000 /* asm-generic signal-defs.h; glibc aarch64 omits it */
#endif
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON 1
#define SYSCALL_DISPATCH_FILTER_ALLOW 0
#define SYSCALL_DISPATCH_FILTER_BLOCK 1
#endif
#define SI_CODE_SYS_USER_DISPATCH 2 /* asm-generic siginfo.h SYS_USER_DISPATCH */
#define SI_CODE_SYS_SECCOMP 1

/* ---- asm syscall sites (addresses are measurements, keep labels) ---- */
extern char probe_svc_site[], probe_svc_ret[];
extern char probe_escape_site[], probe_escape_ret[];
extern char probe_restorer[], probe_restorer_svc[], probe_restorer_ret[];
long probe_svc_call(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
_Noreturn void probe_escape(int code);

__asm__(
    ".text\n"
    ".globl probe_svc_call\n"
    "probe_svc_call:\n"
    "  mov x8, x0\n"
    "  mov x0, x1\n  mov x1, x2\n  mov x2, x3\n"
    "  mov x3, x4\n  mov x4, x5\n  mov x5, x6\n"
    ".globl probe_svc_site\n"
    "probe_svc_site:\n"
    "  svc #0\n"
    ".globl probe_svc_ret\n"
    "probe_svc_ret:\n"
    "  ret\n"
    ".globl probe_escape\n"
    "probe_escape:\n"
    "  mov x8, #94\n" /* __NR_exit_group; x0 = code already */
    ".globl probe_escape_site\n"
    "probe_escape_site:\n"
    "  svc #0\n"
    ".globl probe_escape_ret\n"
    "probe_escape_ret:\n"
    "  brk #0\n"
    ".globl probe_restorer\n"
    "probe_restorer:\n"
    "  mov x8, #139\n" /* __NR_rt_sigreturn */
    ".globl probe_restorer_svc\n"
    "probe_restorer_svc:\n"
    "  svc #0\n"
    ".globl probe_restorer_ret\n"
    "probe_restorer_ret:\n"
    "  brk #0\n");

/* ---- shared handler state (children only; no syscalls in handlers) ---- */
static volatile unsigned long h_entries;
static volatile unsigned long h_call_addr, h_pc, h_sp, h_x30;
static volatile long h_syscall_nr, h_regs8;
static volatile int h_si_code;
static volatile unsigned int h_arch;
static volatile unsigned long h_args[6];
static volatile long h_spoof_result;
static volatile int h_spoof; /* 1: write h_spoof_result into regs[0] */
static volatile int h_single; /* 1: >1 entries means svc re-executed (P3) */

/* SIGSYS handler: records siginfo (raw asm-generic offsets +16/+24/+28, as
 * in reverie-inguest trap/frame.rs) and ucontext, then optionally spoofs. */
static void sigsys_rec(int sig, siginfo_t *info, void *vuc) {
    (void)sig;
    if (++h_entries > 1 && h_single)
        probe_escape(42); /* P3: pc re-executed the svc -> fail loudly */
    h_si_code = info->si_code;
    ucontext_t *uc = (ucontext_t *)vuc;
    const unsigned char *si = (const unsigned char *)info;
    __builtin_memcpy((void *)&h_call_addr, si + 16, 8);
    int32_t nr;
    __builtin_memcpy(&nr, si + 24, 4);
    h_syscall_nr = nr;
    __builtin_memcpy((void *)&h_arch, si + 28, 4);
    h_pc = uc->uc_mcontext.pc;
    h_sp = uc->uc_mcontext.sp;
    h_x30 = uc->uc_mcontext.regs[30];
    h_regs8 = (long)uc->uc_mcontext.regs[8];
    for (int i = 0; i < 6; i++)
        h_args[i] = uc->uc_mcontext.regs[i];
    if ((long)uc->uc_mcontext.regs[8] == SYS_rt_sigreturn)
        probe_escape(44); /* P4 wrong-guess child: sigreturn itself trapped */
    if (h_spoof)
        uc->uc_mcontext.regs[0] = (unsigned long)h_spoof_result;
}

/* ---- BPF helpers ---- */
#define STMT(code_, k_) BPF_STMT(code_, k_)
#define JEQ(k_, jt_, jf_) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, k_, jt_, jf_)
#define LD_NR STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))
#define LD_ARCH STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch))
#define LD_IP_LO STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, instruction_pointer))
#define LD_IP_HI STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4)
#define RET(v_) STMT(BPF_RET + BPF_K, v_)

static void install_filter(struct sock_filter *f, size_t n, int tsync) {
    struct sock_fprog prog = {.len = (unsigned short)n, .filter = f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        probe_escape(50);
    long r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                     tsync ? SECCOMP_FILTER_FLAG_TSYNC : 0, &prog);
    if (r != 0)
        probe_escape(51);
}

static void install_handler(int use_restorer) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_rec;
    sa.sa_flags = SA_SIGINFO;
    if (use_restorer) {
        sa.sa_flags |= SA_RESTORER;
        sa.sa_restorer = (void (*)(void))probe_restorer;
    }
    if (sigaction(SIGSYS, &sa, NULL) != 0)
        probe_escape(52);
}

#define HI(p) ((uint32_t)((unsigned long)(p) >> 32))
#define LO(p) ((uint32_t)(unsigned long)(p))

/* Filter A: TRAP getpid only; escape exit_group allowed at esc|esc+4. */
static void install_filter_a(void) {
    struct sock_filter f[] = {
        LD_ARCH, JEQ(AUDIT_ARCH_AARCH64, 1, 0), RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR, JEQ(94, 0, 5),
        LD_IP_HI, JEQ(HI(probe_escape_site), 0, 3),
        LD_IP_LO, JEQ(LO(probe_escape_site), 4, 0), JEQ(LO(probe_escape_site) + 4, 3, 0),
        LD_NR, JEQ(SYS_getpid, 0, 1),
        RET(SECCOMP_RET_TRAP), RET(SECCOMP_RET_ALLOW),
    };
    install_filter(f, sizeof(f) / sizeof(f[0]), 0);
}

/* Filter B: getpid ALLOW iff ip==addr else ERRNO(0x111); rest ALLOW. */
static void install_filter_b(unsigned long addr) {
    struct sock_filter f[] = {
        LD_ARCH, JEQ(AUDIT_ARCH_AARCH64, 1, 0), RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR, JEQ(94, 0, 5),
        LD_IP_HI, JEQ(HI(probe_escape_site), 0, 3),
        LD_IP_LO, JEQ(LO(probe_escape_site), 8, 0), JEQ(LO(probe_escape_site) + 4, 7, 0),
        LD_NR, JEQ(SYS_getpid, 0, 5),
        LD_IP_HI, JEQ(HI(addr), 0, 2),
        LD_IP_LO, JEQ(LO(addr), 1, 0),
        RET(SECCOMP_RET_ERRNO | 0x111), RET(SECCOMP_RET_ALLOW),
    };
    install_filter(f, sizeof(f) / sizeof(f[0]), 0);
}

/* Filter C: trap everything except rt_sigreturn, gate svc at g|g+4, escape. */
static void install_filter_c(unsigned long gate) {
    struct sock_filter f[] = {
        LD_ARCH, JEQ(AUDIT_ARCH_AARCH64, 1, 0), RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR, JEQ(94, 0, 5),
        LD_IP_HI, JEQ(HI(probe_escape_site), 0, 3),
        LD_IP_LO, JEQ(LO(probe_escape_site), 9, 0), JEQ(LO(probe_escape_site) + 4, 8, 0),
        LD_NR, JEQ(SYS_rt_sigreturn, 6, 0),
        LD_IP_HI, JEQ(HI(gate), 0, 3),
        LD_IP_LO, JEQ(LO(gate), 2, 0), JEQ(LO(gate) + 4, 1, 0),
        RET(SECCOMP_RET_TRAP), RET(SECCOMP_RET_ALLOW),
    };
    install_filter(f, sizeof(f) / sizeof(f[0]), 0);
}

/* Filter D: getpid TRAP; rt_sigreturn ALLOW iff ip==addr else TRAP. */
static void install_filter_d(unsigned long addr) {
    struct sock_filter f[] = {
        LD_ARCH, JEQ(AUDIT_ARCH_AARCH64, 1, 0), RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR, JEQ(94, 0, 5),
        LD_IP_HI, JEQ(HI(probe_escape_site), 0, 3),
        LD_IP_LO, JEQ(LO(probe_escape_site), 10, 0), JEQ(LO(probe_escape_site) + 4, 9, 0),
        LD_NR, JEQ(SYS_rt_sigreturn, 0, 4),
        LD_IP_HI, JEQ(HI(addr), 0, 4),
        LD_IP_LO, JEQ(LO(addr), 3, 2),
        LD_NR, JEQ(SYS_getpid, 0, 1),
        RET(SECCOMP_RET_TRAP), RET(SECCOMP_RET_ALLOW),
    };
    install_filter(f, sizeof(f) / sizeof(f[0]), 0);
}

static void kv_l(const char *k, long v) { printf("%s=%ld\n", k, v); fflush(stdout); }
static void kv_x(const char *k, unsigned long v) { printf("%s=0x%lx\n", k, v); fflush(stdout); }
static void kv_d(const char *k, long v) { printf("%s=%+ld\n", k, v); fflush(stdout); }

/* P0: environment (no filter, runs in parent). */
static void p0_env(void) {
    kv_l("P0_PAGESZ", (long)getauxval(AT_PAGESZ));
    unsigned long hw = getauxval(AT_HWCAP), hw2 = getauxval(AT_HWCAP2);
    kv_x("P0_HWCAP", hw);
    kv_x("P0_HWCAP2", hw2);
    kv_l("P0_HWCAP_ATOMICS_LSE", !!(hw & (1UL << 8)));
    kv_l("P0_HWCAP_SVE", !!(hw & (1UL << 22)));
    kv_l("P0_HWCAP2_BTI", !!(hw2 & (1UL << 17)));
    kv_l("P0_HWCAP_PACA", !!(hw & (1UL << 30)));
#ifdef AT_MINSIGSTKSZ
    kv_l("P0_AT_MINSIGSTKSZ", (long)getauxval(AT_MINSIGSTKSZ));
#endif
    long vl = prctl(PR_SVE_GET_VL, 0, 0, 0, 0);
    kv_l("P0_SVE_VL_BYTES", vl < 0 ? -1 : (vl & 0xffff));
}

/* P1a+P2+P3: trap getpid with sentinel args; handler records + spoofs. */
static void p1a_trap_record(void) {
    install_handler(0);
    install_filter_a();
    h_spoof = 1;
    h_single = 1;
    h_spoof_result = 777;
    long r = probe_svc_call(SYS_getpid, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5);
    unsigned long site = (unsigned long)probe_svc_site;
    kv_l("P1_ENTRIES", (long)h_entries);
    kv_x("P1_SVC_SITE", site);
    kv_x("P1_SI_CALL_ADDR", h_call_addr);
    kv_d("P1_CALL_MINUS_SITE", (long)(h_call_addr - site));
    kv_d("P1_PC_MINUS_SITE", (long)(h_pc - site));
    kv_d("P1_CALL_MINUS_PC", (long)(h_call_addr - h_pc));
    kv_l("P1_SI_CODE", h_si_code);
    kv_l("P1_SI_SYSCALL", h_syscall_nr);
    kv_l("P1_REGS8", h_regs8);
    kv_x("P1_SI_ARCH", h_arch);
    int intact = 1;
    for (int i = 0; i < 6; i++)
        if (h_args[i] != (unsigned long)(0xA0 + i))
            intact = 0;
    kv_l("P2_ARGS_INTACT_X0_TO_X5", intact);
    kv_x("P2_ARG0_SEEN", h_args[0]);
    kv_l("P3_SPOOFED_RETURN", r);
    kv_l("P3_RESUME_OK", (r == 777 && h_entries == 1) ? 1 : 0);
    _exit(0);
}

/* P1b/c: which ip does the FILTER see for svc? addr = candidate. */
static void p1_ip_candidate(unsigned long addr, const char *name) {
    long my_pid = (long)getpid(); /* cache BEFORE filter poisons getpid() */
    install_filter_b(addr);
    long r = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    printf("P1_IP_CANDIDATE_%s=%s (ret=%ld)\n", name,
           (r == my_pid) ? "MATCH" : (r == -0x111 ? "NO" : "OTHER"), r);
    fflush(stdout);
    _exit(0);
}

/* P4: private restorer; filter admits rt_sigreturn only at candidate ip. */
static void p4_restorer(unsigned long addr) {
    install_handler(1);
    install_filter_d(addr);
    h_spoof = 1;
    h_single = 1;
    h_spoof_result = 888;
    long r = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    kv_l("P4_RETURNED", r);
    kv_l("P4_X30_IS_RESTORER", h_x30 == (unsigned long)probe_restorer ? 1 : 0);
    _exit(0);
}

/* P5: sustained forwarding: 100 trapped getpids, handler spoofs real pid. */
static void p5_sustained(void) {
    long pid = (long)getpid();
    install_handler(0);
    install_filter_a();
    h_spoof = 1;
    h_spoof_result = pid;
    int bad = 0;
    for (int i = 0; i < 100; i++)
        if (probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0) != pid)
            bad++;
    kv_l("P5_ENTRIES", (long)h_entries);
    kv_l("P5_BAD_RESULTS", bad);
    _exit(bad == 0 && h_entries == 100 ? 0 : 5);
}

/* P6: BTI gate page. Gate words: [pad] mov x8,#172; svc #0; ret.
 * pad: 0=none(nop), 1=bti c, 2=bti j, 3=bti jc. Entry: 0=blr, 1=br. */
#define INSN_NOP 0xd503201fu
#define INSN_BTI_C 0xd503245fu
#define INSN_BTI_J 0xd503249fu
#define INSN_BTI_JC 0xd50324dfu
#define INSN_MOV_X8_172 0xd2801588u
#define INSN_SVC0 0xd4000001u
#define INSN_RET 0xd65f03c0u

typedef long (*gate_fn)(void);
static long br_call(gate_fn g) {
    long r;
    __asm__ volatile(
        "mov x9, %1\n"
        "adr x30, 1f\n"
        "br x9\n"
        "1: mov %0, x0\n"
        : "=r"(r) : "r"((void *)g) : "x0", "x9", "x30", "memory");
    return r;
}

static void p6_case(int use_bti_prot, uint32_t pad, int via_br, const char *name) {
    long pagesz = sysconf(_SC_PAGESIZE);
    uint32_t *page = mmap(NULL, (size_t)pagesz, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { kv_l("P6_MMAP_FAIL", errno); _exit(60); }
    page[0] = pad; page[1] = INSN_MOV_X8_172; page[2] = INSN_SVC0; page[3] = INSN_RET;
    int prot = PROT_READ | PROT_EXEC | (use_bti_prot ? PROT_BTI : 0);
    if (mprotect(page, (size_t)pagesz, prot) != 0) {
        printf("P6_%s=MPROTECT_FAIL errno=%d\n", name, errno); fflush(stdout);
        _exit(61);
    }
    __builtin___clear_cache((char *)page, (char *)page + 16);
    long r = via_br ? br_call((gate_fn)page) : ((gate_fn)page)();
    printf("P6_%s=%s ret=%ld\n", name, r == (long)getpid() ? "OK" : "WRONG_RET", r);
    fflush(stdout);
    _exit(r == (long)getpid() ? 0 : 6);
}
static void t_p6_plain(void)      { p6_case(0, INSN_NOP,    0, "PLAIN_RX_BLR"); }
static void t_p6_bti_none(void)   { p6_case(1, INSN_NOP,    0, "BTI_NOPAD_BLR"); }
static void t_p6_bti_c(void)      { p6_case(1, INSN_BTI_C,  0, "BTI_C_BLR"); }
static void t_p6_bti_j(void)      { p6_case(1, INSN_BTI_J,  1, "BTI_J_BR"); }
static void t_p6_bti_jc_blr(void) { p6_case(1, INSN_BTI_JC, 0, "BTI_JC_BLR"); }
static void t_p6_bti_jc_br(void)  { p6_case(1, INSN_BTI_JC, 1, "BTI_JC_BR"); }
static void t_p6_bti_c_br(void)   { p6_case(1, INSN_BTI_C,  1, "BTI_C_BR_EXPECT_FAULT"); }
static void t_p6_bti_j_blr(void)  { p6_case(1, INSN_BTI_J,  0, "BTI_J_BLR_EXPECT_FAULT"); }

/* P7: walk sigcontext __reserved records in the handler. */
struct k_sigcontext_mirror {
    uint64_t fault_address;
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
    _Alignas(16) uint8_t reserved[4096];
};
static volatile uint32_t h_rec_magic[16], h_rec_size[16];
static volatile int h_rec_count;
static void sigsys_sve(int sig, siginfo_t *info, void *vuc) {
    (void)sig; (void)info;
    h_entries++;
    ucontext_t *uc = (ucontext_t *)vuc;
    const uint8_t *p = (const uint8_t *)&uc->uc_mcontext +
                       offsetof(struct k_sigcontext_mirror, reserved);
    for (int i = 0; i < 16; i++) {
        uint32_t magic, size;
        __builtin_memcpy(&magic, p, 4);
        __builtin_memcpy(&size, p + 4, 4);
        if (magic == 0 || size < 8)
            break;
        h_rec_magic[h_rec_count] = magic;
        h_rec_size[h_rec_count] = size;
        h_rec_count++;
        p += size;
    }
    kv_x("P7_RESERVED_OFFSET", offsetof(struct k_sigcontext_mirror, reserved));
    uc->uc_mcontext.regs[0] = (unsigned long)h_spoof_result;
}

__attribute__((target("+sve"))) static void dirty_sve(int v) {
    __asm__ volatile("dup z0.b, %w0" ::"r"(v));
}

static void p7_sve_records(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_sve;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &sa, NULL) != 0)
        probe_escape(52);
    install_filter_a();
    h_spoof_result = 999;
    if (getauxval(AT_HWCAP) & (1UL << 22))
        dirty_sve(7);
    probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    kv_l("P7_REC_COUNT", h_rec_count);
    for (int i = 0; i < h_rec_count; i++) {
        printf("P7_REC_%d_MAGIC=0x%08x\nP7_REC_%d_SIZE=%u\n", i,
               h_rec_magic[i], i, h_rec_size[i]);
        fflush(stdout);
    }
    _exit(0);
}

/* P8a: fork inheritance; P8b: TSYNC across threads. */
static void p8_fork_inherit(void) {
    install_handler(0);
    install_filter_a();
    h_spoof = 1; h_spoof_result = 777;
    pid_t g = fork();
    if (g == 0) {
        long r = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
        _exit(r == 777 ? 0 : 3);
    }
    int st = 0;
    waitpid(g, &st, 0);
    kv_l("P8_FORK_CHILD_EXIT", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    kv_l("P8_FORK_CHILD_SIGNAL", WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    _exit(0);
}

static atomic_int p8_go, p8_done;
static volatile long p8_thread_ret;
static void *p8_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&p8_go))
        sched_yield();
    p8_thread_ret = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    atomic_store(&p8_done, 1);
    return NULL;
}
static void p8_tsync(void) {
    install_handler(0);
    pthread_t th;
    if (pthread_create(&th, NULL, p8_thread, NULL) != 0)
        _exit(70);
    struct sock_filter f[] = {
        LD_ARCH, JEQ(AUDIT_ARCH_AARCH64, 1, 0), RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR, JEQ(94, 0, 5),
        LD_IP_HI, JEQ(HI(probe_escape_site), 0, 3),
        LD_IP_LO, JEQ(LO(probe_escape_site), 4, 0), JEQ(LO(probe_escape_site) + 4, 3, 0),
        LD_NR, JEQ(SYS_getpid, 0, 1),
        RET(SECCOMP_RET_TRAP), RET(SECCOMP_RET_ALLOW),
    };
    h_spoof = 1; h_spoof_result = 555;
    install_filter(f, sizeof(f) / sizeof(f[0]), 1); /* TSYNC */
    atomic_store(&p8_go, 1);
    pthread_join(th, NULL);
    kv_l("P8_TSYNC_THREAD_RET", p8_thread_ret);
    kv_l("P8_TSYNC_ENTRIES", (long)h_entries);
    _exit(p8_thread_ret == 555 ? 0 : 8);
}

/* ---- P9-P11: Syscall User Dispatch (SUD) ----
 * Semantics measured, not assumed: [offset, offset+len) is the MONITORED
 * range; syscalls from inside it dispatch to SIGSYS when *selector==BLOCK,
 * syscalls from outside always run. Probe range = the 4-byte svc site. */
static volatile unsigned char sud_sel, sud_sel2;

static int sud_enable(unsigned long off, unsigned long len, volatile unsigned char *sel) {
    return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, off, len, (unsigned long)sel);
}

static void p9_sud_basic(void) {
    install_handler(0);
    h_spoof = 1; h_single = 1; h_spoof_result = 777;
    sud_sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    unsigned long site = (unsigned long)probe_svc_site;
    int rc = sud_enable(site, 4, &sud_sel);
    if (rc != 0) { kv_l("P9_SUD_ENABLE_FAIL_ERRNO", errno); _exit(80); }
    long r = probe_svc_call(SYS_getpid, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5);
    sud_sel = SYSCALL_DISPATCH_FILTER_ALLOW;
    kv_l("P9_ENTRIES", (long)h_entries);
    kv_l("P9_SI_CODE", h_si_code);
    kv_d("P9_CALL_MINUS_SITE", (long)(h_call_addr - site));
    kv_d("P9_PC_MINUS_SITE", (long)(h_pc - site));
    kv_l("P9_SPOOFED_RETURN", r);
    kv_l("P9_SUD_TRAP_OK", (r == 777 && h_entries == 1) ? 1 : 0);
    int intact = 1;
    for (int i = 0; i < 6; i++)
        if (h_args[i] != (unsigned long)(0xA0 + i))
            intact = 0;
    kv_l("P9_ARGS_INTACT", intact);
    prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0);
    _exit(0);
}

static inline unsigned long cntvct(void) {
    unsigned long v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}
static inline unsigned long cntfrq(void) {
    unsigned long v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}

/* P10: cost per trap, cntvct-timed, min of 3 x 20000 iterations. */
static void p10_cost(void) {
    const long N = 20000;
    unsigned long freq = cntfrq();
    kv_l("P10_CNTFRQ_HZ", (long)freq);
    /* baseline: untrapped raw svc */
    unsigned long best = ~0UL;
    for (int t = 0; t < 3; t++) {
        unsigned long t0 = cntvct();
        for (long i = 0; i < N; i++)
            probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
        unsigned long d = cntvct() - t0;
        if (d < best) best = d;
    }
    kv_l("P10_BASELINE_NS_PER_SVC", (long)(best * 1000000000UL / (freq * (unsigned long)N)));
    /* seccomp trap cost */
    pid_t c = fork();
    if (c == 0) {
        install_handler(0);
        install_filter_a();
        h_spoof = 1; h_spoof_result = 1;
        unsigned long b = ~0UL;
        for (int t = 0; t < 3; t++) {
            h_entries = 0;
            unsigned long t0 = cntvct();
            for (long i = 0; i < N; i++)
                probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
            unsigned long d = cntvct() - t0;
            if (h_entries != (unsigned long)N) _exit(81);
            if (d < b) b = d;
        }
        sud_sel = 0;
        printf("P10_SECCOMP_NS_PER_TRAP=%ld\n",
               (long)(b * 1000000000UL / (freq * (unsigned long)N)));
        fflush(stdout);
        _exit(0);
    }
    int st = 0; waitpid(c, &st, 0);
    kv_l("P10_SECCOMP_CHILD_EXIT", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    /* SUD trap cost */
    install_handler(0);
    h_spoof = 1; h_spoof_result = 1;
    sud_sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    if (sud_enable((unsigned long)probe_svc_site, 4, &sud_sel) != 0)
        _exit(80);
    best = ~0UL;
    for (int t = 0; t < 3; t++) {
        h_entries = 0;
        unsigned long t0 = cntvct();
        for (long i = 0; i < N; i++)
            probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
        unsigned long d = cntvct() - t0;
        if (h_entries != (unsigned long)N) _exit(82);
        if (d < best) best = d;
    }
    sud_sel = SYSCALL_DISPATCH_FILTER_ALLOW;
    kv_l("P10_SUD_NS_PER_TRAP", (long)(best * 1000000000UL / (freq * (unsigned long)N)));
    _exit(0);
}

/* Simulated zygote-style allowlist filter (default ERRNO EPERM). prctl and
 * seccomp are allowlisted: the assumption under test. */
static void install_allowlist_filter(void) {
    static const long allowed[] = {
        SYS_read, SYS_write, SYS_exit, SYS_exit_group, SYS_rt_sigreturn,
        SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_brk, SYS_mmap, SYS_mprotect,
        SYS_munmap, SYS_getpid, SYS_gettid, SYS_prctl, SYS_seccomp,
        SYS_newfstatat, SYS_ioctl, SYS_lseek, SYS_futex, SYS_clock_gettime,
        SYS_sched_yield, SYS_set_tid_address, SYS_set_robust_list,
    };
    const size_t n_allowed = sizeof(allowed) / sizeof(allowed[0]);
    const size_t total = 4 + n_allowed + 2; /* head + JEQs + ERRNO + ALLOW */
    struct sock_filter *f = malloc(total * sizeof(*f));
    if (!f) _exit(83);
    f[0] = (struct sock_filter)LD_ARCH;
    f[1] = (struct sock_filter)JEQ(AUDIT_ARCH_AARCH64, 1, 0);
    f[2] = (struct sock_filter)RET(SECCOMP_RET_KILL_PROCESS);
    f[3] = (struct sock_filter)LD_NR;
    for (size_t i = 0; i < n_allowed; i++) {
        size_t pos = 4 + i;
        f[pos] = (struct sock_filter)JEQ((uint32_t)allowed[i],
                                         (uint8_t)(total - 2 - pos), 0);
    }
    f[total - 2] = (struct sock_filter)RET(SECCOMP_RET_ERRNO | EPERM);
    f[total - 1] = (struct sock_filter)RET(SECCOMP_RET_ALLOW);
    install_filter(f, total, 0);
}

/* P11a: trap-everything filter stacked OVER a pre-installed allowlist. */
static void p11_seccomp_stack(void) {
    install_handler(0);
    install_allowlist_filter();
    install_filter_a(); /* stack trap filter; needs prctl+seccomp allowed */
    h_spoof = 1; h_spoof_result = 777;
    long r = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    kv_l("P11_SECCOMP_STACK_RET", r);
    kv_l("P11_SECCOMP_STACK_SI_CODE", h_si_code);
    kv_l("P11_SECCOMP_STACK_TRAP_OK", (r == 777 && h_entries == 1) ? 1 : 0);
    _exit(0);
}

/* P11b: SUD enabled OVER a pre-installed allowlist filter. */
static void p11_sud_over_filter(void) {
    install_handler(0);
    install_allowlist_filter();
    h_spoof = 1; h_spoof_result = 777;
    sud_sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    if (sud_enable((unsigned long)probe_svc_site, 4, &sud_sel) != 0) {
        kv_l("P11_SUD_ENABLE_FAIL_ERRNO", errno);
        _exit(80);
    }
    long r = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    sud_sel = SYSCALL_DISPATCH_FILTER_ALLOW;
    kv_l("P11_SUD_OVER_FILTER_RET", r);
    kv_l("P11_SUD_OVER_FILTER_SI_CODE", h_si_code);
    kv_l("P11_SUD_OVER_FILTER_OK", (r == 777 && h_entries == 1) ? 1 : 0);
    _exit(0);
}

/* P11c: second SUD enable (Wine-style second owner) displaces the first. */
static void p11_sud_second_owner(void) {
    install_handler(0);
    h_spoof = 1; h_spoof_result = 777;
    unsigned long site = (unsigned long)probe_svc_site;
    sud_sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    if (sud_enable(site, 4, &sud_sel) != 0)
        _exit(80);
    sud_sel2 = SYSCALL_DISPATCH_FILTER_ALLOW;
    if (sud_enable(site, 4, &sud_sel2) != 0)
        _exit(84);
    long pid = (long)getpid();
    long r1 = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    kv_l("P11_SECOND_OWNER_DISPLACED_FIRST",
         (r1 == pid && h_entries == 0) ? 1 : 0);
    sud_sel2 = SYSCALL_DISPATCH_FILTER_BLOCK;
    long r2 = probe_svc_call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    kv_l("P11_SECOND_OWNER_SELECTOR_GOVERNS",
         (r2 == 777 && h_entries == 1) ? 1 : 0);
    _exit(0);
}

static void t_p1_site(void)  { p1_ip_candidate((unsigned long)probe_svc_site, "SITE"); }
static void t_p1_site4(void) { p1_ip_candidate((unsigned long)probe_svc_site + 4, "SITE_PLUS4"); }
static void t_p4_svc(void)   { p4_restorer((unsigned long)probe_restorer_svc); }
static void t_p4_svc4(void)  { p4_restorer((unsigned long)probe_restorer_svc + 4); }

struct test_case { const char *name; void (*fn)(void); };
static const struct test_case TESTS[] = {
    {"P1A_TRAP_RECORD", p1a_trap_record},
    {"P1_IP_SITE", t_p1_site},
    {"P1_IP_SITE_PLUS4", t_p1_site4},
    {"P4_RESTORER_SVC", t_p4_svc},
    {"P4_RESTORER_SVC_PLUS4", t_p4_svc4},
    {"P5_SUSTAINED", p5_sustained},
    {"P6_PLAIN_RX_BLR", t_p6_plain},
    {"P6_BTI_NOPAD_BLR", t_p6_bti_none},
    {"P6_BTI_C_BLR", t_p6_bti_c},
    {"P6_BTI_J_BR", t_p6_bti_j},
    {"P6_BTI_JC_BLR", t_p6_bti_jc_blr},
    {"P6_BTI_JC_BR", t_p6_bti_jc_br},
    {"P6_BTI_C_BR_EXPECT_FAULT", t_p6_bti_c_br},
    {"P6_BTI_J_BLR_EXPECT_FAULT", t_p6_bti_j_blr},
    {"P7_SVE_RECORDS", p7_sve_records},
    {"P8_FORK_INHERIT", p8_fork_inherit},
    {"P8_TSYNC", p8_tsync},
    {"P9_SUD_BASIC", p9_sud_basic},
    {"P10_COST", p10_cost},
    {"P11_SECCOMP_STACK", p11_seccomp_stack},
    {"P11_SUD_OVER_FILTER", p11_sud_over_filter},
    {"P11_SUD_SECOND_OWNER", p11_sud_second_owner},
};

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("PROBE_PARENT_PID=%ld\n", (long)getpid());
    p0_env();
    kv_x("PROBE_SVC_SITE", (unsigned long)probe_svc_site);
    kv_x("PROBE_RESTORER", (unsigned long)probe_restorer);
    kv_x("PROBE_RESTORER_SVC", (unsigned long)probe_restorer_svc);
    for (size_t i = 0; i < sizeof(TESTS) / sizeof(TESTS[0]); i++) {
        printf("== TEST %s ==\n", TESTS[i].name);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            TESTS[i].fn(); /* never returns */
            _exit(99);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        if (WIFEXITED(st))
            printf("RESULT %s STATUS=EXITED CODE=%d\n", TESTS[i].name, WEXITSTATUS(st));
        else if (WIFSIGNALED(st))
            printf("RESULT %s STATUS=SIGNALED SIG=%d\n", TESTS[i].name, WTERMSIG(st));
        else
            printf("RESULT %s STATUS=OTHER RAW=0x%x\n", TESTS[i].name, st);
        fflush(stdout);
    }
    printf("PROBE_DONE=1\n");
    return 0;
}

