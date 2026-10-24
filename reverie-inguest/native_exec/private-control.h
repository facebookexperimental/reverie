/* Source-only experimental ABI. Not production exec admission or isolation.
 * The first 64 bytes are frozen by exec-private-runner-design.md.
 * All addresses are owned by the controlled launcher/bootstrap, not guest env.
 */
#ifndef EXEC_PRIVATE_CONTROL_H
#define EXEC_PRIVATE_CONTROL_H
#include <stddef.h>
#include <stdint.h>

#define EXEC_PRIVATE_ABI_VERSION UINT64_C(1)
#define EXEC_PRIVATE_GATE_BASE UINT64_C(0x500000000000)
#define EXEC_PRIVATE_GATE_BYTES UINT64_C(4096)
#define EXEC_PRIVATE_NATIVE_ENTRY UINT64_C(0x50000000007c)
#define EXEC_PRIVATE_GUEST_ENTRY UINT64_C(0x500000000100)
#define EXEC_PRIVATE_RESTORER_ENTRY UINT64_C(0x500000000300)
#define EXEC_PRIVATE_LOCATOR_ADDR UINT64_C(0x500000020000)
#define EXEC_PRIVATE_BOOTSTRAP_END UINT64_C(0x500000080000)
#define EXEC_PRIVATE_CONTROL_ADDR UINT64_C(0x530000000000)
#define EXEC_PRIVATE_INPUT_ADDR UINT64_C(0x530000001000)
#define EXEC_PRIVATE_CONFIG_ADDR UINT64_C(0x530000002000)
#define EXEC_NATIVE_RESUME_ADDR UINT64_C(0x530000003000)
#define EXEC_NATIVE_RESUME_MAGIC UINT64_C(0x3130474552584c48)
#define EXEC_PRIVATE_SIGNAL_BASE UINT64_C(0x530000010000)
#define EXEC_PRIVATE_SIGNAL_BYTES UINT64_C(65536)
#define EXEC_PRIVATE_STACK_BASE UINT64_C(0x530000020000)
#define EXEC_PRIVATE_STACK_BYTES UINT64_C(1048576)
#define EXEC_PRIVATE_BRK_BASE UINT64_C(0x540000000000)
#define EXEC_PRIVATE_BRK_BYTES UINT64_C(8388608)
#define EXEC_PRIVATE_PACKET_LIMIT UINT64_C(4096)
#define EXEC_PRIVATE_EXTENT_CAPACITY 64u

#define EXEC_PRIVATE_GUEST_LOADER_FD 198
#define EXEC_PRIVATE_RUNNER_FD 199
#define EXEC_PRIVATE_TOOL_LOADER_FD 200
#define EXEC_PRIVATE_INIT_INPUT_FD 201
#define EXEC_PRIVATE_NATIVE_CONFIG_FD 202

enum ExecPrivatePhase {
    EXEC_PRIVATE_TOOL_LOADING = 1,
    EXEC_PRIVATE_TOOL_INIT = 2,
    EXEC_PRIVATE_GUEST = 3,
    EXEC_PRIVATE_TOOL_CALLBACK = 4,
    EXEC_PRIVATE_GUEST_INJECTION = 5,
    EXEC_PRIVATE_TOOL_LIFECYCLE = 6
};

_Static_assert(EXEC_PRIVATE_TOOL_CALLBACK == 4 && EXEC_PRIVATE_GUEST_INJECTION == 5 &&
               EXEC_PRIVATE_TOOL_LIFECYCLE == 6, "native lifecycle phase ABI");

/* Native HLNEXEC1 only. This exact projection is loaded by final assembly;
 * it is not a made-up event or a snapshot of already-destroyed guest state.
 * Linux x86-64 user_regs_struct order, independently checked by Rust.
 */
struct ExecNativeResume {
    uint64_t magic, abi_version, byte_len, native_tid;
    uint64_t regs[27];
    uint64_t pkru;
};
_Static_assert(sizeof(struct ExecNativeResume) == 256, "native resume ABI");
_Static_assert(offsetof(struct ExecNativeResume, regs) == 32, "native resume GPR offset");
_Static_assert(offsetof(struct ExecNativeResume, pkru) == 248, "native resume PKRU offset");

struct ExecPrivateMap {
    uint64_t lo, hi, prot, flags;
};
struct ExecPrivateCode {
    uint64_t lo, hi;
};

/* Both memfds must be wholly sealed and <=4096 bytes. NativeConfig controls
 * only the trusted private loader's argv/env; it is NOT init authorization.
 * The separate opaque init packet is redeemed by genuine Rust/coordinator.
 * Each string is one absolute path, with no colon list or $ORIGIN substitution.
 */
struct ExecPrivateNativeConfig {
    uint64_t abi_version, byte_len;
    char runner_path[512];
    char tool_library_path[1024];
};

struct __attribute__((aligned(64))) ExecPrivateControl {
    uint64_t abi_version;             /*   0 */
    uint64_t byte_len;                /*   8 */
    uint64_t phase;                   /*  16; atomic load/store builtins */
    uint64_t guest_fs;                /*  24 */
    uint64_t tool_fs;                 /*  32 */
    uint64_t guest_rsp;               /*  40 */
    uint64_t guest_ld_entry;          /*  48 */
    uint64_t init_input;              /*  56; immutable packet pointer */
    uint64_t init_input_len;          /*  64 */
    uint64_t runtime_ready;           /*  72; 1 only genuine init/publication */
    uint64_t kernel_mask;             /*  80; actual initial guest mask */
    uint64_t kernel_robust_head;      /*  88 */
    uint64_t kernel_robust_len;       /*  96 */
    uint64_t kernel_clear_tid;        /* 104 */
    uint64_t kernel_brk;              /* 112 */
    uint64_t native_tid;              /* 120 */
    uint64_t private_brk_base;        /* 128 */
    uint64_t private_brk_current;     /* 136 */
    uint64_t private_brk_end;         /* 144 */
    uint64_t private_stack_base;      /* 152 */
    uint64_t private_stack_end;       /* 160 */
    uint64_t tool_ld_entry;           /* 168 */
    uint64_t tool_ld_bias;            /* 176 */
    uint64_t runner_entry;            /* 184 */
    uint64_t runner_phdr;             /* 192 */
    uint64_t runner_phnum;            /* 200 */
    uint64_t runner_phent;            /* 208 */
    uint64_t runner_bias;             /* 216 */
    uint64_t guest_ld_lo;             /* 224 */
    uint64_t guest_ld_hi;             /* 232 */
    uint64_t bootstrap_handler;       /* 240 */
    uint64_t bootstrap_restorer;      /* 248 */
    uint64_t bootstrap_stack_base;    /* 256 */
    uint64_t bootstrap_stack_end;     /* 264 */
    uint64_t native_traps;            /* 272 */
    uint64_t private_map_count;       /* 280 */
    uint64_t private_code_count;      /* 288 */
    uint64_t private_clear_tid;       /* 296; actual private registration */
    uint64_t private_robust_head;     /* 304 */
    uint64_t private_robust_len;      /* 312 */
    uint64_t failure_code;            /* 320; diagnostic, never success */
    uint64_t init_input_fd;           /* 328; genuine initializer consumes */
    uint64_t input_mapping_base;     /* 336 */
    uint64_t input_mapping_end;      /* 344 */
    uint64_t guest_resume_mask;       /* 352; genuine runtime strips reserved */
    uint64_t guest_pkru;              /* 360; actual kernel entry rights */
    uint64_t native_state;            /* 368; captured-state/restore flags */
    uint64_t native_config;           /* 376; immutable NativeConfig pointer */
    struct ExecPrivateMap maps[EXEC_PRIVATE_EXTENT_CAPACITY]; /* 384 */
    struct ExecPrivateCode code[EXEC_PRIVATE_EXTENT_CAPACITY]; /* 2432 */
    uint64_t kernel_tsc;              /* 3456; actual PR_GET_TSC mode at exec */
    uint64_t guest_tsc;               /* 3464; once-selected final guest mode */
};

#define EXEC_PRIVATE_NATIVE_CAPTURED UINT64_C(1)
#define EXEC_PRIVATE_NATIVE_RESTORED UINT64_C(2)
#define EXEC_PRIVATE_READY UINT64_C(1)

#define EXEC_PRIVATE_ASSERT_OFFSET(field, offset) \
    _Static_assert(offsetof(struct ExecPrivateControl, field) == offset, \
                   "ExecPrivateControl " #field " offset")
EXEC_PRIVATE_ASSERT_OFFSET(abi_version, 0);
EXEC_PRIVATE_ASSERT_OFFSET(byte_len, 8);
EXEC_PRIVATE_ASSERT_OFFSET(phase, 16);
EXEC_PRIVATE_ASSERT_OFFSET(guest_fs, 24);
EXEC_PRIVATE_ASSERT_OFFSET(tool_fs, 32);
EXEC_PRIVATE_ASSERT_OFFSET(guest_rsp, 40);
EXEC_PRIVATE_ASSERT_OFFSET(guest_ld_entry, 48);
EXEC_PRIVATE_ASSERT_OFFSET(init_input, 56);
EXEC_PRIVATE_ASSERT_OFFSET(tool_ld_entry, 168);
EXEC_PRIVATE_ASSERT_OFFSET(runtime_ready, 72);
EXEC_PRIVATE_ASSERT_OFFSET(guest_resume_mask, 352);
EXEC_PRIVATE_ASSERT_OFFSET(guest_pkru, 360);
EXEC_PRIVATE_ASSERT_OFFSET(maps, 384);
EXEC_PRIVATE_ASSERT_OFFSET(code, 2432);
EXEC_PRIVATE_ASSERT_OFFSET(kernel_tsc, 3456);
EXEC_PRIVATE_ASSERT_OFFSET(guest_tsc, 3464);
_Static_assert(sizeof(struct ExecPrivateControl) == 3520, "owned one-page control ABI");
_Static_assert(sizeof(struct ExecPrivateControl) <= 4096, "control fits its owned page");
_Static_assert(_Alignof(struct ExecPrivateControl) == 64, "control alignment");
_Static_assert(sizeof(struct ExecPrivateNativeConfig) == 1552, "native config ABI");
#undef EXEC_PRIVATE_ASSERT_OFFSET

long private_native_syscall(long, uint64_t, uint64_t, uint64_t,
                            uint64_t, uint64_t, uint64_t);
__attribute__((noreturn)) void private_native_terminal(unsigned);
uint64_t private_native_get_fs(void);
int private_capture_kernel_state(struct ExecPrivateControl *);
int private_restore_kernel_state(struct ExecPrivateControl *);
long private_owned_brk(struct ExecPrivateControl *, uint64_t);
long private_registration_call(struct ExecPrivateControl *, long, const uint64_t[6]);
int private_track_map(struct ExecPrivateControl *, uint64_t, uint64_t,
                      uint64_t, uint64_t);
__attribute__((noreturn)) void private_runner_resume(struct ExecPrivateControl *);
__attribute__((noreturn)) void private_enter_tool_loader(struct ExecPrivateControl *);

/* Defined by the genuine, separate explicit-init Detcore artifact. No stub. */
extern int64_t detcore_liteinst_exec_initialize(struct ExecPrivateControl *);
#endif
