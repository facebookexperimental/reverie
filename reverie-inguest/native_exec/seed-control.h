/* Initial-only seed interpreter ABI. Pending bytes are not a completed-write
 * fact. Only the retained Rust launch owner authenticates and admits completion.
 */
#ifndef REVERIE_SEED_CONTROL_H
#define REVERIE_SEED_CONTROL_H
#include <stddef.h>
#include <stdint.h>
#define SEED_LOADER_FD 198
#define SEED_PACKET_FD 199
#define SEED_CHANNEL_FD 200
#define SEED_PACKET_HEADER_BYTES 128u
#define SEED_PATH_MAX 4096u
#define SEED_SCRATCH_BASE UINT64_C(0x520000000000)
#define SEED_SCRATCH_LIMIT UINT64_C(0x80000)
#define SEED_ABI_VERSION 1u
struct SeedPending {
    unsigned char magic[8];
    uint32_t version, byte_len;
    unsigned char nonce[32], configuration[32], bytes[16];
    uint64_t loader_device, loader_inode, loader_size;
    uint16_t interpreter_len; /* includes the sole terminal NUL */
    unsigned char reserved[6];
};
struct SeedCompletion {
    unsigned char magic[8];
    uint32_t version, byte_len;
    unsigned char nonce[32], configuration[32];
    uint64_t pid, tid, original_rsp, auxv, at_random;
    uint64_t loader_lo, loader_hi, loader_bias, loader_entry, at_base_slot;
    unsigned char bytes[16];
    uint64_t written, reserved;
};
struct SeedGo {
    unsigned char magic[8];
    uint32_t version, byte_len;
    unsigned char nonce[32], configuration[32];
    uint64_t success, reserved;
};
/* Register offsets are consumed by seed-entry.S. No syscall frame is invented. */
struct SeedEntryFrame {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, rflags;
};
_Static_assert(sizeof(struct SeedPending) == 128, "seed pending header");
_Static_assert(offsetof(struct SeedPending, interpreter_len) == 120, "seed path length");
_Static_assert(sizeof(struct SeedCompletion) == 192, "seed completion");
_Static_assert(offsetof(struct SeedCompletion, bytes) == 160, "seed completion bytes");
_Static_assert(sizeof(struct SeedGo) == 96, "seed GO");
_Static_assert(sizeof(struct SeedEntryFrame) == 136, "seed original registers");
_Static_assert(offsetof(struct SeedEntryFrame, rax) == 0, "seed original RAX");
_Static_assert(offsetof(struct SeedEntryFrame, rbx) == 8, "seed original RBX");
_Static_assert(offsetof(struct SeedEntryFrame, rcx) == 16, "seed original RCX");
_Static_assert(offsetof(struct SeedEntryFrame, rdx) == 24, "seed original RDX");
_Static_assert(offsetof(struct SeedEntryFrame, rsi) == 32, "seed original RSI");
_Static_assert(offsetof(struct SeedEntryFrame, rdi) == 40, "seed original RDI");
_Static_assert(offsetof(struct SeedEntryFrame, rbp) == 48, "seed original RBP");
_Static_assert(offsetof(struct SeedEntryFrame, rsp) == 56, "seed original RSP");
_Static_assert(offsetof(struct SeedEntryFrame, r8) == 64, "seed original R8");
_Static_assert(offsetof(struct SeedEntryFrame, r9) == 72, "seed original R9");
_Static_assert(offsetof(struct SeedEntryFrame, r10) == 80, "seed original R10");
_Static_assert(offsetof(struct SeedEntryFrame, r11) == 88, "seed original R11");
_Static_assert(offsetof(struct SeedEntryFrame, r12) == 96, "seed original R12");
_Static_assert(offsetof(struct SeedEntryFrame, r13) == 104, "seed original R13");
_Static_assert(offsetof(struct SeedEntryFrame, r14) == 112, "seed original R14");
_Static_assert(offsetof(struct SeedEntryFrame, r15) == 120, "seed original R15");
_Static_assert(offsetof(struct SeedEntryFrame, rflags) == 128, "seed original flags");
__attribute__((visibility("hidden"))) long seed_syscall6(
    long, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
__attribute__((noreturn, visibility("hidden"))) void seed_relocate(
    void *, uint64_t, struct SeedEntryFrame *);
__attribute__((noreturn, visibility("hidden"))) void seed_bootstrap_resume(
    struct SeedEntryFrame *, uint64_t);
#endif
