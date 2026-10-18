/* Initial-only, libc-free seed interpreter. This does not initialize a Tool or
 * authorize native finish. The watched Rust launch owner admits the completed
 * write; the normal constructor later redeems it without touching retired seed
 * storage. The final assembly tail scrubs writable seed state before ld.so.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "bootstrap-image.h"
#include "seed-control.h"

#define PAGE UINT64_C(4096)
#define MAX_AUX 64u
#define MAX_ARGV 256u
#define MAX_ENVP 4096u
#define MAX_VECTOR_WORDS (1u + MAX_ARGV + 1u + MAX_ENVP + 1u + MAX_AUX * 2u)
#define MAX_MAPS 256u
#define MAP_TEXT_BYTES 65536u
#define MAX_LOADER UINT64_C(16777216)

extern BOOTSTRAP_HIDDEN unsigned char seed_image_start[], seed_image_active_end[];
extern BOOTSTRAP_HIDDEN unsigned char seed_code_end[], seed_data_start[], seed_stack_end[];
extern BOOTSTRAP_HIDDEN struct SeedEntryFrame seed_frame;
__attribute__((noreturn, visibility("hidden"))) void seed_relocated_entry(
    struct SeedEntryFrame *);

struct SeedMap { uint64_t lo, hi, prot; };
static struct SeedPending pending;
static char interpreter[SEED_PATH_MAX];
static struct SeedCompletion completion;
static struct SeedMap maps[MAX_MAPS];
static unsigned char maps_text[MAP_TEXT_BYTES];
static uint64_t original_vector[MAX_VECTOR_WORDS];
static uint64_t map_count, vector_words, stack_lo, stack_hi;
static uint64_t original_auxv, random_address, base_slot, loader_bias;
static uint64_t envelope_bytes, active_bytes, code_bytes;

static long call(long nr, uint64_t a, uint64_t b, uint64_t c,
                 uint64_t d, uint64_t e, uint64_t f) {
    return seed_syscall6(nr, a, b, c, d, e, f);
}
static int failed(long value) { return (uint64_t)value >= (uint64_t)-4095; }
__attribute__((noreturn)) static void fail(unsigned code) {
    /* A terminal stage number, not an ACK or completed-write receipt. */
    call(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) __asm__ volatile("ud2");
}
static struct BootstrapImageOps image_ops(void) {
    struct BootstrapImageOps ops = {0};
    /* No loader applies relocations to this image, at either of its bases.
     * A C aggregate of function addresses can become a relocated constant
     * pool even under -fPIE. Materialize both addresses from the current RIP;
     * the opaque outputs also prevent that constant-pool transformation. */
    __asm__ volatile(
        "lea %c[call](%%rip), %[call_out]\n\t"
        "lea %c[fail](%%rip), %[fail_out]"
        : [call_out] "=r"(ops.call), [fail_out] "=r"(ops.fail)
        : [call] "i"(call), [fail] "i"(fail));
    return ops;
}
static uint64_t up(uint64_t value) { return (value + PAGE - 1) & ~(PAGE - 1); }
static int power_of_two(uint64_t value) { return value && !(value & (value - 1)); }
static int span(uint64_t addr, uint64_t bytes, uint64_t lo, uint64_t hi) {
    return bytes && addr >= lo && addr <= hi && bytes <= hi - addr;
}
static int zero(const unsigned char *p, uint64_t bytes) {
    for (uint64_t i = 0; i < bytes; ++i) if (p[i]) return 0;
    return 1;
}
static int hex(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}
static uint64_t hex_word(uint64_t *cursor, uint64_t end) {
    uint64_t value = 0, count = 0;
    while (*cursor < end) {
        int digit = hex(maps_text[*cursor]);
        if (digit < 0) break;
        if (++count > 16 || value > (UINT64_MAX - (unsigned)digit) / 16) fail(20);
        value = value * 16 + (unsigned)digit;
        ++*cursor;
    }
    if (!count) fail(20);
    return value;
}
static void read_maps(void) {
    const char path[] = "/proc/self/maps";
    long fd = call(SYS_openat, (uint64_t)AT_FDCWD, (uint64_t)path,
                   O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (failed(fd)) fail(20);
    uint64_t used = 0;
    for (;;) {
        if (used == sizeof(maps_text)) fail(20);
        long count = call(SYS_read, fd, (uint64_t)(maps_text + used),
                          sizeof(maps_text) - used, 0, 0, 0);
        if (failed(count)) fail(20);
        if (!count) break;
        used += (uint64_t)count;
    }
    if (call(SYS_close, fd, 0, 0, 0, 0, 0) || !used) fail(20);
    uint64_t cursor = 0, previous = 0;
    map_count = 0;
    while (cursor < used) {
        uint64_t end = cursor;
        while (end < used && maps_text[end] != '\n') ++end;
        if (end == used || map_count == MAX_MAPS) fail(20);
        uint64_t lo = hex_word(&cursor, end);
        if (cursor == end || maps_text[cursor++] != '-') fail(20);
        uint64_t hi = hex_word(&cursor, end);
        if (hi <= lo || lo < previous || cursor + 6 > end ||
            maps_text[cursor++] != ' ') fail(20);
        uint64_t prot = 0;
        if (maps_text[cursor] == 'r') prot |= PROT_READ;
        else if (maps_text[cursor] != '-') fail(20);
        if (maps_text[cursor + 1] == 'w') prot |= PROT_WRITE;
        else if (maps_text[cursor + 1] != '-') fail(20);
        if (maps_text[cursor + 2] == 'x') prot |= PROT_EXEC;
        else if (maps_text[cursor + 2] != '-') fail(20);
        if ((maps_text[cursor + 3] != 'p' && maps_text[cursor + 3] != 's') ||
            maps_text[cursor + 4] != ' ') fail(20);
        maps[map_count++] = (struct SeedMap){lo, hi, prot};
        previous = hi;
        cursor = end + 1;
    }
}
static int mapped(uint64_t lo, uint64_t bytes, uint64_t prot) {
    if (!bytes || lo > UINT64_MAX - bytes) return 0;
    uint64_t cursor = lo, end = lo + bytes;
    for (uint64_t i = 0; i < map_count; ++i) {
        if (maps[i].hi <= cursor) continue;
        if (maps[i].lo > cursor || (maps[i].prot & prot) != prot) return 0;
        cursor = maps[i].hi;
        if (cursor >= end) return 1;
    }
    return 0;
}
static uint64_t stack_word(uint64_t address) {
    if ((address & 7) || !span(address, 8, stack_lo, stack_hi)) fail(21);
    return *(const uint64_t *)(uintptr_t)address;
}
static void capture_stack(struct SeedEntryFrame *frame) {
    stack_lo = stack_hi = 0;
    for (uint64_t i = 0; i < map_count; ++i)
        if (span(frame->rsp, 8, maps[i].lo, maps[i].hi) &&
            (maps[i].prot & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE)) {
            if (stack_hi) fail(21);
            stack_lo = maps[i].lo;
            stack_hi = maps[i].hi;
        }
    if (!stack_hi) fail(21);
    uint64_t argc = stack_word(frame->rsp);
    if (argc > MAX_ARGV) fail(21);
    uint64_t cursor = frame->rsp + 8;
    for (uint64_t i = 0; i < argc; ++i, cursor += 8)
        if (!stack_word(cursor)) fail(21);
    if (stack_word(cursor)) fail(21);
    cursor += 8;
    unsigned envc = 0;
    while (stack_word(cursor)) {
        if (++envc > MAX_ENVP) fail(21);
        cursor += 8;
    }
    cursor += 8;
    original_auxv = cursor;
    unsigned seen_base = 0, seen_random = 0, seen_phdr = 0, seen_phnum = 0;
    unsigned seen_phent = 0, seen_entry = 0, seen_pagesz = 0, seen_execfn = 0;
    int terminated = 0;
    for (unsigned i = 0; i < MAX_AUX; ++i, cursor += 16) {
        uint64_t key = stack_word(cursor), value = stack_word(cursor + 8);
        if (key == AT_NULL) {
            if (value) fail(21);
            cursor += 16;
            terminated = 1;
            break;
        }
        if (key == AT_BASE) {
            ++seen_base; loader_bias = value; base_slot = cursor + 8;
        } else if (key == AT_RANDOM) {
            ++seen_random; random_address = value;
        } else if (key == AT_PHDR) { ++seen_phdr; if (!value) fail(21);
        } else if (key == AT_PHNUM) { ++seen_phnum; if (!value) fail(21);
        } else if (key == AT_PHENT) { ++seen_phent; if (value != sizeof(Elf64_Phdr)) fail(21);
        } else if (key == AT_ENTRY) { ++seen_entry; if (!value) fail(21);
        } else if (key == AT_PAGESZ) { ++seen_pagesz; if (value != PAGE) fail(21);
        } else if (key == AT_EXECFN) { ++seen_execfn; if (!value) fail(21); }
    }
    if (!terminated || seen_base != 1 || seen_random != 1 || seen_phdr != 1 ||
        seen_phnum != 1 || seen_phent != 1 || seen_entry != 1 || seen_pagesz != 1 ||
        seen_execfn != 1 || !span(random_address, 16, stack_lo, stack_hi) ||
        (random_address < cursor && frame->rsp < random_address + 16)) fail(21);
    vector_words = (cursor - frame->rsp) / 8;
    if (vector_words > MAX_VECTOR_WORDS || !span(frame->rsp, cursor - frame->rsp,
                                               stack_lo, stack_hi)) fail(21);
    memcpy(original_vector, (const void *)(uintptr_t)frame->rsp, cursor - frame->rsp);
}
static void read_pending(void) {
    struct stat st;
    long seals = call(SYS_fcntl, SEED_PACKET_FD, F_GET_SEALS, 0, 0, 0, 0);
    if (failed(seals) || (seals & 15) != 15 ||
        call(SYS_fstat, SEED_PACKET_FD, (uint64_t)&st, 0, 0, 0, 0) ||
        !S_ISREG(st.st_mode) || st.st_size < (long)sizeof(pending) ||
        st.st_size > (long)(sizeof(pending) + SEED_PATH_MAX) ||
        call(SYS_pread64, SEED_PACKET_FD, (uint64_t)&pending,
             sizeof(pending), 0, 0, 0) != (long)sizeof(pending)) fail(22);
    if (!bootstrap_equal(pending.magic, "HRSEEDP1", 8) ||
        pending.version != SEED_ABI_VERSION || pending.byte_len != (uint64_t)st.st_size ||
        pending.interpreter_len < 2 || pending.interpreter_len > SEED_PATH_MAX ||
        pending.byte_len != sizeof(pending) + pending.interpreter_len ||
        !zero(pending.reserved, sizeof(pending.reserved)) ||
        call(SYS_pread64, SEED_PACKET_FD, (uint64_t)interpreter,
             pending.interpreter_len, sizeof(pending), 0, 0) != pending.interpreter_len)
        fail(22);
    if (interpreter[0] != '/' || interpreter[pending.interpreter_len - 1]) fail(22);
    for (unsigned i = 0; i + 1 < pending.interpreter_len; ++i)
        if (!interpreter[i]) fail(22);
    struct stat loader;
    /* The ordinary loader keeps its original file backing. The launch owner
     * authenticates captured bytes around the paused mapping readback; this
     * is not a promise of permanent original-inode immutability. */
    long loader_flags = call(SYS_fcntl, SEED_LOADER_FD, F_GETFL, 0, 0, 0, 0);
    if (failed(loader_flags) || (loader_flags & O_ACCMODE) != O_RDONLY ||
        call(SYS_fstat, SEED_LOADER_FD, (uint64_t)&loader, 0, 0, 0, 0) ||
        !S_ISREG(loader.st_mode) || loader.st_size <= 0 ||
        pending.loader_device != (uint64_t)loader.st_dev ||
        pending.loader_inode != (uint64_t)loader.st_ino ||
        pending.loader_size != (uint64_t)loader.st_size) fail(23);
    int type = 0;
    unsigned type_len = sizeof(type);
    if (call(SYS_getsockopt, SEED_CHANNEL_FD, SOL_SOCKET, SO_TYPE,
             (uint64_t)&type, (uint64_t)&type_len, 0) ||
        type_len != sizeof(type) || type != SOCK_SEQPACKET) fail(24);
    /* The kernel exec that entered this seed is complete. Retain the channel
     * through our loader tail jump, but never across a subsequent real exec:
     * the same PID alone must not redeem this launch generation's completion.
     */
    long flags = call(SYS_fcntl, SEED_CHANNEL_FD, F_GETFD, 0, 0, 0, 0);
    if (failed(flags) || call(SYS_fcntl, SEED_CHANNEL_FD, F_SETFD,
                              flags | FD_CLOEXEC, 0, 0, 0)) fail(24);
}
static struct BootstrapImageLayout inspect_images(void) {
    const struct BootstrapImageOps ops = image_ops();
    struct BootstrapImageLayout loader = bootstrap_image_layout(SEED_LOADER_FD, &ops);
    uint64_t alignment = loader.alignment < PAGE ? PAGE : loader.alignment;
    active_bytes = (uint64_t)seed_image_active_end - (uint64_t)seed_image_start;
    code_bytes = (uint64_t)seed_code_end - (uint64_t)seed_image_start;
    if (loader.lo || loader.hi > MAX_LOADER || !power_of_two(alignment) ||
        !loader_bias || (loader_bias & (alignment - 1)) ||
        (uint64_t)seed_image_start != loader_bias ||
        !active_bytes || active_bytes > SEED_SCRATCH_LIMIT || (active_bytes & (PAGE - 1)) ||
        !code_bytes || code_bytes >= active_bytes || (code_bytes & (PAGE - 1)) ||
        (uint64_t)seed_data_start != (uint64_t)seed_code_end || active_bytes > loader.hi ||
        !mapped(loader_bias, sizeof(Elf64_Ehdr), PROT_READ)) fail(25);
    const Elf64_Ehdr *h = (const void *)(uintptr_t)loader_bias;
    if (!bootstrap_equal(h->e_ident, ELFMAG, SELFMAG) ||
        h->e_ident[EI_CLASS] != ELFCLASS64 || h->e_ident[EI_DATA] != ELFDATA2LSB ||
        h->e_machine != EM_X86_64 || h->e_type != ET_DYN || h->e_phnum != 3 ||
        h->e_phentsize != sizeof(Elf64_Phdr) || h->e_phoff > 65536 ||
        !span(h->e_phoff, h->e_phnum * sizeof(Elf64_Phdr), 0, code_bytes) ||
        !mapped(loader_bias + h->e_phoff, h->e_phnum * sizeof(Elf64_Phdr), PROT_READ))
        fail(25);
    const Elf64_Phdr *ph = (const void *)(uintptr_t)(loader_bias + h->e_phoff);
    unsigned loads = 0, stacks = 0;
    for (unsigned i = 0; i < h->e_phnum; ++i) {
        const Elf64_Phdr *p = &ph[i];
        if (p->p_type == PT_GNU_STACK) {
            if (p->p_flags != (PF_R | PF_W)) fail(25);
            ++stacks;
            continue;
        }
        if (p->p_type != PT_LOAD || p->p_align != alignment ||
            p->p_filesz > p->p_memsz) fail(25);
        if (loads == 0) {
            if (p->p_offset || p->p_vaddr || p->p_flags != (PF_R | PF_X) ||
                !p->p_filesz || p->p_memsz != p->p_filesz ||
                up(p->p_memsz) != code_bytes || h->e_entry >= p->p_filesz) fail(25);
        } else if (loads == 1) {
            if (p->p_vaddr != code_bytes || p->p_flags != (PF_R | PF_W) ||
                (p->p_offset & (alignment - 1)) != (p->p_vaddr & (alignment - 1)) ||
                p->p_filesz > active_bytes - code_bytes ||
                p->p_memsz != loader.hi - code_bytes) fail(25);
        } else fail(25);
        ++loads;
    }
    if (loads != 2 || stacks != 1 ||
        !mapped(loader_bias, code_bytes, PROT_READ | PROT_EXEC) ||
        !mapped(loader_bias + code_bytes, active_bytes - code_bytes, PROT_READ | PROT_WRITE) ||
        !mapped(loader_bias, loader.hi, 0)) fail(25);
    envelope_bytes = loader.hi;
    return loader;
}
static void validate_go(void) {
    struct SeedGo go;
    struct iovec iov = {&go, sizeof(go)};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {0};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    if (call(SYS_recvmsg, SEED_CHANNEL_FD, (uint64_t)&message, MSG_CMSG_CLOEXEC, 0, 0, 0)
            != (long)sizeof(go) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        !bootstrap_equal(go.magic, "HRSEEDG1", 8) || go.version != SEED_ABI_VERSION ||
        go.byte_len != sizeof(go) || go.success || go.reserved ||
        !bootstrap_equal(go.nonce, pending.nonce, sizeof(go.nonce)) ||
        !bootstrap_equal(go.configuration, pending.configuration, sizeof(go.configuration))) fail(28);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
        message.msg_controllen < CMSG_LEN(sizeof(int)) ||
        message.msg_controllen > CMSG_SPACE(sizeof(int))) fail(28);
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    struct stat st;
    long seals = call(SYS_fcntl, fd, F_GET_SEALS, 0, 0, 0, 0);
    if (fd < 0 || fd == SEED_CHANNEL_FD || fd == SEED_PACKET_FD ||
        failed(seals) || (seals & 15) != 15 ||
        call(SYS_fstat, fd, (uint64_t)&st, 0, 0, 0, 0) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > 4096) fail(28);
    long flags = call(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0);
    if (failed(flags) || call(SYS_fcntl, fd, F_SETFD, flags | FD_CLOEXEC, 0, 0, 0)) fail(28);
    /* The intended loader tail jump is not an exec. Keep this FD and 200 for the ordinary constructor's
     * authenticated redemption. Its owning Rust parser admits the actual FD.
     */
}
__attribute__((noreturn, visibility("hidden"))) void seed_relocated_entry(
    struct SeedEntryFrame *frame) {
    const struct BootstrapImageOps ops = image_ops();
    if ((uint64_t)seed_image_start != SEED_SCRATCH_BASE || frame != &seed_frame ||
        call(SYS_munmap, loader_bias, envelope_bytes, 0, 0, 0, 0)) fail(26);
    long reserved = call(SYS_mmap, loader_bias, envelope_bytes, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                         (uint64_t)-1, 0);
    if (reserved != (long)loader_bias) fail(26);
    const struct BootstrapReservation reservation = {loader_bias, envelope_bytes};
    struct BootstrapImage loader = bootstrap_map_image(SEED_LOADER_FD, &ops, &reservation);
    if (loader.lo != loader_bias || loader.hi != loader_bias + envelope_bytes ||
        loader.bias != loader_bias ||
        !bootstrap_equal(original_vector, (const void *)(uintptr_t)frame->rsp,
                         vector_words * 8)) fail(26);
    /* The target path was sealed and authenticated by the existing owner.
     * Detach only its private child-namespace interpreter replacement before
     * the ACK. Do not apply native-private capability or seccomp policy here.
     */
    if (call(SYS_umount2, (uint64_t)interpreter, MNT_DETACH, 0, 0, 0, 0)) fail(27);
    memcpy((void *)(uintptr_t)random_address, pending.bytes, sizeof(pending.bytes));
    if (!bootstrap_equal((const void *)(uintptr_t)random_address,
                         pending.bytes, sizeof(pending.bytes)) ||
        !bootstrap_equal(original_vector, (const void *)(uintptr_t)frame->rsp,
                         vector_words * 8) || stack_word(base_slot) != loader_bias) fail(27);
    memset(&completion, 0, sizeof(completion));
    memcpy(completion.magic, "HRSEEDR1", 8);
    completion.version = SEED_ABI_VERSION;
    completion.byte_len = sizeof(completion);
    memcpy(completion.nonce, pending.nonce, sizeof(completion.nonce));
    memcpy(completion.configuration, pending.configuration, sizeof(completion.configuration));
    long pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
    long tid = call(SYS_gettid, 0, 0, 0, 0, 0, 0);
    if (pid <= 0 || tid != pid) fail(27); /* kernel initial image has one thread */
    completion.pid = pid;
    completion.tid = tid;
    completion.original_rsp = frame->rsp;
    completion.auxv = original_auxv;
    completion.at_random = random_address;
    completion.loader_lo = loader.lo;
    completion.loader_hi = loader.hi;
    completion.loader_bias = loader.bias;
    completion.loader_entry = loader.entry;
    completion.at_base_slot = base_slot;
    memcpy(completion.bytes, pending.bytes, sizeof(completion.bytes));
    completion.written = sizeof(completion.bytes);
    if (call(SYS_sendto, SEED_CHANNEL_FD, (uint64_t)&completion, sizeof(completion),
             MSG_NOSIGNAL, 0, 0) != (long)sizeof(completion)) fail(28);
    validate_go();
    if (call(SYS_close, SEED_PACKET_FD, 0, 0, 0, 0, 0)) fail(28);
    /* No C code runs after this call: assembly clears all writable seed data,
     * including live C-stack spills and the saved original register frame,
     * retaining only the public loader-entry word for its final indirect jump.
     * The original guest stack receives no additional writes. */
    seed_bootstrap_resume(frame, loader.entry);
}
__attribute__((noreturn, visibility("hidden"))) void seed_bootstrap_start(
    struct SeedEntryFrame *frame) {
    if (frame != &seed_frame) fail(19);
    read_pending();
    read_maps();
    capture_stack(frame);
    (void)inspect_images();
    /* Acquire the one-use initial interval, including its PROT_NONE tail,
     * without replacing existing mappings. After the original-loader jump,
     * never reclaim or reuse it as seed storage: admitted code may replace it.
     */
    long scratch = call(SYS_mmap, SEED_SCRATCH_BASE, SEED_SCRATCH_LIMIT, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                        (uint64_t)-1, 0);
    if (scratch != (long)SEED_SCRATCH_BASE ||
        call(SYS_mprotect, scratch, active_bytes, PROT_READ | PROT_WRITE, 0, 0, 0)) fail(29);
    memcpy((void *)(uintptr_t)scratch, seed_image_start, active_bytes);
    if (call(SYS_mprotect, scratch, code_bytes, PROT_READ | PROT_EXEC, 0, 0, 0)) fail(29);
    uint64_t entry = SEED_SCRATCH_BASE + ((uint64_t)seed_relocated_entry - loader_bias);
    uint64_t stack = SEED_SCRATCH_BASE + ((uint64_t)seed_stack_end - loader_bias);
    struct SeedEntryFrame *copied_frame = (void *)(uintptr_t)(SEED_SCRATCH_BASE +
                                        ((uint64_t)&seed_frame - loader_bias));
    seed_relocate((void *)(uintptr_t)entry, stack, copied_frame);
}
