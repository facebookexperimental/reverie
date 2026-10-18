/*
 * Test-only libc-free loader peer. It cannot register a Tool, install filters,
 * adopt Detcore state or claim ordinary stock-loader readiness. The real seed
 * must have accepted GO before this entry's assembly marker can execute.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

static long raw(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long out;
    __asm__ volatile("syscall" : "=a"(out)
                     : "a"(n), "D"(a), "S"(b), "d"(c),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return out;
}
__attribute__((noreturn)) static void done(int code) {
    raw(SYS_exit_group, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
static void emit(const char *p, size_t n) {
    if (raw(SYS_write, 1, (long)p, (long)n, 0, 0, 0) != (long)n) done(90);
}
#ifndef FD_CHECKER
static int equal(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (size_t i = 0; i < n; ++i) if (x[i] != y[i]) return 0;
    return 1;
}
#endif
static unsigned number(const char *p) {
    unsigned n = 0;
    if (!*p) done(91);
    for (unsigned i = 0; p[i]; ++i) {
        if (i >= 8 || p[i] < '0' || p[i] > '9' || n > 65535) done(91);
        n = n * 10 + (unsigned)(p[i] - '0');
    }
    return n;
}
#ifndef FD_CHECKER
static unsigned digit(char c) {
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
    done(92);
}
static void token_bytes(unsigned char *out, const char *hex) {
    for (unsigned i = 0; i < 128; ++i) if (!hex[i]) done(92);
    if (hex[128]) done(92);
    for (unsigned i = 0; i < 64; ++i)
        out[i] = (unsigned char)((digit(hex[2*i]) << 4) | digit(hex[2*i+1]));
}
static void put64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(n >> (8*i));
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; ++i) n |= (uint64_t)p[i] << (8*i);
    return n;
}
static void header(unsigned char *p, size_t len, const char *magic,
                   const unsigned char *token) {
    for (size_t i = 0; i < len; ++i) p[i] = 0;
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)magic[i];
    p[8] = 1;
    p[12] = (unsigned char)len;
    p[13] = (unsigned char)(len >> 8);
    for (unsigned i = 0; i < 64; ++i) p[16+i] = token[i];
}
static void send_frame(const unsigned char *p, size_t n) {
    if (raw(SYS_sendto, 200, (long)p, (long)n, MSG_NOSIGNAL, 0, 0) != (long)n)
        done(93);
}
/* Identify the actual received sealed V4 descriptor, never predict its number. */
static int bootstrap_fd(const unsigned char *token) {
    int found = -1;
    for (int fd = 3; fd < 256; ++fd) {
        unsigned char bytes[87];
        if (raw(SYS_pread64, fd, (long)bytes, sizeof(bytes), 0, 0, 0) != (long)sizeof(bytes))
            continue;
        if (!equal(bytes, "REVERIE-LI-V4\0\0\0", 16) || !equal(bytes+23, token, 64))
            continue;
        long seals = raw(SYS_fcntl, fd, F_GET_SEALS, 0, 0, 0, 0);
        if (found != -1 || seals < 0 || (seals & 15) != 15)
            done(94);
        found = fd;
    }
    if (found == -1) done(94);
    return found;
}
#endif

__attribute__((noreturn, visibility("hidden")))
void initial_auxv_fixture(uint64_t *stack) {
    const char **argv = (const char **)(stack + 1);
#ifdef FD_CHECKER
    if (stack[0] != 2) done(91);
    unsigned fd = number(argv[1]);
    if (raw(SYS_fcntl, 200, F_GETFD, 0, 0, 0, 0) != -9 ||
        raw(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0) != -9) done(95);
    emit("STALE_FDS_CLOSED\n", 17);
    done(43);
#else
    if (stack[0] != 4) done(91);
    unsigned mode = number(argv[1]);
    unsigned char token[64];
    token_bytes(token, argv[2]);
    if (!mode) done(42);
    long pid = raw(SYS_getpid, 0, 0, 0, 0, 0, 0);
    if (pid <= 0) done(91);
    if (mode == 4) {
        int fd = bootstrap_fd(token);
        long channel_flags = raw(SYS_fcntl, 200, F_GETFD, 0, 0, 0, 0);
        long bootstrap_flags = raw(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0);
        if (channel_flags < 0 || bootstrap_flags < 0 ||
            !(channel_flags & FD_CLOEXEC) || !(bootstrap_flags & FD_CLOEXEC)) done(95);
        char decimal[12];
        char backwards[12];
        unsigned n = (unsigned)fd, count = 0;
        do { backwards[count++] = (char)('0' + n % 10); n /= 10; } while (n);
        for (unsigned i = 0; i < count; ++i) decimal[i] = backwards[count-i-1];
        decimal[count] = 0;
        const char *args[] = {argv[3], decimal, 0};
        const char *env[] = {0};
        emit("CLOEXEC_ARMED\n", 14);
        raw(SYS_execve, (long)argv[3], (long)args, (long)env, 0, 0, 0);
        done(96);
    }
    if (mode == 3) {
        unsigned char write[192];
        header(write, sizeof(write), "HRSEEDR1", token);
        put64(write+80, (uint64_t)pid);
        put64(write+88, (uint64_t)pid);
        send_frame(write, sizeof(write));
        /* Hold until the actual owner refuses/kills this exact child. */
        unsigned char response;
        if (raw(SYS_recvfrom, 200, (long)&response, 1, 0, 0, 0) > 0) done(98);
        done(44);
    }
    /* Modes5/6 use this same real channel barrier for the parent's retired
     * seed/entry-state audit. They never invoke a late seed cleanup. */
    if (mode != 1 && mode != 2 && mode != 5 && mode != 6) done(91);
    unsigned char take[96];
    header(take, sizeof(take), "HRSEEDT1", token);
    put64(take+80, (uint64_t)pid);
    send_frame(take, sizeof(take));
    unsigned char response[4224];
    long got = raw(SYS_recvfrom, 200, (long)response, sizeof(response), MSG_TRUNC, 0, 0);
    static const char state[] = "component-only-state";
    if (got != (long)(128 + sizeof(state)-1) ||
        !equal(response, "HRSEEDS1", 8) || response[8] != 1 ||
        response[12] != (unsigned char)got || response[13] != (unsigned char)(got >> 8) ||
        !equal(response+16, token, 64) || get64(response+80) != (uint64_t)pid ||
        !get64(response+88) || !get64(response+96) || get64(response+104) != 16 ||
        !equal(response+128, state, sizeof(state)-1)) done(98);
    for (unsigned i = 0; i < 16; ++i) if (response[112+i] != 0xa5) done(98);
    /* Retain the actual STATE separately from the stdout marker stream. */
    if (raw(SYS_write, 2, (long)response, got, 0, 0, 0) != got) done(98);
    emit("STATE_ONCE\n", 11);
    if (mode == 1 || mode == 5 || mode == 6) {
        if (raw(SYS_close, 200, 0, 0, 0, 0, 0)) done(98);
        done(42);
    }
    send_frame(take, sizeof(take));
    /* No second state may be delivered. Refusal may kill us before EOF. */
    if (raw(SYS_recvfrom, 200, (long)response, sizeof(response), MSG_TRUNC, 0, 0) > 0)
        emit("SECOND_STATE\n", 13);
    done(44);
#endif
}
