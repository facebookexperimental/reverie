#define _GNU_SOURCE
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

extern int translation_probe(void), translation_truncate(void);
extern unsigned char translation_branch[], translation_target_one[], translation_target_two[];

static void require(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "guest refusal: %s\n", message);
        exit(42);
    }
}

static void handler(int sig, siginfo_t *info, void *raw) {
    const ucontext_t *context = raw;
    char line[] = "fault-context sig=0x0000000000000000 addr=0x0000000000000000 rip=0x0000000000000000\n";
    const uintptr_t values[] = {(uintptr_t)sig, (uintptr_t)info->si_addr,
        (uintptr_t)context->uc_mcontext.gregs[REG_RIP]};
    const unsigned offsets[] = {20, 44, 67};
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned n = 0; n < 16; ++n)
            line[offsets[i] + n] = "0123456789abcdef"[(values[i] >> (60 - 4 * n)) & 15];
    if (write(2, line, sizeof(line) - 1) != sizeof(line) - 1)
        _exit(44);
    /* This builder regression checks reachability and truthful target PC.
     * Full Linux frame equality is a separate retained RED (dh-o7hi).
     */
    if (sig != SIGSEGV || info->si_addr != translation_target_one ||
        (uintptr_t)context->uc_mcontext.gregs[REG_RIP] !=
            (uintptr_t)translation_target_one)
        _exit(43);
    if (write(1, "fault\n", 6) != 6)
        _exit(44);
    _exit(77);
}

int main(int argc, char **argv) {
    require(argc == 2, "one case");
    require(sysconf(_SC_PAGESIZE) == 4096, "4096-byte pages");
    require((uintptr_t)translation_target_one % 4096 == 0 &&
            (uintptr_t)translation_target_two % 4096 == 0 &&
            (uintptr_t)translation_target_two -
                (uintptr_t)translation_target_one == 4096,
            "dedicated target pages");
    require(translation_branch == (unsigned char *)(uintptr_t)translation_probe + 2 &&
            translation_branch[-2] == 0x31 && translation_branch[-1] == 0xc0 &&
            translation_branch[0] == 0x0f && translation_branch[1] == 0x84,
            "XOR EAX,EAX immediately precedes near JZ");
    if (!strcmp(argv[1], "truncate")) {
        require(translation_truncate() == 3, "ordinary non-UBR fallthrough");
        require(write(1, "truncate=3\n", 11) == 11, "write result");
        return 0;
    }
    int selfmod = !strcmp(argv[1], "selfmod");
    if (!strcmp(argv[1], "unmapped")) {
        struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
        require(sigemptyset(&action.sa_mask) == 0 &&
                    sigaction(SIGSEGV, &action, NULL) == 0, "install handler");
        require(munmap(translation_target_one, 4096) == 0, "unmap owned target");
    } else {
        require(selfmod || !strcmp(argv[1], "readable"), "known case");
    }
    if (selfmod)
        require(mprotect((void *)(uintptr_t)translation_probe, 4096,
                         PROT_READ | PROT_WRITE | PROT_EXEC) == 0, "writable source page");
    require(write(1, "before\n", 7) == 7, "write before marker");
    require(translation_probe() == 1, "first target result");
    if (selfmod) {
        intptr_t displacement = (intptr_t)translation_target_two -
                                ((intptr_t)translation_branch + 6);
        require(displacement >= INT32_MIN && displacement <= INT32_MAX, "rel32 target");
        int32_t relative = (int32_t)displacement;
        memcpy(translation_branch + 2, &relative, sizeof(relative));
        require(translation_probe() == 2, "changed source target result");
        require(write(1, "selfmod=1,2\n", 12) == 12, "write selfmod result");
    } else {
        require(write(1, "result=1\n", 9) == 9, "write result");
    }
    return 0;
}
