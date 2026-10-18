/* Shared bounded ELF PT_LOAD mechanics. Both callers supply source-owned
 * syscall/fatal/tracking operations; no wire value selects these operations.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "bootstrap-image.h"
#define PAGE UINT64_C(4096)
#define MAX_IMAGE UINT64_C(16777216)

__attribute__((visibility("hidden")))
void *memset(void *to, int value, size_t count) {
    volatile unsigned char *p = to;
    for (size_t i = 0; i < count; ++i) p[i] = (unsigned char)value;
    return to;
}
__attribute__((visibility("hidden")))
void *memcpy(void *to, const void *from, size_t count) {
    volatile unsigned char *d = to;
    const volatile unsigned char *s = from;
    for (size_t i = 0; i < count; ++i) d[i] = s[i];
    return to;
}
int bootstrap_equal(const void *a, const void *b, uint64_t count) {
    const unsigned char *x = a, *y = b;
    for (uint64_t i = 0; i < count; ++i) if (x[i] != y[i]) return 0;
    return 1;
}
static int failed(long value) { return (uint64_t)value >= (uint64_t)-4095; }
static uint64_t down(uint64_t value) { return value & ~(PAGE - 1); }
static uint64_t up(uint64_t value) { return (value + PAGE - 1) & ~(PAGE - 1); }
struct BootstrapImageFile {
    Elf64_Ehdr header;
    Elf64_Phdr ph[32];
    struct BootstrapImageLayout layout;
    uint64_t phdr_vaddr;
};
static void inspect(int fd, const struct BootstrapImageOps *ops,
                    struct BootstrapImageFile *file) {
    Elf64_Ehdr h;
    Elf64_Phdr *ph = file->ph;
    struct stat st;
    if (ops->call(SYS_fstat, fd, (uint64_t)&st, 0, 0, 0, 0) ||
        !S_ISREG(st.st_mode) || st.st_size < (long)sizeof(h) ||
        ops->call(SYS_pread64, fd, (uint64_t)&h, sizeof(h), 0, 0, 0) != (long)sizeof(h))
        ops->fail(95);
    if (!bootstrap_equal(h.e_ident, ELFMAG, SELFMAG) || h.e_ident[EI_CLASS] != ELFCLASS64 ||
        h.e_ident[EI_DATA] != ELFDATA2LSB || h.e_machine != EM_X86_64 ||
        h.e_type != ET_DYN || h.e_phentsize != sizeof(Elf64_Phdr) ||
        !h.e_phnum || h.e_phnum > 32 || h.e_phoff > 65536 ||
        h.e_phoff > (uint64_t)st.st_size ||
        (uint64_t)h.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)st.st_size - h.e_phoff)
        ops->fail(96);
    uint64_t bytes = h.e_phnum * sizeof(Elf64_Phdr);
    if (ops->call(SYS_pread64, fd, (uint64_t)ph, bytes, h.e_phoff, 0, 0) != (long)bytes)
        ops->fail(97);
    uint64_t lo = UINT64_MAX, hi = 0, previous_end = 0, phdr_vaddr = UINT64_MAX;
    int loads = 0, entry_ok = 0;
    for (unsigned i = 0; i < h.e_phnum; ++i) if (ph[i].p_type == PT_LOAD) {
        Elf64_Phdr *p = &ph[i];
        if (p->p_filesz > p->p_memsz || p->p_vaddr > (1u << 30) ||
            p->p_memsz > (1u << 30) || p->p_offset > (1u << 30) ||
            p->p_vaddr + p->p_memsz > (1u << 30) ||
            p->p_offset > (uint64_t)st.st_size ||
            p->p_filesz > (uint64_t)st.st_size - p->p_offset ||
            (p->p_vaddr & (PAGE - 1)) != (p->p_offset & (PAGE - 1)) ||
            !p->p_memsz || (loads && down(p->p_vaddr) < previous_end) ||
            ((p->p_flags & (PF_W | PF_X)) == (PF_W | PF_X)))
            ops->fail(98);
        if (down(p->p_vaddr) < lo) lo = down(p->p_vaddr);
        previous_end = up(p->p_vaddr + p->p_memsz);
        if (previous_end > hi) hi = previous_end;
        if ((p->p_flags & PF_X) && h.e_entry >= p->p_vaddr &&
            h.e_entry < p->p_vaddr + p->p_filesz) entry_ok = 1;
        if ((p->p_flags & PF_R) && h.e_phoff >= p->p_offset &&
            h.e_phoff - p->p_offset <= p->p_filesz &&
            bytes <= p->p_filesz - (h.e_phoff - p->p_offset))
            phdr_vaddr = p->p_vaddr + (h.e_phoff - p->p_offset);
        ++loads;
    }
    if (!loads || !entry_ok || hi <= lo || hi - lo > MAX_IMAGE ||
        phdr_vaddr == UINT64_MAX) ops->fail(99);
    file->header = h;
    file->layout = (struct BootstrapImageLayout){lo, hi, 1};
    file->phdr_vaddr = phdr_vaddr;
    for (unsigned i = 0; i < h.e_phnum; ++i) if (ph[i].p_type == PT_LOAD) {
        uint64_t alignment = ph[i].p_align;
        if (alignment > file->layout.alignment) file->layout.alignment = alignment;
    }
}
struct BootstrapImageLayout bootstrap_image_layout(int fd,
                                                   const struct BootstrapImageOps *ops) {
    struct BootstrapImageFile file;
    inspect(fd, ops, &file);
    return file.layout;
}
struct BootstrapImage bootstrap_map_image(int fd, const struct BootstrapImageOps *ops,
                                         const struct BootstrapReservation *reservation) {
    struct BootstrapImageFile file;
    inspect(fd, ops, &file);
    Elf64_Ehdr h = file.header;
    Elf64_Phdr *ph = file.ph;
    uint64_t lo = file.layout.lo, hi = file.layout.hi;
    uint64_t phdr_vaddr = file.phdr_vaddr;
    long region;
    if (reservation) {
        if (reservation->bytes != hi - lo ||
            reservation->base > UINT64_MAX - reservation->bytes ||
            (reservation->base & (PAGE - 1))) ops->fail(100);
        region = (long)reservation->base;
    } else {
        region = ops->call(SYS_mmap, 0, hi - lo, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, (uint64_t)-1, 0);
        if (failed(region)) ops->fail(100);
    }
    uint64_t bias = (uint64_t)region - lo;
    if (ops->track) ops->track(ops->context, region, hi - lo, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS);
    for (unsigned i = 0; i < h.e_phnum; ++i) if (ph[i].p_type == PT_LOAD) {
        Elf64_Phdr *p = &ph[i];
        uint64_t prot = ((p->p_flags & PF_R) ? PROT_READ : 0) |
                        ((p->p_flags & PF_W) ? PROT_WRITE : 0) |
                        ((p->p_flags & PF_X) ? PROT_EXEC : 0);
        uint64_t start = bias + down(p->p_vaddr);
        uint64_t file_end = bias + p->p_vaddr + p->p_filesz;
        uint64_t mem_end = bias + p->p_vaddr + p->p_memsz;
        if (p->p_filesz) {
            long r = ops->call(SYS_mmap, start, up(file_end) - start, prot,
                          MAP_PRIVATE | MAP_FIXED, fd, down(p->p_offset));
            if (r != (long)start) ops->fail(101);
            if (ops->track) ops->track(ops->context, start, up(file_end) - start, prot, MAP_PRIVATE);
            if (mem_end > file_end && file_end != up(file_end)) {
                if (prot & PROT_EXEC) ops->fail(102); /* preserve original W^X refusal */
                if (ops->call(SYS_mprotect, down(file_end), PAGE, prot | PROT_WRITE, 0, 0, 0))
                    ops->fail(103);
                for (uint64_t a = file_end; a < up(file_end); ++a)
                    *(unsigned char *)(uintptr_t)a = 0; /* FULL PAGE, not p_memsz */
                if (ops->call(SYS_mprotect, down(file_end), PAGE, prot, 0, 0, 0)) ops->fail(104);
            }
        }
        uint64_t anon = p->p_filesz ? up(file_end) : start;
        if (up(mem_end) > anon) {
            if (ops->call(SYS_mmap, anon, up(mem_end) - anon, prot,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, (uint64_t)-1, 0) != (long)anon)
                ops->fail(105);
            if (ops->track) ops->track(ops->context, anon, up(mem_end) - anon, prot, MAP_PRIVATE | MAP_ANONYMOUS);
        }
    }
    if (ops->call(SYS_close, fd, 0, 0, 0, 0, 0)) ops->fail(106);
    return (struct BootstrapImage){(uint64_t)region, (uint64_t)region + hi - lo, bias,
                          bias + h.e_entry, bias + phdr_vaddr, h.e_phnum, h.e_phentsize};
}
