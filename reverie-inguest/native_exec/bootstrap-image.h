#ifndef REVERIE_BOOTSTRAP_IMAGE_H
#define REVERIE_BOOTSTRAP_IMAGE_H
#include <stddef.h>
#include <stdint.h>
#define BOOTSTRAP_HIDDEN __attribute__((visibility("hidden")))
struct BootstrapImage { uint64_t lo, hi, bias, entry, phdr, phnum, phent; };
struct BootstrapImageLayout { uint64_t lo, hi, alignment; };
struct BootstrapReservation { uint64_t base, bytes; };
struct BootstrapImageOps {
    long (*call)(long, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    __attribute__((noreturn)) void (*fail)(unsigned);
    void (*track)(void *, uint64_t, uint64_t, uint64_t, uint64_t);
    void *context;
};
BOOTSTRAP_HIDDEN struct BootstrapImageLayout bootstrap_image_layout(
    int, const struct BootstrapImageOps *);
/* reservation is an actual exclusively owned PROT_NONE mmap span, not an
 * arbitrary desired address. The caller owns and proves its complete extent. */
BOOTSTRAP_HIDDEN struct BootstrapImage bootstrap_map_image(
    int, const struct BootstrapImageOps *, const struct BootstrapReservation *);
BOOTSTRAP_HIDDEN int bootstrap_equal(const void *, const void *, uint64_t);
BOOTSTRAP_HIDDEN void *memset(void *, int, size_t);
BOOTSTRAP_HIDDEN void *memcpy(void *, const void *, size_t);
#endif
