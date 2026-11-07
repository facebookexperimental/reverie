/* Isolated atomic-alias lifecycle controls; no production fault hooks. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define PAGE 4096
#define MARKER 0x6b
#define COUNT 32
/* These are actual events. Obsolete preparation-unmap/product-NOREPLACE events
   are required to remain zero, not manufactured to preserve the old vector. */
enum {
    RESERVE, EXTENT, EXTENT_OK, SETUP_FAILED, TARGET_RELEASED,
    CLEANUP, CLEANUP_OK, CLEANUP_FAILED, CLEANUP_MASK, RETAINED_MASK,
    FIRST_UNCHANGED, WORKER_CREATED, WORKER_JOINED, FOREIGN_CREATED,
    FOREIGN_BEFORE, FOREIGN_AFTER, FOREIGN_FINISH, FOREIGN_RELEASED,
    REAL_EEXIST, WRONG_CREATED, WRONG_CLEANUP, WRONG_RELEASED,
    AMBIGUOUS_MAPPED, OWNED_MAPPED, BAD_CLEANUP, DUPLICATE_CLEANUP,
    PREP_UNMAP, DIFFERENT_OWNER, PREFIX_REUSE, PRIOR_RETAINED_INTACT,
    FOREIGN_DESTROYED, PRODUCT_NOREPLACE
};
static _Atomic int active, finished;
static _Atomic long owner_tid;
static _Atomic uintptr_t reservation;
static _Atomic unsigned long counters[COUNT];
static int chosen, ambiguous, operation;
static size_t span;
static uint64_t queried;
static unsigned long attempted_mask;
static uintptr_t wrong_address, foreign_address;
static int wrong_owned, foreign_owned;
static uintptr_t prior_retained[3];
static unsigned int prior_count;
static pthread_t worker;
static _Atomic int request;
static uintptr_t worker_target;
static long worker_tid;
static int worker_collision, worker_errno, worker_mapped;

static _Noreturn void refuse(const char *reason) {
    active = 0;
    dprintf(2, "\nALIAS_FIXTURE_SETUP_FAILURE case=%d operation=%d reason=%s errno=%d\n",
            chosen, operation, reason, errno);
    syscall(SYS_exit_group, 97);
    __builtin_unreachable();
}
static int overlaps(uintptr_t a, size_t n, uintptr_t b, size_t m) {
    return n && m && (a <= b ? b - a < n : a - b < m);
}
static int mapped(uintptr_t a) {
    unsigned char vector;
    long rc;
    do { rc = syscall(SYS_mincore, (void *)a, PAGE, &vector); }
    while (rc == -1 && errno == EINTR);
    if (rc == 0) return 1;
    if (errno != ENOMEM) refuse("mincore");
    return 0;
}
static unsigned long mapped_mask(uintptr_t base, size_t length) {
    unsigned long mask = 0;
    for (size_t i = 0; i < length / PAGE; i++)
        if (mapped(base + i * PAGE)) mask |= 1UL << i;
    return mask;
}
static int all_bytes(uintptr_t address, unsigned char expected) {
    unsigned char bytes[PAGE];
    if (!mapped(address)) return 0;
    struct iovec local = {bytes, PAGE}, remote = {(void *)address, PAGE};
    long rc;
    do { rc = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0); }
    while (rc == -1 && errno == EINTR);
    if (rc != PAGE) return 0;
    for (size_t i = 0; i < PAGE; i++) if (bytes[i] != expected) return 0;
    return 1;
}
static int worker_case(void) {
    return chosen == 3 || chosen == 4 || chosen == 6 || chosen == 7 || chosen == 9;
}
static int successful_setup(void) { return chosen == 4 || chosen == 5 || chosen == 10; }
static void *foreign_allocator(void *unused) {
    (void)unused;
    worker_tid = syscall(SYS_gettid);
    while (!atomic_load_explicit(&request, memory_order_acquire)) {
        long rc = syscall(SYS_futex, &request, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
        if (rc == -1 && errno != EINTR && errno != EAGAIN) {
            worker_errno = errno;
            return 0;
        }
    }
    void *p = (void *)syscall(SYS_mmap, (void *)worker_target, PAGE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) worker_errno = errno;
    else if ((uintptr_t)p != worker_target) {
        if (syscall(SYS_munmap, p, PAGE)) refuse("worker-wrong-address-retirement");
        worker_errno = EOPNOTSUPP;
    } else {
        memset(p, MARKER, PAGE);
        worker_mapped = 1;
    }
    return 0;
}
static void meet_worker(uintptr_t target, int collision) {
    worker_target = target;
    worker_collision = collision;
    atomic_store_explicit(&request, 1, memory_order_release);
    if (syscall(SYS_futex, &request, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) < 0)
        refuse("worker-wake");
    int rc = pthread_join(worker, 0);
    if (rc) { errno = rc; refuse("worker-join"); }
    counters[WORKER_JOINED] = 1;
    if (worker_tid == owner_tid) refuse("same-owner");
    counters[DIFFERENT_OWNER] = 1;
    if (collision) {
        if (worker_mapped || worker_errno != EEXIST) refuse("owned-target-not-EEXIST");
        counters[REAL_EEXIST] = 1;
    } else {
        if (!worker_mapped || worker_errno) refuse("foreign-target-not-owned");
        foreign_address = target;
        foreign_owned = 1;
        counters[FOREIGN_CREATED] = 1;
        if (!all_bytes(target, MARKER)) refuse("foreign-marker");
    }
}
void reverie_alias_failure_arm(int value) {
    if (value < 1 || value > 11 || sysconf(_SC_PAGESIZE) != PAGE)
        refuse("case-or-page-size");
    if (chosen && !(chosen == 10 && value == 10 && finished && operation < 3))
        refuse("repeated-case");
    if (chosen && queried != ((UINT64_C(1) << COUNT) - 1)) refuse("incomplete-prior-query");
    for (unsigned int i = 0; i < prior_count; i++)
        if (mapped_mask(prior_retained[i], 3 * PAGE) != 7) refuse("prior-retention-lost");
    for (unsigned int i = 0; i < COUNT; i++) counters[i] = 0;
    counters[PRIOR_RETAINED_INTACT] = prior_count;
    operation++;
    chosen = value;
    span = (chosen == 7 || chosen == 9 ? 5 : 3) * PAGE;
    ambiguous = 0; finished = 0; queried = 0; attempted_mask = 0;
    owner_tid = 0; reservation = 0; foreign_address = 0; wrong_address = 0;
    foreign_owned = 0; wrong_owned = 0; request = 0;
    worker_tid = 0; worker_errno = 0; worker_mapped = 0; worker_collision = 0;
    if (worker_case()) {
        int rc = pthread_create(&worker, 0, foreign_allocator, 0);
        if (rc) { errno = rc; refuse("worker-create"); }
        counters[WORKER_CREATED] = 1;
    }
    active = 1;
}
void *mmap(void *address, size_t length, int prot, int flags, int fd, off_t offset) {
    long tid = syscall(SYS_gettid), owner = owner_tid;
    int reserve = active && !owner && !address && length == span && prot == PROT_NONE &&
                  flags == (MAP_PRIVATE | MAP_ANONYMOUS) && fd == -1 && offset == 0;
    if (reserve) {
        long unclaimed = 0;
        if (!atomic_compare_exchange_strong(&owner_tid, &unclaimed, tid)) reserve = 0;
        else {
            owner = tid; counters[RESERVE]++;
            if (chosen == 1) {
                active = 0; counters[SETUP_FAILED]++;
                errno = ENOMEM; return MAP_FAILED;
            }
        }
    }
    uintptr_t base = reservation;
    int install = active && tid == owner && base && length == PAGE &&
                  ((uintptr_t)address == base || (uintptr_t)address == base + 2 * PAGE) &&
                  prot == (PROT_READ | PROT_WRITE) && fd >= 0;
    if (install) {
        if (flags & MAP_FIXED_NOREPLACE) counters[PRODUCT_NOREPLACE]++;
        if (flags != (MAP_SHARED | MAP_FIXED)) refuse("product-not-atomic-fixed");
        unsigned long ordinal = ++counters[EXTENT];
        if ((ordinal == 1 && (uintptr_t)address != base) ||
            (ordinal == 2 && (uintptr_t)address != base + 2 * PAGE) || ordinal > 2)
            refuse("extent-shape");
        if (ordinal == 2) {
            if (chosen == 4) meet_worker((uintptr_t)address, 1);
            if (!successful_setup()) {
                active = 0; ambiguous = 1; counters[SETUP_FAILED]++;
                if (chosen == 3 || chosen == 6 || chosen == 7) {
                    if (syscall(SYS_munmap, address, length)) refuse("planted-target-release");
                    counters[TARGET_RELEASED]++;
                    meet_worker((uintptr_t)address, 0);
                }
                if (chosen == 6) {
                    void *p = (void *)syscall(SYS_mmap, 0, length, prot, MAP_SHARED, fd, offset);
                    if (p == MAP_FAILED || overlaps((uintptr_t)p, length, base, span))
                        refuse("wrong-positive-setup");
                    wrong_address = (uintptr_t)p; wrong_owned = 1; counters[WRONG_CREATED]++;
                    errno = EACCES; return p;
                }
                /* Cases2/8/9 leave the original target untouched. */
                errno = ENOMEM; return MAP_FAILED;
            }
        }
    }
    void *p = (void *)syscall(SYS_mmap, address, length, prot, flags, fd, offset);
    int saved = errno;
    if (reserve) {
        if (p == MAP_FAILED) refuse("real-reservation-failed");
        reservation = (uintptr_t)p;
        if (chosen == 11) active = 0;
    }
    if (install) {
        if (p != address) refuse("real-fixed-install-failed");
        counters[EXTENT_OK]++;
        if (counters[EXTENT] == 2) active = 0;
    }
    errno = saved;
    return p;
}
int munmap(void *address, size_t length) {
    uintptr_t base = reservation;
    if (!base || syscall(SYS_gettid) != owner_tid || finished)
        return syscall(SYS_munmap, address, length);
    int inside = overlaps((uintptr_t)address, length, base, span);
    int wrong = wrong_owned && overlaps((uintptr_t)address, length, wrong_address, PAGE);
    if (!inside && !wrong) return syscall(SYS_munmap, address, length);
    if (active) { counters[PREP_UNMAP]++; refuse("explicit-preparation-unmap"); }
    counters[CLEANUP]++;
    unsigned long mask = 0;
    for (size_t i = 0; i < span / PAGE; i++)
        if (overlaps((uintptr_t)address, length, base + i * PAGE, PAGE)) mask |= 1UL << i;
    int shape = wrong ? (uintptr_t)address == wrong_address && length == PAGE :
        ambiguous ? (((uintptr_t)address == base && length == 2 * PAGE) ||
                     (span == 5 * PAGE && (uintptr_t)address == base + 3 * PAGE && length == 2 * PAGE)) :
                    (uintptr_t)address == base && length == span;
    if (!shape) counters[BAD_CLEANUP]++;
    if (mask & attempted_mask) counters[DUPLICATE_CLEANUP]++;
    attempted_mask |= mask;
    if (wrong) counters[WRONG_CLEANUP]++;
    if (ambiguous && (uintptr_t)address == base)
        counters[FIRST_UNCHANGED] = all_bytes(base, 0xa5);
    if (foreign_owned && all_bytes(foreign_address, MARKER)) counters[FOREIGN_BEFORE]++;
    int refusal = (chosen == 5 || chosen == 10 || chosen == 11) ||
                  (chosen == 8 && (uintptr_t)address == base) ||
                  (chosen == 9 && (uintptr_t)address == base + 3 * PAGE);
    int rc, saved;
    if (refusal) { rc = -1; saved = ENOMEM; counters[CLEANUP_FAILED]++; counters[RETAINED_MASK] |= mask; }
    else {
        rc = syscall(SYS_munmap, address, length); saved = errno;
        if (rc) refuse("unplanned-real-cleanup-failure");
        counters[CLEANUP_OK]++; counters[CLEANUP_MASK] |= mask;
        if (wrong) { wrong_owned = 0; counters[WRONG_RELEASED]++; }
        if (foreign_owned && overlaps((uintptr_t)address, length, foreign_address, PAGE)) {
            foreign_owned = 0; counters[FOREIGN_DESTROYED]++;
        }
        if (chosen == 9 && (uintptr_t)address == base && length == 2 * PAGE &&
            counters[PREFIX_REUSE] == 0) {
            meet_worker(base, 0); counters[PREFIX_REUSE] = 1;
        }
    }
    if (foreign_owned && all_bytes(foreign_address, MARKER)) counters[FOREIGN_AFTER]++;
    errno = saved;
    return rc;
}
void reverie_alias_failure_finish(void) {
    if (!chosen || finished || active) refuse("incomplete-or-repeated-finish");
    uintptr_t base = reservation;
    if (base) {
        counters[AMBIGUOUS_MAPPED] = ambiguous && mapped(base + 2 * PAGE);
        unsigned long owned = (1UL << (span / PAGE)) - 1;
        if (ambiguous) owned &= ~(1UL << 2);
        if (chosen == 9) owned &= ~1UL; /* New prefix owner is the fixture worker. */
        counters[OWNED_MAPPED] = mapped_mask(base, span) & owned;
    }
    if (worker_case()) {
        if (counters[WORKER_JOINED] != 1) refuse("worker-not-joined");
        if (!worker_collision && foreign_owned && all_bytes(foreign_address, MARKER)) {
            counters[FOREIGN_FINISH] = 1;
            if (syscall(SYS_munmap, (void *)foreign_address, PAGE)) refuse("foreign-owner-release");
            foreign_owned = 0; counters[FOREIGN_RELEASED] = 1;
        }
    }
    if (chosen == 10) {
        if (prior_count >= 3) refuse("persistent-case-bound");
        prior_retained[prior_count++] = base;
    }
    /* Never reclaim ambiguous or product-retained addresses. Process exit is
       their declared final bound; Rust checks the process-lifetime ledger. */
    finished = 1;
}
unsigned long reverie_alias_failure_count(int index) {
    if (!finished || index < 0 || index >= COUNT || (queried & (UINT64_C(1) << index)))
        refuse("counter-query");
    queried |= UINT64_C(1) << index;
    return counters[index];
}
uintptr_t reverie_alias_failure_address(int index) {
    switch (index) {
    case 0: return reservation;
    case 1: return span;
    case 2: return wrong_address;
    case 3: return ambiguous && reservation ? reservation + 2 * PAGE : 0;
    case 4: return (uintptr_t)operation;
    default: refuse("address-query");
    }
}
