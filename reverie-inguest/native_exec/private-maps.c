/* One shared bounded tracker for genuine private native mapping operations.
 * Kernel success precedes every update. Guest loader maps never enter it.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include "private-control.h"
#define PAGE UINT64_C(4096)
#define DROP_MAP UINT64_MAX
static int overlaps(uint64_t lo, uint64_t hi, uint64_t a, uint64_t b) {
    return lo < b && a < hi;
}
/* Update only after the real native mapping operation succeeds. Split/replace
 * exact page extents; overflow is terminal, never a dropped ownership record.
 * DROP_MAP erases a successfully unmapped range. Guest loader never calls this.
 */
int private_track_map(struct ExecPrivateControl *ctl, uint64_t lo, uint64_t bytes,
                      uint64_t prot, uint64_t flags) {
    uint64_t hi;
    if ((lo & (PAGE - 1)) || !bytes || (bytes & (PAGE - 1)) ||
        lo > UINT64_MAX - bytes || ctl->private_map_count > EXEC_PRIVATE_EXTENT_CAPACITY)
        return -1;
    hi = lo + bytes;
    struct ExecPrivateMap next[EXEC_PRIVATE_EXTENT_CAPACITY];
    unsigned n = 0;
#define APPEND(a,b,p,f) do { \
    if (n == EXEC_PRIVATE_EXTENT_CAPACITY) return -1; \
    next[n++] = (struct ExecPrivateMap){(a),(b),(p),(f)}; \
} while (0)
    for (uint64_t i = 0; i < ctl->private_map_count; ++i) {
        struct ExecPrivateMap m = ctl->maps[i];
        if (!overlaps(lo, hi, m.lo, m.hi)) APPEND(m.lo, m.hi, m.prot, m.flags);
        else {
            if (m.lo < lo) APPEND(m.lo, lo, m.prot, m.flags);
            if (m.hi > hi) APPEND(hi, m.hi, m.prot, m.flags);
        }
    }
    if (prot != DROP_MAP) {
        if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
            return -1;
        APPEND(lo, hi, prot, flags);
    }
#undef APPEND
    for (unsigned i = 1; i < n; ++i) {
        struct ExecPrivateMap item = next[i];
        unsigned j = i;
        while (j && next[j - 1].lo > item.lo) { next[j] = next[j - 1]; --j; }
        next[j] = item;
    }
    unsigned compact = 0;
    for (unsigned i = 0; i < n; ++i) {
        if (compact && next[compact - 1].hi == next[i].lo &&
            next[compact - 1].prot == next[i].prot &&
            next[compact - 1].flags == next[i].flags)
            next[compact - 1].hi = next[i].hi;
        else next[compact++] = next[i];
    }
    unsigned code_count = 0;
    for (unsigned i = 0; i < compact; ++i) {
        ctl->maps[i] = next[i];
        if (next[i].prot & PROT_EXEC) {
            if (code_count == EXEC_PRIVATE_EXTENT_CAPACITY) return -1;
            ctl->code[code_count++] = (struct ExecPrivateCode){next[i].lo, next[i].hi};
        }
    }
    ctl->private_map_count = compact;
    ctl->private_code_count = code_count;
    return 0;
}
