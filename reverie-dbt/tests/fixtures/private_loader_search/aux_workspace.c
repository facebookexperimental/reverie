#include <stddef.h>
#include <stdint.h>
#ifndef WORKSPACE_BYTES
#error WORKSPACE_BYTES must be supplied
#endif

/* Real working state, not file padding. Keep calls internal so loading two
 * workspaces cannot interpose one library's storage through another's PLT. */
static volatile unsigned char workspace[WORKSPACE_BYTES];

static uint64_t checksum(void) {
  uint64_t sum = 0;
  for (size_t i = 0; i < WORKSPACE_BYTES; ++i)
    sum += workspace[i];
  return sum;
}

static uint64_t fill(unsigned char seed) {
  for (size_t i = 0; i < WORKSPACE_BYTES; ++i)
    workspace[i] = (unsigned char)(seed + i);
  return checksum();
}

uint64_t workspace_checksum(void) { return checksum(); }
uint64_t workspace_fill(unsigned char seed) { return fill(seed); }
size_t workspace_size(void) { return WORKSPACE_BYTES; }

#ifdef AUX_REQUIRES_LEAF
extern int leaf_value(void);
/* Callable when the sole dependency is present. The missing-import control
 * never calls it: import resolution must refuse before returning a handle. */
uint64_t workspace_with_dependency(unsigned char seed) {
  return fill(seed) + (uint64_t)(unsigned int)leaf_value();
}
#endif
