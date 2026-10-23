#include "dr_api.h"
#include <stddef.h>
#include <stdint.h>

typedef uint64_t (*fill_fn)(unsigned char);
typedef uint64_t (*checksum_fn)(void);
typedef size_t (*size_fn)(void);

static int equal(const char* a, const char* b) {
  while (*a && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

static void fail(const char* reason) {
  dr_fprintf(STDERR, "AUX_FIXTURE_FAILURE %s\n", reason);
  dr_abort_with_code(93);
  __builtin_unreachable();
}

static uint64_t expected(size_t size, unsigned char seed) {
  uint64_t sum = 0;
  for (size_t i = 0; i < size; ++i)
    sum += (unsigned char)(seed + i);
  return sum;
}

static checksum_fn checked_workspace(dr_auxlib_handle_t handle, size_t wanted_size,
                                     unsigned char seed, uint64_t* sum) {
  fill_fn fill = (fill_fn)dr_lookup_aux_library_routine(handle, "workspace_fill");
  checksum_fn checksum =
      (checksum_fn)dr_lookup_aux_library_routine(handle, "workspace_checksum");
  size_fn size = (size_fn)dr_lookup_aux_library_routine(handle, "workspace_size");
  if (!fill || !checksum || !size || size() != wanted_size)
    fail("workspace exports/size");
  *sum = expected(wanted_size, seed);
  if (fill(seed) != *sum || checksum() != *sum)
    fail("workspace computation");
  return checksum;
}

static dr_auxlib_handle_t load(const char* path) {
  return dr_load_aux_library(path, NULL, NULL);
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  (void)id;
  if (argc < 2)
    fail("mode missing");
  if (equal(argv[1], "startup")) {
    dr_fprintf(STDERR, "AUX_CONTROL_OK startup\n");
    return;
  }
  if (equal(argv[1], "terminal")) {
    if (argc != 3)
      fail("terminal arguments");
    dr_fprintf(STDERR, "AUX_TERMINAL_ATTEMPT\n");
    dr_auxlib_handle_t unexpected = load(argv[2]);
    (void)unexpected;
    /* Even a NULL return is wrong: an indeterminate fixed-map failure must
     * terminate without returning control or attempting a retry/unload. */
    dr_fprintf(STDERR, "AUX_TERMINAL_RETURNED\n");
    fail("indeterminate mapping returned to client");
  }
  int missing = equal(argv[1], "missing");
  int exhaustion = equal(argv[1], "exhaustion");
  if ((!missing && !exhaustion) || argc != 5)
    fail("recovery arguments");
  dr_auxlib_handle_t sentinel = load(argv[2]);
  if (!sentinel)
    fail("sentinel load");
  uint64_t sentinel_sum;
  checksum_fn sentinel_checksum = checked_workspace(sentinel, 4096, 17, &sentinel_sum);
  int attempts = missing ? 3 : 1;
  for (int attempt = 1; attempt <= attempts; ++attempt) {
    dr_fprintf(STDERR, "AUX_FAILURE_ATTEMPT mode=%s attempt=%d\n", argv[1], attempt);
    byte* unexpected_start = NULL;
    byte* unexpected_end = NULL;
    if (dr_load_aux_library(argv[4], &unexpected_start, &unexpected_end) != NULL) {
      dr_fprintf(STDERR, "AUX_UNEXPECTED_LOAD start=%p end=%p\n", unexpected_start,
                 unexpected_end);
      fail("negative auxiliary load succeeded");
    }
    dr_fprintf(STDERR, "AUX_FAILURE_RETURNED mode=%s attempt=%d\n", argv[1], attempt);
    /* Do not refill: that would hide neighbor corruption during cleanup. */
    if (sentinel_checksum() != sentinel_sum)
      fail("sentinel corrupted after failed load");
    dr_auxlib_handle_t valid = load(argv[3]);
    if (!valid)
      fail("valid load after failure");
    uint64_t valid_sum;
    checksum_fn valid_checksum = checked_workspace(valid, 8192, 31, &valid_sum);
    if (valid_checksum() != valid_sum || !dr_unload_aux_library(valid))
      fail("valid unload");
    if (sentinel_checksum() != sentinel_sum)
      fail("sentinel corrupted after valid unload");
    dr_fprintf(STDERR, "AUX_RECOVERY_OK mode=%s attempt=%d\n", argv[1], attempt);
  }
  if (!dr_unload_aux_library(sentinel))
    fail("sentinel unload");
  dr_fprintf(STDERR, "AUX_CONTROL_OK %s\n", argv[1]);
}
