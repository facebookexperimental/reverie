/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef REVERIE_DBT_MAPPING_CAPTURE_TEST_TOPOLOGY_H
#define REVERIE_DBT_MAPPING_CAPTURE_TEST_TOPOLOGY_H

/* Included after private_memory_snapshot_t and the public DR declarations.
 * Test-only: call prepare once before each of three captures, at operation 0,
 * outside Closed and with the private-fact flag released. These DR calls may
 * acquire locks or allocate. No function in this header is a Closed callback.
 *
 * On the supported Linux SDK, configure.cmake.h enables HAVE_MEMINFO_MAPS and
 * dr_query_memory uses get_memory_info_from_os, not the all_memory_areas cache.
 * memquery_linux.c opens /proc/<current native tid>/maps for each query. The
 * exact kernel extent and protection are retained, never clipped to our seven
 * pages or inferred from a runtime filename. The query can add pretend-write
 * flags; exact protection checks below refuse those too.
 */

typedef struct {
  uintptr_t start;
  uintptr_t end;
  uint32_t protection;
  uint32_t query_status; /* 1: OS query; 2: valid extent; 4: whole extent owned. */
} mapping_capture_topology_extent_t;

typedef struct {
  byte* pointer;
  size_t page;
  uint32_t phase;
  uint32_t stage; /* Last reached preparation guard; diagnostic only. */
  bool owned;
  /* Three captures, each with real samples at allocation pages 0, 2 and 5. */
  mapping_capture_topology_extent_t observed[3][3];
} mapping_capture_topology_test_t;

typedef bool (*mapping_capture_topology_owned_t)(
    const private_memory_snapshot_t*, const void*, size_t);

static bool mapping_capture_topology_test_query(
    const private_memory_snapshot_t* owner, mapping_capture_topology_owned_t owned,
    const byte* address, mapping_capture_topology_extent_t* output) {
  byte* base = NULL;
  size_t size = 0;
  uint protection = 0;
  bool queried = dr_query_memory(address, &base, &size, &protection);
  bool bounded = size != 0 && (uintptr_t)base <= UINTPTR_MAX - size;
  *output = (mapping_capture_topology_extent_t){
    (uintptr_t)base, bounded ? (uintptr_t)base + size : 0, protection, queried ? 1U : 0U };
  if (!queried || !bounded ||
      (uintptr_t)address < (uintptr_t)base ||
      (uintptr_t)address >= (uintptr_t)base + size)
    return false;
  output->query_status |= 2;
  if (!owned(owner, base, size))
    return false;
  output->query_status |= 4;
  return true;
}

static bool mapping_capture_topology_test_same(
    const mapping_capture_topology_extent_t* left,
    const mapping_capture_topology_extent_t* right) {
  return left->start == right->start && left->end == right->end &&
      left->protection == right->protection;
}

static bool mapping_capture_topology_test_prepare(mapping_capture_topology_test_t* state,
    const private_memory_snapshot_t* owner, mapping_capture_topology_owned_t owned) {
  if (state != NULL)
    state->stage = 1;
  if (state == NULL || owner == NULL || owned == NULL || state->phase >= 3 ||
      !owned(owner, state, sizeof(*state)))
    return false;
  state->owned = false;
  if (state->phase == 0) {
    /* dr_nonheap_alloc may use a fallback arena. Actual ownership is required
     * below; reachability or allocation API name alone is not a certificate. */
    if (state->pointer != NULL)
      return false;
    state->page = dr_page_size();
    if (state->page == 0 || state->page > SIZE_MAX / 7)
      return false;
    state->pointer = dr_nonheap_alloc(7 * state->page, DR_MEMPROT_READ);
  }
  state->stage = 2;
  if (state->pointer == NULL || state->page == 0 || state->page > SIZE_MAX / 7 ||
      (uintptr_t)state->pointer % state->page != 0 ||
      (uintptr_t)state->pointer > UINTPTR_MAX - 7 * state->page ||
      !owned(owner, state->pointer, 7 * state->page))
    return false;

  state->stage = 3;
  if (state->phase == 1) {
    if (!dr_memory_protect(state->pointer + 2 * state->page, 3 * state->page,
            DR_MEMPROT_READ | DR_MEMPROT_WRITE))
      return false;
    for (size_t page = 2; page < 5; ++page)
      *(volatile byte*)(state->pointer + page * state->page) = (byte)page;
  } else if (state->phase == 2 &&
      !dr_memory_protect(state->pointer + 2 * state->page, 3 * state->page,
          DR_MEMPROT_READ)) {
    return false;
  }

  mapping_capture_topology_extent_t* observed = state->observed[state->phase];
  state->stage = 4;
  if (!mapping_capture_topology_test_query(owner, owned, state->pointer, &observed[0]))
    return false;
  state->stage = 5;
  if (!mapping_capture_topology_test_query(
          owner, owned, state->pointer + 2 * state->page, &observed[1]))
    return false;
  state->stage = 6;
  if (!mapping_capture_topology_test_query(
          owner, owned, state->pointer + 5 * state->page, &observed[2]))
    return false;

  const mapping_capture_topology_extent_t* initial = &state->observed[0][0];
  if (state->phase == 0) {
    state->stage = 7;
    if (initial->start > (uintptr_t)state->pointer ||
        initial->end < (uintptr_t)state->pointer + 7 * state->page ||
        initial->protection != DR_MEMPROT_READ ||
        !mapping_capture_topology_test_same(initial, &observed[1]) ||
        !mapping_capture_topology_test_same(initial, &observed[2]))
      return false;
  } else if (state->phase == 1) {
    state->stage = 8;
    uintptr_t middle = (uintptr_t)state->pointer + 2 * state->page;
    uintptr_t right = (uintptr_t)state->pointer + 5 * state->page;
    if (observed[0].start != initial->start || observed[0].end != middle ||
        observed[0].protection != DR_MEMPROT_READ ||
        observed[1].start != middle || observed[1].end != right ||
        observed[1].protection != (DR_MEMPROT_READ | DR_MEMPROT_WRITE) ||
        observed[2].start != right || observed[2].end != initial->end ||
        observed[2].protection != DR_MEMPROT_READ)
      return false;
  } else {
    state->stage = 9;
    /* Linux mprotect restores access, not VMA coalescing: a formerly writable
     * anonymous middle can remain a separate READ VMA. Require the exact
     * original span to be covered without holes or overlap by the complete,
     * individually owned READ extents observed at all three sample points.
     * Duplicate samples of one merged VMA are allowed, partial overlap is not. */
    uintptr_t covered = initial->start;
    for (size_t sample = 0; sample < 3; ++sample) {
      const mapping_capture_topology_extent_t* current = &observed[sample];
      if (current->start < initial->start || current->end > initial->end ||
          current->protection != DR_MEMPROT_READ || current->start > covered ||
          (current->start < covered &&
           (sample == 0 || !mapping_capture_topology_test_same(
               current, &observed[sample - 1]))))
        return false;
      covered = current->end;
    }
    if (covered != initial->end)
      return false;
  }
  state->owned = true;
  state->stage = 10;
  ++state->phase;
  /* Keep this test allocation until image teardown, including on failure.
   * Never free it from a cancellation/terminal path or during Closed. */
  return true;
}

#endif /* REVERIE_DBT_MAPPING_CAPTURE_TEST_TOPOLOGY_H */
