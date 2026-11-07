/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

/* Explicit live regression barriers. They never write production identity or
 * counter state. A real second clone remains reserved until the first child's
 * actual Tool admission and fact query finish. */
static void test_owner_wait(int stage) {
  for (int i = 0; i < 5000; ++i) {
    if (atomic_load_explicit(&test_owner_stage, memory_order_acquire) >= stage)
      return;
    dr_sleep(1);
  }
  dr_fprintf(diagnostic_file, "OWNER_ADMISSION timeout stage=%d\n", stage);
  exit_runtime_tree(97);
}

static void test_owner_observe(const char* phase, uint64_t count, uint64_t pending) {
  void* dc = dr_get_current_drcontext();
  prototype_counters_t* counters = drmgr_get_tls_field(dc, thread_state_index);
  branch_counter_state_t* state = branch_counter_state(dc);
  branch_counter_state_t before;
  reg_t raw[BRANCH_RAW_SLOTS];
  if (state != NULL) {
    memcpy(&before, state, sizeof(before));
    memcpy(raw, state->raw_slots, sizeof(raw));
  }
  branch_fact_t first, second;
  int a = query_branch_fact((uintptr_t)dc, &first);
  int b = query_branch_fact((uintptr_t)dc, &second);
  process_control_t* entry = process_control_for(counters->kernel_pid);
  uint64_t actual_pending = atomic_load_explicit(
      &entry->pending_thread_clones, memory_order_acquire);
  bool immutable = a == b && memcmp(&first, &second, sizeof(first)) == 0 &&
      (state == NULL || (memcmp(&before, state, sizeof(before)) == 0 &&
       memcmp(raw, state->raw_slots, sizeof(raw)) == 0));
  bool ok = immutable && actual_pending == pending;
  if (branch_counter_enabled) {
    ok = ok && a == BRANCH_FACT_READY && first.count == count && state != NULL &&
        atomic_load_explicit(&state->edge_commits, memory_order_relaxed) == count &&
        first.owner[4] == (uint64_t)atomic_load_explicit(
            &test_owner_birth, memory_order_acquire);
    if (test_owner_bound[4] != 0)
      ok = ok && memcmp(test_owner_bound, first.owner, sizeof(test_owner_bound)) == 0;
    else if (a == BRANCH_FACT_READY)
      memcpy(test_owner_bound, first.owner, sizeof(test_owner_bound));
  } else {
    branch_fact_t zero = {0};
    ok = ok && a == BRANCH_FACT_DISABLED && state == NULL &&
        memcmp(&first, &zero, sizeof(first)) == 0;
  }
  if (!ok)
    atomic_fetch_add_explicit(&test_owner_failures, 1, memory_order_relaxed);
  dr_fprintf(diagnostic_file,
      "OWNER_ADMISSION phase=%s pid=%d tid=%d pending=%llu status=%d "
      "stored=%llu count=%llu owner=%llu,%llu,%llu,%llu,%llu immutable=%d ok=%d\n",
      phase, counters->kernel_pid, (int)dr_get_thread_id(dc),
      (unsigned long long)actual_pending, a,
      (unsigned long long)(state == NULL ? 0 : atomic_load(&state->edge_commits)),
      (unsigned long long)first.count, (unsigned long long)first.owner[0],
      (unsigned long long)first.owner[1], (unsigned long long)first.owner[2],
      (unsigned long long)first.owner[3], (unsigned long long)first.owner[4],
      immutable, ok);
}
