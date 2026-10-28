/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 *
 * Optional original-conditional instruction facts. This is an image-local,
 * per-task mechanism, independent of mixed branch statistics and virtual time.
 * Only the existing native/Rust transport may expose a validated observation.
 */
#ifndef REVERIE_DBT_BRANCH_COUNTER_H
#define REVERIE_DBT_BRANCH_COUNTER_H

/* Hooks are compiled only into the separate native mechanism-test client.
 * A normal client has no trap, observer, target selector or mutation switch. */
#ifndef REVERIE_DBT_BRANCH_COUNTER_TEST
#define BRANCH_COUNTER_TEST_FIELDS
#define BRANCH_COUNTER_TEST_PHASE(...) ((void)0)
#define BRANCH_COUNTER_TEST_GATE(...) ((void)0)
#define BRANCH_COUNTER_TEST_QUERY(...) ((void)0)
#define BRANCH_COUNTER_TEST_PRE(...) ((void)0)
#define BRANCH_COUNTER_TEST_POST(...) ((void)0)
#define BRANCH_COUNTER_TEST_CAS(...) ((void)0)
#define BRANCH_COUNTER_TEST_CAS_MISS(...) ((void)0)
#define BRANCH_COUNTER_TEST_RESTORE(...) ((void)0)
#define BRANCH_COUNTER_TEST_INVALIDATE(...) ((void)0)
#endif

typedef struct {
  _Atomic uint64_t edge_commits;
  uint64_t pending_token;
  bool pending_active;
  bool invalid;
  reg_t* raw_slots;
  /* Populated from existing admission, never inferred from a PID or sampled
   * count. The actual process slot, image epoch and task birth are distinct. */
  uint64_t owner[5];
  int32_t owner_pid, owner_tid;
  bool owner_valid;
  BRANCH_COUNTER_TEST_FIELDS
} branch_counter_state_t;

_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2,
    "branch facts require lock-free 64-bit atomics");
_Static_assert(offsetof(branch_counter_state_t, edge_commits) %
    _Alignof(_Atomic uint64_t) == 0, "branch count atomic alignment");

static bool branch_counter_enabled;
static _Atomic bool branch_counter_unsupported;
static int branch_counter_tls = -1;
static reg_id_t branch_counter_raw_segment;
static uint branch_counter_raw_offset;
static ptr_uint_t branch_counter_original_note;
enum {
  BRANCH_RAW_XAX, BRANCH_RAW_XBX, BRANCH_RAW_XCX, BRANCH_RAW_FLAGS,
  BRANCH_RAW_ACTIVE, BRANCH_RAW_EDGE_START,
  BRANCH_RAW_EDGE_END = BRANCH_RAW_EDGE_START + 4,
  BRANCH_RAW_SUCCESSOR = BRANCH_RAW_EDGE_END + 4,
  BRANCH_RAW_CONTEXT_BEGIN = BRANCH_RAW_SUCCESSOR + 4,
  BRANCH_RAW_FLAGS_SAVED = BRANCH_RAW_CONTEXT_BEGIN + 2,
  BRANCH_RAW_CONTEXT_END = BRANCH_RAW_FLAGS_SAVED + 2,
  BRANCH_RAW_PRE_BEGIN = BRANCH_RAW_CONTEXT_END + 2,
  BRANCH_RAW_PRE_FLAGS, BRANCH_RAW_PRE_END, BRANCH_RAW_ORIGINAL, BRANCH_RAW_SLOTS
};

static bool branch_counter_owned_stub(app_pc pc);

static branch_counter_state_t* branch_counter_state(void* dc) {
  return branch_counter_tls < 0 ? NULL :
      (branch_counter_state_t*)drmgr_get_tls_field(dc, branch_counter_tls);
}

/* A new task starts a fresh physical instruction history. This does not
 * reset shared logical time, and a newly loaded image is a different scope. */
static void branch_counter_initialize(void* dc, branch_counter_state_t* state) {
  memset(state, 0, sizeof(*state));
  state->raw_slots = (reg_t*)((byte*)dr_get_dr_segment_base(
      branch_counter_raw_segment) + branch_counter_raw_offset);
  memset(state->raw_slots, 0, BRANCH_RAW_SLOTS * sizeof(reg_t));
  atomic_init(&state->edge_commits, 0);
  DR_ASSERT(atomic_is_lock_free(&state->edge_commits));
  DR_ASSERT(drmgr_set_tls_field(dc, branch_counter_tls, state));
}

static void branch_counter_thread_init(void* dc) {
  branch_counter_state_t* state = dr_thread_alloc(dc, sizeof(*state));
  DR_ASSERT(state != NULL);
  branch_counter_initialize(dc, state);
}

/* DR invokes this only in the non-CLONE_VM child. Ordinary application
 * clone/vfork with CLONE_VM uses fresh thread-init/raw TLS instead. */
static void branch_counter_fork_init(void* dc) {
  branch_counter_state_t* state = branch_counter_state(dc);
  DR_ASSERT(state != NULL);
  const bool incomplete = state->raw_slots[BRANCH_RAW_ACTIVE] != 0;
  branch_counter_initialize(dc, state);
  state->invalid = incomplete;
}

static void branch_counter_thread_exit(void* dc) {
  branch_counter_state_t* state = branch_counter_state(dc);
  if (state != NULL) {
    DR_ASSERT(drmgr_set_tls_field(dc, branch_counter_tls, NULL));
    dr_thread_free(dc, state, sizeof(*state));
  }
}

static void branch_counter_commit_edge(branch_counter_state_t* state) {
  if (!state->pending_active)
    return;
  const uint64_t token = state->pending_token;
  uint64_t expected = token - 1;
  if (!atomic_compare_exchange_strong_explicit(&state->edge_commits, &expected,
          token, memory_order_relaxed, memory_order_relaxed) && expected < token)
    state->invalid = true;
  /* The token remains valid until the next reservation. A restore or raw
   * continuation that sees it again only observes a count already >= token;
   * there is no second count/clear transaction to interrupt.
   */
}

static int branch_counter_edge_phase(
    const branch_counter_state_t* state, app_pc raw_pc) {
  if (state->raw_slots[BRANCH_RAW_ACTIVE] == 0)
    return -1;
  if (raw_pc >= (app_pc)state->raw_slots[BRANCH_RAW_PRE_BEGIN] &&
      raw_pc < (app_pc)state->raw_slots[BRANCH_RAW_PRE_END])
    return -2; /* Recoverable preparation: the CBR has not executed. */
  if (!state->pending_active)
    return -1;
  for (int i = 0; i < 4; ++i) {
    if (raw_pc >= (app_pc)state->raw_slots[BRANCH_RAW_EDGE_START + i] &&
        raw_pc < (app_pc)state->raw_slots[BRANCH_RAW_EDGE_END + i])
      return i;
  }
  return -1;
}

static bool branch_counter_restore_body(
    void* drcontext, bool restore_memory, dr_restore_state_info_t* info) {
  branch_counter_state_t* state = branch_counter_state(drcontext);
  int phase = state != NULL && info->raw_mcontext_valid
      ? branch_counter_edge_phase(state, info->raw_mcontext->pc) : -1;
  if (phase == -2) {
    info->mcontext->pc = (app_pc)state->raw_slots[BRANCH_RAW_ORIGINAL];
    info->mcontext->xax = state->raw_slots[BRANCH_RAW_XAX];
    info->mcontext->xbx = state->raw_slots[BRANCH_RAW_XBX];
    info->mcontext->xcx = info->raw_mcontext->xcx;
    info->mcontext->xflags = info->raw_mcontext->pc >=
        (app_pc)state->raw_slots[BRANCH_RAW_PRE_FLAGS]
        ? dr_merge_arith_flags(info->raw_mcontext->xflags,
              state->raw_slots[BRANCH_RAW_FLAGS])
        : info->raw_mcontext->xflags;
  } else if (phase >= 0) {
    info->mcontext->pc = (app_pc)state->raw_slots[BRANCH_RAW_SUCCESSOR + phase];
    for (int i = 0; i < 2; ++i) {
      app_pc raw_pc = info->raw_mcontext->pc;
      if (raw_pc >= (app_pc)state->raw_slots[BRANCH_RAW_CONTEXT_BEGIN + i] &&
          raw_pc < (app_pc)state->raw_slots[BRANCH_RAW_CONTEXT_END + i]) {
        info->mcontext->xax = state->raw_slots[BRANCH_RAW_XAX];
        info->mcontext->xbx = state->raw_slots[BRANCH_RAW_XBX];
        info->mcontext->xcx = state->raw_slots[BRANCH_RAW_XCX];
        info->mcontext->xflags = raw_pc >= (app_pc)state->raw_slots[BRANCH_RAW_FLAGS_SAVED + i]
            ? dr_merge_arith_flags(info->raw_mcontext->xflags,
                  state->raw_slots[BRANCH_RAW_FLAGS])
            : info->raw_mcontext->xflags;
      }
    }
    if (restore_memory)
      branch_counter_commit_edge(state);
  }
  BRANCH_COUNTER_TEST_RESTORE(drcontext, restore_memory, info, phase);
  return true;
}

static void branch_counter_store_label(
    void* dc, instrlist_t* bb, instr_t* before, instr_t* label, int offset) {
  instrlist_insert_mov_instr_addr(dc, label, NULL,
      dr_raw_tls_opnd(dc, branch_counter_raw_segment,
        branch_counter_raw_offset + offset * sizeof(reg_t)),
      bb, before, NULL, NULL);
}

static void branch_counter_expand_cbr(
    void* dc, instrlist_t* bb, instr_t* app) {
  DR_ASSERT(instr_is_cbr(app));
  DR_ASSERT(opnd_is_pc(instr_get_target(app)));
  app_pc original = instr_get_app_pc(app);
  app_pc target = opnd_get_pc(instr_get_target(app));
  app_pc fallthrough = instr_get_app_pc(app) + instr_length(dc, app);
  instr_t* fall_short = INSTR_CREATE_label(dc);
  instr_t* taken_short = INSTR_CREATE_label(dc);
  instr_t* fall_body = INSTR_CREATE_label(dc);
  instr_t* taken_body = INSTR_CREATE_label(dc);
  instr_t* fall_end = INSTR_CREATE_label(dc);
  instr_t* taken_end = INSTR_CREATE_label(dc);
  instr_t* context_begin[2] = {INSTR_CREATE_label(dc), INSTR_CREATE_label(dc)};
  instr_t* flags_saved[2] = {INSTR_CREATE_label(dc), INSTR_CREATE_label(dc)};
  instr_t* context_end[2] = {INSTR_CREATE_label(dc), INSTR_CREATE_label(dc)};
  instr_t* pre_begin = INSTR_CREATE_label(dc);
  instr_t* pre_flags = INSTR_CREATE_label(dc);
  instr_t* pre_end = INSTR_CREATE_label(dc);
  instr_t* starts[4] = {fall_short, taken_short, fall_body, taken_body};
  instr_t* ends[4] = {taken_short, fall_body, fall_end, taken_end};
  app_pc successors[4] = {fallthrough, target, fallthrough, target};

  instr_t* prefix = INSTR_CREATE_label(dc);
  instrlist_meta_preinsert(bb, app, prefix);
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
      dr_raw_tls_opnd(dc, branch_counter_raw_segment,
          branch_counter_raw_offset + BRANCH_RAW_ACTIVE * sizeof(reg_t)), OPND_CREATE_INT32(0)));
  /* Part of the inactive metadata publication: no scratch register needed. */
  instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)original,
      dr_raw_tls_opnd(dc, branch_counter_raw_segment,
          branch_counter_raw_offset + BRANCH_RAW_ORIGINAL * sizeof(reg_t)),
      bb, app, NULL, NULL);
  /* Direct label/address publication uses only immediate stores to owned raw
   * TLS: no guest scratch or flag is modified while bounds are incomplete.
   * The active marker remains zero until both scratch spills and every bound
   * are valid. The preparation phase is then recoverable before its first
   * register clobber; it never charges the still-unretired CBR.
   */
  for (int i = 0; i < 4; ++i) {
    branch_counter_store_label(dc, bb, app, starts[i], BRANCH_RAW_EDGE_START + i);
    if (i == 0)
      BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 11);
    branch_counter_store_label(dc, bb, app, ends[i], BRANCH_RAW_EDGE_END + i);
    instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)successors[i],
        dr_raw_tls_opnd(dc, branch_counter_raw_segment,
            branch_counter_raw_offset + (BRANCH_RAW_SUCCESSOR + i) * sizeof(reg_t)),
        bb, app, NULL, NULL);
  }
  for (int i = 0; i < 2; ++i) {
    branch_counter_store_label(dc, bb, app, context_begin[i], BRANCH_RAW_CONTEXT_BEGIN + i);
    branch_counter_store_label(dc, bb, app, flags_saved[i], BRANCH_RAW_FLAGS_SAVED + i);
    branch_counter_store_label(dc, bb, app, context_end[i], BRANCH_RAW_CONTEXT_END + i);
  }
  branch_counter_store_label(dc, bb, app, pre_begin, BRANCH_RAW_PRE_BEGIN);
  branch_counter_store_label(dc, bb, app, pre_flags, BRANCH_RAW_PRE_FLAGS);
  branch_counter_store_label(dc, bb, app, pre_end, BRANCH_RAW_PRE_END);
  dr_insert_write_raw_tls(dc, bb, app, branch_counter_raw_segment,
      branch_counter_raw_offset + BRANCH_RAW_XAX * sizeof(reg_t), DR_REG_XAX);
  dr_insert_write_raw_tls(dc, bb, app, branch_counter_raw_segment,
      branch_counter_raw_offset + BRANCH_RAW_XBX * sizeof(reg_t), DR_REG_XBX);
  instrlist_meta_preinsert(bb, app, pre_begin);
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
      dr_raw_tls_opnd(dc, branch_counter_raw_segment,
          branch_counter_raw_offset + BRANCH_RAW_ACTIVE * sizeof(reg_t)), OPND_CREATE_INT32(1)));
  BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 8);
  dr_save_arith_flags_to_xax(dc, bb, app);
  dr_insert_write_raw_tls(dc, bb, app, branch_counter_raw_segment,
      branch_counter_raw_offset + BRANCH_RAW_FLAGS * sizeof(reg_t), DR_REG_XAX);
  instrlist_meta_preinsert(bb, app, pre_flags);
  drmgr_insert_read_tls_field(dc, branch_counter_tls, bb, app, DR_REG_XAX);
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_ld(dc,
      opnd_create_reg(DR_REG_XBX),
      OPND_CREATE_MEMPTR(DR_REG_XAX, offsetof(branch_counter_state_t, edge_commits))));
  BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 9);
  instr_t* overflow = INSTR_CREATE_label(dc);
  instr_t* token_ready = INSTR_CREATE_label(dc);
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_cmp(dc,
      opnd_create_reg(DR_REG_XBX), OPND_CREATE_INT32(-1)));
  instrlist_meta_preinsert(bb, app,
      INSTR_CREATE_jcc(dc, OP_jz, opnd_create_instr(overflow)));
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_lea(dc,
      opnd_create_reg(DR_REG_XBX),
      opnd_create_base_disp(DR_REG_XBX, DR_REG_NULL, 0, 1, OPSZ_lea)));
  instrlist_meta_preinsert(bb, app,
      INSTR_CREATE_jmp(dc, opnd_create_instr(token_ready)));
  instrlist_meta_preinsert(bb, app, overflow);
  /* Refuse certainty without wrapping the stored count or token. */
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
      OPND_CREATE_MEM8(DR_REG_XAX, offsetof(branch_counter_state_t, invalid)),
      OPND_CREATE_INT8(1)));
  instrlist_meta_preinsert(bb, app, token_ready);
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
      OPND_CREATE_MEMPTR(DR_REG_XAX, offsetof(branch_counter_state_t, pending_token)),
      opnd_create_reg(DR_REG_XBX)));
  instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
      OPND_CREATE_MEM8(DR_REG_XAX, offsetof(branch_counter_state_t, pending_active)),
      OPND_CREATE_INT8(1)));
  BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 10);
  BRANCH_COUNTER_TEST_GATE(dc, bb, app, DR_REG_XBX, 1);
  dr_insert_read_raw_tls(dc, bb, app, branch_counter_raw_segment,
      branch_counter_raw_offset + BRANCH_RAW_FLAGS * sizeof(reg_t), DR_REG_XAX);
  dr_restore_arith_flags_from_xax(dc, bb, app);
  dr_insert_read_raw_tls(dc, bb, app, branch_counter_raw_segment,
      branch_counter_raw_offset + BRANCH_RAW_XBX * sizeof(reg_t), DR_REG_XBX);
  dr_insert_read_raw_tls(dc, bb, app, branch_counter_raw_segment,
      branch_counter_raw_offset + BRANCH_RAW_XAX * sizeof(reg_t), DR_REG_XAX);
  BRANCH_COUNTER_TEST_QUERY(dc, bb, app, -2);
  instrlist_meta_preinsert(bb, app, pre_end);
  for (instr_t* in = instr_get_next(prefix); in != app; in = instr_get_next(in)) {
    if (!instr_is_label(in))
      instr_set_translation(in, original);
  }
  BRANCH_COUNTER_TEST_PRE(dc, bb, app);

  instr_t* branch = instr_clone(dc, app);
  instr_set_meta(branch);
  instr_set_note(branch, NULL);
  instr_set_target(branch, opnd_create_instr(taken_short));
  instr_set_translation(branch, original);
  instrlist_meta_preinsert(bb, app, branch);
  instrlist_meta_preinsert(bb, app, fall_short);
  instr_t* to_fall = INSTR_CREATE_jmp(dc, opnd_create_instr(fall_body));
  instr_set_translation(to_fall, fallthrough);
  instrlist_meta_preinsert(bb, app, to_fall);
  instrlist_meta_preinsert(bb, app, taken_short);
  instr_t* to_taken = INSTR_CREATE_jmp(dc, opnd_create_instr(taken_body));
  instr_set_translation(to_taken, target);
  instrlist_meta_preinsert(bb, app, to_taken);

  for (int i = 0; i < 2; ++i) {
    instr_t* body = i == 0 ? fall_body : taken_body;
    instr_t* end = i == 0 ? fall_end : taken_end;
    app_pc successor = i == 0 ? fallthrough : target;
    instrlist_meta_preinsert(bb, app, body);
    BRANCH_COUNTER_TEST_QUERY(dc, bb, app, i + 2);
    BRANCH_COUNTER_TEST_POST(dc, bb, app, successor);
    /* Owned slots preserve every clobbered value, even if liveness says dead.
     * MOV, LAHF and SETO do not modify arithmetic flags. The context labels
     * distinguish partial flag packing from a complete stored representation.
     */
    const reg_id_t scratch[] = {DR_REG_XAX, DR_REG_XBX, DR_REG_XCX};
    for (int n = 0; n < 3; ++n) {
      dr_insert_write_raw_tls(dc, bb, app, branch_counter_raw_segment,
          branch_counter_raw_offset + n * sizeof(reg_t), scratch[n]);
      if (n == 0)
        BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 1);
    }
    instrlist_meta_preinsert(bb, app, context_begin[i]);
    BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 2);
    instr_t* save_before = instr_get_prev(app);
    dr_save_arith_flags_to_xax(dc, bb, app);
    BRANCH_COUNTER_TEST_PHASE(dc, bb, instr_get_next(instr_get_next(save_before)), 3);
    BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 4);
    dr_insert_write_raw_tls(dc, bb, app, branch_counter_raw_segment,
        branch_counter_raw_offset + BRANCH_RAW_FLAGS * sizeof(reg_t), DR_REG_XAX);
    instrlist_meta_preinsert(bb, app, flags_saved[i]);
    drmgr_insert_read_tls_field(dc, branch_counter_tls, bb, app, DR_REG_XBX);
    instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_ld(dc,
        opnd_create_reg(DR_REG_XCX), OPND_CREATE_MEMPTR(DR_REG_XBX,
            offsetof(branch_counter_state_t, pending_token))));
    instrlist_meta_preinsert(bb, app, INSTR_CREATE_lea(dc,
        opnd_create_reg(DR_REG_XAX), opnd_create_base_disp(
            DR_REG_XCX, DR_REG_NULL, 0, -1, OPSZ_lea)));
    BRANCH_COUNTER_TEST_GATE(dc, bb, app, DR_REG_XCX, 2);
    BRANCH_COUNTER_TEST_CAS(dc, bb, app, false);
    instr_t* commit = INSTR_CREATE_cmpxchg_8(dc,
        OPND_CREATE_MEMPTR(DR_REG_XBX, offsetof(branch_counter_state_t, edge_commits)),
        opnd_create_reg(DR_REG_XCX));
    instr_set_prefix_flag(commit, PREFIX_LOCK);
    instrlist_meta_preinsert(bb, app, commit);
    BRANCH_COUNTER_TEST_CAS(dc, bb, app, true);
    instr_t* committed = INSTR_CREATE_label(dc);
    instrlist_meta_preinsert(bb, app,
        INSTR_CREATE_jcc(dc, OP_jz, opnd_create_instr(committed)));
    BRANCH_COUNTER_TEST_CAS_MISS(dc, bb, app, DR_REG_XBX);
    instrlist_meta_preinsert(bb, app, INSTR_CREATE_cmp(dc,
        opnd_create_reg(DR_REG_XAX), opnd_create_reg(DR_REG_XCX)));
    instrlist_meta_preinsert(bb, app,
        INSTR_CREATE_jcc(dc, OP_jnb, opnd_create_instr(committed)));
    instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
        OPND_CREATE_MEM8(DR_REG_XBX, offsetof(branch_counter_state_t, invalid)),
        OPND_CREATE_INT8(1)));
    instrlist_meta_preinsert(bb, app, committed);
    dr_insert_read_raw_tls(dc, bb, app, branch_counter_raw_segment,
        branch_counter_raw_offset + BRANCH_RAW_FLAGS * sizeof(reg_t), DR_REG_XAX);
    instr_t* restore_before = instr_get_prev(app);
    dr_restore_arith_flags_from_xax(dc, bb, app);
    BRANCH_COUNTER_TEST_PHASE(dc, bb,
        instr_get_next(instr_get_next(restore_before)), 5);
    BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 6);
    for (int n = 2; n >= 0; --n)
      dr_insert_read_raw_tls(dc, bb, app, branch_counter_raw_segment,
          branch_counter_raw_offset + n * sizeof(reg_t), scratch[n]);
    instrlist_meta_preinsert(bb, app, context_end[i]);
    BRANCH_COUNTER_TEST_PHASE(dc, bb, app, 7);
    instrlist_meta_preinsert(bb, app, INSTR_CREATE_mov_st(dc,
        dr_raw_tls_opnd(dc, branch_counter_raw_segment,
            branch_counter_raw_offset + BRANCH_RAW_ACTIVE * sizeof(reg_t)),
        OPND_CREATE_INT32(0)));
    /* Every real post-edge instruction names the actual application successor.
     * NULL translations could yield PC-only restoration, which is insufficient
     * for mandatory asynchronous delivery (retained r2 control failure).
     */
    for (instr_t* in = instr_get_next(body); in != app; in = instr_get_next(in)) {
      if (!instr_is_label(in))
        instr_set_translation(in, successor);
    }
    instrlist_meta_preinsert(bb, app, end);
    instr_t* exit = INSTR_CREATE_jmp(dc, opnd_create_pc(successor));
    instr_set_translation(exit, successor);
    instrlist_preinsert(bb, app, exit);
  }
  instrlist_remove(bb, app);
  instr_destroy(dc, app);
}

/* Return the effective value at a real emitted cache cut without publishing
 * a commit. Callers must not substitute an application PC for raw_pc. */
static bool branch_counter_effective(const branch_counter_state_t* state,
    app_pc raw_pc, uint64_t* count) {
  if (state == NULL || state->invalid ||
      atomic_load_explicit(&branch_counter_unsupported, memory_order_relaxed))
    return false;
  uint64_t value = atomic_load_explicit(&state->edge_commits, memory_order_relaxed);
  if (state->raw_slots[BRANCH_RAW_ACTIVE] != 0) {
    if (raw_pc == NULL)
      return false;
    int phase = branch_counter_edge_phase(state, raw_pc);
    if (phase == -1)
      return false;
    if (phase >= 0 && value < state->pending_token)
      value = state->pending_token;
  }
  *count = value;
  return true;
}

/* DR holds the stopped target's lifetime across this read-only callback.
 * Never derive its raw TLS from the executing observer thread's segment base. */
static void branch_counter_invalidate(void* dc, app_pc source_pc, app_pc target_pc) {
  branch_counter_state_t* state = branch_counter_state(dc);
  if (state == NULL)
    return;
  BRANCH_COUNTER_TEST_INVALIDATE(dc, state, source_pc, target_pc, false);
  state->raw_slots[BRANCH_RAW_ACTIVE] = 0;
  state->pending_active = false;
  BRANCH_COUNTER_TEST_INVALIDATE(dc, state, source_pc, target_pc, true);
}

static void branch_counter_transfer(void* dc, const dr_kernel_xfer_info_t* info) {
  if (info->type == DR_XFER_SIGNAL_DELIVERY) {
    branch_counter_state_t* state = branch_counter_state(dc);
    if (state != NULL)
      state->raw_slots[BRANCH_RAW_ACTIVE] = 0;
  }
}

static dr_emit_flags_t branch_counter_mark(void* dc, void* tag,
    instrlist_t* bb, instr_t* instruction, bool for_trace, bool translating,
    void* user_data) {
  instr_t* original = drmgr_orig_app_instr_for_fetch(dc);
  if (original == NULL || !instr_is_cbr(original) ||
      branch_counter_owned_stub(instr_get_app_pc(original)))
    return DR_EMIT_DEFAULT;
  if (original != instruction || !instr_is_app(instruction) ||
      !opnd_is_pc(instr_get_target(original)) ||
      instr_get_app_pc(original) == NULL || instr_get_note(original) != NULL) {
    atomic_store_explicit(&branch_counter_unsupported, true, memory_order_relaxed);
    return DR_EMIT_DEFAULT;
  }
  instr_set_note(instruction, (void*)branch_counter_original_note);
  return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t branch_counter_expand(void* dc, void* tag,
    instrlist_t* bb, bool for_trace, bool translating) {
  instr_t* original = NULL;
  for (instr_t* in = instrlist_first(bb); in != NULL; in = instr_get_next(in)) {
    if (instr_get_note(in) == (void*)branch_counter_original_note) {
      if (original != NULL || !instr_is_app(in) || !instr_is_cbr(in) ||
          branch_counter_owned_stub(instr_get_app_pc(in))) {
        atomic_store_explicit(&branch_counter_unsupported, true, memory_order_relaxed);
        return DR_EMIT_DEFAULT;
      }
      original = in;
    }
  }
  if (original != NULL)
    branch_counter_expand_cbr(dc, bb, original);
  return DR_EMIT_DEFAULT;
}

/* Register before the native thread-start callback, so binding can retain all
 * loader work from the first application instruction, even before Tool start.
 * No callback or allocation is added when this launch did not opt in. */
static void branch_counter_register(void) {
  if (!branch_counter_enabled)
    return;
  atomic_init(&branch_counter_unsupported, false);
  branch_counter_original_note = drmgr_reserve_note_range(1);
  DR_ASSERT(branch_counter_original_note != DRMGR_NOTE_NONE);
  DR_ASSERT(dr_raw_tls_calloc(&branch_counter_raw_segment,
      &branch_counter_raw_offset, BRANCH_RAW_SLOTS, 0));
  branch_counter_tls = drmgr_register_tls_field();
  DR_ASSERT(branch_counter_tls >= 0);
  DR_ASSERT(drmgr_register_thread_init_event(branch_counter_thread_init));
  DR_ASSERT(drmgr_register_thread_exit_event(branch_counter_thread_exit));
  dr_register_fork_init_event(branch_counter_fork_init);
  DR_ASSERT(drmgr_register_bb_instrumentation_event(NULL, branch_counter_mark, NULL));
  DR_ASSERT(drmgr_register_bb_meta_instru_event(branch_counter_expand, NULL));
  DR_ASSERT(drmgr_register_restore_state_ex_event(branch_counter_restore_body));
  DR_ASSERT(drmgr_register_kernel_xfer_event(branch_counter_transfer));
  dr_register_cache_context_invalidation_event(branch_counter_invalidate);
}
#endif
