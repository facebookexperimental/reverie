/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 *
 * A selected-LOOP component test of the production counter implementation.
 * This client is neither the DBT Rust runtime nor the full Detcore Tool.
 */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

static app_pc selected_pc, helper_pc;
static int gate_mode;
static bool omit_notification;
static void insert_gate(void*, instrlist_t*, instr_t*, reg_id_t, int);
static void record_restore(void*, bool, dr_restore_state_info_t*, int);
static void record_invalidation(void*, void*, app_pc, app_pc, bool);

#define REVERIE_DBT_BRANCH_COUNTER_TEST 1
#define BRANCH_COUNTER_TEST_FIELDS
#define BRANCH_COUNTER_TEST_PHASE(...) ((void)0)
#define BRANCH_COUNTER_TEST_GATE(...) insert_gate(__VA_ARGS__)
#define BRANCH_COUNTER_TEST_QUERY(...) ((void)0)
#define BRANCH_COUNTER_TEST_PRE(...) ((void)0)
#define BRANCH_COUNTER_TEST_POST(...) ((void)0)
#define BRANCH_COUNTER_TEST_CAS(...) ((void)0)
#define BRANCH_COUNTER_TEST_CAS_MISS(...) ((void)0)
#define BRANCH_COUNTER_TEST_RESTORE(...) record_restore(__VA_ARGS__)
#define BRANCH_COUNTER_TEST_INVALIDATE(...) record_invalidation(__VA_ARGS__)
#include "branch_counter.h"

/* Explicit test selection, outside the production all-original-app selector. */
static bool branch_counter_owned_stub(app_pc pc) {
  return pc != selected_pc;
}

enum { TEST_READY, TEST_RELEASE, TEST_BEGIN, TEST_END, TEST_RSP, TEST_SLOTS };
static reg_id_t test_segment;
static uint test_offset;
static void* target_dc;
static reg_t* target_slots;
static branch_counter_state_t* target_state;
static _Atomic unsigned restore_used;
static unsigned invalidations, completions, failures;
static bool flush_result, helper_called, final_seen;
static thread_id_t helper_tid;
static process_id_t helper_pid;
static app_pc helper_observed_pc;
static reg_t clone_flags, parent_tid_pointer, child_tid_pointer;
static reg_t clone_result, helper_getpid_result, helper_exit_status;
static unsigned helper_exits;
static reg_t completion_active;
static bool completion_pending;
static uint64_t completion_count;
static uint64_t final_count;
static branch_counter_state_t before_invalidation;
static reg_t before_raw[BRANCH_RAW_SLOTS];
static app_pc invalidated_source, invalidated_target;
typedef struct {
  bool memory, valid, exact_context, in_gate, effective_valid, effective_unchanged;
  int phase;
  app_pc raw, app, cache_start;
  uint64_t count, effective_count;
} restore_record_t;
static restore_record_t restores[16];

static bool exact_context(const dr_mcontext_t* mc) {
  const reg_t values[] = {mc->xax,mc->xbx,mc->xdx,mc->xsi,mc->xdi,mc->xbp,
    mc->r8,mc->r9,mc->r10,mc->r11,mc->r12,mc->r13,mc->r14,mc->r15};
  for (unsigned i=0;i<14;i++)
    if (values[i] != UINT64_C(0x1122334455667700)+i) return false;
  return mc->xcx == (reg_t)(gate_mode == 1 ? 2 : 1) &&
      mc->xflags == 0xad7 && mc->xsp == target_slots[TEST_RSP] &&
      mc->pc == selected_pc;
}

static void record_restore(void* dc, bool memory,
    dr_restore_state_info_t* info, int phase) {
  if (dc != target_dc || phase == -1) return;
  unsigned i=atomic_fetch_add_explicit(&restore_used,1,memory_order_relaxed);
  if(i>=16) { ++failures; return; }
  restore_record_t* r=&restores[i];
  r->memory=memory;r->valid=info->raw_mcontext_valid;r->phase=phase;
  r->raw=info->raw_mcontext_valid ? info->raw_mcontext->pc : NULL;
  r->app=info->mcontext->pc;r->cache_start=info->fragment_info.cache_start_pc;
  r->in_gate=r->raw >= (app_pc)target_slots[TEST_BEGIN] &&
      r->raw < (app_pc)target_slots[TEST_END];
  r->exact_context=exact_context(info->mcontext);
  r->count=atomic_load_explicit(&target_state->edge_commits,memory_order_relaxed);
  branch_counter_state_t saved_state;
  reg_t saved_raw[BRANCH_RAW_SLOTS];
  memcpy(&saved_state,target_state,sizeof(saved_state));
  memcpy(saved_raw,target_state->raw_slots,sizeof(saved_raw));
  r->effective_valid=branch_counter_effective(target_state,r->raw,&r->effective_count);
  r->effective_unchanged=memcmp(&saved_state,target_state,sizeof(saved_state))==0 &&
      memcmp(saved_raw,target_state->raw_slots,sizeof(saved_raw))==0;
}

static void record_invalidation(void* dc, void* opaque, app_pc source,
    app_pc target, bool after) {
  branch_counter_state_t* state=opaque;
  if (dc != target_dc) return;
  if (!after) {
    memcpy(&before_invalidation,state,sizeof(*state));
    memcpy(before_raw,state->raw_slots,sizeof(before_raw));
    invalidated_source=source;invalidated_target=target;
    return;
  }
  ++invalidations;
  branch_counter_state_t expected;
  memcpy(&expected,&before_invalidation,sizeof(expected));
  expected.pending_active=false;
  reg_t expected_raw[BRANCH_RAW_SLOTS];
  memcpy(expected_raw,before_raw,sizeof(expected_raw));
  expected_raw[BRANCH_RAW_ACTIVE]=0;
  if (memcmp(&expected,state,sizeof(expected)) ||
      memcmp(expected_raw,state->raw_slots,sizeof(expected_raw)) ||
      before_raw[BRANCH_RAW_ACTIVE]!=1 ||
      source < (app_pc)target_slots[TEST_BEGIN] ||
      source >= (app_pc)target_slots[TEST_END] || target!=selected_pc ||
      atomic_load_explicit(&state->edge_commits,memory_order_relaxed) !=
          (uint64_t)(gate_mode == 1 ? 0 : 1))
    ++failures;
}

static void test_thread_init(void* dc) {
  reg_t* slots=(reg_t*)((byte*)dr_get_dr_segment_base(test_segment)+test_offset);
  memset(slots,0,TEST_SLOTS*sizeof(reg_t));
  if (dr_get_thread_id(dc)==dr_get_process_id()) {
    target_dc=dc;target_slots=slots;target_state=branch_counter_state(dc);
  }
}

static void test_label(void* dc, instrlist_t* bb, instr_t* before,
    instr_t* label, int slot) {
  instrlist_insert_mov_instr_addr(dc,label,NULL,
      dr_raw_tls_opnd(dc,test_segment,test_offset+slot*sizeof(reg_t)),
      bb,before,NULL,NULL);
}

static void insert_gate(void* dc, instrlist_t* bb, instr_t* before,
    reg_id_t token_reg, int mode) {
  if (gate_mode!=mode) return;
  instr_t* skip=INSTR_CREATE_label(dc);
  instr_t* begin=INSTR_CREATE_label(dc);
  instr_t* spin=INSTR_CREATE_label(dc);
  instr_t* end=INSTR_CREATE_label(dc);
  /* Both phases stop on the first original conditional only. The saved flags
   * and GPRs already make this complete gate region recoverable. */
  instrlist_meta_preinsert(bb,before,INSTR_CREATE_cmp(dc,
      opnd_create_reg(token_reg),OPND_CREATE_INT32(1)));
  instrlist_meta_preinsert(bb,before,
      INSTR_CREATE_jcc(dc,OP_jnz,opnd_create_instr(skip)));
  instrlist_meta_preinsert(bb,before,INSTR_CREATE_cmp(dc,
      dr_raw_tls_opnd(dc,test_segment,test_offset+TEST_RELEASE*sizeof(reg_t)),
      OPND_CREATE_INT32(0)));
  instrlist_meta_preinsert(bb,before,
      INSTR_CREATE_jcc(dc,OP_jnz,opnd_create_instr(skip)));
  test_label(dc,bb,before,begin,TEST_BEGIN);
  test_label(dc,bb,before,end,TEST_END);
  dr_insert_write_raw_tls(dc,bb,before,test_segment,
      test_offset+TEST_RSP*sizeof(reg_t),DR_REG_XSP);
  instrlist_meta_preinsert(bb,before,begin);
  instrlist_meta_preinsert(bb,before,INSTR_CREATE_mov_st(dc,
      dr_raw_tls_opnd(dc,test_segment,test_offset+TEST_READY*sizeof(reg_t)),
      OPND_CREATE_INT32(1)));
  instrlist_meta_preinsert(bb,before,spin);
  instrlist_meta_preinsert(bb,before,INSTR_CREATE_cmp(dc,
      dr_raw_tls_opnd(dc,test_segment,test_offset+TEST_RELEASE*sizeof(reg_t)),
      OPND_CREATE_INT32(0)));
  instrlist_meta_preinsert(bb,before,
      INSTR_CREATE_jcc(dc,OP_jz,opnd_create_instr(spin)));
  instrlist_meta_preinsert(bb,before,end);
  instrlist_meta_preinsert(bb,before,skip);
}

static void flush_complete(void* unused) {
  (void)unused;
  ++completions;
  completion_active=target_state->raw_slots[BRANCH_RAW_ACTIVE];
  completion_pending=target_state->pending_active;
  completion_count=atomic_load_explicit(&target_state->edge_commits,memory_order_relaxed);
  if (invalidations!=1 || target_state->raw_slots[BRANCH_RAW_ACTIVE]!=0 ||
      target_state->pending_active ||
      atomic_load_explicit(&target_state->edge_commits,memory_order_relaxed) !=
          (uint64_t)(gate_mode==1 ? 0 : 1))
    ++failures;
  /* Completion runs after reclamation and before target resume. Do not query
   * the old, now invalid cache label or claim its address was actually reused. */
  __atomic_store_n(&target_slots[TEST_RELEASE],1,__ATOMIC_RELEASE);
}

static bool filter_syscall(void* dc, int number) {
  (void)dc;(void)number;return true;
}
static void test_thread_exit(void* dc) {
  if (dr_get_thread_id(dc)==helper_tid) ++helper_exits;
}
static void post_syscall(void* dc, int number) {
  if (number==SYS_clone && dc==target_dc)
    clone_result=dr_syscall_get_result(dc);
  if (number==SYS_getpid && dr_get_thread_id(dc)==helper_tid)
    helper_getpid_result=dr_syscall_get_result(dc);
}
static bool pre_syscall(void* dc, int number) {
  if(number==SYS_clone && dc==target_dc) {
    clone_flags=dr_syscall_get_param(dc,0);
    parent_tid_pointer=dr_syscall_get_param(dc,2);
    child_tid_pointer=dr_syscall_get_param(dc,3);
  }
  if(number==SYS_exit && dr_get_thread_id(dc)==helper_tid)
    helper_exit_status=dr_syscall_get_param(dc,0);
  if (number==SYS_getpid && dr_get_thread_id(dc)!=dr_get_process_id()) {
    if (helper_called) { ++failures; return true; }
    helper_called=true;
    helper_tid=dr_get_thread_id(dc);helper_pid=dr_get_process_id();
    dr_mcontext_t mc={sizeof(mc),DR_MC_CONTROL};
    if(!dr_get_mcontext(dc,&mc)) ++failures;
    helper_observed_pc=mc.pc;
    /* The documented syscall mcontext PC names the post-syscall address. */
    if(mc.pc!=helper_pc+2 || helper_tid==helper_pid) ++failures;
    uint64_t deadline=dr_get_milliseconds()+5000;
    while (dr_get_milliseconds()<deadline &&
        (target_slots==NULL ||
         __atomic_load_n(&target_slots[TEST_READY],__ATOMIC_ACQUIRE)==0))
      dr_sleep(1);
    if (target_slots==NULL ||
        __atomic_load_n(&target_slots[TEST_READY],__ATOMIC_ACQUIRE)==0) {
      ++failures;dr_fprintf(STDERR,"CACHE_CONTROL ready-timeout\n");
      dr_exit_process(102);
    }
    /* This is an allowed pre-syscall call, with no client locks held. The
     * original getpid executes after the flush: no return-value substitution. */
    flush_result=dr_flush_region_ex(selected_pc,1,flush_complete,NULL);
    if (!flush_result) ++failures;
  }
  if ((number==SYS_exit || number==SYS_exit_group) &&
      dr_get_thread_id(dc)==dr_get_process_id()) {
    final_seen=true;
    final_count=atomic_load_explicit(&target_state->edge_commits,memory_order_relaxed);
    if (final_count!=2 || target_state->invalid ||
        target_state->raw_slots[BRANCH_RAW_ACTIVE]!=0)
      ++failures;
  }
  return true;
}

static void finished(void) {
  unsigned n=atomic_load_explicit(&restore_used,memory_order_relaxed);
  unsigned actual=0,query=0;
  for(unsigned i=0;i<n && i<16;i++) {
    const restore_record_t* r=&restores[i];
    dr_fprintf(STDERR,"CACHE_RESTORE memory=%d raw_valid=%d phase=%d in_gate=%d "
        "exact_context=%d raw=%p app=%p cache_start=%p count=%llu "
        "effective_valid=%d effective=%llu effective_unchanged=%d\n",
        r->memory,r->valid,r->phase,r->in_gate,r->exact_context,r->raw,r->app,
        r->cache_start,(unsigned long long)r->count,r->effective_valid,
        (unsigned long long)r->effective_count,r->effective_unchanged);
    if (!r->valid || !r->in_gate || !r->exact_context ||
        !r->effective_valid || !r->effective_unchanged ||
        r->effective_count!=(uint64_t)(gate_mode==1 ? 0 : 1) ||
        r->count!=(uint64_t)(gate_mode==2 && r->memory ? 1 : 0) ||
        (gate_mode==1 ? r->phase!=-2 : r->phase<0))
      ++failures;
    if(r->memory) ++actual; else ++query;
  }
  if (!helper_called || !flush_result || completions!=1 ||
      invalidations!=1 || actual==0 || !final_seen || final_count!=2 ||
      clone_flags!=0x350f00 || parent_tid_pointer==0 ||
      parent_tid_pointer!=child_tid_pointer || clone_result!=helper_tid ||
      helper_getpid_result!=helper_pid || helper_exit_status!=0 || helper_exits!=1)
    ++failures;
  dr_fprintf(STDERR,"CACHE_HELPER tid=%u tgid=%u clone=%llu flags=%llu "
      "parent_tid_ptr=%p child_tid_ptr=%p syscall_pc=%p result=%llu "
      "exit_status=%llu thread_exits=%u\n",helper_tid,helper_pid,
      (unsigned long long)clone_result,(unsigned long long)clone_flags,
      (void*)parent_tid_pointer,(void*)child_tid_pointer,helper_observed_pc,
      (unsigned long long)helper_getpid_result,
      (unsigned long long)helper_exit_status,helper_exits);
  dr_fprintf(STDERR,"CACHE_CONTROL mode=%d omitted=%d invalidations=%u "
      "completions=%u actual=%u query=%u final_seen=%d final=%llu failures=%u "
      "completion_active=%llu completion_pending=%d completion_count=%llu "
      "source=%p target=%p\n",gate_mode,omit_notification,invalidations,
      completions,actual,query,final_seen,(unsigned long long)final_count,
      failures,(unsigned long long)completion_active,completion_pending,
      (unsigned long long)completion_count,invalidated_source,invalidated_target);
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  (void)id;
  DR_ASSERT(argc==5);
  gate_mode=strcmp(argv[1],"pre")==0 ? 1 : 2;
  DR_ASSERT(strcmp(argv[1],"pre")==0 || strcmp(argv[1],"post")==0);
  DR_ASSERT(dr_sscanf(argv[2],"%p",&selected_pc)==1 && selected_pc!=NULL);
  DR_ASSERT(dr_sscanf(argv[3],"%p",&helper_pc)==1 && helper_pc!=NULL);
  omit_notification=strcmp(argv[4],"omit")==0;
  DR_ASSERT(omit_notification || strcmp(argv[4],"normal")==0);
  DR_ASSERT(drmgr_init());
  drreg_options_t options={sizeof(options),1,false};
  DR_ASSERT(drreg_init(&options)==DRREG_SUCCESS);
  DR_ASSERT(dr_raw_tls_calloc(&test_segment,&test_offset,TEST_SLOTS,0));
  branch_counter_enabled=true;
  branch_counter_register();
  if(omit_notification)
    DR_ASSERT(dr_unregister_cache_context_invalidation_event(branch_counter_invalidate));
  DR_ASSERT(drmgr_register_thread_init_event(test_thread_init));
  DR_ASSERT(drmgr_register_thread_exit_event(test_thread_exit));
  DR_ASSERT(drmgr_register_filter_syscall_event(filter_syscall));
  DR_ASSERT(drmgr_register_pre_syscall_event(pre_syscall));
  DR_ASSERT(drmgr_register_post_syscall_event(post_syscall));
  DR_ASSERT(drmgr_register_exit_event(finished));
}
