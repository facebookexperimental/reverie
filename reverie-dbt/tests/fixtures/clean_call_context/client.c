#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

static int fixture_index;
static reg_id_t tool_tls_register;
static uint tool_tls_offset;
static app_pc prepare_pc, finish_pc, check_pc[4];
static unsigned completed;
typedef struct {
  bool updated;
  unsigned calls, mode, variant;
  bool prepared;
} fixture_t;

static void require(bool condition, const char* message) {
  if (!condition) {
    dr_fprintf(STDERR, "execution control failure: %s\n", message);
    dr_exit_process(41);
  }
}

/* The application independently checks every register and flag after this
 * real clean call, including application updates while drreg owns registers. */
static void update_context(void) {
  void* dc = dr_get_current_drcontext();
  fixture_t* fixture = drmgr_get_tls_field(dc, fixture_index);
  require(fixture != NULL && fixture->prepared, "prepared callback state");
  ++fixture->calls;
  if (fixture->mode != 2)
    return;
  dr_mcontext_t context = {sizeof(context), DR_MC_ALL};
  require(dr_get_mcontext(dc, &context), "read actual application context");
  context.xcx ^= (reg_t)UINT64_C(0xdeadbeef13579bdf);
  context.xflags ^= 1;
  if (fixture->variant == 3)
    context.xdx ^= (reg_t)UINT64_C(0x123456789abcdef0);
  require(dr_set_mcontext(dc, &context), "write actual application context");
  fixture->updated = true;
}

static void prepare(unsigned mode, unsigned variant) {
  void* dc = dr_get_current_drcontext();
  fixture_t* fixture = drmgr_get_tls_field(dc, fixture_index);
  require(fixture != NULL && mode < 3 && variant < 4, "prepare arguments");
  require(!fixture->prepared, "previous case finished");
  fixture->calls = 0;
  fixture->mode = mode;
  fixture->variant = variant;
  fixture->prepared = true;
  fixture->updated = false;
}

static void finish(void) {
  void* dc = dr_get_current_drcontext();
  fixture_t* fixture = drmgr_get_tls_field(dc, fixture_index);
  require(fixture != NULL && fixture->prepared, "finish prepared case");
  unsigned expected = 1;
  require(fixture->calls == expected, "actual clean-call count");
  require(
      fixture->updated == (fixture->mode == 2), "application update occurred");
  reg_t* tools = (reg_t*)((byte*)dr_get_dr_segment_base(tool_tls_register) +
                          tool_tls_offset);
  if (fixture->variant == 1 || fixture->variant == 3) {
    if (tools[0] != 17)
      dr_fprintf(
          STDERR,
          "tool RCX mismatch variant=%u mode=%u actual=" PFX " expected=17\n",
          fixture->variant,
          fixture->mode,
          tools[0]);
    require(tools[0] == 17, "reserved tool RCX survives the clean call");
  }
  if (fixture->variant == 3) {
    if (tools[1] != 19)
      dr_fprintf(
          STDERR,
          "tool RDX mismatch variant=%u mode=%u actual=" PFX " expected=19\n",
          fixture->variant,
          fixture->mode,
          tools[1]);
    require(tools[1] == 19, "reserved tool RDX survives the clean call");
  }
  fixture->prepared = false;
  dr_atomic_add32_return_sum((volatile int*)&completed, 1);
}

static void thread_init(void* dc) {
  fixture_t* fixture = dr_thread_alloc(dc, sizeof(*fixture));
  require(fixture != NULL, "fixture allocation");
  memset(fixture, 0, sizeof(*fixture));
  require(drmgr_set_tls_field(dc, fixture_index, fixture), "fixture TLS");
}

static void thread_exit(void* dc) {
  fixture_t* fixture = drmgr_get_tls_field(dc, fixture_index);
  require(fixture != NULL && !fixture->prepared, "thread completed its cases");
  dr_thread_free(dc, fixture, sizeof(*fixture));
}

static void module_load(void* dc, const module_data_t* module, bool loaded) {
  app_pc p = (app_pc)dr_get_proc_address(module->handle, "clean_call_prepare");
  if (p == NULL)
    return;
  require(prepare_pc == NULL, "unique application module");
  prepare_pc = p;
  finish_pc = (app_pc)dr_get_proc_address(module->handle, "clean_call_finish");
  const char* names[] = {
      "clean_call_check_inline",
      "clean_call_check_rcx",
      "clean_call_check_flags",
      "clean_call_check_combined"};
  for (unsigned i = 0; i < 4; ++i) {
    check_pc[i] = (app_pc)dr_get_proc_address(module->handle, names[i]);
    require(check_pc[i] != NULL, "exported probe boundary");
  }
  require(finish_pc != NULL, "exported finish boundary");
}

static dr_emit_flags_t instrument(
    void* dc,
    void* tag,
    instrlist_t* bb,
    instr_t* instruction,
    bool for_trace,
    bool translating,
    void* data) {
  if (!instr_is_app(instruction))
    return DR_EMIT_DEFAULT;
  app_pc pc = instr_get_app_pc(instruction);
  if (pc == prepare_pc)
    dr_insert_clean_call(
        dc,
        bb,
        instruction,
        (void*)prepare,
        false,
        2,
        opnd_create_reg(DR_REG_XDI),
        opnd_create_reg(DR_REG_XSI));
  if (pc == finish_pc)
    dr_insert_clean_call(dc, bb, instruction, (void*)finish, false, 0);
  for (unsigned variant = 0; variant < 4; ++variant) {
    if (pc != check_pc[variant])
      continue;
    require(instruction == instrlist_first_app(bb), "real basic-block entry");
    reg_id_t reserved = DR_REG_NULL, reserved_rdx = DR_REG_NULL;
    if ((variant == 1 || variant == 3)) {
      drvector_t allowed;
      require(
          drreg_init_and_fill_vector(&allowed, false) == DRREG_SUCCESS,
          "allowed register set");
      require(
          drreg_set_vector_entry(&allowed, DR_REG_XCX, true) == DRREG_SUCCESS,
          "reserve RCX only");
      require(
          drreg_reserve_register(dc, bb, instruction, &allowed, &reserved) ==
                  DRREG_SUCCESS &&
              reserved == DR_REG_XCX,
          "actual RCX reservation");
      drvector_delete(&allowed);
      instrlist_meta_preinsert(
          bb,
          instruction,
          INSTR_CREATE_mov_imm(
              dc, opnd_create_reg(reserved), OPND_CREATE_INTPTR(17)));
    }
    if (variant == 3) {
      drvector_t allowed;
      require(
          drreg_init_and_fill_vector(&allowed, false) == DRREG_SUCCESS,
          "RDX set");
      require(
          drreg_set_vector_entry(&allowed, DR_REG_XDX, true) == DRREG_SUCCESS,
          "RDX only");
      require(
          drreg_reserve_register(
              dc, bb, instruction, &allowed, &reserved_rdx) == DRREG_SUCCESS &&
              reserved_rdx == DR_REG_XDX,
          "actual RDX reservation");
      drvector_delete(&allowed);
      instrlist_meta_preinsert(
          bb,
          instruction,
          INSTR_CREATE_mov_imm(
              dc, opnd_create_reg(reserved_rdx), OPND_CREATE_INTPTR(19)));
    }
    if ((variant == 2 || variant == 3)) {
      require(
          drreg_reserve_aflags(dc, bb, instruction) == DRREG_SUCCESS,
          "actual flags reservation");
      instrlist_meta_preinsert(
          bb,
          instruction,
          INSTR_CREATE_cmp(
              dc, opnd_create_reg(DR_REG_XCX), OPND_CREATE_INT8(0)));
    }
    dr_insert_clean_call_ex(
        dc,
        bb,
        instruction,
        (void*)update_context,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT,
        0);
    if (variant == 1 || variant == 3)
      dr_insert_write_raw_tls(
          dc, bb, instruction, tool_tls_register, tool_tls_offset, DR_REG_XCX);
    if (variant == 3) {
      dr_insert_write_raw_tls(
          dc,
          bb,
          instruction,
          tool_tls_register,
          tool_tls_offset + sizeof(reg_t),
          DR_REG_XDX);
      require(
          drreg_unreserve_register(dc, bb, instruction, reserved_rdx) ==
              DRREG_SUCCESS,
          "RDX reservation release");
    }
    if ((variant == 1 || variant == 3))
      require(
          drreg_unreserve_register(dc, bb, instruction, reserved) ==
              DRREG_SUCCESS,
          "RCX reservation release");
    if ((variant == 2 || variant == 3))
      require(
          drreg_unreserve_aflags(dc, bb, instruction) == DRREG_SUCCESS,
          "flags reservation release");
  }
  return DR_EMIT_DEFAULT;
}

static void exit_event(void) {
  require(completed == 9612, "all independently checked cases completed");
  dr_fprintf(
      STDOUT, "client completed cases=%u actual_clean_call=1\n", completed);
  drmgr_unregister_bb_insertion_event(instrument);
  drmgr_unregister_module_load_event(module_load);
  drmgr_unregister_thread_init_event(thread_init);
  drmgr_unregister_thread_exit_event(thread_exit);
  drmgr_unregister_tls_field(fixture_index);
  require(dr_raw_tls_cfree(tool_tls_offset, 2), "tool TLS release");
  require(drreg_exit() == DRREG_SUCCESS, "drreg exit");
  drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  drreg_options_t options = {sizeof(options), 8, false};
  require(
      drmgr_init() && drreg_init(&options) == DRREG_SUCCESS,
      "SDK initialization");
  fixture_index = drmgr_register_tls_field();
  require(fixture_index >= 0, "TLS allocation");
  require(
      dr_raw_tls_calloc(&tool_tls_register, &tool_tls_offset, 2, 0),
      "tool TLS allocation");
  require(
      drmgr_register_thread_init_event(thread_init),
      "thread init registration");
  require(
      drmgr_register_thread_exit_event(thread_exit),
      "thread exit registration");
  require(drmgr_register_module_load_event(module_load), "module registration");
  require(
      drmgr_register_bb_instrumentation_event(NULL, instrument, NULL),
      "instrumentation registration");
  require(drmgr_register_exit_event(exit_event), "exit registration");
}
