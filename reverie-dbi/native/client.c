/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/user.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drx.h"

#ifndef X86_64
#error "The Reverie DynamoRIO prototype currently requires x86-64"
#endif

typedef int64_t (*syscall_invoker_t)(uintptr_t, int64_t, const uint64_t *);
typedef int32_t (*register_reader_t)(uintptr_t, struct user_regs_struct *);

typedef struct {
  uint64_t branches;
  uint64_t observed_syscalls;
  uint64_t rewritten_syscalls;
} prototype_counters_t;

typedef struct {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} cpuid_result_t;

#define CPUID_RESULT(a, b, c, d) {(a), (b), (c), (d)}
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define BIT32(bit) (UINT32_C(1) << (bit))

/* Keep this synthetic CPU identity aligned with Hermit's ptrace backend. */
static const cpuid_result_t basic_cpuid[] = {
    CPUID_RESULT(0x0000000D, 0x756E6547, 0x6C65746E, 0x49656E69),
    CPUID_RESULT(0x00000663, 0x00000800, 0x90B82201, 0x078BFBFD),
    CPUID_RESULT(0x00000001, 0x00000000, 0x0000004D, 0x002C307D),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000120, 0x01C0003F, 0x0000003F, 0x00000001),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000003, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00180FB9, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000001, 0x00000100, 0x00000001),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
};

static const cpuid_result_t extended_cpuid[] = {
    CPUID_RESULT(0x8000000A, 0x756E6547, 0x6C65746E, 0x49656E69),
    CPUID_RESULT(0x00000663, 0x00000000, 0x00000001, 0x20100800),
    CPUID_RESULT(0x554D4551, 0x72695620, 0x6C617574, 0x55504320),
    CPUID_RESULT(0x72657620, 0x6E6F6973, 0x352E3220, 0x0000002B),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x01FF01FF, 0x01FF01FF, 0x40020140, 0x40020140),
    CPUID_RESULT(0x00000000, 0x42004200, 0x02008140, 0x00808140),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00003028, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    CPUID_RESULT(0x00000000, 0x00000000, 0x00000000, 0x00000000),
};

#define LEAF7_EBX_TSX (BIT32(4) | BIT32(11))
#define LEAF7_EBX_AVX512                                                       \
  (BIT32(16) | BIT32(17) | BIT32(21) | BIT32(26) | BIT32(27) | BIT32(28) |     \
   BIT32(30) | BIT32(31))
#define LEAF7_ECX_AVX512                                                       \
  (BIT32(1) | BIT32(6) | BIT32(11) | BIT32(12) | BIT32(14))
#define LEAF7_EDX_AVX512 (BIT32(2) | BIT32(3) | BIT32(8) | BIT32(23))

extern void reverie_dbi_runtime_thread_init(prototype_counters_t *counters);
extern int32_t reverie_dbi_runtime_pre_syscall(
    void *context, prototype_counters_t *counters, int32_t tid, int32_t pid,
    int64_t sysnum, const uint64_t *args, uint64_t branches, int64_t *result,
    syscall_invoker_t invoke_syscall, register_reader_t read_registers);
extern void reverie_dbi_runtime_totals(uint64_t *branches, uint64_t *syscalls,
                                       uint64_t *rewritten);

static _Atomic uint64_t branch_count __attribute__((aligned(64)));
static int thread_state_index;
static ptr_uint_t cpuid_marker_note;

static cpuid_result_t deterministic_cpuid(uint32_t leaf, uint32_t subleaf) {
  cpuid_result_t result = {0};

  if (leaf < ARRAY_SIZE(basic_cpuid)) {
    result = basic_cpuid[leaf];
  } else if (leaf >= UINT32_C(0x80000000) &&
             leaf - UINT32_C(0x80000000) < ARRAY_SIZE(extended_cpuid)) {
    result = extended_cpuid[leaf - UINT32_C(0x80000000)];
  }

  if (leaf == 1)
    result.ecx &= ~BIT32(30); /* RDRAND */
  if (leaf == 7) {
    if (subleaf != 0)
      return (cpuid_result_t){0};
    result.ebx &= ~(LEAF7_EBX_TSX | BIT32(18) | LEAF7_EBX_AVX512);
    result.ecx &= ~LEAF7_ECX_AVX512;
    result.edx &= ~LEAF7_EDX_AVX512;
  }
  return result;
}

static void emulate_cpuid(void) {
  void *drcontext = dr_get_current_drcontext();
  dr_mcontext_t registers = {sizeof(registers), DR_MC_INTEGER};
  cpuid_result_t result;

  DR_ASSERT(dr_get_mcontext(drcontext, &registers));
  result =
      deterministic_cpuid((uint32_t)registers.xax, (uint32_t)registers.xcx);
  registers.xax = result.eax;
  registers.xbx = result.ebx;
  registers.xcx = result.ecx;
  registers.xdx = result.edx;
  DR_ASSERT(dr_set_mcontext(drcontext, &registers));
}

static dr_emit_flags_t rewrite_cpuid(void *drcontext, void *tag,
                                     instrlist_t *bb, bool for_trace,
                                     bool translating) {
  instr_t *instruction;
  instr_t *next;

  for (instruction = instrlist_first_app(bb); instruction != NULL;
       instruction = next) {
    emulated_instr_t emulated;
    instr_t *marker;
    next = instr_get_next_app(instruction);
    if (instr_get_opcode(instruction) != OP_cpuid)
      continue;

    emulated = (emulated_instr_t){
        sizeof(emulated), instr_get_app_pc(instruction), instruction, 0};
    if (!drmgr_insert_emulation_start(drcontext, bb, instruction, &emulated))
      DR_ASSERT(false);
    marker = INSTR_CREATE_nop(drcontext);
    instr_set_translation(marker, instr_get_app_pc(instruction));
    instr_set_note(marker, (void *)cpuid_marker_note);
    instrlist_replace(bb, instruction, marker);
    drmgr_insert_emulation_end(drcontext, bb, next);
  }
  return DR_EMIT_DEFAULT;
}

static bool is_counted_branch(instr_t *instruction) {
  return instr_is_cbr(instruction) || instr_is_ubr(instruction) ||
         instr_is_call(instruction) || instr_is_return(instruction);
}

static dr_emit_flags_t instrument_instruction(void *drcontext, void *tag,
                                              instrlist_t *bb,
                                              instr_t *instruction,
                                              bool for_trace, bool translating,
                                              void *user_data) {
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == cpuid_marker_note) {
    dr_insert_clean_call_ex(
        drcontext, bb, instruction, (void *)emulate_cpuid,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT, 0);
    return DR_EMIT_DEFAULT;
  }
  if (!instr_is_app(instruction) || !is_counted_branch(instruction))
    return DR_EMIT_DEFAULT;

  if (!drx_insert_counter_update(drcontext, bb, instruction, SPILL_SLOT_MAX + 1,
                                 &branch_count, 1,
                                 DRX_COUNTER_64BIT | DRX_COUNTER_LOCK))
    DR_ASSERT(false);

  return DR_EMIT_DEFAULT;
}

static int64_t invoke_syscall(uintptr_t context, int64_t sysnum,
                              const uint64_t *args) {
  return (int64_t)dr_invoke_syscall_as_app((void *)context, (int)sysnum, 6,
                                           args[0], args[1], args[2], args[3],
                                           args[4], args[5]);
}

static int32_t read_registers(uintptr_t context, struct user_regs_struct *out) {
  dr_mcontext_t registers = {sizeof(registers), DR_MC_ALL};
  memset(out, 0, sizeof(*out));
  if (!dr_get_mcontext((void *)context, &registers))
    return 0;

  out->r15 = registers.r15;
  out->r14 = registers.r14;
  out->r13 = registers.r13;
  out->r12 = registers.r12;
  out->rbp = registers.xbp;
  out->rbx = registers.xbx;
  out->r11 = registers.r11;
  out->r10 = registers.r10;
  out->r9 = registers.r9;
  out->r8 = registers.r8;
  out->rax = registers.xax;
  out->rcx = registers.xcx;
  out->rdx = registers.xdx;
  out->rsi = registers.xsi;
  out->rdi = registers.xdi;
  out->orig_rax = registers.xax;
  out->rip = (uint64_t)registers.xip;
  out->eflags = registers.xflags;
  out->rsp = registers.xsp;
  return 1;
}

static bool filter_syscall(void *drcontext, int sysnum) { return true; }

static bool pre_syscall(void *drcontext, int sysnum) {
  uint64_t args[6];
  int64_t result = 0;
  int i;
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);

  DR_ASSERT(counters != NULL);
  for (i = 0; i != 6; ++i)
    args[i] = (uint64_t)dr_syscall_get_param(drcontext, i);

  if (reverie_dbi_runtime_pre_syscall(
          drcontext, counters, (int32_t)dr_get_thread_id(drcontext),
          (int32_t)dr_get_process_id(), (int64_t)sysnum, args,
          atomic_load_explicit(&branch_count, memory_order_relaxed), &result,
          invoke_syscall, read_registers)) {
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }
  return true;
}

static void thread_init(void *drcontext) {
  prototype_counters_t *counters =
      (prototype_counters_t *)dr_thread_alloc(drcontext, sizeof(*counters));
  DR_ASSERT(counters != NULL);
  reverie_dbi_runtime_thread_init(counters);
  DR_ASSERT(drmgr_set_tls_field(drcontext, thread_state_index, counters));
}

static void thread_exit(void *drcontext) {
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  if (counters != NULL)
    dr_thread_free(drcontext, counters, sizeof(*counters));
}

static void event_exit(void) {
  uint64_t branches;
  uint64_t syscalls;
  uint64_t rewritten;

  reverie_dbi_runtime_totals(&branches, &syscalls, &rewritten);
  dr_fprintf(STDERR,
             "reverie-dbi: branches=%llu syscalls=%llu rewritten_writes=%llu\n",
             branches, syscalls, rewritten);
  drx_exit();
  drmgr_unregister_tls_field(thread_state_index);
  drreg_exit();
  drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  drreg_options_t register_options = {sizeof(register_options), 1, false};

  dr_set_client_name("Reverie DynamoRIO backend prototype",
                     "https://github.com/rrnewton/reverie");
  if (!drmgr_init() || !drx_init() ||
      drreg_init(&register_options) != DRREG_SUCCESS)
    DR_ASSERT(false);
  cpuid_marker_note = drmgr_reserve_note_range(1);
  if (cpuid_marker_note == DRMGR_NOTE_NONE)
    DR_ASSERT(false);
  thread_state_index = drmgr_register_tls_field();
  if (thread_state_index == -1)
    DR_ASSERT(false);

  drmgr_register_exit_event(event_exit);
  if (!drmgr_register_thread_init_event(thread_init) ||
      !drmgr_register_thread_exit_event(thread_exit) ||
      !drmgr_register_bb_app2app_event(rewrite_cpuid, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL, instrument_instruction,
                                               NULL) ||
      !drmgr_register_filter_syscall_event(filter_syscall) ||
      !drmgr_register_pre_syscall_event(pre_syscall))
    DR_ASSERT(false);
}
