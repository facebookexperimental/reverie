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

extern void reverie_dbi_runtime_thread_init(prototype_counters_t *counters);
extern int32_t reverie_dbi_runtime_pre_syscall(
    void *context, prototype_counters_t *counters, int32_t tid, int32_t pid,
    int64_t sysnum, const uint64_t *args, uint64_t branches, int64_t *result,
    syscall_invoker_t invoke_syscall, register_reader_t read_registers);
extern void reverie_dbi_runtime_totals(uint64_t *branches, uint64_t *syscalls,
                                       uint64_t *rewritten);

static _Atomic uint64_t branch_count __attribute__((aligned(64)));
static int thread_state_index;

static bool is_counted_branch(instr_t *instruction) {
  return instr_is_cbr(instruction) || instr_is_ubr(instruction) ||
         instr_is_call(instruction) || instr_is_return(instruction);
}

static dr_emit_flags_t instrument_instruction(void *drcontext, void *tag,
                                              instrlist_t *bb,
                                              instr_t *instruction,
                                              bool for_trace, bool translating,
                                              void *user_data) {
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
  thread_state_index = drmgr_register_tls_field();
  if (thread_state_index == -1)
    DR_ASSERT(false);

  drmgr_register_exit_event(event_exit);
  if (!drmgr_register_thread_init_event(thread_init) ||
      !drmgr_register_thread_exit_event(thread_exit) ||
      !drmgr_register_bb_instrumentation_event(NULL, instrument_instruction,
                                               NULL) ||
      !drmgr_register_filter_syscall_event(filter_syscall) ||
      !drmgr_register_pre_syscall_event(pre_syscall))
    DR_ASSERT(false);
}
