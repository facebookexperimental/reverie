/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drwrap.h"
#include "drx.h"

#ifndef X86_64
#error "The Reverie DynamoRIO prototype currently requires x86-64"
#endif

typedef int64_t (*syscall_invoker_t)(uintptr_t, int64_t, const uint64_t *);
typedef int32_t (*register_reader_t)(uintptr_t, struct user_regs_struct *);
typedef int32_t (*register_writer_t)(uintptr_t, const struct user_regs_struct *);
typedef int32_t (*memory_reader_t)(uintptr_t, uint8_t *, size_t);
typedef size_t (*memory_writer_t)(uintptr_t, const uint8_t *, size_t);

typedef struct {
  uint64_t branches;
  uint64_t observed_syscalls;
  uint64_t rewritten_syscalls;
  void *runtime_state;
  uint64_t pending_thread_clone;
  uint64_t thread_clone_flags;
  uint64_t thread_clone_ctid;
  uint64_t pending_thread_start;
  int32_t virtual_pid;
  int32_t virtual_ppid;
  int32_t virtual_tid;
  int32_t pending_virtual_child;
  uint64_t pending_clone_flags;
} prototype_counters_t;

#define VIRTUAL_ROOT_PID INT32_C(3)
#define VIRTUAL_INIT_PID INT32_C(1)
#define VIRTUAL_IDENTITY_FD 197
#define CLIENT_THREAD_START_FAILURE_EXIT_CODE 125
#define DBI_DIAGNOSTIC_FD 198
#define VIRTUAL_IDENTITY_MAGIC UINT64_C(0x5245565049443033)
#define MAX_VIRTUAL_IDENTITIES 8192

typedef struct {
  int32_t host;
  int32_t virtual_id;
} virtual_identity_t;

typedef struct {
  uint64_t magic;
  atomic_flag lock;
  _Atomic int32_t next_virtual_id;
  /* The launch-time descriptor identity survives exec, unlike numeric fd 0. */
  bool initial_stdin_valid;
  struct stat initial_stdin;
  /* The root resolves the coordinator environment before any fork. Copied
   * runtimes inherit this shared flag instead of consulting Rust's post-fork
   * environment state. */
  bool external_global;
  size_t count;
  virtual_identity_t identities[MAX_VIRTUAL_IDENTITIES];
} virtual_identity_state_t;

typedef struct {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} cpuid_result_t;

#define CPUID_RESULT(a, b, c, d) {(a), (b), (c), (d)}
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define BIT32(bit) (UINT32_C(1) << (bit))
#define X32_SYSCALL_BIT UINT32_C(0x40000000)
#define X86_32_SYS_SETPGID 57
#define X86_32_SYS_SETSID 66

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

// Emits a pre-formatted line of tool output through DynamoRIO's own I/O. The
// simple observation tools (syscall histogram, strace) call back through this
// rather than writing to fd 2 directly: the guest can close its stderr before
// exit, and app-level writes re-enter the syscall interception path.
typedef void (*reverie_emit_fn_t)(const char *buf, size_t len);
typedef void (*reverie_idle_fn_t)(void);
// TODO-HUMAN-REVIEW(PR-162): Review the additive stdout-emit runtime callback ABI.
typedef struct {
  reverie_emit_fn_t emit;
  reverie_idle_fn_t idle;
  int32_t panic_on_unsupported_syscalls;
  int32_t unsupported_report_fd;
  // AUTONOMOUS-BOT-IMPLEMENTED
  // Re-entrancy-safe stdout emitter (DynamoRIO I/O on STDOUT), used by tools
  // such as chunky_print that suppress guest stdout writes and re-emit the
  // buffered bytes to the real stdout at a flush boundary. Added at the end of
  // the struct so the existing field layout is unchanged.
  reverie_emit_fn_t emit_stdout;
} runtime_callbacks_t;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#90): Confirm diagnostic fd ownership across exec.
// Inherited from the launcher so guest stderr redirections cannot capture it.
static file_t diagnostic_file;
static char unsupported_report_path[4096];
static file_t unsupported_report_file = INVALID_FILE;
static void reverie_dbi_emit(const char *buf, size_t len) {
  dr_write_file(diagnostic_file, buf, len);
}
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-162): Review the native stdout emit path.
// Emits pre-formatted bytes to real stdout via DynamoRIO's own I/O. Like
// `reverie_dbi_emit`, this avoids re-entering the syscall interception path that
// an app-level `write(1, ...)` would trigger, and works even after the guest has
// closed its own stdout.
static void reverie_dbi_emit_stdout(const char *buf, size_t len) {
  dr_write_file(STDOUT, buf, len);
}

// TODO-HUMAN-REVIEW(PR-131): Review the native thread lifecycle callback ABI.
extern int32_t reverie_dbi_runtime_thread_init(
    prototype_counters_t *counters, void *context, int32_t tid, int32_t pid,
    int32_t in_tree_ppid, uint64_t branches, int32_t defer_runtime,
    syscall_invoker_t invoke_syscall, register_reader_t read_registers,
    register_writer_t write_registers);
extern int32_t reverie_dbi_runtime_thread_created(
    prototype_counters_t *counters, void *context, int32_t parent_tid,
    int32_t pid, uint64_t branches, int32_t child_tid, uint64_t child_tid_addr,
    uint64_t flags, syscall_invoker_t invoke_syscall,
    register_reader_t read_registers, register_writer_t write_registers);

extern void reverie_dbi_runtime_thread_exit(prototype_counters_t *counters,
                                            void *context, int32_t tid,
                                            syscall_invoker_t invoke_syscall);
extern uint64_t reverie_dbi_runtime_image_init(void);
extern void reverie_dbi_runtime_exec_failed(prototype_counters_t *counters,
                                            int32_t pid);
extern void reverie_dbi_runtime_background_init(void *argument);
extern int32_t reverie_dbi_runtime_ready(uint64_t image_generation);
extern void reverie_dbi_runtime_process_exit(void);
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-219): Review copied-child argument and errno policy ABI.
extern int32_t reverie_dbi_runtime_copied_syscall(int64_t sysnum,
                                                  const uint64_t *args);
// TODO-HUMAN-REVIEW(PR-154): Review the deferred lifecycle syscall callback ABI.
extern int32_t reverie_dbi_runtime_pre_syscall(
    void *context, prototype_counters_t *counters, int32_t tid, int32_t pid,
    uint64_t image_generation, int64_t sysnum, const uint64_t *args,
    uint64_t branches, int64_t *result, int64_t *deferred_sysnum,
    uint64_t *deferred_args, syscall_invoker_t invoke_syscall,
    register_reader_t read_registers, register_writer_t write_registers,
    memory_reader_t read_memory, memory_writer_t write_memory,
    reverie_emit_fn_t emit);
extern const char *reverie_dbi_runtime_name(void);
extern void reverie_dbi_runtime_totals(uint64_t *branches, uint64_t *syscalls,
                                       uint64_t *rewritten,
                                       uint64_t *memory_hash);

static _Atomic uint64_t branch_count __attribute__((aligned(64)));
static _Atomic uint64_t stdin_read_count;
static _Atomic uint64_t pending_thread_starts;
static _Atomic uint64_t virtual_time_ns = UINT64_C(1000000000);
static _Atomic uint64_t image_generation;
static int thread_state_index;
static int compat_gateway_index;
static ptr_uint_t cpuid_marker_note;
static ptr_uint_t rdtsc_marker_note;
static ptr_uint_t rdtscp_marker_note;
static bool report_summary;

// Deterministic virtual timestamp counter. Under DBI only one guest thread runs
// at a time (guest threads are cooperatively serialized by Detcore at syscall
// boundaries), so the sequence of rdtsc/rdtscp interceptions is a deterministic
// total order. Emitting a fixed-stride monotonically increasing value therefore
// yields bitwise-identical rdtsc/rdtscp output across repeated runs, mirroring
// the CPUID emulation which also replaces a nondeterministic instruction with a
// deterministic in-client value. The stride is an arbitrary positive constant
// that keeps values strictly increasing so guests computing rdtsc deltas never
// observe a zero or negative interval.
static _Atomic uint64_t virtual_tsc __attribute__((aligned(64)));
#define VIRTUAL_TSC_STRIDE UINT64_C(100)
static process_id_t runtime_owner_pid;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-84): Review isolation-aware process-group termination.
static process_id_t runtime_process_group;
static void exit_runtime_tree(int exit_code) {
  // A copied child cannot kill its own process group and then run DynamoRIO
  // cleanup. Kill the launch-group leader instead; the out-of-group launcher reaps it and
  // terminates the remaining isolated group after preserving its exit status.
  if (runtime_process_group != 0 &&
      runtime_process_group != dr_get_process_id())
    kill((pid_t)runtime_process_group, SIGKILL);
  dr_exit_process(exit_code);
}
static int32_t virtual_process_id = VIRTUAL_ROOT_PID;
static int32_t virtual_parent_process_id = VIRTUAL_INIT_PID;
static virtual_identity_state_t *virtual_identity_state;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-154): Review serialized clone identity handoff.
static atomic_flag pending_clone_lock = ATOMIC_FLAG_INIT;
static _Atomic int32_t pending_clone_virtual_child;
static _Atomic int32_t pending_clone_creator_pid;
static _Atomic uint64_t pending_clone_flags;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-262): Review copied-vfork native-gate lifetime.
static _Atomic int32_t copied_vfork_pid;
/* A copied child initializes its inherited Rust runtime on its first syscall.
 * Track the process that completed that handoff rather than a boolean: nested
 * fork children inherit the parent's globals and must rebase again. */
static process_id_t copied_process_runtime_pid;

static bool map_inherited_virtual_identity_state(void) {
  struct stat status;
  void *mapping;
  if (fstat(VIRTUAL_IDENTITY_FD, &status) != 0 ||
      status.st_size != (off_t)sizeof(*virtual_identity_state))
    return false;
  mapping = mmap(NULL, sizeof(*virtual_identity_state), PROT_READ | PROT_WRITE,
                 MAP_SHARED, VIRTUAL_IDENTITY_FD, 0);
  if (mapping == MAP_FAILED)
    return false;
  virtual_identity_state = (virtual_identity_state_t *)mapping;
  if (virtual_identity_state->magic == VIRTUAL_IDENTITY_MAGIC)
    return true;
  munmap(mapping, sizeof(*virtual_identity_state));
  virtual_identity_state = NULL;
  return false;
}

static void initialize_virtual_identity_state(bool external_global) {
  int descriptor;
  if (map_inherited_virtual_identity_state())
    return;

  descriptor = (int)syscall(SYS_memfd_create, "reverie-dbi-pids", 0);
  DR_ASSERT(descriptor >= 0);
  DR_ASSERT(ftruncate(descriptor, sizeof(*virtual_identity_state)) == 0);
  if (descriptor != VIRTUAL_IDENTITY_FD) {
    DR_ASSERT(dup2(descriptor, VIRTUAL_IDENTITY_FD) == VIRTUAL_IDENTITY_FD);
    close(descriptor);
  }
  DR_ASSERT(fcntl(VIRTUAL_IDENTITY_FD, F_SETFD, 0) == 0);
  virtual_identity_state = (virtual_identity_state_t *)mmap(
      NULL, sizeof(*virtual_identity_state), PROT_READ | PROT_WRITE, MAP_SHARED,
      VIRTUAL_IDENTITY_FD, 0);
  DR_ASSERT(virtual_identity_state != MAP_FAILED);
  memset(virtual_identity_state, 0, sizeof(*virtual_identity_state));
  virtual_identity_state->magic = VIRTUAL_IDENTITY_MAGIC;
  atomic_flag_clear(&virtual_identity_state->lock);
  atomic_init(&virtual_identity_state->next_virtual_id, VIRTUAL_ROOT_PID + 1);
  virtual_identity_state->initial_stdin_valid =
      fstat(STDIN_FILENO, &virtual_identity_state->initial_stdin) == 0;
  virtual_identity_state->external_global = external_global;
}

static bool runtime_uses_external_global(void) {
  return virtual_identity_state != NULL &&
         virtual_identity_state->external_global;
}

static void virtual_identity_lock(void) {
  while (atomic_flag_test_and_set_explicit(&virtual_identity_state->lock,
                                           memory_order_acquire))
    dr_thread_yield();
}

static void virtual_identity_unlock(void) {
  atomic_flag_clear_explicit(&virtual_identity_state->lock,
                             memory_order_release);
}

static int32_t allocate_virtual_identity(void) {
  return atomic_fetch_add_explicit(&virtual_identity_state->next_virtual_id, 1,
                                   memory_order_relaxed);
}

static int32_t ensure_virtual_identity(int32_t host) {
  int32_t virtual_id;
  size_t i;
  DR_ASSERT(host > 0);

  virtual_identity_lock();
  for (i = 0; i < virtual_identity_state->count; ++i) {
    if (virtual_identity_state->identities[i].host == host) {
      virtual_id = virtual_identity_state->identities[i].virtual_id;
      virtual_identity_unlock();
      return virtual_id;
    }
  }
  DR_ASSERT(virtual_identity_state->count < MAX_VIRTUAL_IDENTITIES);
  virtual_id = atomic_fetch_add_explicit(
      &virtual_identity_state->next_virtual_id, 1, memory_order_relaxed);
  virtual_identity_state->identities[virtual_identity_state->count++] =
      (virtual_identity_t){host, virtual_id};
  virtual_identity_unlock();
  return virtual_id;
}

static void remember_virtual_identity(int32_t host, int32_t virtual_id) {
  size_t i;
  if (host <= 0 || virtual_id <= 0)
    return;

  virtual_identity_lock();
  for (i = 0; i < virtual_identity_state->count; ++i) {
    if (virtual_identity_state->identities[i].host == host ||
        virtual_identity_state->identities[i].virtual_id == virtual_id) {
      virtual_identity_state->identities[i] =
          (virtual_identity_t){host, virtual_id};
      virtual_identity_unlock();
      return;
    }
  }
  DR_ASSERT(virtual_identity_state->count < MAX_VIRTUAL_IDENTITIES);
  virtual_identity_state->identities[virtual_identity_state->count++] =
      (virtual_identity_t){host, virtual_id};
  virtual_identity_unlock();
}

static int32_t virtual_identity_for_host(int32_t host) {
  int32_t result = host;
  size_t i;
  if (host <= 0)
    return host;

  virtual_identity_lock();
  for (i = 0; i < virtual_identity_state->count; ++i) {
    if (virtual_identity_state->identities[i].host == host) {
      result = virtual_identity_state->identities[i].virtual_id;
      break;
    }
  }
  virtual_identity_unlock();
  return result;
}

static bool lookup_virtual_identity(int32_t host, int32_t *virtual_id) {
  size_t i;
  bool found = false;
  if (host <= 0)
    return false;

  virtual_identity_lock();
  for (i = 0; i < virtual_identity_state->count; ++i) {
    if (virtual_identity_state->identities[i].host == host) {
      *virtual_id = virtual_identity_state->identities[i].virtual_id;
      found = true;
      break;
    }
  }
  virtual_identity_unlock();
  return found;
}

static int32_t host_identity_for_guest(int32_t identity) {
  int32_t result = -1;
  size_t i;
  if (identity <= 0)
    return identity;

  virtual_identity_lock();
  for (i = 0; i < virtual_identity_state->count; ++i) {
    if (virtual_identity_state->identities[i].virtual_id == identity ||
        virtual_identity_state->identities[i].host == identity) {
      result = virtual_identity_state->identities[i].host;
      break;
    }
  }
  virtual_identity_unlock();
  return result;
}

static bool is_known_virtual_identity(int32_t value) {
  size_t i;
  bool found = false;
  if (value <= 0)
    return false;

  virtual_identity_lock();
  for (i = 0; i < virtual_identity_state->count; ++i) {
    if (virtual_identity_state->identities[i].virtual_id == value) {
      found = true;
      break;
    }
  }
  virtual_identity_unlock();
  return found;
}

static int32_t virtualize_host_identity(int32_t value) {
  return is_known_virtual_identity(value) ? value
                                          : virtual_identity_for_host(value);
}

typedef struct {
  uint64_t rlim_cur;
  uint64_t rlim_max;
} virtual_rlimit_t;

#define VIRTUAL_RLIMIT_COUNT ((size_t)RLIMIT_RTTIME + 1)
static virtual_rlimit_t virtual_limits[VIRTUAL_RLIMIT_COUNT];
static void *resource_lock;

static bool read_app(const void *address, void *value, size_t size);
static bool write_app(void *address, const void *value, size_t size);

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

// Return the next deterministic virtual TSC value. Strictly increasing per
// interception; see the `virtual_tsc` declaration for the determinism argument.
static uint64_t next_virtual_tsc(void) {
  return atomic_fetch_add_explicit(&virtual_tsc, VIRTUAL_TSC_STRIDE,
                                   memory_order_relaxed) +
         VIRTUAL_TSC_STRIDE;
}

// Emulate rdtsc: return the 64-bit virtual TSC in EDX:EAX, leaving all other
// registers (notably ECX) untouched, exactly as the hardware rdtsc does.
static void emulate_rdtsc(void) {
  void *drcontext = dr_get_current_drcontext();
  dr_mcontext_t registers = {sizeof(registers), DR_MC_INTEGER};
  uint64_t tsc = next_virtual_tsc();

  DR_ASSERT(dr_get_mcontext(drcontext, &registers));
  registers.xax = (reg_t)(tsc & UINT32_C(0xFFFFFFFF));
  registers.xdx = (reg_t)((tsc >> 32) & UINT32_C(0xFFFFFFFF));
  DR_ASSERT(dr_set_mcontext(drcontext, &registers));
}

// Emulate rdtscp: like rdtsc, but also set ECX to the TSC_AUX value. A
// deterministic run must report a stable processor id, so TSC_AUX is fixed at 0
// (matching Detcore's `RdtscResult` aux handling for a single virtual CPU).
static void emulate_rdtscp(void) {
  void *drcontext = dr_get_current_drcontext();
  dr_mcontext_t registers = {sizeof(registers), DR_MC_INTEGER};
  uint64_t tsc = next_virtual_tsc();

  DR_ASSERT(dr_get_mcontext(drcontext, &registers));
  registers.xax = (reg_t)(tsc & UINT32_C(0xFFFFFFFF));
  registers.xdx = (reg_t)((tsc >> 32) & UINT32_C(0xFFFFFFFF));
  registers.xcx = 0;
  DR_ASSERT(dr_set_mcontext(drcontext, &registers));
}

// Replace rdtsc and rdtscp instructions with a marker nop, mirroring
// rewrite_cpuid. The instrumentation event installs the matching clean call.
static dr_emit_flags_t rewrite_rdtsc(void *drcontext, void *tag,
                                     instrlist_t *bb, bool for_trace,
                                     bool translating) {
  instr_t *instruction;
  instr_t *next;

  for (instruction = instrlist_first_app(bb); instruction != NULL;
       instruction = next) {
    emulated_instr_t emulated;
    instr_t *marker;
    int opcode;
    ptr_uint_t note = 0;
    next = instr_get_next_app(instruction);
    opcode = instr_get_opcode(instruction);
    if (opcode == OP_rdtsc)
      note = rdtsc_marker_note;
    else if (opcode == OP_rdtscp)
      note = rdtscp_marker_note;
    else
      continue;

    emulated = (emulated_instr_t){
        sizeof(emulated), instr_get_app_pc(instruction), instruction, 0};
    if (!drmgr_insert_emulation_start(drcontext, bb, instruction, &emulated))
      DR_ASSERT(false);
    marker = INSTR_CREATE_nop(drcontext);
    instr_set_translation(marker, instr_get_app_pc(instruction));
    instr_set_note(marker, (void *)note);
    instrlist_replace(bb, instruction, marker);
    drmgr_insert_emulation_end(drcontext, bb, next);
  }
  return DR_EMIT_DEFAULT;
}

static bool is_compat_syscall_instruction(instr_t *instruction) {
  return instr_is_syscall(instruction) && instr_is_interrupt(instruction) &&
         instr_get_interrupt_number(instruction) == 0x80;
}

static void mark_compat_syscall_gateway(void) {
  void *drcontext = dr_get_current_drcontext();
  DR_ASSERT(drmgr_set_tls_field(drcontext, compat_gateway_index, (void *)1));
}

static int64_t invoke_syscall(uintptr_t context, int64_t sysnum,
                              const uint64_t *args);
static int32_t read_registers(uintptr_t context, struct user_regs_struct *out);
static int32_t write_registers(uintptr_t context,
                               const struct user_regs_struct *in);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-ratchet11): Review the in-tree parent-pid surface.
// The real parent pid of the current process within the traced tree, or -1 when
// this is the tree root. DynamoRIO follows clone/fork children
// (-follow_children), so a non-root process's real OS parent is always its
// in-tree parent; the root's real parent is the out-of-tree launcher, which the
// `Guest::ppid` contract reports as no parent (`None`). The root is identified
// by its virtual identity being the root sentinel, assigned in `dr_client_main`
// when its pid is absent from the shared virtual-identity map.
// `virtual_process_id` is a per-process constant, so this is stable for every
// thread of the process.
static int32_t in_tree_parent_pid(void) {
  return virtual_process_id == VIRTUAL_ROOT_PID ? -1
                                                : (int32_t)dr_get_parent_id();
}

// TODO-HUMAN-REVIEW(PR-131): Review the child entry-block scheduling gate.
static void start_pending_thread(void) {
  void *drcontext = dr_get_current_drcontext();
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  if (counters == NULL || counters->pending_thread_start == 0)
    return;

  int32_t init_result = reverie_dbi_runtime_thread_init(
      counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(), in_tree_parent_pid(),
      atomic_load_explicit(&branch_count, memory_order_relaxed), 0,
      invoke_syscall, read_registers, write_registers);
  // TODO-HUMAN-REVIEW(PR-134): Confirm retryable native child startup.
  if (init_result > 0) {
    counters->pending_thread_start = 2;
    return;
  }
  if (init_result < 0) {
    dr_fprintf(diagnostic_file,
               "reverie-dbi: runtime thread initialization failed\n");
    exit_runtime_tree(101);
    return;
  }
  counters->pending_thread_start = 0;
  atomic_fetch_sub_explicit(&pending_thread_starts, 1, memory_order_release);
}

static bool is_counted_branch(instr_t *instruction) {
  return instr_is_cbr(instruction) || instr_is_ubr(instruction) ||
         instr_is_call(instruction) || instr_is_return(instruction);
}

static dr_emit_flags_t analyze_syscall_gateway(
    void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
    bool translating, void **user_data) {
  instr_t *instruction;
  *user_data = NULL;
  for (instruction = instrlist_first(bb); instruction != NULL;
       instruction = instr_get_next(instruction)) {
    if (instr_opcode_valid(instruction) &&
        is_compat_syscall_instruction(instruction)) {
      *user_data = (void *)1;
      break;
    }
  }
  return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t instrument_instruction(void *drcontext, void *tag,
                                              instrlist_t *bb,
                                              instr_t *instruction,
                                              bool for_trace, bool translating,
                                              void *user_data) {
  if (instr_is_app(instruction) && instruction == instrlist_first_app(bb) &&
      atomic_load_explicit(&pending_thread_starts, memory_order_acquire) != 0) {
    dr_insert_clean_call_ex(
        drcontext, bb, instruction, (void *)start_pending_thread,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT,
        0);
  }
  if (user_data != NULL && instruction == instrlist_first(bb)) {
    dr_insert_clean_call(drcontext, bb, instruction,
                         (void *)mark_compat_syscall_gateway, false, 0);
  }
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == cpuid_marker_note) {
    dr_insert_clean_call_ex(
        drcontext, bb, instruction, (void *)emulate_cpuid,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT, 0);
    return DR_EMIT_DEFAULT;
  }
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == rdtsc_marker_note) {
    dr_insert_clean_call_ex(
        drcontext, bb, instruction, (void *)emulate_rdtsc,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT, 0);
    return DR_EMIT_DEFAULT;
  }
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == rdtscp_marker_note) {
    dr_insert_clean_call_ex(
        drcontext, bb, instruction, (void *)emulate_rdtscp,
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

static bool translate_identity_argument(uint64_t *argument) {
  int32_t identity = (int32_t)*argument;
  int32_t host;
  if (identity <= 0)
    return true;
  host = host_identity_for_guest(identity);
  if (host <= 0)
    return false;
  *argument = (uint64_t)(uint32_t)host;
  return true;
}

static int64_t invoke_raw_syscall(uintptr_t context, int64_t sysnum,
                                  const uint64_t *args) {
  return (int64_t)dr_invoke_syscall_as_app((void *)context, (int)sysnum, 6,
                                           args[0], args[1], args[2], args[3],
                                           args[4], args[5]);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-106): keep the identity memfd (fd 197) and diagnostic fd
// (198) alive across close/fcntl(F_SETFD)/dup2/dup3 in copied children.
// RESIDUAL: close_range is not intercepted and can still close the memfd.
static bool preserve_internal_descriptors(uintptr_t context, int sysnum,
                                          const uint64_t *args,
                                          int64_t *result) {
  int fd = (int)args[0];
  (void)context;
  if (sysnum == SYS_close &&
      (fd == VIRTUAL_IDENTITY_FD || fd == DBI_DIAGNOSTIC_FD)) {
    *result = 0;
    return true;
  }
  if (sysnum == SYS_fcntl &&
      (fd == VIRTUAL_IDENTITY_FD || fd == DBI_DIAGNOSTIC_FD) &&
      args[1] == F_SETFD) {
    *result = 0;
    return true;
  }
  if ((sysnum == SYS_dup2 || sysnum == SYS_dup3) &&
      ((int)args[1] == VIRTUAL_IDENTITY_FD ||
       (int)args[1] == DBI_DIAGNOSTIC_FD)) {
    *result = (int64_t)args[1];
    return true;
  }
  return false;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-106): map virtual PID/TID args to host IDs for
// PID-consuming syscalls. RESIDUAL: negative (process-group) targets such as
// kill(-pgid)/wait4(-pgid) pass through untranslated; pgid/sid not yet modeled.
static bool translate_identity_arguments(int sysnum, uint64_t *args) {
  switch (sysnum) {
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-259): Review virtual get_robust_list target translation.
  case SYS_get_robust_list:
  case SYS_kill:
  case SYS_tkill:
  case SYS_wait4:
  case SYS_getpgid:
  case SYS_getsid:
  case SYS_sched_getaffinity:
  case SYS_sched_setaffinity:
  case SYS_sched_getparam:
  case SYS_sched_setparam:
  case SYS_sched_getscheduler:
  case SYS_sched_setscheduler:
    return translate_identity_argument(&args[0]);
  case SYS_tgkill:
    return translate_identity_argument(&args[0]) &&
           translate_identity_argument(&args[1]);
  case SYS_setpgid:
    return translate_identity_argument(&args[0]) &&
           translate_identity_argument(&args[1]);
  case SYS_waitid:
    return args[0] != P_PID || translate_identity_argument(&args[1]);
  case SYS_prlimit64:
    return args[0] == 0 || translate_identity_argument(&args[0]);
  case SYS_getpriority:
  case SYS_setpriority:
    return args[0] != PRIO_PROCESS || args[1] == 0 ||
           translate_identity_argument(&args[1]);
  default:
    return true;
  }
}

static int64_t unknown_identity_error(int sysnum) {
  return sysnum == SYS_wait4 || sysnum == SYS_waitid ? -ECHILD : -ESRCH;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-106): map host PID/TID results back to virtual IDs.
// RESIDUAL: getpgid/getsid results absent from the identity table (an untracked
// host group/session leader) fall through to the raw host value and leak it.
static int64_t virtualize_identity_result(prototype_counters_t *counters,
                                          int sysnum, int64_t result) {
  if (result <= 0)
    return result;
  switch (sysnum) {
  case SYS_getpid:
    return counters->virtual_pid;
  case SYS_getppid:
    return counters->virtual_ppid;
  case SYS_gettid:
    return counters->virtual_tid;
  case SYS_fork:
  case SYS_vfork:
  case SYS_clone:
  case SYS_clone3:
  case SYS_wait4:
  case SYS_getpgid:
  case SYS_getsid:
  case SYS_set_tid_address:
    return virtualize_host_identity((int32_t)result);
  default:
    return result;
  }
}

static void virtualize_waitid_info(const uint64_t *args) {
  siginfo_t info;
  void *info_address = (void *)(uintptr_t)args[2];
  if (info_address != NULL && read_app(info_address, &info, sizeof(info)) &&
      info.si_pid > 0) {
    info.si_pid = virtualize_host_identity(info.si_pid);
    write_app(info_address, &info, sizeof(info));
  }
}

static bool clone_identity_flags(int sysnum, const uint64_t *args,
                                 uint64_t *flags) {
  switch (sysnum) {
  case SYS_fork:
    *flags = 0;
    return true;
  case SYS_vfork:
    *flags = CLONE_VM | CLONE_VFORK;
    return true;
  case SYS_clone:
    *flags = args[0];
    return true;
  case SYS_clone3:
    *flags = 0;
    return args[0] != 0 && args[1] >= sizeof(*flags) &&
           read_app((const void *)(uintptr_t)args[0], flags, sizeof(*flags));
  default:
    return false;
  }
}

static bool is_clone_syscall(int sysnum) {
  return sysnum == SYS_fork || sysnum == SYS_vfork || sysnum == SYS_clone ||
         sysnum == SYS_clone3;
}

static void acquire_clone_identity_handoff(void) {
  while (atomic_flag_test_and_set_explicit(&pending_clone_lock,
                                           memory_order_acquire))
    dr_sleep(1);
}

static void release_clone_identity_handoff(int32_t virtual_child) {
  int32_t expected = virtual_child;
  if (virtual_child == 0)
    return;
  if (atomic_compare_exchange_strong_explicit(
          &pending_clone_virtual_child, &expected, 0, memory_order_acq_rel,
          memory_order_acquire)) {
    atomic_store_explicit(&pending_clone_flags, 0, memory_order_relaxed);
    atomic_store_explicit(&pending_clone_creator_pid, 0, memory_order_relaxed);
    atomic_flag_clear_explicit(&pending_clone_lock, memory_order_release);
  }
}

static bool prepare_clone_identity(prototype_counters_t *counters, int sysnum,
                                   const uint64_t *args) {
  uint64_t flags;
  if (!clone_identity_flags(sysnum, args, &flags))
    return false;
  DR_ASSERT(counters->pending_virtual_child == 0);
  if ((flags & CLONE_THREAD) == 0)
    acquire_clone_identity_handoff();
  counters->pending_virtual_child = allocate_virtual_identity();
  counters->pending_clone_flags = flags;
  if ((flags & CLONE_THREAD) == 0) {
    atomic_store_explicit(&pending_clone_flags, flags, memory_order_relaxed);
    atomic_store_explicit(&pending_clone_creator_pid,
                          (int32_t)dr_get_process_id(), memory_order_relaxed);
    atomic_store_explicit(&pending_clone_virtual_child,
                          counters->pending_virtual_child, memory_order_release);
  }
  return true;
}

static int32_t complete_clone_identity(prototype_counters_t *counters,
                                       int64_t result) {
  int32_t virtual_child = counters->pending_virtual_child;
  uint64_t flags = counters->pending_clone_flags;
  int32_t mapped;
  if (virtual_child == 0)
    return 0;

  if (result > 0) {
    if ((flags & CLONE_THREAD) != 0 &&
        lookup_virtual_identity((int32_t)result, &mapped))
      virtual_child = mapped;
    else
      remember_virtual_identity((int32_t)result, virtual_child);
  } else if (result == 0) {
    int32_t host_tid = (int32_t)dr_get_thread_id(dr_get_current_drcontext());
    if ((flags & CLONE_THREAD) != 0 &&
        lookup_virtual_identity(host_tid, &mapped))
      virtual_child = mapped;
    else
      remember_virtual_identity(host_tid, virtual_child);
    if ((flags & CLONE_THREAD) != 0) {
      counters->virtual_tid = virtual_child;
    } else {
      int32_t parent = counters->virtual_pid;
      remember_virtual_identity((int32_t)dr_get_process_id(), virtual_child);
      if ((flags & CLONE_VM) != 0)
        return virtual_child;
      counters->virtual_pid = virtual_child;
      counters->virtual_ppid = parent;
      counters->virtual_tid = virtual_child;
      virtual_parent_process_id = parent;
      virtual_process_id = virtual_child;
    }
  }
  if ((flags & CLONE_THREAD) == 0 &&
      (result <= 0 || (flags & CLONE_VM) == 0))
    release_clone_identity_handoff(virtual_child);
  counters->pending_virtual_child = 0;
  if (!(result == 0 && (flags & CLONE_THREAD) == 0 &&
        runtime_owner_pid != 0 && dr_get_process_id() != runtime_owner_pid &&
        runtime_uses_external_global()))
    counters->pending_clone_flags = 0;
  return virtual_child;
}

static bool pending_identity_is_process(const prototype_counters_t *counters) {
  return counters->pending_virtual_child != 0 &&
         (counters->pending_clone_flags & CLONE_THREAD) == 0;
}

static int64_t invoke_syscall(uintptr_t context, int64_t sysnum,
                              const uint64_t *args) {
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      (void *)context, thread_state_index);
  uint64_t translated[6];
  int64_t result;
  bool is_clone;
  DR_ASSERT(counters != NULL);
  memcpy(translated, args, sizeof(translated));
  if (!translate_identity_arguments((int)sysnum, translated))
    return unknown_identity_error((int)sysnum);

  if (sysnum == SYS_getpid)
    return pending_identity_is_process(counters)
               ? counters->pending_virtual_child
               : counters->virtual_pid;
  if (sysnum == SYS_getppid)
    return counters->virtual_ppid;
  if (sysnum == SYS_gettid)
    return counters->pending_virtual_child != 0
               ? counters->pending_virtual_child
               : counters->virtual_tid;

  is_clone = prepare_clone_identity(counters, (int)sysnum, translated);
  if (preserve_internal_descriptors(context, (int)sysnum, translated, &result))
    return result;
  result = invoke_raw_syscall(context, sysnum, translated);
  if (is_clone) {
    int32_t virtual_child = complete_clone_identity(counters, result);
    if (result > 0)
      return virtual_child;
    return result;
  }
  if (sysnum == SYS_waitid && result >= 0)
    virtualize_waitid_info(translated);
  return virtualize_identity_result(counters, (int)sysnum, result);
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

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-167): Review the DBI guest register-write callback.
// The write counterpart to read_registers: overwrite the application's integer
// register file with the tool-supplied values. DynamoRIO permits dr_set_mcontext
// from a pre-/post-syscall event, and the modified context is used when the
// application resumes (the pc/xip field is ignored outside kernel-transfer
// events, so it is intentionally not written here). Reads the current mcontext
// first so control/segment fields DynamoRIO manages are preserved.
static int32_t write_registers(uintptr_t context,
                               const struct user_regs_struct *in) {
  dr_mcontext_t registers = {sizeof(registers), DR_MC_ALL};
  if (!dr_get_mcontext((void *)context, &registers))
    return 0;

  registers.r15 = in->r15;
  registers.r14 = in->r14;
  registers.r13 = in->r13;
  registers.r12 = in->r12;
  registers.xbp = in->rbp;
  registers.xbx = in->rbx;
  registers.r11 = in->r11;
  registers.r10 = in->r10;
  registers.r9 = in->r9;
  registers.r8 = in->r8;
  registers.xax = in->rax;
  registers.xcx = in->rcx;
  registers.xdx = in->rdx;
  registers.xsi = in->rsi;
  registers.xdi = in->rdi;
  registers.xflags = in->eflags;
  registers.xsp = in->rsp;

  if (!dr_set_mcontext((void *)context, &registers))
    return 0;
  return 1;
}

static int32_t read_memory(uintptr_t address, uint8_t *out, size_t size) {
  return read_app((const void *)address, out, size) ? 1 : 0;
}

// TODO-HUMAN-REVIEW(PR-234): Review the fault-safe DBI memory-write callback ABI.
// TODO-HUMAN-REVIEW(PR-237): Review page-bounded partial-write semantics.
static size_t write_memory(uintptr_t address, const uint8_t *value, size_t size) {
  size_t total = 0;
  const size_t page_size = dr_page_size();
  while (address != 0 && total < size && address <= UINTPTR_MAX - total) {
    const uintptr_t current = address + total;
    const size_t page_remaining = page_size - current % page_size;
    const size_t segment = size - total < page_remaining ? size - total
                                                         : page_remaining;
    size_t bytes_written = 0;
    dr_safe_write((void *)current, segment, value + total, &bytes_written);
    total += bytes_written;
    if (bytes_written != segment)
      break;
  }
  return total;
}

static void init_virtual_limits(void) {
  for (size_t resource = 0; resource < VIRTUAL_RLIMIT_COUNT; ++resource)
    virtual_limits[resource] = (virtual_rlimit_t){UINT64_MAX, UINT64_MAX};

  virtual_limits[RLIMIT_STACK] =
      (virtual_rlimit_t){UINT64_C(8388608), UINT64_MAX};
  virtual_limits[RLIMIT_NPROC] =
      (virtual_rlimit_t){UINT64_C(1000000), UINT64_C(1000000)};
  virtual_limits[RLIMIT_NOFILE] =
      (virtual_rlimit_t){UINT64_C(1048576), UINT64_C(1048576)};
  virtual_limits[RLIMIT_MEMLOCK] =
      (virtual_rlimit_t){UINT64_C(67108864), UINT64_C(67108864)};
  virtual_limits[RLIMIT_SIGPENDING] =
      (virtual_rlimit_t){UINT64_C(1000000), UINT64_C(1000000)};
  virtual_limits[RLIMIT_MSGQUEUE] =
      (virtual_rlimit_t){UINT64_C(819200), UINT64_C(819200)};
  virtual_limits[RLIMIT_NICE] = (virtual_rlimit_t){0, 0};
  virtual_limits[RLIMIT_RTPRIO] = (virtual_rlimit_t){0, 0};
}

static bool handle_virtual_resource(int sysnum, const uint64_t *args,
                                    int64_t *result) {
  bool is_get = sysnum == SYS_getrlimit;
  bool is_set = sysnum == SYS_setrlimit;
  bool is_prlimit = sysnum == SYS_prlimit64;
  if (!is_get && !is_set && !is_prlimit)
    return false;

  if (is_prlimit && args[0] != 0 &&
      (process_id_t)args[0] != dr_get_process_id()) {
    *result = -ESRCH;
    return true;
  }

  uint64_t resource = is_prlimit ? args[1] : args[0];
  if (resource >= VIRTUAL_RLIMIT_COUNT) {
    *result = -EINVAL;
    return true;
  }

  const void *new_address =
      (const void *)(uintptr_t)(is_set ? args[1] : (is_prlimit ? args[2] : 0));
  void *old_address =
      (void *)(uintptr_t)(is_get ? args[1] : (is_prlimit ? args[3] : 0));
  virtual_rlimit_t requested;
  bool has_requested = new_address != NULL;
  if ((is_set && !has_requested) ||
      (has_requested &&
       !read_app(new_address, &requested, sizeof(requested)))) {
    *result = -EFAULT;
    return true;
  }
  if (is_get && old_address == NULL) {
    *result = -EFAULT;
    return true;
  }

  dr_mutex_lock(resource_lock);
  virtual_rlimit_t current = virtual_limits[resource];
  if (has_requested && requested.rlim_cur > requested.rlim_max) {
    dr_mutex_unlock(resource_lock);
    *result = -EINVAL;
    return true;
  }
  if (has_requested && requested.rlim_max > current.rlim_max) {
    dr_mutex_unlock(resource_lock);
    *result = -EPERM;
    return true;
  }
  if (old_address != NULL &&
      !write_app(old_address, &current, sizeof(current))) {
    dr_mutex_unlock(resource_lock);
    *result = -EFAULT;
    return true;
  }
  if (has_requested)
    virtual_limits[resource] = requested;
  dr_mutex_unlock(resource_lock);
  *result = 0;
  return true;
}

static bool clock_supported(clockid_t clockid) {
  switch (clockid) {
  case CLOCK_REALTIME:
  case CLOCK_MONOTONIC:
  case CLOCK_PROCESS_CPUTIME_ID:
  case CLOCK_THREAD_CPUTIME_ID:
  case (clockid_t)-6:
  case (clockid_t)-2:
#ifdef CLOCK_MONOTONIC_RAW
  case CLOCK_MONOTONIC_RAW:
#endif
#ifdef CLOCK_REALTIME_COARSE
  case CLOCK_REALTIME_COARSE:
#endif
#ifdef CLOCK_MONOTONIC_COARSE
  case CLOCK_MONOTONIC_COARSE:
#endif
#ifdef CLOCK_BOOTTIME
  case CLOCK_BOOTTIME:
#endif
#ifdef CLOCK_REALTIME_ALARM
  case CLOCK_REALTIME_ALARM:
#endif
#ifdef CLOCK_BOOTTIME_ALARM
  case CLOCK_BOOTTIME_ALARM:
#endif
#ifdef CLOCK_TAI
  case CLOCK_TAI:
#endif
    return true;
  default:
    return false;
  }
}

static bool is_process_cpu_clock(clockid_t clockid) {
  return clockid == CLOCK_PROCESS_CPUTIME_ID || clockid == (clockid_t)-6;
}

static bool is_thread_cpu_clock(clockid_t clockid) {
  return clockid == CLOCK_THREAD_CPUTIME_ID || clockid == (clockid_t)-2;
}

static uint64_t observe_virtual_time(void) {
  return atomic_fetch_add_explicit(&virtual_time_ns, UINT64_C(1000),
                                   memory_order_seq_cst);
}

static struct timespec virtual_timespec(uint64_t nanoseconds) {
  return (struct timespec){
      .tv_sec = (time_t)(nanoseconds / UINT64_C(1000000000)),
      .tv_nsec = (long)(nanoseconds % UINT64_C(1000000000)),
  };
}

static bool read_app(const void *address, void *value, size_t size) {
  size_t bytes_read = 0;
  return address != NULL && dr_safe_read(address, size, value, &bytes_read) &&
         bytes_read == size;
}

static bool write_app(void *address, const void *value, size_t size) {
  size_t bytes_written = 0;
  return address != NULL &&
         dr_safe_write(address, size, value, &bytes_written) &&
         bytes_written == size;
}

static bool timespec_nanoseconds(const struct timespec *value,
                                 uint64_t *nanoseconds) {
  if (value->tv_sec < 0 || value->tv_nsec < 0 || value->tv_nsec >= 1000000000L)
    return false;
  if ((uint64_t)value->tv_sec >
      (UINT64_MAX - (uint64_t)value->tv_nsec) / UINT64_C(1000000000))
    return false;
  *nanoseconds =
      (uint64_t)value->tv_sec * UINT64_C(1000000000) + (uint64_t)value->tv_nsec;
  return true;
}

static void advance_virtual_time(uint64_t nanoseconds, bool absolute) {
  if (!absolute) {
    atomic_fetch_add_explicit(&virtual_time_ns, nanoseconds,
                              memory_order_seq_cst);
    return;
  }

  uint64_t current =
      atomic_load_explicit(&virtual_time_ns, memory_order_seq_cst);
  while (current < nanoseconds &&
         !atomic_compare_exchange_weak_explicit(
             &virtual_time_ns, &current, nanoseconds, memory_order_seq_cst,
             memory_order_seq_cst)) {
  }
}

static bool handle_virtual_clock(uintptr_t context, int sysnum,
                                 const uint64_t *args, int64_t *result) {
  switch (sysnum) {
  case SYS_clock_gettime: {
    clockid_t clockid = (clockid_t)args[0];
    if (!clock_supported(clockid)) {
      *result = -EINVAL;
      return true;
    }
    struct timespec value = virtual_timespec(observe_virtual_time());
    *result = write_app((void *)(uintptr_t)args[1], &value, sizeof(value))
                  ? 0
                  : -EFAULT;
    return true;
  }
  case SYS_clock_getres: {
    clockid_t clockid = (clockid_t)args[0];
    if (!clock_supported(clockid)) {
      *result = -EINVAL;
      return true;
    }
    if (args[1] == 0) {
      *result = 0;
      return true;
    }
    const struct timespec resolution = {.tv_sec = 0, .tv_nsec = 1000};
    *result =
        write_app((void *)(uintptr_t)args[1], &resolution, sizeof(resolution))
            ? 0
            : -EFAULT;
    return true;
  }
  case SYS_clock_nanosleep: {
    clockid_t clockid = (clockid_t)args[0];
    int flags = (int)args[1];
    if (!clock_supported(clockid) || is_thread_cpu_clock(clockid) ||
        (flags & ~TIMER_ABSTIME) != 0) {
      *result = -EINVAL;
      return true;
    }

    /* Preserve real blocking so peer threads and signals can make progress. */
    if (flags == 0 && !is_process_cpu_clock(clockid))
      return false;

    struct timespec request;
    uint64_t nanoseconds;
    if (!read_app((const void *)(uintptr_t)args[2], &request,
                  sizeof(request))) {
      *result = -EFAULT;
      return true;
    }
    if (!timespec_nanoseconds(&request, &nanoseconds)) {
      *result = -EINVAL;
      return true;
    }
    if (is_process_cpu_clock(clockid)) {
      advance_virtual_time(nanoseconds, (flags & TIMER_ABSTIME) != 0);
      *result = 0;
      return true;
    }

    uint64_t current =
        atomic_load_explicit(&virtual_time_ns, memory_order_seq_cst);
    uint64_t delay = nanoseconds > current ? nanoseconds - current : 0;
    struct timespec relative = virtual_timespec(delay);
    const uint64_t sleep_args[6] = {
        (uint64_t)(uintptr_t)&relative,
        0,
    };
    *result = invoke_syscall(context, SYS_nanosleep, sleep_args);
    if (*result == 0)
      advance_virtual_time(nanoseconds, true);
    return true;
  }
  case SYS_clock_settime:
    *result = clock_supported((clockid_t)args[0]) ? -EPERM : -EINVAL;
    return true;
  case SYS_gettimeofday: {
    uint64_t nanoseconds = observe_virtual_time();
    if (args[0] != 0) {
      const struct timeval value = {
          .tv_sec = (time_t)(nanoseconds / UINT64_C(1000000000)),
          .tv_usec = (suseconds_t)((nanoseconds % UINT64_C(1000000000)) /
                                   UINT64_C(1000)),
      };
      if (!write_app((void *)(uintptr_t)args[0], &value, sizeof(value))) {
        *result = -EFAULT;
        return true;
      }
    }
    if (args[1] != 0) {
      const struct timezone timezone = {0};
      if (!write_app((void *)(uintptr_t)args[1], &timezone, sizeof(timezone))) {
        *result = -EFAULT;
        return true;
      }
    }
    *result = 0;
    return true;
  }
#ifdef SYS_time
  case SYS_time: {
    time_t seconds = (time_t)(observe_virtual_time() / UINT64_C(1000000000));
    if (args[0] != 0 &&
        !write_app((void *)(uintptr_t)args[0], &seconds, sizeof(seconds))) {
      *result = -EFAULT;
      return true;
    }
    *result = (int64_t)seconds;
    return true;
  }
#endif
  default:
    return false;
  }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(hermit#705): Confirm vDSO time neutralization routes guest
// clock reads through the shared Detcore tool (2021 epoch) rather than the raw
// host TSC, matching the ptrace backend.
//
// Neutralize one guest vDSO time symbol by overwriting its entry point with a
// tiny `mov $sysnum, %eax; syscall; ret` thunk. glibc's vDSO fast path then
// issues a real, trapped syscall instead of reading the raw host TSC, so the
// call flows through pre_syscall() where the external Detcore tool virtualizes
// it (and the prototype runtime still services it via handle_virtual_clock()).
// This mirrors reverie-ptrace/src/vdso.rs, whose vDSO neutralization is why the
// ptrace backend already reports the deterministic epoch; the previous
// drwrap_skip_call() path answered from the base-zero prototype clock and never
// reached the real tool, so `date` printed 1970 under Detcore (hermit#705).
static void neutralize_vdso_symbol(const module_data_t *module, const char *name,
                                   long sysnum) {
  app_pc address = (app_pc)dr_get_proc_address(module->handle, name);
  if (address == NULL)
    return;

  /*
   * mov $sysnum, %eax; syscall; ret  (8 bytes). vDSO entries are padded to a
   * 16-byte alignment, so overwriting the first 8 bytes stays within the symbol
   * and the trailing `ret` prevents fall-through into the original body.
   */
  const uint8_t thunk[8] = {
      0xb8,
      (uint8_t)(sysnum),
      (uint8_t)(sysnum >> 8),
      (uint8_t)(sysnum >> 16),
      (uint8_t)(sysnum >> 24),
      0x0f,
      0x05,
      0xc3,
  };

  size_t region_size = (size_t)(module->end - module->start);
  if (!dr_memory_protect((void *)module->start, region_size,
                         DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC)) {
    dr_fprintf(diagnostic_file,
               "reverie-dbi: failed to unprotect vdso to neutralize %s\n", name);
    return;
  }
  memcpy(address, thunk, sizeof(thunk));
  DR_ASSERT(dr_memory_protect((void *)module->start, region_size,
                              DR_MEMPROT_READ | DR_MEMPROT_EXEC));

  /*
   * Discard any cached translation of the vDSO so the patched bytes take
   * effect. The delayed form is the flush variant permitted from a module-load
   * callback; it completes before any new code enters the cache, i.e. before the
   * guest first calls the patched entry.
   */
  dr_delay_flush_region(module->start, region_size, 0, NULL);
}

static void module_load(void *drcontext, const module_data_t *module,
                        bool loaded) {
  neutralize_vdso_symbol(module, "__vdso_clock_gettime", SYS_clock_gettime);
  neutralize_vdso_symbol(module, "__vdso_clock_getres", SYS_clock_getres);
  neutralize_vdso_symbol(module, "__vdso_gettimeofday", SYS_gettimeofday);
#ifdef SYS_getcpu
  neutralize_vdso_symbol(module, "__vdso_getcpu", SYS_getcpu);
#endif
#ifdef SYS_time
  neutralize_vdso_symbol(module, "__vdso_time", SYS_time);
#endif
}

static bool fd_matches_stdin(void *drcontext, int fd) {
#ifdef SYS_fstat
  struct stat candidate_stat = {0};
  uint64_t stat_args[6] = {(uint64_t)fd,
                           (uint64_t)(uintptr_t)&candidate_stat};
  if (!virtual_identity_state->initial_stdin_valid)
    return false;
  if (invoke_syscall((uintptr_t)drcontext, SYS_fstat, stat_args) < 0)
    return false;
  return virtual_identity_state->initial_stdin.st_dev == candidate_stat.st_dev &&
         virtual_identity_state->initial_stdin.st_ino == candidate_stat.st_ino &&
         virtual_identity_state->initial_stdin.st_rdev == candidate_stat.st_rdev;
#else
  return false;
#endif
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#77): Confirm pipe EAGAIN retry preserves signal and
// short-I/O semantics.
static bool fd_is_pipe(void *drcontext, int fd) {
#ifdef SYS_fstat
  struct stat value = {0};
  uint64_t stat_args[6] = {(uint64_t)fd, (uint64_t)(uintptr_t)&value};
  return invoke_syscall((uintptr_t)drcontext, SYS_fstat, stat_args) == 0 &&
         S_ISFIFO(value.st_mode);
#else
  return false;
#endif
}

static short pipe_io_events(int sysnum) {
  switch (sysnum) {
#ifdef SYS_read
  case SYS_read:
#endif
#ifdef SYS_readv
  case SYS_readv:
#endif
    return POLLIN;
#ifdef SYS_write
  case SYS_write:
#endif
#ifdef SYS_writev
  case SYS_writev:
#endif
    return POLLOUT;
  default:
    return 0;
  }
}

static void retry_pipe_eagain(void *drcontext, int sysnum, const uint64_t *args,
                              int64_t *result) {
#if defined(SYS_poll)
  short events = pipe_io_events(sysnum);
  int fd = (int)args[0];
  if (*result != -EAGAIN || events == 0 || !fd_is_pipe(drcontext, fd))
    return;

  while (*result == -EAGAIN) {
    struct pollfd ready = {.fd = fd, .events = events};
    uint64_t poll_args[6] = {(uint64_t)(uintptr_t)&ready, 1,
                             (uint64_t)(int64_t)-1};
    int64_t poll_result =
        invoke_syscall((uintptr_t)drcontext, SYS_poll, poll_args);
    if (poll_result < 0) {
      *result = poll_result;
      return;
    }
    *result = invoke_syscall((uintptr_t)drcontext, sysnum, args);
  }
#else
  (void)drcontext;
  (void)sysnum;
  (void)args;
  (void)result;
#endif
}

static bool syscall_reads_stdin(void *drcontext, int sysnum,
                                const uint64_t *args) {
  int fd;
  switch (sysnum) {
#ifdef SYS_read
  case SYS_read:
#endif
#ifdef SYS_readv
  case SYS_readv:
#endif
#ifdef SYS_pread64
  case SYS_pread64:
#endif
#ifdef SYS_preadv
  case SYS_preadv:
#endif
#ifdef SYS_preadv2
  case SYS_preadv2:
#endif
#ifdef SYS_recvfrom
  case SYS_recvfrom:
#endif
#ifdef SYS_recvmsg
  case SYS_recvmsg:
#endif
#ifdef SYS_recvmmsg
  case SYS_recvmmsg:
#endif
#ifdef SYS_splice
  case SYS_splice:
#endif
#ifdef SYS_tee
  case SYS_tee:
#endif
#ifdef SYS_copy_file_range
  case SYS_copy_file_range:
#endif
    fd = (int)args[0];
    break;
#ifdef SYS_sendfile
  case SYS_sendfile:
    fd = (int)args[1];
    break;
#endif
  default:
    return false;
  }
  return fd_matches_stdin(drcontext, fd);
}

static bool filter_syscall(void *drcontext, int sysnum) { return true; }

static bool has_copied_runtime(void);
static bool is_copied_vfork_process(void);
static void ensure_runtime_background(void);
static void runtime_background_init(void *argument);

static bool is_exec_syscall(int sysnum) {
  return sysnum == SYS_execve
#ifdef SYS_execveat
         || sysnum == SYS_execveat
#endif
      ;
}

// TODO-HUMAN-REVIEW(PR-131): Review clone metadata and registration ordering.
static bool thread_clone_metadata(void *drcontext, int sysnum, uint64_t *flags,
                                  uint64_t *child_tid_addr) {
  // AUTONOMOUS-BOT-IMPLEMENTED
  if (sysnum == SYS_clone) {
    *flags = (uint64_t)dr_syscall_get_param(drcontext, 0);
    *child_tid_addr = (uint64_t)dr_syscall_get_param(drcontext, 3);
    return (*flags & CLONE_THREAD) != 0;
  }
#ifdef SYS_clone3
  uint64_t clone3_args[4];
  // AUTONOMOUS-BOT-IMPLEMENTED
  if (sysnum == SYS_clone3 &&
      read_app((const void *)dr_syscall_get_param(drcontext, 0), clone3_args,
               sizeof(clone3_args)) &&
      (clone3_args[0] & CLONE_THREAD) != 0) {
    *flags = clone3_args[0];
    *child_tid_addr = clone3_args[2];
    return true;
  }
#endif
  return false;
}

static void zero_wait_rusage(void *address) {
  if (address != NULL) {
    struct rusage usage = {0};
    write_app(address, &usage, sizeof(usage));
  }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-106): emulate getpid/getppid/gettid in copied children
// from the shared virtual-identity map so forks never observe host PIDs.
static bool emulate_identity_getter(prototype_counters_t *counters, int sysnum,
                                    int64_t *result) {
  int32_t mapped;
  switch (sysnum) {
  case SYS_getpid:
    *result = lookup_virtual_identity((int32_t)dr_get_process_id(), &mapped)
                  ? mapped
                  : (pending_identity_is_process(counters)
                         ? counters->pending_virtual_child
                         : counters->virtual_pid);
    return true;
  case SYS_getppid:
    *result = lookup_virtual_identity((int32_t)dr_get_parent_id(), &mapped)
                  ? mapped
                  : counters->virtual_ppid;
    return true;
  case SYS_gettid:
    *result =
        lookup_virtual_identity(
            (int32_t)dr_get_thread_id(dr_get_current_drcontext()), &mapped)
            ? mapped
            : (counters->pending_virtual_child != 0
                   ? counters->pending_virtual_child
                   : counters->virtual_tid);
    return true;
  default:
    return false;
  }
}

static bool prepare_original_identity_syscall(void *drcontext,
                                              prototype_counters_t *counters,
                                              int sysnum,
                                              const uint64_t *args) {
  uint64_t translated[6];
  int i;
  memcpy(translated, args, sizeof(translated));
  if (!translate_identity_arguments(sysnum, translated)) {
    dr_syscall_set_result(drcontext, (reg_t)unknown_identity_error(sysnum));
    return false;
  }
  for (i = 0; i != 6; ++i) {
    if (translated[i] != args[i])
      dr_syscall_set_param(drcontext, i, (reg_t)translated[i]);
  }
  (void)prepare_clone_identity(counters, sysnum, translated);
  return true;
}

// TODO-HUMAN-REVIEW(PR-66): Confirm wait-result normalization preserves wait
// semantics.
static void post_syscall(void *drcontext, int sysnum) {
  ptr_int_t syscall_result = (ptr_int_t)dr_syscall_get_result(drcontext);
  ptr_int_t host_syscall_result = syscall_result;
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  DR_ASSERT(counters != NULL);

  if (counters->pending_virtual_child != 0 && is_clone_syscall(sysnum)) {
    int32_t virtual_child = complete_clone_identity(counters, syscall_result);
    if (syscall_result > 0) {
      syscall_result = virtual_child;
      dr_syscall_set_result(drcontext, (reg_t)syscall_result);
    }
  }

  syscall_result = virtualize_identity_result(counters, sysnum, syscall_result);
  if (syscall_result != host_syscall_result)
    dr_syscall_set_result(drcontext, (reg_t)syscall_result);

  if (sysnum == SYS_wait4 && syscall_result > 0) {
    syscall_result = virtualize_host_identity((int32_t)syscall_result);
    dr_syscall_set_result(drcontext, (reg_t)syscall_result);
  }

  if (sysnum == SYS_waitid) {
    siginfo_t info;
    void *info_address = (void *)dr_syscall_get_param(drcontext, 2);
    if (info_address != NULL && read_app(info_address, &info, sizeof(info)) &&
        info.si_pid > 0) {
      info.si_pid = virtualize_host_identity(info.si_pid);
      write_app(info_address, &info, sizeof(info));
    }
  }

  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process()))
    return;

  if (counters->pending_thread_clone != 0) {
    if (host_syscall_result >= 0) {
      int32_t registration = reverie_dbi_runtime_thread_created(
          counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
          (int32_t)dr_get_process_id(),
          atomic_load_explicit(&branch_count, memory_order_relaxed),
          (int32_t)host_syscall_result, counters->thread_clone_ctid,
          counters->thread_clone_flags, invoke_syscall, read_registers,
          write_registers);
      if (registration < 0) {
        dr_fprintf(diagnostic_file,
                   "reverie-dbi: child thread registration failed\n");
        exit_runtime_tree(101);
        return;
      }
    }
    counters->pending_thread_clone = 0;
  }
  if (is_exec_syscall(sysnum)) {
    reverie_dbi_runtime_exec_failed(counters, (int32_t)dr_get_process_id());
    return;
  }

  if (syscall_result < 0)
    return;
  // AUTONOMOUS-BOT-IMPLEMENTED
  if (sysnum == SYS_wait4 && syscall_result > 0) {
    zero_wait_rusage((void *)dr_syscall_get_param(drcontext, 3));
    // AUTONOMOUS-BOT-IMPLEMENTED
  } else if (sysnum == SYS_waitid) {
    siginfo_t info;
    void *info_address = (void *)dr_syscall_get_param(drcontext, 2);
    if (info_address != NULL && read_app(info_address, &info, sizeof(info)) &&
        info.si_pid != 0) {
      info.si_utime = 0;
      info.si_stime = 0;
      write_app(info_address, &info, sizeof(info));
      zero_wait_rusage((void *)dr_syscall_get_param(drcontext, 4));
    }
  }
}

static bool has_copied_runtime(void) {
  return runtime_owner_pid != 0 && dr_get_process_id() != runtime_owner_pid;
}

static bool is_copied_vfork_process(void) {
  return has_copied_runtime() &&
         atomic_load_explicit(&copied_vfork_pid, memory_order_acquire) ==
             (int32_t)dr_get_process_id();
}

static void report_copied_unsupported_syscall(int sysnum) {
  if (unsupported_report_file != INVALID_FILE)
    dr_fprintf(unsupported_report_file, "@%d\n", sysnum);
}

static bool pre_syscall(void *drcontext, int sysnum) {
  if (((uint32_t)sysnum & X32_SYSCALL_BIT) != 0) {
    dr_fprintf(diagnostic_file,
               "reverie-dbi: x32-marked syscalls are unsupported\n");
    exit_runtime_tree(102);
    return false;
  }
  bool decoded_compat_gateway =
      drmgr_get_tls_field(drcontext, compat_gateway_index) != NULL;
  DR_ASSERT(drmgr_set_tls_field(drcontext, compat_gateway_index, NULL));
  if (decoded_compat_gateway) {
    dr_fprintf(diagnostic_file,
               "reverie-dbi: compat int 0x80 syscalls are unsupported\n");
    exit_runtime_tree(102);
    return false;
  }
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-84): Review process-group mutation refusal in isolated runtimes.
  // Group containment does not rely on mutable gateway bytes: copied
  // runtimes reject the ambiguous i386 raw numbers even if gateway proof races.
  if (runtime_process_group != 0 &&
      (sysnum == SYS_setsid || sysnum == SYS_setpgid ||
       (has_copied_runtime() &&
        (sysnum == X86_32_SYS_SETPGID || sysnum == X86_32_SYS_SETSID)))) {
    dr_syscall_set_result(drcontext, (reg_t)-EPERM);
    return false;
  }

  uint64_t args[6];
  int64_t result = 0;
  int i;
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  DR_ASSERT(counters != NULL);

  // TODO-HUMAN-REVIEW(PR-134): Review post-application runtime bootstrap.
  if (!has_copied_runtime())
    ensure_runtime_background();

  /* A delayed entry-block flush is not synchronous.  If a native child reaches
   * a syscall through an inherited fragment, start it here after the
   * thread-init event has returned so the parent post-clone callback can
   * register it. */
  // TODO-HUMAN-REVIEW(PR-134): Confirm the delayed-flush syscall fallback.
  while (!has_copied_runtime() && counters->pending_thread_start != 0) {
    start_pending_thread();
    if (counters->pending_thread_start != 0)
      dr_sleep(1);
  }

  for (i = 0; i != 6; ++i)
    args[i] = (uint64_t)dr_syscall_get_param(drcontext, i);

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-255): Review copied-process Detcore state rebasing.
  if (has_copied_runtime() && runtime_uses_external_global() &&
      !is_copied_vfork_process() &&
      copied_process_runtime_pid != dr_get_process_id()) {
    int32_t initialized = reverie_dbi_runtime_thread_init(
        counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(), in_tree_parent_pid(),
        atomic_load_explicit(&branch_count, memory_order_relaxed), 0,
        invoke_syscall, read_registers, write_registers);
    if (initialized != 0) {
      dr_fprintf(diagnostic_file,
                 "reverie-dbi: copied process state initialization failed\n");
      exit_runtime_tree(101);
      return false;
    }
    copied_process_runtime_pid = dr_get_process_id();
  }

  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process())) {
    // Record this copied child's virtual identity before any refusal so the
    // shared host<->virtual map stays coherent even when the syscall is later
    // rejected by the fail-closed unsupported-syscall policy below.
    if (counters->pending_virtual_child != 0) {
      remember_virtual_identity((int32_t)dr_get_process_id(),
                                counters->pending_virtual_child);
      remember_virtual_identity(
          (int32_t)dr_get_thread_id(dr_get_current_drcontext()),
          counters->pending_virtual_child);
    }
    int32_t copied_action =
        reverie_dbi_runtime_copied_syscall((int64_t)sysnum, args);
    // Negative actions are deterministic errno values synthesized by the
    // copied-child policy. They avoid executing a host-dependent syscall while
    // preserving the error that the instrumented root observes.
    if (copied_action < 0) {
      dr_syscall_set_result(drcontext, (reg_t)copied_action);
      return false;
    }
    if (copied_action == 1) {
      dr_fprintf(diagnostic_file,
                 "detcore-dbi: unsupported syscall %d in copied child\n", sysnum);
      exit_runtime_tree(101);
      return false;
    }
    if (copied_action == 2) {
      report_copied_unsupported_syscall(sysnum);
      return true;
    }
    DR_ASSERT(copied_action == 0);
#ifdef SYS_execveat
    // TODO-HUMAN-REVIEW(PR-587): Fail closed before copied children bypass the
    // Detcore runtime callback.
    if (sysnum == SYS_execveat) {
      dr_syscall_set_result(drcontext, (reg_t)-ENOSYS);
      return false;
    }
#endif
    if (preserve_internal_descriptors((uintptr_t)drcontext, sysnum, args,
                                      &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    if (emulate_identity_getter(counters, sysnum, &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    /* A copied child runs no Rust Tool (reverie_dbi_runtime_copied_syscall
     * declined above), so the native virtual clock and virtual resource limits
     * are its only determinism layer for time and rlimits. Apply the same
     * fallbacks the root process gets below, otherwise a forked child would read
     * real host time (clock_gettime/gettimeofday/time) and real host rlimits
     * (getrlimit/setrlimit/prlimit64), diverging run to run while the root stays
     * virtualized. This runs after the fail-closed unsupported-syscall check, so
     * it never resurrects a rejected syscall. */
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-ratchet12): Review copied-child clock/resource virtualization.
    if (handle_virtual_clock((uintptr_t)drcontext, sysnum, args, &result) ||
        handle_virtual_resource(sysnum, args, &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    return prepare_original_identity_syscall(drcontext, counters, sysnum, args);
  }
  while (!reverie_dbi_runtime_ready(
      atomic_load_explicit(&image_generation, memory_order_acquire)))
    dr_sleep(1);
  uint64_t clone_flags = 0;
  uint64_t clone_ctid = 0;
  if (thread_clone_metadata(drcontext, sysnum, &clone_flags, &clone_ctid)) {
    DR_ASSERT(counters->pending_thread_clone == 0);
    counters->pending_thread_clone = 1;
    counters->thread_clone_flags = clone_flags;
    counters->thread_clone_ctid = clone_ctid;
  }

  if (syscall_reads_stdin(drcontext, sysnum, args))
    atomic_fetch_add_explicit(&stdin_read_count, 1, memory_order_relaxed);

  int64_t deferred_sysnum = sysnum;
  uint64_t deferred_args[6] = {0};
  int32_t action = reverie_dbi_runtime_pre_syscall(
      drcontext, counters, (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(),
      atomic_load_explicit(&image_generation, memory_order_acquire),
      (int64_t)sysnum, args,
      atomic_load_explicit(&branch_count, memory_order_relaxed), &result,
      &deferred_sysnum, deferred_args, invoke_syscall, read_registers,
      write_registers, read_memory, write_memory, reverie_dbi_emit);
  if (action != 0 && counters->pending_thread_clone != 0)
    counters->pending_thread_clone = 0;

  if (action < 0 || action > 2) {
    exit_runtime_tree(101);
    return false;
  }
  if (action == 1) {
    retry_pipe_eagain(drcontext, sysnum, args, &result);
    result = virtualize_identity_result(counters, sysnum, result);
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }
  if (action == 2) {
    uint64_t clone_flags = 0;
    uint64_t clone_ctid = 0;
    int i;
    sysnum = (int)deferred_sysnum;
    memcpy(args, deferred_args, sizeof(args));
    dr_syscall_set_sysnum(drcontext, sysnum);
    for (i = 0; i != 6; ++i)
      dr_syscall_set_param(drcontext, i, (reg_t)args[i]);
    if (thread_clone_metadata(drcontext, sysnum, &clone_flags, &clone_ctid)) {
      counters->pending_thread_clone = 1;
      counters->thread_clone_flags = clone_flags;
      counters->thread_clone_ctid = clone_ctid;
    }
    if (preserve_internal_descriptors((uintptr_t)drcontext, sysnum, args,
                                      &result) ||
        emulate_identity_getter(counters, sysnum, &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-255): Review pre-exit guest-transport deregistration.
    if (runtime_uses_external_global() && sysnum == SYS_exit_group)
      reverie_dbi_runtime_thread_exit(
          counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
          invoke_syscall);
    return prepare_original_identity_syscall(drcontext, counters, sysnum, args);
  }

  /* Prototype runtimes can decline these calls; external Tools such as
   * Detcore own their complete syscall policy and handle them above. */
  if (handle_virtual_clock((uintptr_t)drcontext, sysnum, args, &result) ||
      handle_virtual_resource(sysnum, args, &result)) {
    counters->branches =
        atomic_load_explicit(&branch_count, memory_order_relaxed);
    counters->observed_syscalls += 1;
    counters->rewritten_syscalls += 1;
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }
  return prepare_original_identity_syscall(drcontext, counters, sysnum, args);
}

static void thread_init(void *drcontext) {
  prototype_counters_t *counters =
      (prototype_counters_t *)dr_thread_alloc(drcontext, sizeof(*counters));
  int32_t host_tid = (int32_t)dr_get_thread_id(drcontext);
  int32_t pending_child =
      atomic_load_explicit(&pending_clone_virtual_child, memory_order_acquire);
  int32_t clone_creator =
      pending_child != 0
          ? atomic_load_explicit(&pending_clone_creator_pid, memory_order_relaxed)
          : 0;
  if ((int32_t)dr_get_process_id() == clone_creator)
    pending_child = 0;
  uint64_t clone_flags =
      pending_child != 0
          ? atomic_load_explicit(&pending_clone_flags, memory_order_relaxed)
          : 0;
  bool is_thread = (clone_flags & CLONE_THREAD) != 0;
  DR_ASSERT(counters != NULL);
  memset(counters, 0, sizeof(*counters));
  DR_ASSERT(drmgr_set_tls_field(drcontext, thread_state_index, counters));

  int32_t pending_thread_start =
      !has_copied_runtime() && dr_get_thread_id(drcontext) != dr_get_process_id() &&
      reverie_dbi_runtime_ready(
          atomic_load_explicit(&image_generation, memory_order_acquire));
  int32_t init_result = reverie_dbi_runtime_thread_init(
      counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(), in_tree_parent_pid(),
      atomic_load_explicit(&branch_count, memory_order_relaxed), 1, invoke_syscall,
      read_registers, write_registers);
  if (init_result < 0) {
    dr_fprintf(diagnostic_file,
               "reverie-dbi: runtime thread initialization failed\n");
    exit_runtime_tree(101);
    return;
  }
  counters->virtual_pid =
      pending_child != 0 && !is_thread ? pending_child : virtual_process_id;
  counters->virtual_ppid = pending_child != 0 && !is_thread
                               ? virtual_process_id
                               : virtual_parent_process_id;
  counters->virtual_tid =
      pending_child != 0 ? pending_child : ensure_virtual_identity(host_tid);
  counters->pending_virtual_child = 0;
  counters->pending_clone_flags = pending_child != 0 ? clone_flags : 0;
  if (pending_child != 0) {
    if (!is_thread && (clone_flags & CLONE_VFORK) != 0)
      atomic_store_explicit(&copied_vfork_pid,
                            (int32_t)dr_get_process_id(),
                            memory_order_release);
    if (!is_thread)
      remember_virtual_identity((int32_t)dr_get_process_id(), pending_child);
    remember_virtual_identity(host_tid, pending_child);
    release_clone_identity_handoff(pending_child);
  }

  counters->pending_thread_start = (uint64_t)pending_thread_start;
  if (pending_thread_start != 0) {
    dr_mcontext_t context = {sizeof(context), DR_MC_CONTROL};
    atomic_fetch_add_explicit(&pending_thread_starts, 1, memory_order_release);
    DR_ASSERT(dr_get_mcontext(drcontext, &context));
    DR_ASSERT(dr_delay_flush_region(context.pc, 1, 0, NULL));
  }
}

static void thread_exit(void *drcontext) {
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  if (counters != NULL &&
      (!has_copied_runtime() ||
       (runtime_uses_external_global() && !is_copied_vfork_process()))) {
    reverie_dbi_runtime_thread_exit(counters, drcontext,
                                    dr_get_thread_id(drcontext),
                                    invoke_syscall);
    dr_thread_free(drcontext, counters, sizeof(*counters));
  }
}

static void event_exit(void) {
  if (!has_copied_runtime() ||
      (runtime_uses_external_global() && !is_copied_vfork_process()))
    reverie_dbi_runtime_process_exit();
  uint64_t branches;
  uint64_t syscalls;
  uint64_t rewritten;
  uint64_t stdin_reads;
  uint64_t memory_hash;

  if (report_summary && !has_copied_runtime()) {
    reverie_dbi_runtime_totals(&branches, &syscalls, &rewritten, &memory_hash);
    stdin_reads = atomic_load_explicit(&stdin_read_count, memory_order_relaxed);
    dr_fprintf(diagnostic_file,
               "reverie-dbi: tool=%s branches=%llu syscalls=%llu "
               "rewritten=%llu stdin_reads=%llu memory_hash=%016llx\n",
               reverie_dbi_runtime_name(), branches, syscalls, rewritten,
               stdin_reads, memory_hash);
  }
  if (unsupported_report_file != INVALID_FILE) {
    dr_close_file(unsupported_report_file);
    unsupported_report_file = INVALID_FILE;
  }
  dr_mutex_destroy(resource_lock);
  drwrap_exit();
  drx_exit();
  drmgr_unregister_tls_field(compat_gateway_index);
  drmgr_unregister_tls_field(thread_state_index);
  drreg_exit();
  drmgr_exit();
}

static void runtime_idle(void) { dr_sleep(1); }

static _Atomic int32_t runtime_background_state;

static runtime_callbacks_t runtime_callbacks = {
    reverie_dbi_emit, runtime_idle, 0, 0, reverie_dbi_emit_stdout};

static void runtime_background_init(void *argument) {
  (void)argument;
  atomic_store_explicit(&runtime_background_state, 2, memory_order_release);
  reverie_dbi_runtime_background_init(&runtime_callbacks);
}

static void ensure_runtime_background(void) {
  int32_t expected = 0;
  if (!atomic_compare_exchange_strong_explicit(
          &runtime_background_state, &expected, 1, memory_order_acq_rel,
          memory_order_acquire))
    return;

  // TODO-HUMAN-REVIEW(PR-134): Review fail-fast native runtime bootstrap.
  if (!dr_create_client_thread(runtime_background_init,
                               (void *)reverie_dbi_emit)) {
    atomic_store_explicit(&runtime_background_state, 0, memory_order_release);
    dr_fprintf(diagnostic_file,
               "reverie-dbi: failed to start background client thread\n");
    dr_exit_process(CLIENT_THREAD_START_FAILURE_EXIT_CODE);
  }
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  drreg_options_t register_options = {sizeof(register_options), 1, false};
  bool external_global = false;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-external-global") == 0)
      external_global = true;
  }
  diagnostic_file = STDERR;
  atomic_store_explicit(&runtime_background_state, 0, memory_order_release);
  runtime_owner_pid = dr_get_process_id();
  initialize_virtual_identity_state(external_global);
  if (lookup_virtual_identity((int32_t)runtime_owner_pid,
                              &virtual_process_id)) {
    int32_t host_parent = (int32_t)getppid();
    if (!lookup_virtual_identity(host_parent, &virtual_parent_process_id))
      virtual_parent_process_id = VIRTUAL_INIT_PID;
  } else {
    virtual_process_id = VIRTUAL_ROOT_PID;
    virtual_parent_process_id = VIRTUAL_INIT_PID;
    remember_virtual_identity((int32_t)runtime_owner_pid, virtual_process_id);
  }
  atomic_store_explicit(&image_generation, reverie_dbi_runtime_image_init(),
                        memory_order_release);
  resource_lock = dr_mutex_create();
  DR_ASSERT(resource_lock != NULL);
  init_virtual_limits();

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-summary") == 0)
      report_summary = true;
    else if (strcmp(argv[i], "-diagnostic_fd") == 0) {
      int fd;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%d", &fd) == 1);
      DR_ASSERT(fd >= 0);
      diagnostic_file = (file_t)fd;
    }
    else if (strcmp(argv[i], "-unsupported-report-path") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(strlen(argv[i]) < sizeof(unsupported_report_path));
      dr_snprintf(unsupported_report_path, sizeof(unsupported_report_path),
                  "%s", argv[i]);
    }
    else if (strcmp(argv[i], "-panic-on-unsupported-syscalls") == 0)
      runtime_callbacks.panic_on_unsupported_syscalls = 1;
    else if (strcmp(argv[i], "-isolated-process-group") == 0)
      runtime_process_group = (process_id_t)getpgrp();
  }

  if (unsupported_report_path[0] != 0) {
    unsupported_report_file =
        dr_open_file(unsupported_report_path, DR_FILE_WRITE_ONLY);
    if (unsupported_report_file == INVALID_FILE)
      dr_fprintf(diagnostic_file,
                 "reverie-dbi: failed to open private unsupported-syscall report\n");
  }
  runtime_callbacks.unsupported_report_fd = (int32_t)unsupported_report_file;

  dr_set_client_name("Reverie DynamoRIO backend prototype",
                     "https://github.com/rrnewton/reverie");
  if (!drmgr_init() || !drwrap_init() || !drx_init() ||
      drreg_init(&register_options) != DRREG_SUCCESS)
    DR_ASSERT(false);
  cpuid_marker_note = drmgr_reserve_note_range(1);
  if (cpuid_marker_note == DRMGR_NOTE_NONE)
    DR_ASSERT(false);
  rdtsc_marker_note = drmgr_reserve_note_range(1);
  rdtscp_marker_note = drmgr_reserve_note_range(1);
  if (rdtsc_marker_note == DRMGR_NOTE_NONE ||
      rdtscp_marker_note == DRMGR_NOTE_NONE)
    DR_ASSERT(false);
  thread_state_index = drmgr_register_tls_field();
  compat_gateway_index = drmgr_register_tls_field();
  if (thread_state_index == -1 || compat_gateway_index == -1)
    DR_ASSERT(false);
  drmgr_register_exit_event(event_exit);
  if (!drmgr_register_module_load_event(module_load) ||
      !drmgr_register_thread_init_event(thread_init) ||
      !drmgr_register_thread_exit_event(thread_exit) ||
      !drmgr_register_bb_app2app_event(rewrite_cpuid, NULL) ||
      !drmgr_register_bb_app2app_event(rewrite_rdtsc, NULL) ||
      !drmgr_register_bb_instrumentation_event(analyze_syscall_gateway,
                                               instrument_instruction, NULL) ||
      !drmgr_register_filter_syscall_event(filter_syscall) ||
      !drmgr_register_pre_syscall_event(pre_syscall) ||
      !drmgr_register_post_syscall_event(post_syscall))
    DR_ASSERT(false);
}
