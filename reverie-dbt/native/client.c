/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drwrap.h"
#include "drx.h"
#include "reverie_vdso_symbols.h"
#include "task_membership.h"

#ifndef X86_64
#error "The Reverie DynamoRIO prototype currently requires x86-64"
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#ifndef SHM_REMAP
#define SHM_REMAP 040000
#endif
#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#endif
#ifndef F_GETOWN_EX
#define F_GETOWN_EX 16
#endif
#ifndef FIOSETOWN
#define FIOSETOWN 0x8901
#endif
#ifndef SIOCSPGRP
#define SIOCSPGRP 0x8902
#endif
#ifndef FIOGETOWN
#define FIOGETOWN 0x8903
#endif
#ifndef SIOCGPGRP
#define SIOCGPGRP 0x8904
#endif

typedef int64_t (*syscall_invoker_t)(uintptr_t, int64_t, const uint64_t*);
typedef int32_t (*register_reader_t)(uintptr_t, struct user_regs_struct*);
typedef int32_t (*register_writer_t)(uintptr_t, const struct user_regs_struct*);
typedef int32_t (*memory_reader_t)(uintptr_t, uint8_t*, size_t);
typedef size_t (*memory_writer_t)(uintptr_t, const uint8_t*, size_t);
typedef int32_t (
    *memory_compare_exchange_t)(uintptr_t, uint32_t, uint32_t, uint32_t*);

typedef struct {
  int32_t physical_pid;
  int32_t physical_tid;
  uint64_t procfs_device;
  uint64_t procfs_inode;
} controller_capture_fact_t;
_Static_assert(sizeof(controller_capture_fact_t) == 24, "capture fact ABI size");
typedef int32_t (*controller_capture_control_t)(
    uintptr_t, uint32_t, controller_capture_fact_t*);

typedef struct {
  uint64_t start;
  uint64_t end;
} private_memory_range_t;

typedef struct {
  uint64_t owner[4]; // table device/inode, append-only slot, image epoch
  uint64_t version;
  uint32_t state; // 0: unavailable, 1: ready
  uint32_t count;
  private_memory_range_t ranges[3];
} private_memory_snapshot_t;
_Static_assert(sizeof(private_memory_snapshot_t) == 96,
    "private memory snapshot ABI");
typedef int32_t (*runtime_private_memory_t)(
    uintptr_t, const private_memory_snapshot_t*, private_memory_snapshot_t*);

typedef struct {
  int32_t signal;
  int32_t delivered_signal;
  unsigned char signal_info[128];
  int32_t signal_info_changed;
  uint32_t reserved;
  int64_t deferred_sysnum;
  uint64_t deferred_args[6];
} dbt_signal_event_t;
_Static_assert(sizeof(dbt_signal_event_t) == 200, "DBT signal ABI size");

typedef struct process_control process_control_t;
typedef struct {
  // Only published positive-PID slots can enter this cache. Those slots are
  // never recycled; the birth and PID remain immutable for their lifetime.
  process_control_t* entry;
  int32_t birth;
  int32_t mediated_pid;
} capture_owner_t;

typedef struct {
  uint64_t branches;
  uint64_t observed_syscalls;
  uint64_t rewritten_syscalls;
  void* runtime_state;
  uint64_t pending_thread_clone;
  uint64_t thread_clone_flags;
  uint64_t thread_clone_ctid;
  uint64_t pending_thread_start;
  int32_t kernel_pid;
  int32_t kernel_ppid;
  int32_t kernel_tid;
  int32_t pending_birth_token;
  uint64_t pending_clone_flags;
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review branch-count preemption
  // bookkeeping. Branch count observed at this thread's most recent synthetic
  // sched_yield preemption. Appended at the end of the struct so the existing
  // field layout (mirrored by detcore-dbt `NativeThreadScratch` and the
  // prototype `PrototypeCounters` prefix view) is unchanged; the `memset` in
  // `thread_init` zero-initializes it for every runtime.
  uint64_t last_yield_branch;
  // One-shot delivery latch for the process-clone result callback. Kept
  // client-only so identity handoff state can retain its existing CLONE_VM
  // lifetime without causing a later syscall to repeat the callback.
  uint64_t pending_process_clone_result;
  uint64_t pending_process_clone_flags;
  uint64_t pending_process_clone_ctid;
  int64_t pending_process_clone_exit_signal;
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review safe-point preemption thread
  // state. Client-only safe-point preemption state, appended AFTER the fields
  // the Rust `NativeThreadScratch` mirrors. Rust writes only that shorter
  // prefix, and the client `dr_thread_alloc`s + `memset`s the full
  // `prototype_counters_t`, so these are zero-initialized and never touched by
  // the Rust side. 1 while an injected sched_yield is in flight (between the
  // redirect to the stub and `preempt_return`); prevents nesting a second
  // preemption.
  uint64_t preempt_pending;
  // Saved interrupted machine context (integer + control + FP/SIMD) captured by
  // `maybe_preempt` and restored by `preempt_return` so the injected syscall is
  // transparent to the guest. Allocated per thread when preemption is enabled.
  dr_mcontext_t* preempt_mcontext;
  // Process identity whose protected-evidence thread count includes this
  // client-owned thread state. Fork-child duplicate exit callbacks retain the
  // parent's identity and therefore cannot decrement the child's count.
  process_id_t evidence_thread_process;
  // One-shot guard for the runtime thread-exit hook. Some exit syscalls do not
  // receive a DynamoRIO thread_exit callback; others can receive both paths.
  uint64_t runtime_thread_exit_called;
  // Separate from the preemption slot: no suspended continuation can overwrite
  // another's registers or enter Rust while its thread-state borrow is live.
  uint64_t signal_token;
  uint64_t signal_image_generation;
  process_id_t signal_owner_pid;
  thread_id_t signal_owner_tid;
  uint32_t signal_phase; // 1: captured, 2: Rust returned, 3: terminal syscall
  bool signal_registers_changed;
  dr_mcontext_t* signal_mcontext;
  dbt_signal_event_t signal_event;
  int32_t signal_action;
  uint64_t syscall_interruption;
  uint64_t syscall_interruption_generation;
  process_id_t syscall_interruption_pid;
  thread_id_t syscall_interruption_tid;
  // Set while this thread runs the client's pre- or post-system-call event,
  // the only events from which DynamoRIO recovers a client write to a page it
  // made read-only (`runtime_compare_exchange_u32`).
  bool in_syscall_event;
  // Set only after the real Tool's successful thread-start hook. A fork copy
  // retains the parent's PID, which cannot acknowledge the child's admission.
  capture_owner_t capture_owner;
} prototype_counters_t;

#define TASK_STATE_FD 197
#define CLIENT_THREAD_START_FAILURE_EXIT_CODE 125
#define DBT_DIAGNOSTIC_FD 198
// Layout 7 combines controller admission and private-memory image ownership.
#define TASK_STATE_MAGIC UINT64_C(0x5245565049443037)
#define MAX_TASK_MEMBERSHIPS 8192
#define TEST_REUSED_TID_STALE 0
#define EXEC_HELPER_RETIREMENT_TIMEOUT_MS UINT64_C(60000)

struct process_control {
  int32_t kernel_pid;
  int32_t birth_token;
  bool root_process;
  // Reserved before a process clone enters Linux; only successful Tool
  // admission or that exact failed clone transaction retires the reservation.
  _Atomic bool capture_pending_admission;
  // 0: unclaimed, 1: appending, 2: append attempt finished (including error).
  // The existing birth owner is shared by threads, never by another process.
  _Atomic uint32_t terminal_stats_state;
  _Atomic uint64_t pending_thread_clones;
  _Atomic uint64_t image_epoch;
  _Atomic uint64_t finished_helper_epoch;
  // Published by finished_helper_epoch after this helper's acknowledged FINAL.
  int32_t helper_pid;
  uint64_t helper_start_time;
  // Protected by task_state->lock. Published extents belong to this exact
  // image, not to whichever process later reuses its numeric PID.
  private_memory_snapshot_t private_memory;
  uint32_t memory_published;
  uint32_t memory_retired;
};
_Static_assert(sizeof(process_control_t) == 160, "shared process control layout");

typedef struct {
  uint64_t magic;
  atomic_flag lock;
  _Atomic int32_t next_birth_token;
  int32_t root_pid;
  int32_t root_birth_token;
  _Atomic size_t process_control_count;
  process_control_t process_controls[MAX_TASK_MEMBERSHIPS];
  _Atomic bool thread_clone_process_exit_test_exercised;
  /* The launch-time descriptor identity survives exec, unlike numeric fd 0. */
  bool initial_stdin_valid;
  struct stat initial_stdin;
  /* The root resolves the coordinator environment before any fork. Copied
   * runtimes inherit this shared flag instead of consulting Rust's post-fork
   * environment state. */
  bool external_global;
  _Atomic bool capture_uncertain;
  bool capture_procfs_valid;
  uint64_t capture_procfs_device;
  uint64_t capture_procfs_inode;
  // Recreating an invalid inherited transport cannot restore memory authority.
  // This withdrawal follows fork/exec with the table, not just this image.
  bool private_memory_authority;
  size_t task_count;
  task_membership_t tasks[MAX_TASK_MEMBERSHIPS];
} task_state_t;

#define X32_SYSCALL_BIT UINT32_C(0x40000000)
#define X86_32_SYS_SETPGID 57
#define X86_32_SYS_SETSID 66

// Emits a pre-formatted line of tool output through DynamoRIO's own I/O. The
// simple observation tools (syscall histogram, strace) call back through this
// rather than writing to fd 2 directly: the guest can close its stderr before
// exit, and app-level writes re-enter the syscall interception path.
typedef void (*reverie_emit_fn_t)(const char* buf, size_t len);
typedef void (*reverie_idle_fn_t)(void);
#define REVERIE_DBT_RUNTIME_ABI_VERSION 11u
#define REVERIE_DBT_STARTUP_STANDALONE 1u
#define REVERIE_DBT_STARTUP_COORDINATED 2u
// TODO-HUMAN-REVIEW(PR-162): Review the additive stdout-emit runtime callback
// ABI.
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
  // Structured tracing records use a distinct authenticated transport. Raw
  // lifecycle and unsupported-syscall diagnostics remain on `emit`.
  reverie_emit_fn_t emit_evidence;
  // DbtEvidenceLogLevel discriminant: off/error/warn/info/debug/trace = 0..5.
  int32_t evidence_log_level;
  // Atomic compare-and-exchange of an aligned guest word
  // (`runtime_compare_exchange_u32`), the runtime's
  // MemoryAccess::compare_exchange_u32. Added in ABI version 8.
  memory_compare_exchange_t compare_exchange_u32;
  controller_capture_control_t controller_capture_control;
  // Fixed-size current-owner query or foreign owner/version validation.
  runtime_private_memory_t runtime_private_memory;
} runtime_callbacks_t;
_Static_assert(sizeof(runtime_callbacks_t) == 72, "runtime callbacks ABI size");
_Static_assert(offsetof(runtime_callbacks_t, controller_capture_control) == 56,
    "controller capture callback ABI offset");
_Static_assert(offsetof(runtime_callbacks_t, runtime_private_memory) == 64,
    "private memory callback ABI offset");
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#90): Confirm diagnostic fd ownership across exec.
// Inherited from the launcher so guest stderr redirections cannot capture it.
static file_t diagnostic_file;
static char unsupported_report_path[4096];
static file_t unsupported_report_file = INVALID_FILE;
static void reverie_dbt_emit(const char* buf, size_t len) {
  dr_write_file(diagnostic_file, buf, len);
}
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-162): Review the native stdout emit path.
// Emits pre-formatted bytes to real stdout via DynamoRIO's own I/O. Like
// `reverie_dbt_emit`, this avoids re-entering the syscall interception path
// that an app-level `write(1, ...)` would trigger, and works even after the
// guest has closed its own stdout.
static void reverie_dbt_emit_stdout(const char* buf, size_t len) {
  dr_write_file(STDOUT, buf, len);
}
static void reverie_dbt_emit_evidence(const char* buf, size_t len);
static void runtime_idle(void);

// TODO-HUMAN-REVIEW(PR-131): Review the native thread lifecycle callback ABI.
extern int32_t reverie_dbt_runtime_thread_init(
    prototype_counters_t* counters,
    void* context,
    int32_t tid,
    int32_t pid,
    int32_t in_tree_ppid,
    uint64_t branches,
    int32_t defer_runtime,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers,
    register_writer_t write_registers);
extern uint32_t reverie_dbt_runtime_abi_version(void);
extern size_t reverie_dbt_runtime_callbacks_size(void);
extern int32_t reverie_dbt_runtime_thread_created_v2(
    prototype_counters_t* counters,
    void* context,
    int32_t parent_tid,
    int32_t pid,
    uint64_t branches,
    int32_t child_tid,
    int32_t child_runtime_tid,
    uint64_t child_tid_addr,
    uint64_t flags,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers,
    register_writer_t write_registers);

extern void reverie_dbt_runtime_thread_exit(
    prototype_counters_t* counters,
    void* context,
    int32_t tid,
    syscall_invoker_t invoke_syscall);
extern uint64_t reverie_dbt_runtime_image_init(void);
extern void reverie_dbt_runtime_exec_failed(
    prototype_counters_t* counters,
    int32_t pid);
extern int32_t reverie_dbt_runtime_process_clone_result(
    prototype_counters_t* counters,
    void* context,
    int32_t parent_tid,
    int32_t parent_pid,
    uint64_t branches,
    int64_t sysnum,
    int64_t result,
    int32_t child_tid,
    uint64_t child_tid_addr,
    uint64_t flags,
    int32_t exit_signal,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers,
    register_writer_t write_registers);
extern int32_t reverie_dbt_runtime_background_init_v3(
    void* argument,
    uint32_t native_mode);
extern int32_t reverie_dbt_runtime_ready(uint64_t image_generation);
extern void reverie_dbt_runtime_process_exit(void);
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-219): Review copied-child argument and errno policy ABI.
extern int32_t reverie_dbt_runtime_copied_syscall(
    int64_t sysnum,
    const uint64_t* args);
// TODO-HUMAN-REVIEW(PR-154): Review the deferred lifecycle syscall callback
// ABI.
extern int32_t reverie_dbt_runtime_pre_syscall(
    void* context,
    prototype_counters_t* counters,
    int32_t tid,
    int32_t pid,
    uint64_t image_generation,
    int64_t sysnum,
    const uint64_t* args,
    uint64_t branches,
    int64_t* result,
    int64_t* deferred_sysnum,
    uint64_t* deferred_args,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers,
    register_writer_t write_registers,
    memory_reader_t read_memory,
    memory_writer_t write_memory,
    reverie_emit_fn_t emit);
extern int32_t reverie_dbt_runtime_signal_event(
    void* context, void* counters, int32_t tid, int32_t pid,
    uint64_t image_generation, uint64_t branches, dbt_signal_event_t* event,
    syscall_invoker_t invoke_syscall, register_reader_t read_registers,
    register_writer_t write_registers, memory_reader_t read_memory,
    memory_writer_t write_memory, reverie_emit_fn_t emit);
// Answers one rdtsc (with_aux == 0) or rdtscp: 1 with *tsc (and *aux) written
// when the runtime's tool answers it, 0 when the runtime leaves it to the
// client's fixed-stride counter, negative on failure (ABI version 5).
extern int32_t reverie_dbt_runtime_rdtsc(
    void* context,
    prototype_counters_t* counters,
    int32_t tid,
    int32_t pid,
    uint64_t branches,
    int32_t with_aux,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers,
    register_writer_t write_registers,
    reverie_emit_fn_t emit,
    uint64_t* tsc,
    uint32_t* aux);
// Answers one cpuid for leaf and subleaf: 1 with registers[0..3] written as
// EAX, EBX, ECX and EDX, negative on failure (ABI version 9). The client has no
// CPUID table of its own; under Detcore the answer is Detcore's machine
// description, the one /proc/cpuinfo is rendered from.
extern int32_t reverie_dbt_runtime_cpuid(
    void* context,
    prototype_counters_t* counters,
    int32_t tid,
    int32_t pid,
    uint64_t branches,
    uint32_t leaf,
    uint32_t subleaf,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers,
    register_writer_t write_registers,
    reverie_emit_fn_t emit,
    uint32_t registers[4]);
extern const char* reverie_dbt_runtime_name(void);
extern uint8_t reverie_dbt_runtime_kind_code(void);
extern void reverie_dbt_runtime_totals(
    uint64_t* branches,
    uint64_t* syscalls,
    uint64_t* rewritten,
    uint64_t* memory_hash);

static _Atomic uint64_t branch_count __attribute__((aligned(64)));
static _Atomic uint64_t stdin_read_count;
static _Atomic int32_t runtime_background_state;
static _Atomic uint64_t image_generation;
static _Atomic bool runtime_backend_failure;
static int thread_state_index;
static reg_id_t admission_state_tls_register;
static uint admission_state_tls_offset;
static int compat_gateway_index;
static ptr_uint_t cpuid_marker_note;
static ptr_uint_t rdtsc_marker_note;
static ptr_uint_t rdtscp_marker_note;
static bool report_summary;
static bool test_wait_for_background;
static bool test_delay_exec_helper_exit;
static bool test_kill_announced_child;
static bool test_thread_exit_evidence;
static bool test_leave_process_clone_result_pending;
static bool test_backend_failure;
static bool test_copied_backend_failure;
static bool test_skip_terminal_cleanup;
static bool test_backend_failure_sender_lookup_miss;
static bool test_compare_exchange;
static bool test_controller_capture;
static atomic_flag controller_capture_self_tested = ATOMIC_FLAG_INIT;
static void run_controller_capture_self_test(void);
enum {
  PRIVATE_MEMORY_TEST_NONE,
  PRIVATE_MEMORY_TEST_READY,
  PRIVATE_MEMORY_TEST_RETIRE,
  PRIVATE_MEMORY_TEST_LOST_EXEC,
  PRIVATE_MEMORY_TEST_ROUTES,
};
static int test_private_memory;
static bool test_private_memory_loss_injected;
static atomic_flag compare_exchange_self_tested = ATOMIC_FLAG_INIT;
static void run_compare_exchange_self_test(void);
static uint32_t compare_exchange_word(
    uint32_t* word,
    uint32_t expected,
    uint32_t desired);
/* How many exchanges compare_exchange_word has made, for the self-test's check
 * that runtime_compare_exchange_u32 goes through it. */
static _Atomic uint64_t compare_exchange_word_calls;
static bool test_reused_tid;
static bool test_thread_clone_process_exit;
static bool test_thread_start_write;
static bool test_stalled_thread_start;
static uint64_t test_thread_start_write_address;
static _Atomic bool test_reused_tid_exercised;
static _Atomic bool test_reused_tid_waited;
// Typed backend-statistics sink path. When the launcher passes
// `-stats_path <path>`, each real runtime image appends exactly one fixed-size
// binary record to this file at `event_exit` (or before terminating the tree
// for a copied syscall refusal), using DynamoRIO's own
// append-mode file I/O (O_APPEND, so concurrent process images append their
// 144-byte records atomically without interleaving). The launcher decodes and
// commutatively aggregates every record in the process tree (see
// src/backend_stats.rs). An empty path means stats collection is off. Using a
// shared path instead of an inherited fd avoids the drrun->guest exec fd
// inheritance problem that the diagnostic fd works around.
static char stats_path[4096];
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review branch-count preemption
// configuration. Deterministic branch-count preemption. When
// `preemption_enabled` (set from the
// `-preemption-quantum N` client arg with N > 0), the client injects a
// synthetic sched_yield scheduler turn every `preemption_quantum` counted app
// branches so a running guest thread returns control to Detcore's scheduler
// between syscalls. Both default to the disabled state, so guests run unchanged
// unless the quantum is supplied.
static bool preemption_enabled;
static uint64_t preemption_quantum;
// When true, preemption is delivered only at PCs in the guest's main executable
// (see `pc_in_main_executable`). Default true (conservative). Set to false via
// the `HERMIT_DBT_PREEMPT_ANYPC` environment variable to allow delivery at any
// PC, which is needed for guests whose starving loop runs inside libc.
static bool preempt_gate_main_only = true;

// Deterministic virtual timestamp counter. Under DBT only one guest thread runs
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
static bool has_copied_runtime(void);
static bool is_copied_vfork_process(void);
static void finalize_runtime_process(void);
static void mark_backend_failure(void);
static void publish_copied_terminal_stats(process_control_t* process);
static void complete_runtime_thread_exit(
    prototype_counters_t* counters,
    void* drcontext,
    bool explicit_exit,
    bool exit_group);
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-84): Review isolation-aware process-group termination.
// The run's root: the launcher's child, which execs drrun into the guest.
// Found from the launcher's pid by walking parents (`launch_root_below`), so it
// does not depend on the guest's process groups or sessions. The name is
// historical: it was the launch process group, whose id was the root's pid.
static process_id_t runtime_process_group;
// Whether the launcher contains the run by its process group, which a guest's
// setsid or setpgid would leave (`-contain-by-process-group`).
static bool contain_by_process_group;

// The parent of `pid`, from /proc/<pid>/stat, or 0 where it cannot be read.
static process_id_t parent_of(process_id_t pid) {
  char path[64];
  char buffer[512];
  dr_snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;
  ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
  close(fd);
  if (length <= 0)
    return 0;
  buffer[length] = '\0';
  // The name is in parentheses and may hold anything; the state and the
  // parent follow the last ')'.
  char* tail = strrchr(buffer, ')');
  int parent = 0;
  char state = 0;
  if (tail == NULL || dr_sscanf(tail + 1, " %c %d", &state, &parent) != 2)
    return 0;
  return (process_id_t)parent;
}

// The run's root: this process or the ancestor of it whose parent is the
// launcher, or whose parent is outside this PID namespace (0). A process the
// launcher adopted after its parent exited is its own root here; the launcher
// drains it when the run's root exits.
static process_id_t launch_root_below(process_id_t launcher) {
  process_id_t pid = dr_get_process_id();
  for (int depth = 0; depth < 4096; depth++) {
    process_id_t parent = parent_of(pid);
    if (parent == 0 || parent == launcher)
      return pid;
    pid = parent;
  }
  return 0;
}
static void terminate_runtime_tree(int exit_code) {
  // A copied child cannot kill its own process group and then run DynamoRIO
  // cleanup. Kill the run's root instead; the launcher reaps it and
  // terminates the rest of the run after preserving its exit status.
  if (runtime_process_group != 0 &&
      runtime_process_group != dr_get_process_id())
    kill((pid_t)runtime_process_group, SIGKILL);
  // The live terminal-record regression deliberately removes event_exit from
  // the failing copied child's execution. It must publish before killing root.
  if (test_skip_terminal_cleanup && has_copied_runtime())
    syscall(SYS_exit_group, exit_code);
  dr_exit_process(exit_code);
}

static void exit_runtime_tree(int exit_code) {
  mark_backend_failure();
  terminate_runtime_tree(exit_code);
}

// Only called from the normal copied syscall callback, after admission and
// callback locks have been released. The stats sink's DR file I/O is not an
// async-signal-safe operation and does not belong in arbitrary fatal contexts.
static void exit_copied_syscall_failure(process_control_t* process) {
  mark_backend_failure();
  // Uncontained runs can keep their parent alive; retain their existing
  // event_exit publication and DR cleanup. Only root termination races that
  // cleanup and needs the early record.
  if (runtime_process_group != 0 &&
      runtime_process_group != dr_get_process_id()) {
    publish_copied_terminal_stats(process);
    if (test_copied_backend_failure)
      publish_copied_terminal_stats(process); // Exercise idempotent publication.
  }
  terminate_runtime_tree(101);
}

#define EVIDENCE_CHANNEL_HEADER_LEN 80
#define EVIDENCE_TOKEN_LEN 32
#define EVIDENCE_ADDRESS_LEN 16
#define EVIDENCE_BUFFER_CAPACITY (1024 * 1024)
// A followed tree may create many short-lived app and scheduler processes.
// Bound client memory explicitly, fail closed at capacity, and reclaim only a
// finalized slot whose exact pid+starttime identity no longer exists.
#define EVIDENCE_MAX_SENDERS 8192
#define EVIDENCE_FRAME_START 1
#define EVIDENCE_FRAME_DATA 2
#define EVIDENCE_FRAME_EXEC 3
#define EVIDENCE_FRAME_EXEC_CANCEL 4
#define EVIDENCE_FRAME_FINAL 5
#define EVIDENCE_FRAME_ERROR 6
#define EVIDENCE_FRAME_CHILD 7
#define EVIDENCE_FINAL_GUEST_COMPLETED 0
#define EVIDENCE_FINAL_BACKEND_FAILURE 1
#define EVIDENCE_CONFIG_PAGE_SIZE 4096

static const unsigned char evidence_channel_magic[8] =
    {'R', 'V', 'D', 'B', 'T', 'E', '3', 0};
typedef union {
  struct {
    unsigned char enabled;
    unsigned char address[EVIDENCE_ADDRESS_LEN];
    unsigned char token[EVIDENCE_TOKEN_LEN];
  } value;
  unsigned char page[EVIDENCE_CONFIG_PAGE_SIZE];
} evidence_config_page_t;

// The application and client share one address space. Keep the endpoint and
// the gate-active bit on their own directly referenced page, then seal the page
// read-only before the first application instruction. Integrity never relies
// on the token being secret.
static evidence_config_page_t evidence_config_page
    __attribute__((aligned(EVIDENCE_CONFIG_PAGE_SIZE)));
typedef union {
  runtime_callbacks_t value;
  unsigned char page[EVIDENCE_CONFIG_PAGE_SIZE];
} runtime_callbacks_page_t;
_Static_assert(
    sizeof(runtime_callbacks_page_t) == EVIDENCE_CONFIG_PAGE_SIZE,
    "runtime callback page must occupy exactly one page");

// The guest and client share one address space, and this client loads at a
// stable preferred address. Keep every callback and policy field on a dedicated
// page, finish initialization in `dr_client_main`, and seal it before the first
// application instruction. Otherwise a syscall-free guest entry point could
// replace `emit_evidence` before the first syscall starts the background
// runtime, then forge records while the callback-depth gate is legitimately
// active.
static int32_t runtime_compare_exchange_u32(
    uintptr_t address,
    uint32_t expected,
    uint32_t desired,
    uint32_t* observed);
static runtime_callbacks_page_t runtime_callbacks_page
    __attribute__((aligned(EVIDENCE_CONFIG_PAGE_SIZE))) = {
        .value =
            {
                .emit = reverie_dbt_emit,
                .idle = runtime_idle,
                .panic_on_unsupported_syscalls = 0,
                .unsupported_report_fd = 0,
                .emit_stdout = reverie_dbt_emit_stdout,
                .emit_evidence = reverie_dbt_emit,
                .evidence_log_level = 0,
                .compare_exchange_u32 = runtime_compare_exchange_u32,
            },
};
typedef struct {
  process_id_t process;
  uint64_t start_time;
  uint64_t sequence;
  bool started;
  bool exec_pending;
  bool overflow;
  bool transport_failed;
  bool finalization_started;
  bool finalized;
  bool backend_failure;
  bool initialization_record_sent;
  uint32_t active_threads;
} evidence_sender_state_t;

static unsigned char* evidence_buffer;
static size_t evidence_buffer_length;
static void* evidence_lock;
static evidence_sender_state_t* evidence_senders;
static _Thread_local uint32_t evidence_callback_depth;
// Unlike the evidence tag, this is consulted by the admission ownership gate
// before any new signal callback can acquire runtime/thread-state references.
static _Thread_local uint32_t native_runtime_entries;
/* Only the terminal path of an unadmitted PID-namespace child sets this. */
static _Thread_local bool namespace_admission_refused;

static bool evidence_is_enabled(void) {
  return evidence_config_page.value.enabled != 0;
}

static void evidence_callback_enter(void) {
  ++native_runtime_entries;
  ++evidence_callback_depth;
}

static void evidence_callback_leave(void) {
  DR_ASSERT(native_runtime_entries != 0);
  --native_runtime_entries;
  DR_ASSERT(evidence_callback_depth != 0);
  --evidence_callback_depth;
}

static bool
decode_hex(const char* encoded, unsigned char* out, size_t out_len) {
  size_t index;
  if (encoded == NULL || strlen(encoded) != out_len * 2)
    return false;
  for (index = 0; index < out_len; ++index) {
    unsigned char high = (unsigned char)encoded[index * 2];
    unsigned char low = (unsigned char)encoded[index * 2 + 1];
    if (high >= '0' && high <= '9')
      high = (unsigned char)(high - '0');
    else if (high >= 'a' && high <= 'f')
      high = (unsigned char)(high - 'a' + 10);
    else
      return false;
    if (low >= '0' && low <= '9')
      low = (unsigned char)(low - '0');
    else if (low >= 'a' && low <= 'f')
      low = (unsigned char)(low - 'a' + 10);
    else
      return false;
    out[index] = (unsigned char)((high << 4) | low);
  }
  return true;
}

static void put_u32_le(unsigned char* out, uint32_t value) {
  out[0] = (unsigned char)(value & 0xff);
  out[1] = (unsigned char)((value >> 8) & 0xff);
  out[2] = (unsigned char)((value >> 16) & 0xff);
  out[3] = (unsigned char)((value >> 24) & 0xff);
}

static void put_u64_le(unsigned char* out, uint64_t value) {
  int byte;
  for (byte = 0; byte != 8; ++byte)
    out[byte] = (unsigned char)((value >> (byte * 8)) & 0xff);
}

static uint64_t
evidence_hash_update(uint64_t hash, const unsigned char* bytes, size_t length) {
  while (length-- != 0)
    hash = (hash ^ *bytes++) * UINT64_C(0x00000100000001b3);
  return hash;
}

static uint64_t evidence_frame_hash(
    uint64_t seed,
    unsigned char kind,
    size_t payload_length,
    uint64_t sequence,
    const unsigned char* payload) {
  unsigned char encoded_length[4];
  unsigned char encoded_sequence[8];
  put_u32_le(encoded_length, (uint32_t)payload_length);
  put_u64_le(encoded_sequence, sequence);
  seed = evidence_hash_update(seed, &kind, 1);
  seed = evidence_hash_update(seed, encoded_length, sizeof(encoded_length));
  seed = evidence_hash_update(seed, encoded_sequence, sizeof(encoded_sequence));
  return evidence_hash_update(seed, payload, payload_length);
}

static bool
evidence_write_all(int descriptor, const unsigned char* buffer, size_t length) {
  while (length != 0) {
    ssize_t written = write(descriptor, buffer, length);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return false;
    buffer += (size_t)written;
    length -= (size_t)written;
  }
  return true;
}

static bool evidence_send_frame(
    unsigned char kind,
    const unsigned char* payload,
    size_t payload_length,
    uint64_t sequence) {
  struct sockaddr_un address;
  unsigned char header[EVIDENCE_CHANNEL_HEADER_LEN] = {0};
  socklen_t address_length;
  const struct timeval timeout = {.tv_sec = 0, .tv_usec = 250000};
  int attempt;

  if (payload_length > EVIDENCE_BUFFER_CAPACITY)
    return false;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(
      address.sun_path + 1,
      evidence_config_page.value.address,
      sizeof(evidence_config_page.value.address));
  address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                               sizeof(evidence_config_page.value.address));

  memcpy(header, evidence_channel_magic, sizeof(evidence_channel_magic));
  memcpy(
      header + 8,
      evidence_config_page.value.token,
      sizeof(evidence_config_page.value.token));
  header[40] = kind;
  put_u32_le(header + 48, (uint32_t)payload_length);
  put_u64_le(header + 56, sequence);
  put_u64_le(
      header + 64,
      evidence_frame_hash(
          UINT64_C(0xcbf29ce484222325),
          kind,
          payload_length,
          sequence,
          payload));
  put_u64_le(
      header + 72,
      evidence_frame_hash(
          UINT64_C(0x9e3779b97f4a7c15),
          kind,
          payload_length,
          sequence,
          payload));

  // A frame is applied only once by sequence plus its two payload hashes. If
  // the collector accepted it but its ACK was lost, resend the identical frame
  // instead of converting scheduler delay into evidence failure.
  for (attempt = 0; attempt != 20; ++attempt) {
    unsigned char acknowledgement = 1;
    ssize_t received;
    bool ok;
    int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
      dr_sleep(1);
      continue;
    }
    if (setsockopt(
            descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) !=
            0 ||
        setsockopt(
            descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) !=
            0 ||
        connect(descriptor, (const struct sockaddr*)&address, address_length) !=
            0) {
      close(descriptor);
      dr_sleep(1);
      continue;
    }
    ok = evidence_write_all(descriptor, header, sizeof(header)) &&
        evidence_write_all(descriptor, payload, payload_length);
    do {
      received = ok ? read(descriptor, &acknowledgement, 1) : -1;
    } while (received < 0 && errno == EINTR);
    close(descriptor);
    if (received == 1)
      return acknowledgement == 0;
    dr_sleep(1);
  }
  return false;
}

typedef enum {
  PROCESS_IDENTITY_ERROR = -1,
  PROCESS_IDENTITY_ABSENT = 0,
  PROCESS_IDENTITY_PRESENT = 1,
} process_identity_result_t;

static process_identity_result_t read_process_identity(
    process_id_t process,
    uint64_t* start_time,
    char* state) {
  char path[64];
  char stat_buffer[1024];
  char* cursor;
  char* end;
  int descriptor;
  int length;
  int field;
  uint64_t parsed = 0;
  length = dr_snprintf(path, sizeof(path), "/proc/%d/stat", (int)process);
  if (length <= 0 || (size_t)length >= sizeof(path))
    return PROCESS_IDENTITY_ERROR;
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0)
    return errno == ENOENT || errno == ESRCH ? PROCESS_IDENTITY_ABSENT
                                           : PROCESS_IDENTITY_ERROR;
  do {
    length = (int)read(descriptor, stat_buffer, sizeof(stat_buffer) - 1);
  } while (length < 0 && errno == EINTR);
  int read_error = length < 0 ? errno : 0;
  close(descriptor);
  if (read_error == ENOENT || read_error == ESRCH)
    return PROCESS_IDENTITY_ABSENT;
  if (length <= 0 || (size_t)length >= sizeof(stat_buffer))
    return PROCESS_IDENTITY_ERROR;
  stat_buffer[length] = 0;
  cursor = strrchr(stat_buffer, ')');
  if (cursor == NULL)
    return PROCESS_IDENTITY_ERROR;
  ++cursor;
  for (field = 3; field <= 22; ++field) {
    while (*cursor == ' ')
      ++cursor;
    if (*cursor == 0)
      return PROCESS_IDENTITY_ERROR;
    end = cursor;
    while (*end != 0 && *end != ' ')
      ++end;
    if (field == 3) {
      if (end - cursor != 1)
        return PROCESS_IDENTITY_ERROR;
      *state = *cursor;
    }
    if (field == 22) {
      if (cursor == end)
        return PROCESS_IDENTITY_ERROR;
      while (cursor != end) {
        if (*cursor < '0' || *cursor > '9')
          return PROCESS_IDENTITY_ERROR;
        parsed = parsed * 10 + (uint64_t)(*cursor++ - '0');
      }
      *start_time = parsed;
      return PROCESS_IDENTITY_PRESENT;
    }
    cursor = end;
  }
  return PROCESS_IDENTITY_ERROR;
}

static bool evidence_process_start_time(
    process_id_t process,
    uint64_t* start_time) {
  char state;
  return read_process_identity(process, start_time, &state) ==
      PROCESS_IDENTITY_PRESENT;
}

static bool evidence_current_identity(
    process_id_t* process,
    uint64_t* start_time) {
  *process = (process_id_t)getpid();
  return evidence_process_start_time(*process, start_time);
}

static evidence_sender_state_t* evidence_sender_locked(void) {
  process_id_t process;
  uint64_t start_time;
  evidence_sender_state_t* empty = NULL;
  evidence_sender_state_t* reusable = NULL;
  size_t index;
  if (!evidence_current_identity(&process, &start_time))
    return NULL;
  for (index = 0; index != EVIDENCE_MAX_SENDERS; ++index) {
    evidence_sender_state_t* candidate = &evidence_senders[index];
    if (candidate->process == process && candidate->start_time == start_time)
      return candidate;
    if (candidate->process == 0 && empty == NULL)
      empty = candidate;
    if (candidate->finalized && reusable == NULL) {
      uint64_t observed_start_time;
      if (!evidence_process_start_time(
              candidate->process, &observed_start_time) ||
          observed_start_time != candidate->start_time)
        reusable = candidate;
    }
  }
  if (empty == NULL)
    empty = reusable;
  if (empty == NULL) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: evidence sender-state capacity exceeded\n");
    return NULL;
  }
  memset(empty, 0, sizeof(*empty));
  empty->process = process;
  empty->start_time = start_time;
  return empty;
}

static void mark_backend_failure(void) {
  evidence_sender_state_t* sender;
  // Make the failure sticky before the sender lookup: that lookup reads procfs
  // and can fail transiently. Cleanup must never recover the lookup and emit a
  // normal FINAL after an internal failure.
  atomic_store_explicit(&runtime_backend_failure, true, memory_order_release);
  if (!evidence_is_enabled() || evidence_lock == NULL)
    return;
  if (test_backend_failure_sender_lookup_miss) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: skipped backend failure sender lookup for testing\n");
    return;
  }
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender != NULL)
    sender->backend_failure = true;
  dr_mutex_unlock(evidence_lock);
}

static bool evidence_flush_locked(
    evidence_sender_state_t* sender,
    unsigned char terminal_kind) {
  if (sender == NULL || sender->finalized)
    return false;
  if (!sender->started) {
    if (!evidence_send_frame(EVIDENCE_FRAME_START, NULL, 0, 0))
      return false;
    sender->sequence = 1;
    sender->started = true;
  }
  if (sender->overflow) {
    static const unsigned char message[] = "client evidence buffer overflow";
    (void)evidence_send_frame(
        EVIDENCE_FRAME_ERROR, message, sizeof(message) - 1, sender->sequence++);
    return false;
  }
  if (evidence_buffer_length != 0) {
    if (!evidence_send_frame(
            EVIDENCE_FRAME_DATA,
            evidence_buffer,
            evidence_buffer_length,
            sender->sequence++))
      return false;
    evidence_buffer_length = 0;
  }
  if (terminal_kind != 0) {
    unsigned char final_outcome = EVIDENCE_FINAL_GUEST_COMPLETED;
    const unsigned char* payload = NULL;
    size_t payload_length = 0;
    if (terminal_kind == EVIDENCE_FRAME_FINAL) {
      sender->backend_failure |=
          atomic_load_explicit(&runtime_backend_failure, memory_order_acquire);
      final_outcome = sender->backend_failure ? EVIDENCE_FINAL_BACKEND_FAILURE
                                              : EVIDENCE_FINAL_GUEST_COMPLETED;
      payload = &final_outcome;
      payload_length = sizeof(final_outcome);
    }
    if (!evidence_send_frame(
            terminal_kind, payload, payload_length, sender->sequence++))
      return false;
    if (terminal_kind == EVIDENCE_FRAME_EXEC)
      sender->exec_pending = true;
    else if (terminal_kind == EVIDENCE_FRAME_EXEC_CANCEL)
      sender->exec_pending = false;
    else if (terminal_kind == EVIDENCE_FRAME_FINAL) {
      sender->started = false;
      sender->finalized = true;
    }
  }
  return true;
}

static bool evidence_flush(unsigned char terminal_kind) {
  bool ok;
  evidence_sender_state_t* sender;
  if (!evidence_is_enabled())
    return true;
  // The live negative test withholds the child's frames after the parent has
  // announced it, then kills it. Publication must refuse that missing process.
  if (test_kill_announced_child && runtime_process_group != 0 &&
      dr_get_process_id() != runtime_process_group)
    return true;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender == NULL) {
    dr_mutex_unlock(evidence_lock);
    return false;
  }
  if (terminal_kind == EVIDENCE_FRAME_EXEC_CANCEL && !sender->exec_pending) {
    dr_mutex_unlock(evidence_lock);
    return false;
  }
  if (terminal_kind == EVIDENCE_FRAME_EXEC && sender->exec_pending) {
    dr_mutex_unlock(evidence_lock);
    return false;
  }
  ok =
      !sender->transport_failed && evidence_flush_locked(sender, terminal_kind);
  if (!ok)
    sender->transport_failed = true;
  dr_mutex_unlock(evidence_lock);
  return ok;
}

static void require_evidence_flush(unsigned char terminal_kind) {
  if (!evidence_flush(terminal_kind)) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: protected evidence transport failed\n");
    exit_runtime_tree(101);
  }
}

static void reverie_dbt_emit_evidence(const char* buf, size_t len) {
  bool ok;
  evidence_sender_state_t* sender;
  if (!evidence_is_enabled()) {
    reverie_dbt_emit(buf, len);
    return;
  }
  if (test_kill_announced_child && runtime_process_group != 0 &&
      dr_get_process_id() != runtime_process_group)
    return;
  if (evidence_callback_depth == 0) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: rejected evidence outside a protected callback\n");
    exit_runtime_tree(101);
    return;
  }
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (len == 0 || len > EVIDENCE_BUFFER_CAPACITY - 4) {
    if (sender != NULL)
      sender->overflow = true;
  } else {
    put_u32_le(evidence_buffer, (uint32_t)len);
    memcpy(evidence_buffer + 4, buf, len);
    evidence_buffer_length = len + 4;
  }
  // Each structured tracing callback is one authenticated DATA frame. The ACK
  // arrives before this callback returns, preserving callback order across
  // processes instead of deferring records until a later syscall or exit.
  ok = sender != NULL && !sender->transport_failed &&
      evidence_flush_locked(sender, 0);
  if (!ok && sender != NULL)
    sender->transport_failed = true;
  dr_mutex_unlock(evidence_lock);
  if (!ok) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: protected evidence record send failed\n");
    exit_runtime_tree(101);
  }
}

static bool evidence_announce_child(process_id_t child) {
  unsigned char payload[12];
  evidence_sender_state_t* sender;
  uint64_t child_start_time;
  bool ok;
  if (!evidence_is_enabled())
    return true;
  if (child <= 0 || !evidence_process_start_time(child, &child_start_time))
    return false;
  put_u32_le(payload, (uint32_t)child);
  put_u64_le(payload + 4, child_start_time);
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender != NULL && !sender->started)
    ok = evidence_flush_locked(sender, 0);
  else
    ok = sender != NULL;
  if (ok)
    ok = !sender->transport_failed &&
        evidence_send_frame(
            EVIDENCE_FRAME_CHILD, payload, sizeof(payload), sender->sequence++);
  if (!ok && sender != NULL)
    sender->transport_failed = true;
  dr_mutex_unlock(evidence_lock);
  return ok;
}

static void require_evidence_child(process_id_t child) {
  if (!evidence_announce_child(child)) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: protected child evidence announcement failed\n");
    exit_runtime_tree(101);
  }
}

static void evidence_thread_enter(prototype_counters_t* counters) {
  evidence_sender_state_t* sender;
  if (!evidence_is_enabled())
    return;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender == NULL || sender->active_threads == UINT32_MAX) {
    dr_mutex_unlock(evidence_lock);
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: protected evidence thread count failed\n");
    exit_runtime_tree(101);
    return;
  }
  ++sender->active_threads;
  counters->evidence_thread_process = dr_get_process_id();
  dr_mutex_unlock(evidence_lock);
}

static void evidence_count_fork_child_thread(prototype_counters_t* counters) {
  evidence_sender_state_t* sender;
  process_id_t process = dr_get_process_id();
  if (!evidence_is_enabled() || counters->evidence_thread_process == process)
    return;

  // DynamoRIO keeps the calling application thread across fork without
  // issuing a new thread_init callback in the child. Count that surviving
  // thread at the child-side clone boundary, before it can create and join
  // additional threads whose exits would otherwise look like the process end.
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender == NULL || sender->active_threads != 0) {
    dr_mutex_unlock(evidence_lock);
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: protected fork-child thread count failed\n");
    exit_runtime_tree(101);
    return;
  }
  sender->active_threads = 1;
  counters->evidence_thread_process = process;
  dr_mutex_unlock(evidence_lock);
}

static void evidence_emit_image_initialization(void) {
  static const char record[] =
      "1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: "
      "protected evidence initialized\n";
  evidence_sender_state_t* sender;
  bool emit = false;
  if (!evidence_is_enabled())
    return;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender != NULL && !sender->initialization_record_sent) {
    sender->initialization_record_sent = true;
    emit = true;
  }
  dr_mutex_unlock(evidence_lock);
  if (!emit) {
    if (sender == NULL) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: protected evidence image initialization failed\n");
      exit_runtime_tree(101);
    }
    return;
  }
  reverie_dbt_emit_evidence(record, sizeof(record) - 1);
}

static void evidence_initialize_fork_child_thread(
    prototype_counters_t* counters) {
  evidence_count_fork_child_thread(counters);
  evidence_callback_enter();
  evidence_emit_image_initialization();
  evidence_callback_leave();
}

static void evidence_thread_leave(prototype_counters_t* counters) {
  evidence_sender_state_t* sender;
  bool last_thread;
  process_id_t process = dr_get_process_id();
  if (!evidence_is_enabled() || counters->evidence_thread_process != process)
    return;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender == NULL || sender->active_threads == 0) {
    dr_mutex_unlock(evidence_lock);
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: protected evidence thread exit was uncounted\n");
    exit_runtime_tree(101);
    return;
  }
  last_thread = --sender->active_threads == 0;
  counters->evidence_thread_process = 0;
  dr_mutex_unlock(evidence_lock);
  if (last_thread &&
      !(test_kill_announced_child && runtime_process_group != 0 &&
        process != runtime_process_group))
    finalize_runtime_process();
}

static void initialize_evidence_transport(void) {
  if (!evidence_is_enabled())
    return;
  evidence_lock = dr_mutex_create();
  evidence_buffer = (unsigned char*)dr_global_alloc(EVIDENCE_BUFFER_CAPACITY);
  evidence_senders = (evidence_sender_state_t*)dr_global_alloc(
      sizeof(evidence_sender_state_t) * EVIDENCE_MAX_SENDERS);
  DR_ASSERT(
      evidence_lock != NULL && evidence_buffer != NULL &&
      evidence_senders != NULL);
  memset(
      evidence_senders,
      0,
      sizeof(evidence_sender_state_t) * EVIDENCE_MAX_SENDERS);
}
static int32_t runtime_process_id;
static bool runtime_is_root;
static int32_t runtime_parent_process_id;
static task_state_t* task_state;
static uint64_t task_state_device;
static uint64_t task_state_inode;
static bool task_state_identity_valid;
static bool task_state_identity_lost;
// Separate from the process/helper owner: CLONE_VM children share this token,
// while a separate-VM fork receives its own existing process-control slot.
static size_t runtime_memory_owner_slot = SIZE_MAX;
static uint64_t runtime_memory_owner_epoch;
static process_id_t runtime_memory_owner_pid;
// Private to this image, including its one background helper. Copied children
// never start an inherited helper; their first exec claims their own record.
static process_control_t* runtime_process_control;
static uint64_t runtime_process_epoch;
static bool runtime_retirement_requested;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-154): Review serialized clone identity handoff.
static atomic_flag pending_clone_lock = ATOMIC_FLAG_INIT;
static _Atomic int32_t pending_clone_birth_token;
static _Atomic int32_t pending_clone_creator_pid;
static _Atomic uint64_t pending_clone_flags;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-262): Review copied-vfork native-gate lifetime.
static _Atomic int32_t copied_vfork_pid;
/* A copied child initializes its inherited Rust runtime on its first syscall.
 * Track the process that completed that handoff rather than a boolean: nested
 * fork children inherit the parent's globals and must rebase again. */
static process_id_t copied_process_runtime_pid;

/* Latch for `scrub_guest_stack_residue`: 0 means the application's dead stack
 * may still hold DynamoRIO addresses and the next scrub point must clear it.
 * The INITIAL scrub is NOT syscall-triggered -- it runs at the guest's first
 * application instruction, before the guest has executed anything, which is
 * exactly what makes erasing the region sound. (An earlier revision scrubbed at
 * the first syscall; by then the guest has run and its own writes below the
 * stack pointer would be destroyed. This comment described that superseded
 * design.) Set
 * once per DynamoRIO initialization and re-armed after a clone-family syscall,
 * the other point at which DynamoRIO is measured to deposit its own addresses
 * on the application stack. Declared here, ahead of `post_syscall`, so the
 * re-arm can reach it. */
static _Atomic int32_t guest_stack_scrubbed;

/* Set once the first scrub has run. Distinguishes the initial scrub, where the
 * dead stack below the application's stack pointer is DynamoRIO's and the
 * loader's, from every later (clone-re-armed) scrub, by which time the guest
 * has run and its own dead frames are in the same range. */
static _Atomic int32_t guest_stack_initially_scrubbed;

/* Clean call that performs the INITIAL scrub at the guest's first application
 * instruction. Declared here, ahead of `instrument_instruction`, so the
 * instrumentation hook can reach it; defined beside
 * `scrub_guest_stack_residue`, whose rules it exists to make sound. */
static void scrub_guest_stack_before_first_instruction(void);

static bool map_inherited_task_state(void) {
  struct stat status;
  void* mapping;
  if (fstat(TASK_STATE_FD, &status) != 0) {
    // DR records followed exec before removing its private environment marker.
    // A missing inherited descriptor must not masquerade as a fresh root.
    if (errno != EBADF || dr_is_post_execve())
      task_state_identity_lost = true;
    return false;
  }
  if (status.st_size != (off_t)sizeof(*task_state)) {
    task_state_identity_lost = true;
    return false;
  }
  mapping = mmap(
      NULL,
      sizeof(*task_state),
      PROT_READ | PROT_WRITE,
      MAP_SHARED,
      TASK_STATE_FD,
      0);
  if (mapping == MAP_FAILED) {
    task_state_identity_lost = true;
    return false;
  }
  task_state = (task_state_t*)mapping;
  if (task_state->magic == TASK_STATE_MAGIC) {
    task_state_device = (uint64_t)status.st_dev;
    task_state_inode = (uint64_t)status.st_ino;
    task_state_identity_valid = task_state->private_memory_authority;
    return true;
  }
  task_state_identity_lost = true;
  munmap(mapping, sizeof(*task_state));
  task_state = NULL;
  return false;
}

/* Authenticate the initial proc numbering view while the root has not run.
 * Keep only object identity, never a directory capability in the guest table. */
static void initialize_capture_procfs_view(void) {
  struct stat root, self, numeric;
  struct statfs filesystem;
  char pid_name[32];
  int root_fd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0)
    return;
  int length = dr_snprintf(
      pid_name, sizeof(pid_name), "%d", (int)dr_get_process_id());
  bool valid = length > 0 && (size_t)length < sizeof(pid_name) &&
      fstat(root_fd, &root) == 0 && S_ISDIR(root.st_mode) &&
      fstatfs(root_fd, &filesystem) == 0 &&
      filesystem.f_type == PROC_SUPER_MAGIC &&
      fstatat(root_fd, "self", &self, 0) == 0 &&
      fstatat(root_fd, pid_name, &numeric, 0) == 0 &&
      S_ISDIR(self.st_mode) && S_ISDIR(numeric.st_mode) &&
      self.st_dev == numeric.st_dev && self.st_ino == numeric.st_ino;
  int closed = close(root_fd);
  if (valid && closed == 0) {
    task_state->capture_procfs_device = (uint64_t)root.st_dev;
    task_state->capture_procfs_inode = (uint64_t)root.st_ino;
    task_state->capture_procfs_valid = true;
  }
}

static bool capture_may_initialize(bool descriptor_absent, bool followed_exec) {
  return descriptor_absent && !followed_exec;
}

static void initialize_task_state(bool external_global) {
  int descriptor;
  struct stat initial_descriptor;
  bool descriptor_absent = fstat(TASK_STATE_FD, &initial_descriptor) != 0 &&
      errno == EBADF;
  bool initial_absence =
      capture_may_initialize(descriptor_absent, dr_is_post_execve());
  if (map_inherited_task_state())
    return;

  descriptor = (int)syscall(SYS_memfd_create, "reverie-dbt-pids", 0);
  DR_ASSERT(descriptor >= 0);
  DR_ASSERT(ftruncate(descriptor, sizeof(*task_state)) == 0);
  if (descriptor != TASK_STATE_FD) {
    DR_ASSERT(dup2(descriptor, TASK_STATE_FD) == TASK_STATE_FD);
    close(descriptor);
  }
  DR_ASSERT(fcntl(TASK_STATE_FD, F_SETFD, 0) == 0);
  task_state = (task_state_t*)mmap(
      NULL,
      sizeof(*task_state),
      PROT_READ | PROT_WRITE,
      MAP_SHARED,
      TASK_STATE_FD,
      0);
  DR_ASSERT(task_state != MAP_FAILED);
  memset(task_state, 0, sizeof(*task_state));
  task_state->magic = TASK_STATE_MAGIC;
  atomic_flag_clear(&task_state->lock);
  atomic_init(&task_state->next_birth_token, 1);
  atomic_init(&task_state->process_control_count, 0);
  task_state->root_pid = (int32_t)dr_get_process_id();
  task_state->root_birth_token = atomic_fetch_add_explicit(
      &task_state->next_birth_token, 1, memory_order_relaxed);
  task_state->tasks[0] = (task_membership_t){
      task_state->root_pid, task_state->root_birth_token};
  task_state->task_count = 1;
  atomic_init(
      &task_state->thread_clone_process_exit_test_exercised, false);
  task_state->initial_stdin_valid =
      fstat(STDIN_FILENO, &task_state->initial_stdin) == 0;
  task_state->external_global = external_global;
  atomic_init(&task_state->capture_uncertain, !initial_absence);
  task_state->private_memory_authority = !task_state_identity_lost;
  struct stat backing;
  if (fstat(TASK_STATE_FD, &backing) == 0) {
    task_state_device = (uint64_t)backing.st_dev;
    task_state_inode = (uint64_t)backing.st_ino;
    task_state_identity_valid = task_state->private_memory_authority;
  } else {
    atomic_store_explicit(
        &task_state->capture_uncertain, true, memory_order_release);
    task_state->private_memory_authority = false;
  }
  if (initial_absence)
    initialize_capture_procfs_view();
}

/* Only a known new child can be checked here. Linux assigns TID 1 to a new
 * PID namespace's init; an ordinary child/thread cannot acquire its living
 * namespace init's TID. Initial client launch and exec reset the birth latch
 * and are not child admission. This catches direct NEWPID births and the first
 * child after PID-for-children changes without revalidating clone arguments.
 * Joining an already populated PID namespace in a standalone Tool is outside
 * this guard's scope; shared Detcore already refuses setns/unshare. */
static void release_clone_identity_handoff(int32_t birth_token);

static bool require_supported_child_pid_namespace(void) {
  if (syscall(SYS_gettid) != 1)
    return true;
  dr_fprintf(diagnostic_file,
      "reverie-dbt: refusing nested PID namespace task admission: "
      "container-observed child identity transport is not implemented\n");
  /* The cached outer PGID may alias an inner task. Do not signal it or run
   * client teardown against inherited parent state. DR must still remove this
   * task's record: a raw exit would leave a shared-VM parent's teardown waiting
   * for a dead task. Its application SYS_exit path performs thread cleanup
   * without the exit_group sweep over numerically matching process IDs. */
  namespace_admission_refused = true;
  release_clone_identity_handoff(atomic_load_explicit(
      &pending_clone_birth_token, memory_order_acquire));
  (void)dr_invoke_syscall_as_app(
      dr_get_current_drcontext(), SYS_exit, 1, (reg_t)101);
  /* The terminal syscall cannot return. Keep an API failure child-local. */
  syscall(SYS_exit_group, 101);
  return false;
}

static bool runtime_uses_external_global(void) {
  return task_state != NULL &&
      task_state->external_global;
}

static void task_state_lock(void) {
  while (atomic_flag_test_and_set_explicit(
      &task_state->lock, memory_order_acquire))
    dr_thread_yield();
}

static void task_state_unlock(void) {
  atomic_flag_clear_explicit(
      &task_state->lock, memory_order_release);
}

static int32_t next_birth_token(void) {
  return atomic_fetch_add_explicit(
      &task_state->next_birth_token, 1, memory_order_relaxed);
}

static bool lookup_task_birth(int32_t tid, int32_t* birth);

// Only initialize entries that have not been published in the atomic count.
static void initialize_process_control_locked(
    task_state_t* state, process_control_t* entry, int32_t kernel_pid,
    int32_t birth_token, bool pending) {
  entry->kernel_pid = kernel_pid;
  entry->birth_token = birth_token;
  entry->root_process = kernel_pid == state->root_pid &&
      birth_token == state->root_birth_token;
  atomic_init(&entry->capture_pending_admission, pending);
  atomic_init(&entry->terminal_stats_state, 0);
  atomic_init(&entry->pending_thread_clones, 0);
  atomic_init(&entry->image_epoch, 0);
  atomic_init(&entry->finished_helper_epoch, 0);
  entry->helper_pid = 0;
  entry->helper_start_time = 0;
  memset(&entry->private_memory, 0, sizeof(entry->private_memory));
  entry->memory_published = 0;
  entry->memory_retired = 0;
}

static void capture_mark_owner_uncertain(task_state_t* state) {
  if (state != NULL)
    atomic_store_explicit(&state->capture_uncertain, true, memory_order_release);
}

static void capture_mark_uncertain(void) {
  capture_mark_owner_uncertain(task_state);
}

/* These two locked operations also supply the synthetic component-test seam.
 * The live wrappers below always use the existing shared task-state owner. */
static void reserve_capture_admission_locked(task_state_t* state, int32_t birth) {
  size_t count = atomic_load_explicit(
      &state->process_control_count, memory_order_acquire);
  if (birth <= 0 || count > MAX_TASK_MEMBERSHIPS) {
    capture_mark_owner_uncertain(state);
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    process_control_t* entry = &state->process_controls[i];
    // Only authoritative failed creation leaves a counted slot in this state.
    // It has never had a published PID or a cached owner. Query readers can
    // already scan its atomics, so reuse uses stores, never atomic_init/memset.
    // A published memory token also permanently excludes a slot from reuse.
    if (entry->kernel_pid == 0 && entry->memory_published == 0 &&
        !atomic_load_explicit(
            &entry->capture_pending_admission, memory_order_acquire)) {
      atomic_store_explicit(
          &entry->capture_pending_admission, true, memory_order_release);
      entry->birth_token = birth;
      entry->root_process = false;
      atomic_store_explicit(&entry->terminal_stats_state, 0, memory_order_relaxed);
      atomic_store_explicit(&entry->pending_thread_clones, 0, memory_order_release);
      atomic_store_explicit(&entry->image_epoch, 0, memory_order_relaxed);
      atomic_store_explicit(&entry->finished_helper_epoch, 0, memory_order_relaxed);
      entry->helper_pid = 0;
      entry->helper_start_time = 0;
      return;
    }
  }
  if (count == MAX_TASK_MEMBERSHIPS) {
    capture_mark_owner_uncertain(state);
    return;
  }
  initialize_process_control_locked(
      state, &state->process_controls[count], 0, birth, true);
  // The initialized pending flag is visible before Linux can create the task.
  atomic_store_explicit(
      &state->process_control_count, count + 1, memory_order_release);
}

static void cancel_failed_capture_admission_locked(task_state_t* state, int32_t birth) {
  for (size_t i = 0; i < state->process_control_count; ++i) {
    process_control_t* entry = &state->process_controls[i];
    if (entry->birth_token == birth) {
      // A negative kernel clone result created no child. A conflicting
      // publication is uncertainty, never permission to clear a live owner.
      if (entry->kernel_pid == 0)
        atomic_store_explicit(
            &entry->capture_pending_admission, false, memory_order_release);
      else
        capture_mark_owner_uncertain(state);
      return;
    }
  }
  capture_mark_owner_uncertain(state);
}

/* The birth is reserved before Linux can create the task. Identity publication
 * and the parent's clone return cannot discharge it. */
static void reserve_capture_admission(int32_t birth_token) {
  if (task_state == NULL)
    return;
  task_state_lock();
  reserve_capture_admission_locked(task_state, birth_token);
  task_state_unlock();
}

static void cancel_failed_capture_admission(int32_t birth_token) {
  if (task_state == NULL || birth_token <= 0)
    return;
  task_state_lock();
  cancel_failed_capture_admission_locked(task_state, birth_token);
  task_state_unlock();
}

static process_control_t* process_control_for(int32_t kernel_pid) {
  int32_t birth_token;
  if (!lookup_task_birth(kernel_pid, &birth_token) || birth_token <= 0) {
    dr_fprintf(diagnostic_file,
        "reverie-dbt: missing process birth publication for kernel task %d\n",
        kernel_pid);
    exit_runtime_tree(101);
    return NULL;
  }
  task_state_lock();
  for (size_t i = 0; i < task_state->process_control_count; ++i) {
    process_control_t* entry = &task_state->process_controls[i];
    if (entry->birth_token == birth_token &&
        (entry->kernel_pid == 0 || entry->kernel_pid == kernel_pid)) {
      if (entry->kernel_pid == 0)
        entry->kernel_pid = kernel_pid;
      task_state_unlock();
      return entry;
    }
  }
  if (task_state->process_control_count >= MAX_TASK_MEMBERSHIPS) {
    capture_mark_uncertain();
    task_state_unlock();
    dr_fprintf(diagnostic_file, "reverie-dbt: process ownership table exhausted\n");
    exit_runtime_tree(101);
    return NULL;
  }
  size_t count = atomic_load_explicit(
      &task_state->process_control_count, memory_order_relaxed);
  process_control_t* entry = &task_state->process_controls[count];
  initialize_process_control_locked(task_state, entry, kernel_pid, birth_token, false);
  atomic_store_explicit(
      &task_state->process_control_count, count + 1, memory_order_release);
  task_state_unlock();
  return entry;
}

/* Bind before entering Rust's Tool-start hook, using the existing process
 * admission lookup. A fork copy is rebound to its own positive-PID slot; exec
 * starts with zeroed TLS and authenticates the inherited owner again. No
 * capture query or successful Tool acknowledgment performs this lookup. */
static void bind_capture_owner(prototype_counters_t* counters) {
  process_control_t* entry = process_control_for((int32_t)dr_get_process_id());
  if (counters->capture_owner.entry != entry ||
      counters->capture_owner.birth != entry->birth_token) {
    counters->capture_owner = (capture_owner_t){entry, entry->birth_token, 0};
  }
}

// Cleanup may run for an early failure without a prepared process owner. Do
// not create an entry or recursively enter the fatal path in that case.
static process_control_t* existing_process_control(int32_t kernel_pid) {
  int32_t birth_token;
  if (task_state == NULL ||
      !lookup_task_birth(kernel_pid, &birth_token) || birth_token <= 0)
    return NULL;
  process_control_t* found = NULL;
  task_state_lock();
  for (size_t i = 0; i < task_state->process_control_count; ++i) {
    process_control_t* entry = &task_state->process_controls[i];
    if (entry->kernel_pid == kernel_pid && entry->birth_token == birth_token) {
      found = entry;
      break;
    }
  }
  task_state_unlock();
  return found;
}

static _Atomic uint64_t* pending_thread_clones_for(int32_t kernel_pid) {
  return &process_control_for(kernel_pid)->pending_thread_clones;
}

// The vendor retirement observer can run inside DR's heap teardown. Its short
// critical section cannot call DR (including dr_thread_yield), allocate, or
// cross a syscall/RPC. Other users of this same lock also release it before
// kernel clone/exec, so a copied-vfork child cannot inherit a suspended owner.
static void private_memory_lock(void) {
  while (atomic_flag_test_and_set_explicit(
      &task_state->lock, memory_order_acquire))
    __asm__ volatile("pause" ::: "memory");
}

static void retire_private_memory(void) {
  if (task_state == NULL || runtime_memory_owner_slot == SIZE_MAX)
    return;
  private_memory_lock();
  if (runtime_memory_owner_slot < task_state->process_control_count) {
    process_control_t* entry =
        &task_state->process_controls[runtime_memory_owner_slot];
    if (atomic_load_explicit(&entry->image_epoch, memory_order_relaxed) ==
        runtime_memory_owner_epoch) {
      entry->memory_retired = 1;
      if (entry->private_memory.state != 0) {
        entry->private_memory.state = 0;
        if (entry->private_memory.version != UINT64_MAX)
          ++entry->private_memory.version;
      }
    }
  }
  task_state_unlock();
}

static void retire_private_memory_for_exec(void) {
  // A vfork/CLONE_VM child's exec switches that child to a new mm; it does not
  // transfer the parent's reservations. Actual old-mm releases still notify
  // the vendor observer. A real owner exec conservatively retires even if it
  // fails, and can only publish anew after a successful image initialization.
  if (dr_get_process_id() == runtime_memory_owner_pid)
    retire_private_memory();
  if (test_private_memory == PRIVATE_MEMORY_TEST_LOST_EXEC &&
      !dr_is_post_execve() && !test_private_memory_loss_injected) {
    test_private_memory_loss_injected = true;
    // Explicit control-backing fault injection, not guest close semantics.
    if (syscall(SYS_close, TASK_STATE_FD) != 0) {
      dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_TEST loss-injection-failed\n");
      dr_exit_process(101);
    }
    dr_fprintf(diagnostic_file,
        "PRIVATE_MEMORY_TEST control-backing-loss-injected=1\n");
  }
}

static int32_t runtime_private_memory(
    uintptr_t context,
    const private_memory_snapshot_t* expected,
    private_memory_snapshot_t* out) {
  (void)context;
  private_memory_snapshot_t wanted = {0};
  if (expected != NULL)
    wanted = *expected;
  if (out == NULL)
    return 0;
  memset(out, 0, sizeof(*out));
  if (task_state == NULL || !task_state_identity_valid)
    return 0;
  size_t slot = expected == NULL ? runtime_memory_owner_slot : wanted.owner[2];
  uint64_t epoch = expected == NULL ? runtime_memory_owner_epoch : wanted.owner[3];
  if (expected != NULL &&
      (wanted.owner[0] != task_state_device || wanted.owner[1] != task_state_inode))
    return 0;
  private_memory_lock();
  bool ready = false;
  if (slot < task_state->process_control_count) {
    process_control_t* entry = &task_state->process_controls[slot];
    const private_memory_snapshot_t* value = &entry->private_memory;
    ready = entry->memory_published != 0 && entry->memory_retired == 0 &&
        atomic_load_explicit(&entry->image_epoch, memory_order_relaxed) == epoch &&
        value->state == 1 && value->count > 0 && value->count <= 3 &&
        value->owner[0] == task_state_device && value->owner[1] == task_state_inode &&
        value->owner[2] == slot && value->owner[3] == epoch &&
        (expected == NULL || value->version == wanted.version);
    if (ready)
      *out = *value;
  }
  task_state_unlock();
  return ready ? 1 : 0;
}

static bool private_memory_test_check(bool condition, const char* check) {
  if (condition)
    return true;
  dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_TEST failed=%s\n", check);
  dr_exit_process(101);
  return false;
}

static bool private_memory_test_unavailable(
    const private_memory_snapshot_t* expected) {
  private_memory_snapshot_t output;
  const private_memory_snapshot_t zero = {0};
  memset(&output, 0xa5, sizeof(output));
  return runtime_private_memory(0, expected, &output) == 0 &&
      memcmp(&output, &zero, sizeof(output)) == 0;
}

static uint32_t private_memory_test_notifications;

static void count_private_memory_test_notification(void) {
  ++private_memory_test_notifications;
}

static bool run_private_memory_route_test(
    const private_memory_snapshot_t* current) {
  reg_t first = current->ranges[0].start;
  reg_t last = current->ranges[current->count - 1].end;
  reg_t page = dr_page_size();
  if (!private_memory_test_check(
          page > 0 && page <= UINT64_MAX / 2 && first >= 2 * page &&
              last <= UINT64_MAX - page,
          "route-test-address-bounds"))
    return false;
  reg_t outside = first - 2 * page;
  const struct {
    const char* name;
    int sysnum;
    reg_t args[6];
    uint32_t notifications;
  } cases[] = {
      {"mmap-fixed-overlap", SYS_mmap, {first, 1, 0, MAP_FIXED}, 1},
      {"mmap-nonfixed-overlap", SYS_mmap, {first, 1}, 0},
      {"mmap-noreplace-overlap", SYS_mmap, {first, 1, 0, MAP_FIXED_NOREPLACE}, 0},
      {"mmap-fixed-disjoint", SYS_mmap, {outside, page, 0, MAP_FIXED}, 0},
      {"mmap-fixed-overflow", SYS_mmap, {UINT64_MAX - 7, 16, 0, MAP_FIXED}, 1},
      {"munmap-overlap", SYS_munmap, {first, 1}, 1},
      {"munmap-disjoint", SYS_munmap, {outside, page}, 0},
      {"munmap-left-adjacent", SYS_munmap, {first - page, page}, 0},
      {"munmap-right-adjacent", SYS_munmap, {last, page}, 0},
      {"munmap-left-crossing", SYS_munmap, {first - 1, 2}, 1},
      {"munmap-right-crossing", SYS_munmap, {last - 1, 2}, 1},
      {"munmap-zero", SYS_munmap, {first, 0}, 0},
      {"munmap-overflow", SYS_munmap, {UINT64_MAX - 7, 16}, 1},
      {"mremap-source", SYS_mremap, {first, page, page}, 1},
      {"mremap-source-shrink", SYS_mremap, {first - page, page + 1, page}, 1},
      {"mremap-source-growth", SYS_mremap, {first - page, page, page + 1}, 1},
      {"mremap-zero-size-alias", SYS_mremap, {first, 0, 1}, 1},
      {"mremap-zero-extents", SYS_mremap, {first, 0, 0}, 0},
      {"mremap-fixed-destination", SYS_mremap,
          {outside, page, page, MREMAP_FIXED, first}, 1},
      {"mremap-ignored-destination", SYS_mremap,
          {outside, page, page, 0, first}, 0},
      {"mremap-disjoint", SYS_mremap, {outside, page, page}, 0},
      {"mremap-source-overflow", SYS_mremap, {UINT64_MAX - 7, 16, 1}, 1},
      {"mremap-destination-overflow", SYS_mremap,
          {outside, 16, 16, MREMAP_FIXED, UINT64_MAX - 7}, 1},
      {"mremap-both-overlap", SYS_mremap,
          {first, page, page, MREMAP_FIXED, first}, 2},
      {"mprotect-commit", SYS_mprotect, {first, page, PROT_READ | PROT_WRITE}, 0},
      {"shmat-remap", SYS_shmat, {0, 0, SHM_REMAP}, 1},
      {"shmat-nonremap", SYS_shmat, {0, 0, 0}, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    // No application thread runs at this initialization-only test seam. Feed
    // the actual production dispatcher/overlap path, without a kernel call or
    // reviving any retired authority. The existing retire mode separately
    // checks the real observer's unavailable/zero-output publication.
    private_memory_test_notifications = 0;
    dr_set_private_reservation_retirement_callback(
        count_private_memory_test_notification);
    dr_test_private_reservation_syscall(cases[i].sysnum, cases[i].args);
    dr_set_private_reservation_retirement_callback(retire_private_memory);
    if (!private_memory_test_check(
            private_memory_test_notifications == cases[i].notifications,
            cases[i].name))
      return false;
    dr_fprintf(diagnostic_file,
        "PRIVATE_MEMORY_TEST route=%s notifications=%u\n",
        cases[i].name, private_memory_test_notifications);
  }
  private_memory_snapshot_t output;
  memset(&output, 0xa5, sizeof(output));
  if (!private_memory_test_check(
          runtime_private_memory(0, current, &output) == 1 &&
              memcmp(&output, current, sizeof(output)) == 0,
          "route-test-preserves-live-token"))
    return false;
  dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_TEST routes=27 live_token=1\n");
  return true;
}

static bool run_private_memory_self_test(void) {
  if (test_private_memory == PRIVATE_MEMORY_TEST_NONE)
    return true;
  bool followed = dr_is_post_execve();
  if (test_private_memory == PRIVATE_MEMORY_TEST_LOST_EXEC && followed) {
    if (!private_memory_test_check(
            private_memory_test_unavailable(NULL), "followed-exec-unavailable"))
      return false;
    dr_fprintf(diagnostic_file,
        "PRIVATE_MEMORY_TEST followed-exec-unavailable=1\n");
    return true;
  }

  private_memory_snapshot_t current;
  memset(&current, 0xa5, sizeof(current));
  if (!private_memory_test_check(
          runtime_private_memory(0, NULL, &current) == 1 &&
              current.state == 1 && current.count > 0 && current.count <= 3 &&
              current.version > 0,
          "current-ready"))
    return false;
  for (uint32_t i = 0; i < current.count; ++i)
    if (!private_memory_test_check(
            current.ranges[i].start < current.ranges[i].end &&
                (i == 0 || current.ranges[i - 1].end <= current.ranges[i].start),
            "canonical-ranges"))
      return false;
  private_memory_snapshot_t output;
  memset(&output, 0xa5, sizeof(output));
  if (!private_memory_test_check(
          runtime_private_memory(0, &current, &output) == 1 &&
              memcmp(&output, &current, sizeof(output)) == 0,
          "live-token"))
    return false;
  private_memory_snapshot_t wrong = current;
  wrong.owner[0] ^= 1;
  if (!private_memory_test_check(
          private_memory_test_unavailable(&wrong), "wrong-owner"))
    return false;
  wrong = current;
  wrong.version ^= 1;
  if (!private_memory_test_check(
          private_memory_test_unavailable(&wrong), "wrong-version"))
    return false;
  dr_fprintf(diagnostic_file,
      "PRIVATE_MEMORY_TEST ready=1 followed_exec=%d "
      "wrong_owner_rejected=1 wrong_version_rejected=1\n", followed ? 1 : 0);
  if (test_private_memory == PRIVATE_MEMORY_TEST_ROUTES)
    return run_private_memory_route_test(&current);
  if (test_private_memory == PRIVATE_MEMORY_TEST_RETIRE) {
    retire_private_memory();
    if (!private_memory_test_check(
            private_memory_test_unavailable(&current) &&
                private_memory_test_unavailable(NULL),
            "retired-token"))
      return false;
    dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_TEST retired=1\n");
  }
  return true;
}

static bool private_ranges_contain(
    const private_memory_snapshot_t* value, const byte* start, size_t size) {
  uint64_t lo = (uint64_t)(uintptr_t)start;
  if (size == 0 || lo > UINT64_MAX - size)
    return false;
  for (uint32_t i = 0; i < value->count; ++i)
    if (value->ranges[i].start <= lo && lo + size <= value->ranges[i].end)
      return true;
  return false;
}

static void initialize_private_memory(
    const byte* preempt, const byte* signal, size_t page_size) {
  dr_private_reservation_t regions[3] = {0};
  private_memory_snapshot_t value = {0};
  size_t count = dr_get_private_reservations(regions, 3);
  bool ready = task_state_identity_valid && count > 0 && count <= 3;
  for (size_t i = 0; ready && i < count; ++i) {
    uint64_t start = (uint64_t)(uintptr_t)regions[i].start;
    if (regions[i].size == 0 || start > UINT64_MAX - regions[i].size) {
      ready = false;
      break;
    }
    value.ranges[i] = (private_memory_range_t){start, start + regions[i].size};
    value.count++;
  }
  // Stable canonical ordering is part of the fixed snapshot. Validation must
  // return exactly these extents, including zeroed unused slots.
  for (uint32_t i = 1; i < value.count; ++i) {
    private_memory_range_t range = value.ranges[i];
    uint32_t j = i;
    while (j > 0 && value.ranges[j - 1].start > range.start) {
      value.ranges[j] = value.ranges[j - 1];
      --j;
    }
    value.ranges[j] = range;
  }
  for (uint32_t i = 1; i < value.count; ++i)
    if (value.ranges[i - 1].end > value.ranges[i].start)
      ready = false;
  ready = ready && signal != NULL &&
      private_ranges_contain(&value, signal, page_size) &&
      (preempt == NULL || private_ranges_contain(&value, preempt, page_size));
  runtime_memory_owner_slot =
      (size_t)(runtime_process_control - task_state->process_controls);
  runtime_memory_owner_epoch = runtime_process_epoch;
  runtime_memory_owner_pid = dr_get_process_id();
  private_memory_lock();
  process_control_t* entry = runtime_process_control;
  uint64_t previous = entry->private_memory.version;
  value.owner[0] = task_state_device;
  value.owner[1] = task_state_inode;
  value.owner[2] = runtime_memory_owner_slot;
  value.owner[3] = runtime_memory_owner_epoch;
  value.version = previous == UINT64_MAX ? UINT64_MAX : previous + 1;
  value.state = ready && previous != UINT64_MAX ? 1 : 0;
  entry->private_memory = value;
  entry->memory_published = 1;
  entry->memory_retired = value.state == 0;
  task_state_unlock();
  dr_set_private_reservation_retirement_callback(retire_private_memory);
}

static void rebind_private_memory_after_clone(uint64_t flags) {
  process_id_t child = dr_get_process_id();
  if ((flags & CLONE_VM) != 0 || child == runtime_memory_owner_pid ||
      runtime_memory_owner_slot == SIZE_MAX)
    return;
  process_control_t* entry = process_control_for((int32_t)child);
  if (entry == NULL)
    return;
  private_memory_lock();
  private_memory_snapshot_t value = {0};
  uint32_t retired = 1;
  if (runtime_memory_owner_slot < task_state->process_control_count) {
    process_control_t* parent =
        &task_state->process_controls[runtime_memory_owner_slot];
    if (atomic_load_explicit(&parent->image_epoch, memory_order_relaxed) ==
        runtime_memory_owner_epoch) {
      value = parent->private_memory;
      retired = parent->memory_retired;
    }
  }
  size_t child_slot = (size_t)(entry - task_state->process_controls);
  uint64_t child_epoch =
      atomic_load_explicit(&entry->image_epoch, memory_order_relaxed);
  uint64_t previous = entry->private_memory.version;
  value.owner[0] = task_state_device;
  value.owner[1] = task_state_inode;
  value.owner[2] = child_slot;
  value.owner[3] = child_epoch;
  value.version = previous == UINT64_MAX ? UINT64_MAX : previous + 1;
  if (previous == UINT64_MAX) {
    value.state = 0;
    retired = 1;
  }
  entry->private_memory = value;
  entry->memory_published = 1;
  entry->memory_retired = retired;
  runtime_memory_owner_slot = child_slot;
  runtime_memory_owner_epoch = child_epoch;
  runtime_memory_owner_pid = child;
  task_state_unlock();
}

// 1 means kernel exit is complete, 0 means still pending, -1 is a failure.
static int confirm_previous_helper_exit(void) {
  process_id_t helper = (process_id_t)runtime_process_control->helper_pid;
  if (helper <= 0)
    return -1;

  // A client helper is a clone child of an application thread, including when
  // another thread becomes the leader during exec. __WALL includes its zero
  // exit signal; omitting __WNOTHREAD includes children of the whole group.
  // Observe without reaping first: SIG_IGN/SA_NOCLDWAIT can auto-reap a helper
  // after parent exec, and a guest CLONE_PARENT child could reuse its PID.
  siginfo_t info = {0};
  int result = waitid(
      P_PID, (id_t)helper, &info, WEXITED | WNOHANG | WNOWAIT | __WALL);
  int wait_error = result < 0 ? errno : 0;
  if (wait_error == EINTR)
    return 0;
  if (wait_error != 0 && wait_error != ECHILD)
    return -1;

  uint64_t start_time;
  char state;
  process_identity_result_t identity =
      read_process_identity(helper, &start_time, &state);
  if (identity == PROCESS_IDENTITY_ERROR)
    return -1;
  if (identity == PROCESS_IDENTITY_ABSENT ||
      start_time != runtime_process_control->helper_start_time)
    return 1;
  if (wait_error == ECHILD)
    return state == 'Z' || state == 'X' ? 1 : -1;
  if (info.si_pid == 0)
    return 0;
  if (info.si_pid != helper || info.si_code != CLD_EXITED ||
      info.si_status != 0 || (state != 'Z' && state != 'X'))
    return -1;

  // The acknowledged sender's pid/start-time identity matches the waitable
  // zombie. This is the same identity contract as protected evidence. No guest
  // or other application thread runs in this image yet, so nobody can reap
  // that zombie between this check and the targeted wait. Consume only this
  // helper, keeping repeated exec from accumulating client-owned zombies.
  int status;
  pid_t reaped = waitpid((pid_t)helper, &status, WNOHANG | __WALL);
  if (reaped < 0 && errno == EINTR)
    return 0;
  return reaped == helper && WIFEXITED(status) && WEXITSTATUS(status) == 0
      ? 1
      : -1;
}

static bool claim_runtime_image(void) {
  runtime_process_control = process_control_for(runtime_process_id);
  runtime_is_root = runtime_process_control->root_process;
  task_state_lock();
  uint64_t previous = atomic_load_explicit(
      &runtime_process_control->image_epoch, memory_order_relaxed);
  if (previous == UINT64_MAX) {
    task_state_unlock();
    dr_fprintf(diagnostic_file, "reverie-dbt: runtime image epoch overflowed\n");
    exit_runtime_tree(101);
    return false;
  }
  runtime_process_epoch = previous + 1;
  atomic_store_explicit(
      &runtime_process_control->image_epoch,
      runtime_process_epoch,
      memory_order_release);
  task_state_unlock();

  // Every owner syscall starts the helper before native execution, or exits
  // on spawn failure. Thus an owner that execs has a real predecessor helper,
  // even for a runtime whose background entry returns immediately. A copied
  // fork/vfork child has no own image epoch until this first real exec.
  if (previous == 0)
    return true;

  // Successful exec created this image. Ask the old helper to retire through
  // its idle callback and await its own acknowledged FINAL and kernel exit
  // before any new thread callback can publish START. Returning from the
  // helper callback alone has not released its shared descriptor table.
  // Failed exec never reaches this claim.
  // This host-time budget only bounds lifecycle control; it never enters the
  // guest clock, and expiry cannot stand in for evidence completion.
  struct timespec started;
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: could not time exec helper retirement\n");
    exit_runtime_tree(101);
    return false;
  }
  for (;;) {
    if (atomic_load_explicit(
            &runtime_process_control->finished_helper_epoch,
            memory_order_acquire) == previous) {
      int completion = confirm_previous_helper_exit();
      if (completion > 0)
        return true;
      if (completion < 0) {
        dr_fprintf(
            diagnostic_file,
            "reverie-dbt: could not confirm previous runtime helper kernel "
            "exit for image epoch %llu\n",
            (unsigned long long)previous);
        exit_runtime_tree(101);
        return false;
      }
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      dr_fprintf(
          diagnostic_file, "reverie-dbt: could not time exec helper retirement\n");
      exit_runtime_tree(101);
      return false;
    }
    int64_t elapsed_ms = (int64_t)(now.tv_sec - started.tv_sec) * INT64_C(1000) +
        (now.tv_nsec - started.tv_nsec) / INT64_C(1000000);
    if (elapsed_ms >= (int64_t)EXEC_HELPER_RETIREMENT_TIMEOUT_MS) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: previous runtime helper did not finish image epoch "
          "%llu before exec retirement timeout\n",
          (unsigned long long)previous);
      exit_runtime_tree(101);
      return false;
    }
    dr_sleep(1);
  }
}

static void finish_pending_thread_clone(int32_t kernel_pid) {
  uint64_t pending_before = atomic_fetch_sub_explicit(
      pending_thread_clones_for(kernel_pid), 1, memory_order_acq_rel);
  DR_ASSERT(pending_before > 0);
}

static bool lookup_task_birth(int32_t tid, int32_t* birth);
static void publish_task_birth(int32_t tid, int32_t birth, bool authoritative) {
  if (tid <= 0 || birth <= 0)
    return;
  task_state_lock();
  for (size_t i = 0; i < task_state->task_count; ++i) {
    if (task_state->tasks[i].tid == tid) {
      /* Current child/self and a thread's gated parent own the transaction.
       * A process parent may return after its child has died and the PID was
       * reused: it only fills an absent membership, never replaces this one. */
      task_membership_publish(&task_state->tasks[i], birth, authoritative);
      task_state_unlock();
      return;
    }
  }
  DR_ASSERT(task_state->task_count < MAX_TASK_MEMBERSHIPS);
  task_state->tasks[task_state->task_count++] =
      (task_membership_t){tid, birth};
  task_state_unlock();
}

/* Only the explicit stale-admission regression uses an unowned token. It
 * cannot reach a guest identity field or the production birth publisher. */
static void inject_stale_task_birth_for_test(int32_t tid) {
  task_state_lock();
  for (size_t i = 0; i < task_state->task_count; ++i) {
    if (task_state->tasks[i].tid == tid) {
      task_state->tasks[i].birth_token = TEST_REUSED_TID_STALE;
      task_state_unlock();
      return;
    }
  }
  DR_ASSERT(task_state->task_count < MAX_TASK_MEMBERSHIPS);
  task_state->tasks[task_state->task_count++] =
      (task_membership_t){tid, TEST_REUSED_TID_STALE};
  task_state_unlock();
}

static bool lookup_task_birth(int32_t tid, int32_t* birth) {
  bool found = false;
  if (tid <= 0)
    return false;
  task_state_lock();
  for (size_t i = 0; i < task_state->task_count; ++i) {
    if (task_state->tasks[i].tid == tid) {
      *birth = task_state->tasks[i].birth_token;
      found = true;
      break;
    }
  }
  task_state_unlock();
  return found;
}

static int32_t controller_capture_from_owner(
    task_state_t* state, capture_owner_t* owner, int32_t pid, int32_t tid,
    uint32_t operation, bool backing_valid, controller_capture_fact_t* out) {
  memset(out, 0, sizeof(*out));
  if (!backing_valid) {
    capture_mark_owner_uncertain(state);
    return 0;
  }
  if (state == NULL || owner == NULL || pid <= 0 || tid <= 0 || operation > 1)
    return 0;
  size_t count = atomic_load_explicit(
      &state->process_control_count, memory_order_acquire);
  if (count > MAX_TASK_MEMBERSHIPS) {
    capture_mark_owner_uncertain(state);
    return 0;
  }
  uintptr_t first = (uintptr_t)&state->process_controls[0];
  uintptr_t address = (uintptr_t)owner->entry;
  if (address < first || address - first >= count * sizeof(process_control_t) ||
      (address - first) % sizeof(process_control_t) != 0 || owner->birth <= 0)
    return 0;
  // The cache is populated only from a positive-PID process_control_for result.
  // Its keys are immutable; canceled pid-zero slots never escape that lookup.
  // An inherited parent's cache cannot authenticate the child's actual PID.
  if (owner->entry->kernel_pid != pid || owner->entry->birth_token != owner->birth)
    return 0;
  if (operation == 1) {
    owner->mediated_pid = pid;
    atomic_store_explicit(
        &owner->entry->capture_pending_admission, false, memory_order_release);
    return 1;
  }
  if (owner->mediated_pid != pid)
    return 0;

  bool pending = false;
  for (size_t i = 0; i < count; ++i) {
    process_control_t* entry = &state->process_controls[i];
    pending |= atomic_load_explicit(
        &entry->capture_pending_admission, memory_order_acquire);
    pending |= atomic_load_explicit(
                   &entry->pending_thread_clones, memory_order_acquire) != 0;
  }
  // Pending is read BEFORE sticky: a copied transition publishes uncertainty
  // before successful Tool admission can release its pending reservation.
  // Query runs under the shared serial guard. A new kernel task either needs
  // that same grant or already has an unadmitted/sticky ancestor in this scan.
  // No query/ack depends on the unrelated membership lock or a dead lock owner.
  bool uncertain = atomic_load_explicit(
      &state->capture_uncertain, memory_order_acquire);
  bool certain = !pending && !uncertain && state->external_global &&
      state->capture_procfs_valid;
  if (certain) {
    out->physical_pid = pid;
    out->physical_tid = tid;
    out->procfs_device = state->capture_procfs_device;
    out->procfs_inode = state->capture_procfs_inode;
  }
  return certain;
}

static int32_t controller_capture_control(
    uintptr_t context, uint32_t operation, controller_capture_fact_t* out) {
  if (out == NULL)
    return 0;
  memset(out, 0, sizeof(*out));
  if (context == 0 || (void*)context != dr_get_current_drcontext() ||
      task_state == NULL || task_state->magic != TASK_STATE_MAGIC)
    return 0;
  prototype_counters_t* counters =
      drmgr_get_tls_field((void*)context, thread_state_index);
  if (counters == NULL)
    return 0;
  int32_t pid = (int32_t)dr_get_process_id();
  int32_t tid = (int32_t)dr_get_thread_id((void*)context);
  if (pid <= 0 || tid <= 0 || operation > 1)
    return 0;
  struct stat backing;
  bool backing_valid = fstat(TASK_STATE_FD, &backing) == 0 &&
      (uint64_t)backing.st_dev == task_state_device &&
      (uint64_t)backing.st_ino == task_state_inode &&
      backing.st_size == (off_t)sizeof(*task_state);
  return controller_capture_from_owner(task_state, &counters->capture_owner,
      pid, tid, operation, backing_valid, out);
}

static int32_t ensure_task_membership(int32_t tid) {
  int32_t birth;
  if (!lookup_task_birth(tid, &birth) || birth <= 0)
    publish_task_birth(tid, next_birth_token(), true);
  return tid;
}

/* A helper is an observed non-application task. Keep its tombstone so a late
 * process-parent completion cannot reinsert a stale application membership.
 * A later actual application birth may replace it authoritatively. */
static void publish_helper_membership(int32_t tid) {
  task_state_lock();
  for (size_t i = 0; i < task_state->task_count; ++i) {
    if (task_state->tasks[i].tid == tid) {
      task_state->tasks[i].birth_token = 0;
      task_state_unlock();
      return;
    }
  }
  DR_ASSERT(task_state->task_count < MAX_TASK_MEMBERSHIPS);
  task_state->tasks[task_state->task_count++] = (task_membership_t){tid, 0};
  task_state_unlock();
}

static int32_t known_task_identity(int32_t identity) {
  if (identity <= 0)
    return identity;
  task_state_lock();
  bool known = task_membership_contains(
      task_state->tasks, task_state->task_count, identity);
  task_state_unlock();
  return known ? identity : -1;
}

static bool read_app(const void* address, void* value, size_t size);
static bool write_app(void* address, const void* value, size_t size);

static dr_emit_flags_t rewrite_cpuid(
    void* drcontext,
    void* tag,
    instrlist_t* bb,
    bool for_trace,
    bool translating) {
  instr_t* instruction;
  instr_t* next;

  for (instruction = instrlist_first_app(bb); instruction != NULL;
       instruction = next) {
    emulated_instr_t emulated;
    instr_t* marker;
    next = instr_get_next_app(instruction);
    if (instr_get_opcode(instruction) != OP_cpuid)
      continue;

    emulated = (emulated_instr_t){
        sizeof(emulated), instr_get_app_pc(instruction), instruction, 0};
    if (!drmgr_insert_emulation_start(drcontext, bb, instruction, &emulated))
      DR_ASSERT(false);
    marker = INSTR_CREATE_nop(drcontext);
    instr_set_translation(marker, instr_get_app_pc(instruction));
    instr_set_note(marker, (void*)cpuid_marker_note);
    instrlist_replace(bb, instruction, marker);
    drmgr_insert_emulation_end(drcontext, bb, next);
  }
  return DR_EMIT_DEFAULT;
}

// Return the next deterministic virtual TSC value. Strictly increasing per
// interception; see the `virtual_tsc` declaration for the determinism argument.
static uint64_t next_virtual_tsc(void) {
  return atomic_fetch_add_explicit(
             &virtual_tsc, VIRTUAL_TSC_STRIDE, memory_order_relaxed) +
      VIRTUAL_TSC_STRIDE;
}

static int64_t
invoke_syscall(uintptr_t context, int64_t sysnum, const uint64_t* args);
static int32_t read_registers(uintptr_t context, struct user_regs_struct* out);
static int32_t write_registers(
    uintptr_t context,
    const struct user_regs_struct* in);

static void ensure_runtime_background(void);
// The TSC an rdtsc or rdtscp returns. A runtime whose tool answers it is asked
// first: under Detcore that is Detcore's virtual clock, charged and logged as
// under ptrace, so the guest's TSC names the same instant as its
// clock_gettime. A runtime that leaves it to the client, and a copied child,
// which runs no runtime (its clock syscalls are answered here too), get the
// fixed-stride counter.
static uint64_t guest_tsc(void* drcontext, bool with_aux, uint32_t* aux) {
  *aux = 0;
  if (!has_copied_runtime() ||
      (runtime_uses_external_global() && !is_copied_vfork_process())) {
    prototype_counters_t* counters = (prototype_counters_t*)drmgr_get_tls_field(
        drcontext, thread_state_index);
    uint64_t tsc = 0;
    uint32_t runtime_aux = 0;
    int32_t answered;
    DR_ASSERT(counters != NULL);
    // The loader reads the TSC before its first syscall, which is where a
    // runtime owner otherwise starts the runtime; start it here the same way.
    if (!has_copied_runtime())
      ensure_runtime_background();
    while (!reverie_dbt_runtime_ready(
        atomic_load_explicit(&image_generation, memory_order_acquire)))
      dr_sleep(1);
    evidence_callback_enter();
    answered = reverie_dbt_runtime_rdtsc(
        drcontext,
        counters,
        (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(),
        atomic_load_explicit(&branch_count, memory_order_relaxed),
        with_aux ? 1 : 0,
        invoke_syscall,
        read_registers,
        write_registers,
        reverie_dbt_emit,
        &tsc,
        &runtime_aux);
    evidence_callback_leave();
    if (answered == 1) {
      *aux = runtime_aux;
      return tsc;
    }
    if (answered != 0) {
      exit_runtime_tree(101);
      return 0;
    }
  }
  return next_virtual_tsc();
}

// Emulate cpuid by asking the runtime's tool, as guest_tsc asks it for the
// TSC. A copied child runs no runtime, so it has no machine description to
// answer from; its CPUID is refused by name rather than answered from a
// second table.
static void emulate_cpuid(void) {
  void* drcontext = dr_get_current_drcontext();
  dr_mcontext_t registers = {sizeof(registers), DR_MC_INTEGER};
  uint32_t result[4] = {0};
  int32_t answered = -1;

  DR_ASSERT(dr_get_mcontext(drcontext, &registers));
  if (!has_copied_runtime() ||
      (runtime_uses_external_global() && !is_copied_vfork_process())) {
    prototype_counters_t* counters = (prototype_counters_t*)drmgr_get_tls_field(
        drcontext, thread_state_index);
    DR_ASSERT(counters != NULL);
    if (!has_copied_runtime())
      ensure_runtime_background();
    while (!reverie_dbt_runtime_ready(
        atomic_load_explicit(&image_generation, memory_order_acquire)))
      dr_sleep(1);
    evidence_callback_enter();
    answered = reverie_dbt_runtime_cpuid(
        drcontext,
        counters,
        (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(),
        atomic_load_explicit(&branch_count, memory_order_relaxed),
        (uint32_t)registers.xax,
        (uint32_t)registers.xcx,
        invoke_syscall,
        read_registers,
        write_registers,
        reverie_dbt_emit,
        result);
    evidence_callback_leave();
  } else {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: refusing cpuid in a copied child, which runs no runtime "
        "to answer it from the machine description\n");
  }
  if (answered != 1) {
    exit_runtime_tree(101);
    return;
  }
  registers.xax = result[0];
  registers.xbx = result[1];
  registers.xcx = result[2];
  registers.xdx = result[3];
  DR_ASSERT(dr_set_mcontext(drcontext, &registers));
}

// Emulate rdtsc: return the 64-bit TSC in EDX:EAX, leaving all other
// registers (notably ECX) untouched, exactly as the hardware rdtsc does.
static void emulate_rdtsc(void) {
  void* drcontext = dr_get_current_drcontext();
  dr_mcontext_t registers = {sizeof(registers), DR_MC_INTEGER};
  uint32_t aux;
  uint64_t tsc = guest_tsc(drcontext, false, &aux);

  DR_ASSERT(dr_get_mcontext(drcontext, &registers));
  registers.xax = (reg_t)(tsc & UINT32_C(0xFFFFFFFF));
  registers.xdx = (reg_t)((tsc >> 32) & UINT32_C(0xFFFFFFFF));
  DR_ASSERT(dr_set_mcontext(drcontext, &registers));
}

// Emulate rdtscp: like rdtsc, but also set ECX to the TSC_AUX value: the
// runtime's (Detcore's, for its single virtual CPU), or 0 with the
// fixed-stride counter, so a deterministic run reports a stable processor id.
static void emulate_rdtscp(void) {
  void* drcontext = dr_get_current_drcontext();
  dr_mcontext_t registers = {sizeof(registers), DR_MC_INTEGER};
  uint32_t aux;
  uint64_t tsc = guest_tsc(drcontext, true, &aux);

  DR_ASSERT(dr_get_mcontext(drcontext, &registers));
  registers.xax = (reg_t)(tsc & UINT32_C(0xFFFFFFFF));
  registers.xdx = (reg_t)((tsc >> 32) & UINT32_C(0xFFFFFFFF));
  registers.xcx = (reg_t)aux;
  DR_ASSERT(dr_set_mcontext(drcontext, &registers));
}

// Replace rdtsc and rdtscp instructions with a marker nop, mirroring
// rewrite_cpuid. The instrumentation event installs the matching clean call.
static dr_emit_flags_t rewrite_rdtsc(
    void* drcontext,
    void* tag,
    instrlist_t* bb,
    bool for_trace,
    bool translating) {
  instr_t* instruction;
  instr_t* next;

  for (instruction = instrlist_first_app(bb); instruction != NULL;
       instruction = next) {
    emulated_instr_t emulated;
    instr_t* marker;
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
    instr_set_note(marker, (void*)note);
    instrlist_replace(bb, instruction, marker);
    drmgr_insert_emulation_end(drcontext, bb, next);
  }
  return DR_EMIT_DEFAULT;
}

static bool is_compat_syscall_instruction(instr_t* instruction) {
  return instr_is_syscall(instruction) && instr_is_interrupt(instruction) &&
      instr_get_interrupt_number(instruction) == 0x80;
}

static void mark_compat_syscall_gateway(void) {
  void* drcontext = dr_get_current_drcontext();
  DR_ASSERT(drmgr_set_tls_field(drcontext, compat_gateway_index, (void*)1));
}

static int64_t
invoke_syscall(uintptr_t context, int64_t sysnum, const uint64_t* args);
static int32_t read_registers(uintptr_t context, struct user_regs_struct* out);
static int32_t write_registers(
    uintptr_t context,
    const struct user_regs_struct* in);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-ratchet11): Review the in-tree parent-pid surface.
// The real parent pid of the current process within the traced tree, or -1 when
// this is the tree root. DynamoRIO follows clone/fork children
// (-follow_children), so a non-root process's real OS parent is always its
// in-tree parent; the root's real parent is the out-of-tree launcher, which the
// `Guest::ppid` contract reports as no parent (`None`). The root is identified
// by the original kernel PID/birth transaction retained in process control.
// `runtime_process_id` is a per-process constant, so this is stable for every
// thread of the process.
static int32_t in_tree_parent_pid(void) {
  return runtime_is_root && runtime_process_id == (int32_t)dr_get_process_id() ? -1
                                                : (int32_t)dr_get_parent_id();
}

// TODO-HUMAN-REVIEW(PR-131): Review the child entry-block scheduling gate.
static void set_pending_thread_start(
    prototype_counters_t* counters,
    uint64_t pending) {
  counters->pending_thread_start = pending;
  /* Every caller runs in the thread whose admission state is being updated.
   * The raw TLS copy makes the basic-block check a single direct TLS load. */
  uint64_t* slots =
      (uint64_t*)((byte*)dr_get_dr_segment_base(admission_state_tls_register) +
                  admission_state_tls_offset);
  slots[0] = pending;
}

static void try_start_pending_thread(void) {
  void* drcontext = dr_get_current_drcontext();
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  int32_t published_birth_token;
  uint64_t pending_thread_clones;
  bool mapping_found = false;
  if (counters == NULL || counters->pending_thread_start == 0)
    return;

  /* The clone parent overwrites the host mapping before decrementing the
   * shared count. While any thread clone is pending, a retained entry can
   * still describe an earlier thread that used the same host TID. */
  pending_thread_clones = atomic_load_explicit(
      pending_thread_clones_for(counters->kernel_pid), memory_order_acquire);
  if (test_thread_clone_process_exit &&
      counters->kernel_pid == task_state->root_pid && pending_thread_clones == 1 &&
      atomic_load_explicit(
          &task_state->thread_clone_process_exit_test_exercised,
          memory_order_acquire) &&
      lookup_task_birth(
          (int32_t)dr_get_thread_id(drcontext), &published_birth_token)) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: exited process blocked a surviving thread clone\n");
    exit_runtime_tree(91);
    return;
  }
  if (test_reused_tid && pending_thread_clones != 0)
    atomic_store_explicit(&test_reused_tid_waited, true, memory_order_release);
  if (pending_thread_clones == 0 && !mapping_found)
    mapping_found = lookup_task_birth(
        (int32_t)dr_get_thread_id(drcontext), &published_birth_token);
  if (pending_thread_clones != 0 || !mapping_found) {
    set_pending_thread_start(counters, 2);
    return;
  }
  if (test_reused_tid && published_birth_token == TEST_REUSED_TID_STALE) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: reused host TID did not receive expected birth "
        "identity\n");
    exit_runtime_tree(91);
    return;
  }
  counters->kernel_tid = (int32_t)dr_get_thread_id(drcontext);

  int32_t init_result = 0;
  if (!has_copied_runtime() ||
      (runtime_uses_external_global() && !is_copied_vfork_process())) {
    bind_capture_owner(counters);
    evidence_callback_enter();
    init_result = reverie_dbt_runtime_thread_init(
        counters,
        drcontext,
        (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(),
        in_tree_parent_pid(),
        atomic_load_explicit(&branch_count, memory_order_relaxed),
        0,
        invoke_syscall,
        read_registers,
        write_registers);
    evidence_callback_leave();
  }
  // TODO-HUMAN-REVIEW(PR-134): Confirm retryable native child startup.
  if (init_result > 0) {
    set_pending_thread_start(counters, 2);
    return;
  }
  if (init_result < 0) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: runtime thread initialization failed\n");
    exit_runtime_tree(101);
    return;
  }
  set_pending_thread_start(counters, 0);
}

static void start_pending_thread(void) {
  prototype_counters_t* counters = (prototype_counters_t*)drmgr_get_tls_field(
      dr_get_current_drcontext(), thread_state_index);
  struct timespec started;
  const uint64_t timeout_ms = test_stalled_thread_start ? 100 : 60000;
  if (counters == NULL || counters->pending_thread_start == 0)
    return;
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: cannot read thread admission deadline clock\n");
    exit_runtime_tree(97);
    return;
  }
  // This is also an entry-block clean call. Returning a retry to DynamoRIO
  // would let the child execute guest instructions before its Tool admits it.
  while (counters->pending_thread_start != 0) {
    try_start_pending_thread();
    if (counters->pending_thread_start == 0)
      return;
    // The runtime may block inside its Tool thread-start hook until the
    // scheduler admits the child. Check only a returned retry: a successful
    // admission must not fail because the Tool legitimately waited longer.
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: cannot read thread admission deadline clock\n");
      exit_runtime_tree(97);
      return;
    }
    uint64_t elapsed_ms = (uint64_t)(now.tv_sec - started.tv_sec) * 1000;
    if (now.tv_nsec >= started.tv_nsec)
      elapsed_ms += (uint64_t)(now.tv_nsec - started.tv_nsec) / 1000000;
    else
      elapsed_ms -=
          (uint64_t)(started.tv_nsec - now.tv_nsec + 999999) / 1000000;
    if (elapsed_ms >= timeout_ms) {
      uint64_t pending = atomic_load_explicit(
          pending_thread_clones_for(counters->kernel_pid),
          memory_order_acquire);
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: thread admission timed out: kernel_pid=%d "
          "host_tid=%d pending_clones=%llu pending_start=%llu "
          "timeout_ms=%llu\n",
          counters->kernel_pid,
          (int)dr_get_thread_id(dr_get_current_drcontext()),
          (unsigned long long)pending,
          (unsigned long long)counters->pending_thread_start,
          (unsigned long long)timeout_ms);
      exit_runtime_tree(96);
      return;
    }
    dr_sleep(1);
  }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the branch-count preemption hook.
// Defined below, after the runtime-readiness predicates it consults.
static void maybe_preempt(app_pc pc);
static void preempt_return(void);
static void signal_admission_return(void);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the injected-syscall stub.
// A tiny generated code region used as the redirect target that delivers a real
// `sched_yield` to the guest at a safe point. Its bytes are `syscall; ud2`: the
// `syscall` (with rax preloaded to SYS_sched_yield by the redirect) flows
// through the ordinary `pre_syscall` handler and Detcore's deterministic
// sched_yield path; the block starting at the trailing `ud2` carries a
// `preempt_return` clean call that redirects back to the captured guest
// context, so the `ud2` never actually executes (it is only a trap if the
// return path is somehow bypassed). Allocated once when preemption is enabled.
#define PREEMPT_STUB_SYSCALL_LEN 2 /* bytes of `syscall` (0F 05) */
#define PREEMPT_STUB_LEN 4 /* syscall (2) + ud2 (2) */
static byte* preempt_stub;
static byte* signal_stub;

static bool is_counted_branch(instr_t* instruction) {
  return instr_is_cbr(instruction) || instr_is_ubr(instruction) ||
      instr_is_call(instruction) || instr_is_return(instruction);
}

static dr_emit_flags_t analyze_syscall_gateway(
    void* drcontext,
    void* tag,
    instrlist_t* bb,
    bool for_trace,
    bool translating,
    void** user_data) {
  instr_t* instruction;
  *user_data = NULL;
  for (instruction = instrlist_first(bb); instruction != NULL;
       instruction = instr_get_next(instruction)) {
    if (instr_opcode_valid(instruction) &&
        is_compat_syscall_instruction(instruction)) {
      *user_data = (void*)1;
      break;
    }
  }
  return DR_EMIT_DEFAULT;
}

static bool admission_registers_available(void* drcontext, bool restored) {
  reg_id_t reg = DR_REG_NULL;
  for (;;) {
    drreg_reserve_info_t info = {sizeof(info)};
    if (drreg_reservation_info_ex(drcontext, reg, &info) != DRREG_SUCCESS ||
        info.reserved || (restored && !info.holds_app_value))
      return false;
    if (reg == DR_REG_STOP_GPR)
      return true;
    reg = reg == DR_REG_NULL ? DR_REG_START_GPR : reg + 1;
  }
}

static void insert_thread_admission(
    void* drcontext,
    instrlist_t* bb,
    instr_t* instruction) {
  const dr_cleancall_save_t context_flags =
      DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT;
  /* drreg cannot combine MULTIPATH with WRITES_APP_CONTEXT. Materialize all
   * unreserved application values before branching, so skipping the call cannot
   * skip a lazy restore or an update to a live spill. If another instrumenter
   * owns a register, keep the original unconditional call instead. */
  if (!admission_registers_available(drcontext, false)) {
    dr_insert_clean_call_ex(
        drcontext,
        bb,
        instruction,
        (void*)start_pending_thread,
        context_flags,
        0);
    return;
  }
  DR_ASSERT(drreg_restore_all(drcontext, bb, instruction) == DRREG_SUCCESS);
  if (!admission_registers_available(drcontext, true)) {
    dr_insert_clean_call_ex(
        drcontext,
        bb,
        instruction,
        (void*)start_pending_thread,
        context_flags,
        0);
    return;
  }

  instr_t* skip = INSTR_CREATE_label(drcontext);
  instr_t* call = INSTR_CREATE_label(drcontext);
  instr_t* restore = INSTR_CREATE_label(drcontext);
  /* The pending path restores the application register before the clean call
   * and saves its possibly updated value afterward. Both paths then execute
   * the same final restore. The saved slot is valid at every linear decoder
   * position even when the call is skipped. No instruction here changes flags.
   */
  dr_save_reg(drcontext, bb, instruction, DR_REG_XCX, SPILL_SLOT_1);
  dr_insert_read_raw_tls(
      drcontext,
      bb,
      instruction,
      admission_state_tls_register,
      admission_state_tls_offset,
      DR_REG_XCX);
  instrlist_meta_preinsert(
      bb, instruction, INSTR_CREATE_jecxz(drcontext, opnd_create_instr(skip)));
  instrlist_meta_preinsert(
      bb, instruction, INSTR_CREATE_jmp(drcontext, opnd_create_instr(call)));
  instrlist_meta_preinsert(bb, instruction, skip);
  instrlist_meta_preinsert(
      bb, instruction, INSTR_CREATE_jmp(drcontext, opnd_create_instr(restore)));
  instrlist_meta_preinsert(bb, instruction, call);
  dr_restore_reg(drcontext, bb, instruction, DR_REG_XCX, SPILL_SLOT_1);
  dr_insert_clean_call_ex(
      drcontext,
      bb,
      instruction,
      (void*)start_pending_thread,
      context_flags,
      0);
  dr_save_reg(drcontext, bb, instruction, DR_REG_XCX, SPILL_SLOT_1);
  instrlist_meta_preinsert(bb, instruction, restore);
  dr_restore_reg(drcontext, bb, instruction, DR_REG_XCX, SPILL_SLOT_1);
}

static dr_emit_flags_t instrument_instruction(
    void* drcontext,
    void* tag,
    instrlist_t* bb,
    instr_t* instruction,
    bool for_trace,
    bool translating,
    void* user_data) {
  // Private control instructions never enter application branch accounting,
  // stack scrubbing, thread admission, or the synthetic sched_yield path.
  if (instr_is_app(instruction) && signal_stub != NULL) {
    app_pc pc = instr_get_app_pc(instruction);
    if (pc >= signal_stub && pc < signal_stub + PREEMPT_STUB_LEN) {
      if (pc == signal_stub + PREEMPT_STUB_SYSCALL_LEN)
        dr_insert_clean_call(drcontext, bb, instruction,
                             (void*)signal_admission_return, false, 0);
      return DR_EMIT_DEFAULT;
    }
  }
  // A shared fragment can be compiled before any thread clone is pending.
  // Always retain the runtime check: thread-init's mcontext PC is not a valid
  // application entry address on Linux, so it cannot flush an older fragment.
  if (instr_is_app(instruction) && instruction == instrlist_first_app(bb)) {
    insert_thread_admission(drcontext, bb, instruction);
  }
  // The INITIAL guest-stack scrub runs HERE -- at the first application
  // instruction -- and not, as it once did, at the first application syscall.
  // That is what makes its blunt positional rule true instead of merely
  // plausible: at this point DynamoRIO's initialization is complete and off the
  // application stack, and the guest has executed ZERO instructions, so every
  // byte below the stack pointer really is DynamoRIO's or the loader's. Any
  // byte the guest writes -- including before its first syscall, which is the
  // case `first_scrub_marker.c` plants -- is written strictly after this and
  // therefore survives. Gated at instrumentation time so that once the scrub
  // has run no further block carries the call.
  if (instr_is_app(instruction) && instruction == instrlist_first_app(bb) &&
      atomic_load_explicit(
          &guest_stack_initially_scrubbed, memory_order_acquire) == 0) {
    dr_insert_clean_call_ex(
        drcontext,
        bb,
        instruction,
        (void*)scrub_guest_stack_before_first_instruction,
        DR_CLEANCALL_READS_APP_CONTEXT,
        0);
  }
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the branch-count preemption hook.
  // Mirrors the `start_pending_thread` hook above: at the first application
  // instruction of a block, invoke `maybe_preempt`, which injects a synthetic
  // sched_yield scheduler turn once the per-thread branch quantum elapses.
  // Gated at instrumentation time on `preemption_enabled` (a `dr_client_main`
  // constant) so disabled runs incur zero added instrumentation.
  if (preemption_enabled && preempt_stub != NULL && instr_is_app(instruction) &&
      instruction == instrlist_first_app(bb)) {
    app_pc block_pc = instr_get_app_pc(instruction);
    // Blocks inside the injected-syscall stub are handled specially and never
    // carry the ordinary preemption hook. The block starting at the trailing
    // `ud2` gets the `preempt_return` clean call that resumes the guest; the
    // stub's `syscall` block needs no preemption instrumentation (it flows
    // through `pre_syscall` like any syscall).
    if (block_pc >= preempt_stub &&
        block_pc < preempt_stub + PREEMPT_STUB_LEN) {
      if (block_pc == preempt_stub + PREEMPT_STUB_SYSCALL_LEN) {
        dr_insert_clean_call(
            drcontext,
            bb,
            instruction,
            (void*)preempt_return,
            /*save_fpstate=*/false,
            0);
      }
      return DR_EMIT_DEFAULT;
    }
    // Ordinary application block: at its first instruction, invoke
    // `maybe_preempt`. It must be FULLY transparent, so `save_fpstate = true`
    // makes DynamoRIO save/restore the floating-point/vector state around the
    // call; we do not declare WRITES_APP_CONTEXT. We pass the block's
    // application PC so `maybe_preempt` can deliver the yield only at a SAFE
    // POINT (a PC in the guest's own main executable, never mid-sequence inside
    // libc/ld).
    dr_insert_clean_call(
        drcontext,
        bb,
        instruction,
        (void*)maybe_preempt,
        /*save_fpstate=*/true,
        1,
        OPND_CREATE_INTPTR(block_pc));
  }
  if (user_data != NULL && instruction == instrlist_first(bb)) {
    dr_insert_clean_call(
        drcontext,
        bb,
        instruction,
        (void*)mark_compat_syscall_gateway,
        false,
        0);
  }
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == cpuid_marker_note) {
    dr_insert_clean_call_ex(
        drcontext,
        bb,
        instruction,
        (void*)emulate_cpuid,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT,
        0);
    return DR_EMIT_DEFAULT;
  }
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == rdtsc_marker_note) {
    dr_insert_clean_call_ex(
        drcontext,
        bb,
        instruction,
        (void*)emulate_rdtsc,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT,
        0);
    return DR_EMIT_DEFAULT;
  }
  if (instr_is_app(instruction) &&
      (ptr_uint_t)instr_get_note(instruction) == rdtscp_marker_note) {
    dr_insert_clean_call_ex(
        drcontext,
        bb,
        instruction,
        (void*)emulate_rdtscp,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT,
        0);
    return DR_EMIT_DEFAULT;
  }
  if (!instr_is_app(instruction) || !is_counted_branch(instruction))
    return DR_EMIT_DEFAULT;

  if (!drx_insert_counter_update(
          drcontext,
          bb,
          instruction,
          SPILL_SLOT_MAX + 1,
          &branch_count,
          1,
          DRX_COUNTER_64BIT | DRX_COUNTER_LOCK))
    DR_ASSERT(false);

  return DR_EMIT_DEFAULT;
}

static int64_t
invoke_raw_syscall(uintptr_t context, int64_t sysnum, const uint64_t* args);

/* Whether this syscall sets or reports an asynchronous-I/O owner: the process,
 * thread or process group Linux signals (SIGIO, or the F_SETSIG signal) when
 * the descriptor becomes ready. The socket ioctls carry F_SETOWN's encoding
 * through an int pointer; Linux hands them to the same f_setown/f_getown. */
static bool is_owner_syscall(int sysnum, uint32_t cmd) {
  if (sysnum == SYS_fcntl)
    return cmd == F_SETOWN || cmd == F_SETOWN_EX || cmd == F_GETOWN ||
        cmd == F_GETOWN_EX;
  if (sysnum == SYS_ioctl)
    return cmd == FIOSETOWN || cmd == SIOCSPGRP || cmd == FIOGETOWN ||
        cmd == SIOCGPGRP;
  return false;
}

static int64_t owner_raw_syscall(
    uintptr_t context,
    int64_t sysnum,
    uint64_t a0,
    uint64_t a1,
    uint64_t a2) {
  const uint64_t args[6] = {a0, a1, a2, 0, 0, 0};
  return invoke_raw_syscall(context, sysnum, args);
}

/* The kernel process group admitted by the existing owner screen. */
static fcntl_group_view_t caller_group_view(uintptr_t context) {
  int64_t caller_group = owner_raw_syscall(context, SYS_getpgid, 0, 0, 0);
  fcntl_group_view_t groups = {
      .caller_group = caller_group > 0 ? (int32_t)caller_group : 0,
  };
  return groups;
}

/* Apply the retained unknown-owner screen to F_SETOWN or F_SETOWN_EX. */
static bool screen_owner_value(
    uintptr_t context, int32_t type, int32_t* value) {
  fcntl_group_view_t groups = caller_group_view(context);
  task_state_lock();
  bool screened = type < 0
      ? screen_setown_entries(task_state->tasks, task_state->task_count,
            &groups, value)
      : screen_owner_entries(task_state->tasks, task_state->task_count,
            &groups, type, value);
  task_state_unlock();
  return screened;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(hermit-3955): Review DBT fcntl/ioctl owner translation.
/* Run an owner syscall (see `is_owner_syscall`) with guest IDs translated to
 * host IDs and the reported owner translated back. The guest names owners by
 * its own IDs while Linux resolves them in the host PID space, so passing them
 * through either fails with ESRCH or makes an unrelated host task the owner.
 *
 * Both routes to the kernel come here: syscalls a Tool injects, and the
 * guest's own syscalls, which `prepare_original_task_syscall` executes
 * here and skips. The translated owner lives in this frame's copy, so the
 * guest's registers and memory are never rewritten and no state outlives the
 * call; none of these commands blocks. An owner that cannot be read is passed
 * through so the kernel reports EFAULT. */
static int64_t
execute_owner_syscall(uintptr_t context, int sysnum, const uint64_t* args) {
  uint64_t translated[6];
  uint32_t cmd = (uint32_t)args[1];
  void* guest_owner = (void*)(uintptr_t)args[2];
  fcntl_owner_ex_t owner;
  int32_t who;
  int64_t result;

  memcpy(translated, args, sizeof(translated));
  if (sysnum == SYS_fcntl && cmd == F_SETOWN) {
    who = (int32_t)args[2];
    if (screen_owner_value(context, -1, &who))
      translated[2] = (uint64_t)(int64_t)who;
  } else if (sysnum == SYS_fcntl && cmd == F_SETOWN_EX) {
    if (read_app(guest_owner, &owner, sizeof(owner)) &&
        screen_owner_value(context, owner.type, &owner.pid))
      translated[2] = (uint64_t)(uintptr_t)&owner;
  } else if (sysnum == SYS_ioctl && (cmd == FIOSETOWN || cmd == SIOCSPGRP)) {
    if (read_app(guest_owner, &who, sizeof(who)) &&
        screen_owner_value(context, -1, &who))
      translated[2] = (uint64_t)(uintptr_t)&who;
  }
  result = invoke_raw_syscall(context, sysnum, translated);

  return result;
}

static bool validate_task_argument(uint64_t* argument) {
  int32_t identity = (int32_t)*argument;
  int32_t host;
  if (identity <= 0)
    return true;
  host = known_task_identity(identity);
  if (host <= 0)
    return false;
  *argument = (uint64_t)(uint32_t)host;
  return true;
}

static int64_t
invoke_raw_syscall(uintptr_t context, int64_t sysnum, const uint64_t* args) {
  prototype_counters_t* counters = drmgr_get_tls_field(
      (void*)context, thread_state_index);
  reg_t raw_args[6];
  for (int i = 0; i < 6; ++i) raw_args[i] = (reg_t)args[i];
  dr_syscall_invoke_result_t invocation;
  /* DR attributes only this write's fresh EPIPE receipt to the application
   * task. Queued payloads and explicit Tool replacements remain untouched. */
  int32_t sigpipe_pid = 0;
  if (sysnum == SYS_write || sysnum == SYS_writev || sysnum == SYS_pwrite64 ||
      sysnum == SYS_pwritev || sysnum == SYS_pwritev2)
    sigpipe_pid = (int32_t)dr_get_process_id();
  if (!dr_invoke_syscall_as_app_with_result_and_sigpipe_identity(
          (void*)context, (int)sysnum, 6, raw_args, sigpipe_pid, &invocation)) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: returning syscall injection ownership refused\n");
    exit_runtime_tree(101);
    return -EIO;
  }
  if (invocation.interruption != 0) {
    if (counters == NULL || counters->syscall_interruption != 0) {
      dr_fprintf(diagnostic_file, "reverie-dbt: nested syscall interruption refused\n");
      exit_runtime_tree(101);
      return -EIO;
    }
    counters->syscall_interruption = invocation.interruption;
    counters->syscall_interruption_generation =
        atomic_load_explicit(&image_generation, memory_order_acquire);
    counters->syscall_interruption_pid = dr_get_process_id();
    counters->syscall_interruption_tid = dr_get_thread_id((void*)context);
  }
  return (int64_t)invocation.value;
}

static bool is_exec_syscall(int sysnum);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-411): Review close_range splitting around the internal
// identity and diagnostic descriptors.
#ifdef SYS_close_range
static int64_t close_range_preserving_internal_descriptors(
    uintptr_t context,
    const uint64_t* args) {
  const uint32_t first = (uint32_t)args[0];
  const uint32_t last = (uint32_t)args[1];
  uint32_t flags = (uint32_t)args[2];
  int64_t result;

  if (first > last ||
      (flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC)) != 0)
    return -EINVAL;

  if ((flags & CLOSE_RANGE_UNSHARE) != 0) {
    const uint64_t unshare_args[6] = {CLONE_FILES, 0, 0, 0, 0, 0};
    result = invoke_raw_syscall(context, SYS_unshare, unshare_args);
    if (result < 0)
      return result;
    flags &= ~CLOSE_RANGE_UNSHARE;
  }

  if (first < TASK_STATE_FD) {
    const uint32_t range_last =
        last < TASK_STATE_FD ? last : TASK_STATE_FD - 1;
    const uint64_t close_args[6] = {first, range_last, flags, 0, 0, 0};
    result = invoke_raw_syscall(context, SYS_close_range, close_args);
    if (result < 0)
      return result;
  }
  if (last > DBT_DIAGNOSTIC_FD) {
    const uint32_t range_first =
        first > DBT_DIAGNOSTIC_FD ? first : DBT_DIAGNOSTIC_FD + 1;
    const uint64_t close_args[6] = {range_first, last, flags, 0, 0, 0};
    result = invoke_raw_syscall(context, SYS_close_range, close_args);
    if (result < 0)
      return result;
  }
  return 0;
}
#endif

// The runtime's own descriptors, the identity memfd (fd 197) and the
// diagnostic file (fd 198), are not open as far as the guest knows: the rule
// every in-process backend shares (reverie_inguest::reserved_fds). This C
// client is still that rule's fourth copy, covering only the calls below;
// other calls naming 197 or 198 are not yet checked.
static bool is_internal_descriptor(int fd) {
  return fd == TASK_STATE_FD || fd == DBT_DIAGNOSTIC_FD;
}

// A guest dup2/dup3 onto 197 or 198: Linux would succeed, giving the guest a
// copy at that number, and this client cannot yet move its own descriptor
// out of the way. A fail-closed run (Hermit's default) therefore ends with the
// policy-refusal status Detcore's own refusals use (HERMIT_POLICY_REFUSAL_EXIT,
// 122), naming the call; a run that allows unsupported syscalls gets EBADF.
static int64_t refuse_dup_onto_internal_descriptor(int sysnum, int target) {
  if (!runtime_callbacks_page.value.panic_on_unsupported_syscalls)
    return -EBADF;
  dr_fprintf(
      diagnostic_file,
      "reverie-dbt: refusing %s onto descriptor %d, which the DBT runtime "
      "owns; moving it out of the guest's way is not implemented\n",
      sysnum == SYS_dup2 ? "dup2" : "dup3",
      target);
  // Through exit_runtime_tree, so the protected evidence records that the run
  // ended here rather than finding its outcome missing.
  exit_runtime_tree(122);
  return -EBADF;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-106): keep the identity memfd (fd 197) and diagnostic fd
// (198) alive across close/fcntl(F_SETFD)/dup2/dup3 in copied children.
static bool preserve_internal_descriptors(
    uintptr_t context,
    int sysnum,
    const uint64_t* args,
    int64_t* result) {
  int fd = (int)args[0];
  // A close of a number the guest does not have open fails, as on Linux.
  if (sysnum == SYS_close && is_internal_descriptor(fd)) {
    *result = -EBADF;
    return true;
  }
#ifdef SYS_close_range
  // AUTONOMOUS-BOT-IMPLEMENTED
  if (sysnum == SYS_close_range) {
    const uint32_t first = (uint32_t)args[0];
    const uint32_t last = (uint32_t)args[1];
    if ((first <= TASK_STATE_FD && TASK_STATE_FD <= last) ||
        (first <= DBT_DIAGNOSTIC_FD && DBT_DIAGNOSTIC_FD <= last)) {
      *result = close_range_preserving_internal_descriptors(context, args);
      return true;
    }
  }
#endif
  if (sysnum == SYS_fcntl && is_internal_descriptor(fd) &&
      args[1] == F_SETFD) {
    *result = -EBADF;
    return true;
  }
  if ((sysnum == SYS_dup2 || sysnum == SYS_dup3) &&
      is_internal_descriptor((int)args[1])) {
    *result = refuse_dup_onto_internal_descriptor(sysnum, (int)args[1]);
    return true;
  }
  return false;
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-106): retained PID-target admission policy.
// Residual native policy: except for get_robust_list, positive task targets must
// be known members; unknown targets retain the prior errno/impossible-target
// behavior. Accepted numbers are unchanged. Negative group targets retain
// their existing pass-through.
// Shared ownership of helper exclusion remains separate work.
static bool validate_task_arguments(int sysnum, uint64_t* args) {
  switch (sysnum) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-259): Review get_robust_list target admission.
    case SYS_get_robust_list: {
      int32_t birth = 0;
      bool found = lookup_task_birth((int32_t)args[0], &birth);
      return task_membership_allows_robust_query(found, birth);
    }
    case SYS_kill:
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-453): Review pidfd_open target admission.
    case SYS_pidfd_open:
    case SYS_tkill:
    case SYS_wait4:
    case SYS_sched_setaffinity:
    case SYS_sched_setparam:
    case SYS_sched_setscheduler:
      return validate_task_argument(&args[0]);
    case SYS_rt_sigqueueinfo:
    case SYS_rt_tgsigqueueinfo:
      // Let the kernel validate siginfo and target identity in its own order.
      // An unknown task PID must never address an unrelated host process;
      // using an impossible PID preserves EFAULT/EPERM before ESRCH as well.
      if (!validate_task_argument(&args[0]))
        args[0] = INT32_MAX;
      if (sysnum == SYS_rt_tgsigqueueinfo &&
          !validate_task_argument(&args[1]))
        args[1] = INT32_MAX;
      return true;
    case SYS_tgkill:
      return validate_task_argument(&args[0]) &&
          validate_task_argument(&args[1]);
    case SYS_setpgid:
      return validate_task_argument(&args[0]) &&
          validate_task_argument(&args[1]);
    case SYS_waitid:
      return args[0] != P_PID || validate_task_argument(&args[1]);
    case SYS_prlimit64:
      return args[0] == 0 || validate_task_argument(&args[0]);
    case SYS_setpriority:
      return args[0] != PRIO_PROCESS || args[1] == 0 ||
          validate_task_argument(&args[1]);
    default:
      return true;
  }
}

static int64_t
unknown_identity_error(uintptr_t context, int sysnum, const uint64_t* args) {
  if (sysnum == SYS_pidfd_open) {
    uint64_t validation_args[6];
    int64_t result;
    memcpy(validation_args, args, sizeof(validation_args));
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-453): Preserve Linux pidfd_open validation order.
    // INT32_MAX is outside Linux's PID range. Asking the running kernel to
    // validate the original flags against that impossible PID preserves its
    // EINVAL-before-ESRCH order without passing an unknown task PID through
    // to a potentially unrelated host process.
    validation_args[0] = INT32_MAX;
    result = invoke_raw_syscall(context, SYS_pidfd_open, validation_args);
    if (result >= 0) {
      uint64_t close_args[6] = {(uint64_t)result, 0, 0, 0, 0, 0};
      (void)invoke_raw_syscall(context, SYS_close, close_args);
      return -ESRCH;
    }
    return result;
  }
  return sysnum == SYS_wait4 || sysnum == SYS_waitid ? -ECHILD : -ESRCH;
}

static bool
clone_identity_flags(int sysnum, const uint64_t* args, uint64_t* flags) {
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
          read_app((const void*)(uintptr_t)args[0], flags, sizeof(*flags));
    default:
      return false;
  }
}

static bool process_clone_metadata(
    int sysnum,
    const uint64_t* args,
    uint64_t* flags,
    uint64_t* child_tid_addr,
    int32_t* exit_signal) {
  switch (sysnum) {
    case SYS_fork:
      *flags = 0;
      *child_tid_addr = 0;
      *exit_signal = SIGCHLD;
      return true;
    case SYS_vfork:
      *flags = CLONE_VM | CLONE_VFORK;
      *child_tid_addr = 0;
      *exit_signal = SIGCHLD;
      return true;
    case SYS_clone:
      *flags = args[0];
      *child_tid_addr = args[3];
      *exit_signal = (int32_t)(*flags & 0xff);
      return true;
#ifdef SYS_clone3
    case SYS_clone3: {
      uint64_t clone3_args[5];
      if (args[0] == 0 || args[1] < sizeof(clone3_args) ||
          !read_app(
              (const void*)(uintptr_t)args[0],
              clone3_args,
              sizeof(clone3_args)))
        return false;
      *flags = clone3_args[0];
      *child_tid_addr = clone3_args[2];
      *exit_signal = (int32_t)clone3_args[4];
      return true;
    }
#endif
    default:
      return false;
  }
}

/* The addresses where Linux stores the new child's TID: `parent_tid`, in the
 * parent, for CLONE_PARENT_SETTID, and `child_tid`, in the child, for
 * CLONE_CHILD_SETTID. They are clone's third and fourth arguments, or
 * clone3's parent_tid and child_tid fields; fork and vfork take neither. */

static bool is_clone_syscall(int sysnum) {
  return sysnum == SYS_fork || sysnum == SYS_vfork || sysnum == SYS_clone ||
      sysnum == SYS_clone3;
}

/* This is an observation boundary, not a syscall policy. A failed attempt
 * remains uncertain too. Pending ordinary forks protect the interval before a
 * copied child's first vfork fastpath reaches this permanent mark. */
static bool capture_lifecycle_is_uncertain(int sysnum, const uint64_t* args) {
  if (sysnum == SYS_unshare || sysnum == SYS_setns)
    return true;
  if (is_clone_syscall(sysnum)) {
    uint64_t flags;
    return !clone_identity_flags(sysnum, args, &flags) ||
        (flags & (CLONE_VFORK | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER)) != 0;
  }
  return false;
}

static void capture_observe_lifecycle(int sysnum, const uint64_t* args) {
  if (capture_lifecycle_is_uncertain(sysnum, args))
    capture_mark_uncertain();
}

typedef enum {
  /* Guest::inject observes its synchronous backend/API result after existing
   * clone birth bookkeeping. Only application syscalls have a
   * DynamoRIO post-event that can consume the callback latch. */
  CLONE_SYSCALL_INJECTED,
  CLONE_SYSCALL_ORIGINAL,
} clone_syscall_origin_t;

static bool fail_if_process_clone_result_pending(
    const prototype_counters_t* counters,
    int sysnum) {
  if (counters->pending_process_clone_result == 0)
    return false;
  dr_fprintf(
      diagnostic_file,
      "reverie-dbt: stale process-clone result state before syscall %d\n",
      sysnum);
  exit_runtime_tree(101);
  return true;
}

static void acquire_clone_identity_handoff(void) {
  while (atomic_flag_test_and_set_explicit(
      &pending_clone_lock, memory_order_acquire))
    dr_sleep(1);
}

static void release_clone_identity_handoff(int32_t birth_token) {
  int32_t expected = birth_token;
  if (birth_token == 0)
    return;
  if (atomic_compare_exchange_strong_explicit(
          &pending_clone_birth_token,
          &expected,
          0,
          memory_order_acq_rel,
          memory_order_acquire)) {
    atomic_store_explicit(&pending_clone_flags, 0, memory_order_relaxed);
    atomic_store_explicit(&pending_clone_creator_pid, 0, memory_order_relaxed);
    atomic_flag_clear_explicit(&pending_clone_lock, memory_order_release);
  }
}

static bool prepare_clone_birth(
    prototype_counters_t* counters,
    int sysnum,
    const uint64_t* args,
    clone_syscall_origin_t origin) {
  uint64_t flags;
  capture_observe_lifecycle(sysnum, args);
  if (fail_if_process_clone_result_pending(counters, sysnum))
    return false;
  if (!clone_identity_flags(sysnum, args, &flags))
    return false;
  DR_ASSERT(counters->pending_birth_token == 0);
  if ((flags & CLONE_THREAD) == 0)
    acquire_clone_identity_handoff();
  counters->pending_birth_token = next_birth_token();
  counters->pending_clone_flags = flags;
  if ((flags & CLONE_THREAD) == 0)
    reserve_capture_admission(counters->pending_birth_token);
  if (origin == CLONE_SYSCALL_ORIGINAL && (flags & CLONE_THREAD) == 0) {
    uint64_t child_tid_addr = 0;
    int32_t exit_signal = -1;
    counters->pending_process_clone_result = 1;
    counters->pending_process_clone_flags = flags;
    counters->pending_process_clone_ctid = 0;
    counters->pending_process_clone_exit_signal = -1;
    if (process_clone_metadata(
            sysnum, args, &flags, &child_tid_addr, &exit_signal)) {
      counters->pending_process_clone_flags = flags;
      counters->pending_process_clone_ctid = child_tid_addr;
      counters->pending_process_clone_exit_signal = exit_signal;
    }
  }
  if ((flags & CLONE_THREAD) != 0) {
    if (test_thread_start_write &&
        (sysnum != SYS_clone ||
         !read_app(
             (const void*)(uintptr_t)args[1],
             &test_thread_start_write_address,
             sizeof(test_thread_start_write_address)))) {
      exit_runtime_tree(95);
      return false;
    }
    atomic_fetch_add_explicit(
        pending_thread_clones_for(counters->kernel_pid),
        1,
        memory_order_acq_rel);
    if (test_thread_clone_process_exit &&
        counters->kernel_pid != task_state->root_pid) {
      atomic_store_explicit(
          &task_state->thread_clone_process_exit_test_exercised,
          true,
          memory_order_release);
      dr_fprintf(
          diagnostic_file, "THREAD_CLONE_PROCESS_EXIT_TEST exercised=1\n");
      exit_runtime_tree(94);
      return false;
    }
  } else {
    atomic_store_explicit(&pending_clone_flags, flags, memory_order_relaxed);
    atomic_store_explicit(
        &pending_clone_creator_pid,
        (int32_t)dr_get_process_id(),
        memory_order_relaxed);
    atomic_store_explicit(
        &pending_clone_birth_token,
        counters->pending_birth_token,
        memory_order_release);
  }
  return true;
}

/* The return is a positive kernel clone result, or zero. The private birth
 * serial is consumed here and never reaches a runtime or guest PID field. */
static int32_t complete_clone_birth(
    prototype_counters_t* counters,
    int64_t result) {
  int32_t birth_token = counters->pending_birth_token;
  uint64_t flags = counters->pending_clone_flags;
  if (birth_token == 0)
    return 0;
  if (result < 0 && (flags & CLONE_THREAD) == 0)
    cancel_failed_capture_admission(birth_token);
  if (result == 0 && !require_supported_child_pid_namespace())
    return 0;

  if (result > 0) {
    if ((flags & CLONE_THREAD) == 0) {
      require_evidence_child((process_id_t)result);
      if (test_kill_announced_child && kill((pid_t)result, SIGKILL) != 0) {
        dr_fprintf(
            diagnostic_file,
            "reverie-dbt: failed to kill announced test child\n");
        exit_runtime_tree(101);
      }
    }
    if (test_reused_tid && (flags & CLONE_THREAD) != 0) {
      int32_t injected = 0;
      int attempts;
      inject_stale_task_birth_for_test((int32_t)result);
      if (!lookup_task_birth((int32_t)result, &injected) ||
          injected != TEST_REUSED_TID_STALE) {
        publish_task_birth((int32_t)result, birth_token, true);
        finish_pending_thread_clone(counters->kernel_pid);
        exit_runtime_tree(92);
        return 0;
      }
      for (attempts = 0; attempts != 1000; ++attempts) {
        if (atomic_load_explicit(&test_reused_tid_waited, memory_order_acquire))
          break;
        dr_sleep(1);
      }
      if (attempts == 1000) {
        publish_task_birth((int32_t)result, birth_token, true);
        finish_pending_thread_clone(counters->kernel_pid);
        exit_runtime_tree(93);
        return 0;
      }
      atomic_store_explicit(
          &test_reused_tid_exercised, true, memory_order_release);
      if (test_thread_start_write) {
        int written = -1;
        dr_sleep(20);
        bool readable = read_app(
            (const void*)(uintptr_t)test_thread_start_write_address,
            &written,
            sizeof(written));
        if (!readable || written != 0) {
          dr_fprintf(
              diagnostic_file,
              "reverie-dbt: child wrote memory before thread admission "
              "readable=%d written=%d\n",
              readable,
              written);
          exit_runtime_tree(95);
          return 0;
        }
        dr_fprintf(diagnostic_file, "THREAD_START_WRITE_TEST blocked=1\n");
      }
    }
    /* Publish this clone transaction before releasing child admission. A
     * retained record for an earlier TID incarnation cannot admit the child. */
    publish_task_birth(
        (int32_t)result, birth_token, (flags & CLONE_THREAD) != 0);
  } else if (result == 0) {
    int32_t host_tid = (int32_t)dr_get_thread_id(dr_get_current_drcontext());
    if ((flags & CLONE_THREAD) == 0)
      evidence_initialize_fork_child_thread(counters);
    publish_task_birth(host_tid, birth_token, true);
    if ((flags & CLONE_THREAD) != 0) {
      counters->kernel_tid = host_tid;
    } else {
      int32_t parent = counters->kernel_pid;
      publish_task_birth((int32_t)dr_get_process_id(), birth_token, true);
      rebind_private_memory_after_clone(flags);
      if ((flags & CLONE_VFORK) != 0) {
        atomic_store_explicit(
            &copied_vfork_pid,
            (int32_t)dr_get_process_id(),
            memory_order_release);
        release_clone_identity_handoff(birth_token);
      }
      if ((flags & CLONE_VM) != 0)
        return 0;
      counters->kernel_pid = (int32_t)dr_get_process_id();
      counters->kernel_ppid = parent;
      counters->kernel_tid = host_tid;
      runtime_parent_process_id = parent;
      runtime_process_id = (int32_t)dr_get_process_id();
      runtime_is_root = false;
    }
  }
  if ((flags & CLONE_THREAD) != 0 && result != 0) {
    if (test_stalled_thread_start && result > 0)
      dr_fprintf(diagnostic_file, "STALLED_THREAD_START_TEST exercised=1\n");
    else
      finish_pending_thread_clone(counters->kernel_pid);
  } else if (
      (flags & CLONE_THREAD) == 0 && (result <= 0 || (flags & CLONE_VM) == 0)) {
    release_clone_identity_handoff(birth_token);
  }
  counters->pending_birth_token = 0;
  if (!(result == 0 && (flags & CLONE_THREAD) == 0 && runtime_owner_pid != 0 &&
        dr_get_process_id() != runtime_owner_pid &&
        runtime_uses_external_global()))
    counters->pending_clone_flags = 0;
  return result > 0 ? (int32_t)result : 0;
}

typedef struct {
  struct msghdr msg_hdr;
  unsigned int msg_len;
} evidence_mmsghdr_t;

static bool sockaddr_is_evidence(const void* address, size_t length) {
  struct sockaddr_un candidate;
  const size_t expected =
      offsetof(struct sockaddr_un, sun_path) + 1 + EVIDENCE_ADDRESS_LEN;
  if (!evidence_is_enabled() || address == NULL || length != expected ||
      !read_app(address, &candidate, expected))
    return false;
  return candidate.sun_family == AF_UNIX && candidate.sun_path[0] == 0 &&
      memcmp(
          candidate.sun_path + 1,
          evidence_config_page.value.address,
          EVIDENCE_ADDRESS_LEN) == 0;
}

static bool message_targets_evidence(const void* address) {
  struct msghdr message;
  return address != NULL && read_app(address, &message, sizeof(message)) &&
      sockaddr_is_evidence(message.msg_name, message.msg_namelen);
}

static bool proc_link_is_memory(const char* link, size_t length) {
  static const char prefix[] = "/proc/";
  static const char suffix[] = "/mem";
  return length >= sizeof(prefix) - 1 + sizeof(suffix) - 1 &&
      memcmp(link, prefix, sizeof(prefix) - 1) == 0 &&
      memcmp(
          link + length - (sizeof(suffix) - 1), suffix, sizeof(suffix) - 1) ==
      0;
}

static bool fd_is_proc_mem(uintptr_t context, int fd) {
  char descriptor_path[64];
  char target[4096];
  uint64_t arguments[6];
  int path_length = dr_snprintf(
      descriptor_path, sizeof(descriptor_path), "/proc/self/fd/%d", fd);
  int64_t target_length;
  if (path_length <= 0 || (size_t)path_length >= sizeof(descriptor_path))
    return false;
  memset(arguments, 0, sizeof(arguments));
  arguments[0] = (uint64_t)(uint32_t)AT_FDCWD;
  arguments[1] = (uint64_t)(uintptr_t)descriptor_path;
  arguments[2] = (uint64_t)(uintptr_t)target;
  arguments[3] = sizeof(target) - 1;
  target_length = invoke_raw_syscall(context, SYS_readlinkat, arguments);
  if (target_length <= 0 || (size_t)target_length >= sizeof(target))
    return false;
  target[target_length] = 0;
  return proc_link_is_memory(target, (size_t)target_length);
}

static bool
path_is_proc_mem(uintptr_t context, int directory_fd, const void* path) {
  uint64_t open_arguments[6] = {
      (uint64_t)(uint32_t)directory_fd,
      (uint64_t)(uintptr_t)path,
      O_PATH | O_CLOEXEC,
      0,
  };
  int64_t descriptor;
  bool matches;
  if (path == NULL)
    return false;
  descriptor = invoke_raw_syscall(context, SYS_openat, open_arguments);
  if (descriptor < 0)
    return false;
  matches = fd_is_proc_mem(context, (int)descriptor);
  const uint64_t close_arguments[6] = {(uint64_t)descriptor};
  (void)invoke_raw_syscall(context, SYS_close, close_arguments);
  return matches;
}

static bool syscall_returns_open_fd(int sysnum) {
  return sysnum == SYS_open || sysnum == SYS_creat || sysnum == SYS_openat
#ifdef SYS_openat2
      || sysnum == SYS_openat2
#endif
      ;
}

static bool
reject_opened_proc_mem(uintptr_t context, int sysnum, int64_t descriptor) {
  if (!evidence_is_enabled() || descriptor < 0 ||
      !syscall_returns_open_fd(sysnum) ||
      !fd_is_proc_mem(context, (int)descriptor))
    return false;
  const uint64_t close_arguments[6] = {(uint64_t)descriptor};
  (void)invoke_raw_syscall(context, SYS_close, close_arguments);
  return true;
}

static bool
syscall_uses_proc_mem_fd(uintptr_t context, int sysnum, const uint64_t* args) {
  switch (sysnum) {
    case SYS_read:
    case SYS_write:
    case SYS_pread64:
    case SYS_pwrite64:
    case SYS_readv:
    case SYS_writev:
#ifdef SYS_preadv
    case SYS_preadv:
#endif
#ifdef SYS_pwritev
    case SYS_pwritev:
#endif
#ifdef SYS_preadv2
    case SYS_preadv2:
#endif
#ifdef SYS_pwritev2
    case SYS_pwritev2:
#endif
    case SYS_lseek:
      return fd_is_proc_mem(context, (int)args[0]);
    case SYS_mmap:
      return args[4] != (uint64_t)-1 && fd_is_proc_mem(context, (int)args[4]);
#ifdef SYS_sendfile
    case SYS_sendfile:
      return fd_is_proc_mem(context, (int)args[0]) ||
          fd_is_proc_mem(context, (int)args[1]);
#endif
#ifdef SYS_splice
    case SYS_splice:
      return fd_is_proc_mem(context, (int)args[0]) ||
          fd_is_proc_mem(context, (int)args[2]);
#endif
#ifdef SYS_copy_file_range
    case SYS_copy_file_range:
      return fd_is_proc_mem(context, (int)args[0]) ||
          fd_is_proc_mem(context, (int)args[2]);
#endif
    default:
      return false;
  }
}

static bool range_overlaps_page(
    uint64_t address,
    uint64_t length,
    const void* page,
    size_t page_length) {
  const uintptr_t page_start = (uintptr_t)page;
  const uintptr_t page_end = page_start + page_length;
  const uintptr_t start = (uintptr_t)address;
  uintptr_t end;
  if (length == 0)
    return false;
  if (length > UINTPTR_MAX - start)
    end = UINTPTR_MAX;
  else
    end = start + (uintptr_t)length;
  return start < page_end && end > page_start;
}

static bool range_overlaps_protected_evidence_state(
    uint64_t address,
    uint64_t length) {
  return range_overlaps_page(
             address,
             length,
             &evidence_config_page,
             sizeof(evidence_config_page)) ||
      range_overlaps_page(
             address,
             length,
             &runtime_callbacks_page,
             sizeof(runtime_callbacks_page));
}

static bool syscall_targets_protected_evidence_state(
    int sysnum,
    const uint64_t* args) {
  switch (sysnum) {
    case SYS_mprotect:
    case SYS_munmap:
    case SYS_madvise:
#ifdef SYS_pkey_mprotect
    case SYS_pkey_mprotect:
#endif
      return range_overlaps_protected_evidence_state(args[0], args[1]);
    case SYS_mremap:
      if (range_overlaps_protected_evidence_state(args[0], args[1]))
        return true;
      return (args[3] & MREMAP_FIXED) != 0 &&
          range_overlaps_protected_evidence_state(args[4], args[2]);
    case SYS_mmap:
      return (args[3] & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0 &&
          range_overlaps_protected_evidence_state(args[0], args[1]);
#ifdef SYS_process_madvise
    case SYS_process_madvise:
      // The target ranges live in application memory and can race validation;
      // evidence mode does not permit this cross-process mutation primitive.
      return true;
#endif
#ifdef SYS_shmat
    case SYS_shmat:
      // SHM_REMAP can replace an existing mapping and supplies no segment
      // length in the syscall arguments, so it cannot be range-validated safely
      // here.
      return (args[2] & SHM_REMAP) != 0;
#endif
#if defined(SYS_io_uring_setup) || defined(SYS_io_uring_enter) || \
    defined(SYS_io_uring_register)
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup:
#endif
#ifdef SYS_io_uring_enter
    case SYS_io_uring_enter:
#endif
#ifdef SYS_io_uring_register
    case SYS_io_uring_register:
#endif
      // Submission queues execute fd, memory, and socket operations without
      // traversing the intercepted syscall path that protects this channel.
      return true;
#endif
    default:
      return false;
  }
}

// The io_uring family is refused as unavailable, with the ENOSYS that Detcore's
// policy returns for it, so enabling evidence does not change what a program
// that probes io_uring and falls back observes. Every other guarded operation
// is refused as forbidden.
static int64_t protected_evidence_refusal(int sysnum) {
  switch (sysnum) {
#if defined(SYS_io_uring_setup) || defined(SYS_io_uring_enter) || \
    defined(SYS_io_uring_register)
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup:
#endif
#ifdef SYS_io_uring_enter
    case SYS_io_uring_enter:
#endif
#ifdef SYS_io_uring_register
    case SYS_io_uring_register:
#endif
      return -ENOSYS;
#endif
    default:
      return -EPERM;
  }
}

// Reject app-originated traffic to the evidence endpoint even if the guest has
// recovered the client arguments or token from shared address-space state. The
// native sender uses client-private libc syscalls while the guest is stopped,
// so it never traverses this application-syscall policy.
static bool protect_evidence_socket_syscall(
    uintptr_t context,
    int sysnum,
    const uint64_t* args,
    int64_t* result) {
  if (!evidence_is_enabled())
    return false;
  if (syscall_targets_protected_evidence_state(sysnum, args) ||
      syscall_uses_proc_mem_fd(context, sysnum, args))
    goto forbidden;
  switch (sysnum) {
    case SYS_connect:
      if (!sockaddr_is_evidence((const void*)(uintptr_t)args[1], args[2]))
        return false;
      break;
    case SYS_sendto:
      if (!sockaddr_is_evidence((const void*)(uintptr_t)args[4], args[5]))
        return false;
      break;
    case SYS_sendmsg:
      if (!message_targets_evidence((const void*)(uintptr_t)args[1]))
        return false;
      break;
#ifdef SYS_sendmmsg
    case SYS_sendmmsg: {
      uint64_t index;
      if (args[1] == 0 || args[2] > 1024)
        return false;
      for (index = 0; index < args[2]; ++index) {
        evidence_mmsghdr_t message;
        uintptr_t address = (uintptr_t)args[1] + index * sizeof(message);
        if (!read_app((const void*)address, &message, sizeof(message)))
          return false;
        if (sockaddr_is_evidence(
                message.msg_hdr.msg_name, message.msg_hdr.msg_namelen))
          goto forbidden;
      }
      return false;
    }
#endif
    case SYS_open:
    case SYS_creat:
      if (!path_is_proc_mem(context, AT_FDCWD, (const void*)(uintptr_t)args[0]))
        return false;
      break;
    case SYS_openat:
#ifdef SYS_openat2
    case SYS_openat2:
#endif
      if (!path_is_proc_mem(
              context, (int)args[0], (const void*)(uintptr_t)args[1]))
        return false;
      break;
#ifdef SYS_process_vm_readv
    case SYS_process_vm_readv:
#endif
#ifdef SYS_process_vm_writev
    case SYS_process_vm_writev:
#endif
    case SYS_ptrace:
#ifdef SYS_pidfd_getfd
    case SYS_pidfd_getfd:
#endif
      break;
    default:
      return false;
  }

forbidden:
  *result = protected_evidence_refusal(sysnum);
  return true;
}

static int64_t
invoke_syscall(uintptr_t context, int64_t sysnum, const uint64_t* args) {
  prototype_counters_t* counters = (prototype_counters_t*)drmgr_get_tls_field(
      (void*)context, thread_state_index);
  uint64_t translated[6];
  int64_t result;
  bool is_clone;
  DR_ASSERT(counters != NULL);
  capture_observe_lifecycle((int)sysnum, args);
  if (protect_evidence_socket_syscall(context, (int)sysnum, args, &result))
    return result;
  memcpy(translated, args, sizeof(translated));
  if (!validate_task_arguments((int)sysnum, translated))
    return unknown_identity_error(context, (int)sysnum, args);
  if (is_owner_syscall((int)sysnum, (uint32_t)args[1]))
    return execute_owner_syscall(context, (int)sysnum, args);

  is_clone = prepare_clone_birth(
      counters, (int)sysnum, translated, CLONE_SYSCALL_INJECTED);
  if (preserve_internal_descriptors(context, (int)sysnum, translated, &result))
    return result;
  if (is_exec_syscall((int)sysnum)) {
    retire_private_memory_for_exec();
    require_evidence_flush(EVIDENCE_FRAME_EXEC);
  }
  if (sysnum == SYS_exit || sysnum == SYS_exit_group)
    complete_runtime_thread_exit(
        counters,
        (void*)context,
        sysnum == SYS_exit,
        sysnum == SYS_exit_group);
  result = invoke_raw_syscall(context, sysnum, translated);
  if (is_exec_syscall((int)sysnum) && result < 0) {
    require_evidence_flush(EVIDENCE_FRAME_EXEC_CANCEL);
  }
  if (reject_opened_proc_mem(context, (int)sysnum, result))
    return -EPERM;
  if (is_clone) {
    (void)complete_clone_birth(counters, result);
    return result;
  }
  return result;
}

static int32_t read_registers(uintptr_t context, struct user_regs_struct* out) {
  dr_mcontext_t registers = {sizeof(registers), DR_MC_ALL};
  prototype_counters_t* counters =
      drmgr_get_tls_field((void*)context, thread_state_index);
  memset(out, 0, sizeof(*out));
  if (counters != NULL && counters->signal_token != 0)
    registers = *counters->signal_mcontext;
  else if (!dr_get_mcontext((void*)context, &registers))
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
// TODO-HUMAN-REVIEW(PR-167): Review the DBT guest register-write callback.
// The write counterpart to read_registers: overwrite the application's integer
// register file with the tool-supplied values. DynamoRIO permits
// dr_set_mcontext from a pre-/post-syscall event, and the modified context is
// used when the application resumes (the pc/xip field is ignored outside
// kernel-transfer events, so it is intentionally not written here). Reads the
// current mcontext first so control/segment fields DynamoRIO manages are
// preserved.
static int32_t write_registers(
    uintptr_t context,
    const struct user_regs_struct* in) {
  dr_mcontext_t registers = {sizeof(registers), DR_MC_ALL};
  prototype_counters_t* counters =
      drmgr_get_tls_field((void*)context, thread_state_index);
  bool signal_owned = counters != NULL && counters->signal_token != 0;
  if (signal_owned)
    registers = *counters->signal_mcontext;
  else if (!dr_get_mcontext((void*)context, &registers))
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

  if (signal_owned) {
    registers.pc = (app_pc)in->rip;
    *counters->signal_mcontext = registers;
    counters->signal_registers_changed = true;
  } else if (!dr_set_mcontext((void*)context, &registers))
    return 0;
  return 1;
}

static int32_t read_memory(uintptr_t address, uint8_t* out, size_t size) {
  return read_app((const void*)address, out, size) ? 1 : 0;
}

// TODO-HUMAN-REVIEW(PR-234): Review the fault-safe DBT memory-write callback
// ABI.
// TODO-HUMAN-REVIEW(PR-237): Review page-bounded partial-write semantics.
static size_t
write_memory(uintptr_t address, const uint8_t* value, size_t size) {
  size_t total = 0;
  const size_t page_size = dr_page_size();
  while (address != 0 && total < size && address <= UINTPTR_MAX - total) {
    const uintptr_t current = address + total;
    const size_t page_remaining = page_size - current % page_size;
    const size_t segment =
        size - total < page_remaining ? size - total : page_remaining;
    size_t bytes_written = 0;
    dr_safe_write((void*)current, segment, value + total, &bytes_written);
    total += bytes_written;
    if (bytes_written != segment)
      break;
  }
  return total;
}

static bool read_app(const void* address, void* value, size_t size) {
  size_t bytes_read = 0;
  return address != NULL && dr_safe_read(address, size, value, &bytes_read) &&
      bytes_read == size;
}

static bool write_app(void* address, const void* value, size_t size) {
  size_t bytes_written = 0;
  return address != NULL &&
      dr_safe_write(address, size, value, &bytes_written) &&
      bytes_written == size;
}

// Overwrite `address` inside the vDSO `module` with `code` and flush any cached
// translation of the vDSO. Returns false, leaving the vDSO unchanged, if it
// cannot be made writable.
static bool patch_vdso_symbol(
    const module_data_t* module,
    const char* name,
    app_pc address,
    const uint8_t* code,
    size_t code_size) {
  size_t region_size = (size_t)(module->end - module->start);
  if (!dr_memory_protect(
          (void*)module->start,
          region_size,
          DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC)) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: failed to unprotect vdso to neutralize %s\n",
        name);
    return false;
  }
  memcpy(address, code, code_size);
  DR_ASSERT(dr_memory_protect(
      (void*)module->start, region_size, DR_MEMPROT_READ | DR_MEMPROT_EXEC));

  /*
   * Discard any cached translation of the vDSO so the patched bytes take
   * effect. The delayed form is the flush variant permitted from a module-load
   * callback; it completes before any new code enters the cache, i.e. before
   * the guest first calls the patched entry.
   */
  dr_delay_flush_region(module->start, region_size, 0, NULL);
  return true;
}

/* The vDSO's SONAME, which DynamoRIO reports as the module's preferred name. */
#define VDSO_SONAME "linux-vdso.so.1"

/* Bytes in the `mov $sysnum, %eax; syscall; ret` and -ENOSYS stubs. */
#define VDSO_THUNK_SIZE 8

/* The dynamic symbol table of the vDSO image mapped at `base`. */
typedef struct {
  const char* strings;
  const Elf64_Sym* symbols;
  Elf64_Word count;
} vdso_symtab_t;

/*
 * Locate the dynamic symbol table of the ELF image mapped at `base` (the vDSO).
 * Returns false if the image has no DT_HASH, whose second word is the only
 * symbol count the dynamic section records.
 */
static bool vdso_find_symtab(app_pc base, vdso_symtab_t* table) {
  const Elf64_Ehdr* header = (const Elf64_Ehdr*)base;
  const Elf64_Phdr* program =
      (const Elf64_Phdr*)((const char*)header + header->e_phoff);
  uintptr_t load_offset = 0;
  const Elf64_Dyn* dynamic = NULL;
  for (int index = 0; index < header->e_phnum; index++) {
    if (program[index].p_type == PT_LOAD)
      load_offset =
          (uintptr_t)base + program[index].p_offset - program[index].p_vaddr;
    if (program[index].p_type == PT_DYNAMIC)
      dynamic = (const Elf64_Dyn*)(base + program[index].p_offset);
  }
  if (dynamic == NULL)
    return false;
  const Elf64_Word* hash = NULL;
  table->strings = NULL;
  table->symbols = NULL;
  for (const Elf64_Dyn* entry = dynamic; entry->d_tag != DT_NULL; entry++) {
    if (entry->d_tag == DT_STRTAB)
      table->strings = (const char*)(load_offset + entry->d_un.d_ptr);
    else if (entry->d_tag == DT_SYMTAB)
      table->symbols = (const Elf64_Sym*)(load_offset + entry->d_un.d_ptr);
    else if (entry->d_tag == DT_HASH)
      hash = (const Elf64_Word*)(load_offset + entry->d_un.d_ptr);
  }
  if (table->strings == NULL || table->symbols == NULL || hash == NULL)
    return false;
  table->count = hash[1];
  return true;
}

/*
 * Is `symbol` an exported entry point? This mirrors `vdso_exports` in
 * reverie-ptrace/src/vdso.rs and fails closed on the type: only data and
 * bookkeeping symbols are skipped, so a symbol of any other type is code.
 */
static bool vdso_is_entry_point(const Elf64_Sym* symbol) {
  switch (ELF64_ST_TYPE(symbol->st_info)) {
    case STT_OBJECT:
    case STT_TLS:
    case STT_COMMON:
    case STT_SECTION:
    case STT_FILE:
      return false;
    default:
      return ELF64_ST_BIND(symbol->st_info) != STB_LOCAL &&
          symbol->st_shndx != SHN_UNDEF && symbol->st_shndx != SHN_ABS;
  }
}

/*
 * The bytes a stub may overwrite at `symbol`: its st_size rounded up to the
 * vDSO's 16-byte function alignment, cut short at the next entry point.
 */
static size_t vdso_entry_space(
    const vdso_symtab_t* table,
    const Elf64_Sym* symbol) {
  size_t space = ((size_t)symbol->st_size + 15) & ~(size_t)15;
  for (Elf64_Word index = 0; index < table->count; index++) {
    const Elf64_Sym* other = &table->symbols[index];
    if (vdso_is_entry_point(other) && other->st_value > symbol->st_value &&
        other->st_value - symbol->st_value < space)
      space = (size_t)(other->st_value - symbol->st_value);
  }
  return space;
}

/*
 * Overwrite vDSO entry point `name` at `symbol` with `code`, or exit the
 * runtime tree: an entry point left running the kernel's code would be read
 * outside the tool's view.
 */
static void replace_vdso_entry(
    const module_data_t* module,
    const vdso_symtab_t* table,
    const char* name,
    const Elf64_Sym* symbol,
    const uint8_t* code,
    size_t code_size) {
  size_t space = vdso_entry_space(table, symbol);
  if (space < code_size) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: vdso %s has %zu bytes, too few for its %zu-byte stub\n",
        name,
        space,
        code_size);
    exit_runtime_tree(101);
    return;
  }
  if (!patch_vdso_symbol(
          module, name, module->start + symbol->st_value, code, code_size))
    exit_runtime_tree(101);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(hermit#705): Confirm vDSO time neutralization routes guest
// clock reads through the shared Detcore tool (2021 epoch) rather than the raw
// host TSC, matching the ptrace backend.
//
// Neutralize one guest vDSO syscall fast path by overwriting its entry point
// with a tiny `mov $sysnum, %eax; syscall; ret` thunk. glibc's vDSO fast path
// then issues a real, trapped syscall instead of reading the raw host TSC, so
// the call flows through pre_syscall() where the external Detcore tool
// virtualizes it (the prototype runtime lets it reach the host). This mirrors
// reverie-ptrace/src/vdso.rs, whose vDSO
// neutralization is why the ptrace backend already reports the deterministic
// epoch; the previous drwrap_skip_call() path answered from the base-zero
// prototype clock and never reached the real tool, so `date` printed 1970
// under Detcore (hermit#705).
static void neutralize_vdso_syscall(
    const module_data_t* module,
    const vdso_symtab_t* table,
    const char* name,
    const Elf64_Sym* symbol,
    long sysnum) {
  /*
   * mov $sysnum, %eax; syscall; ret  (8 bytes). The trailing `ret` prevents
   * fall-through into the original body.
   */
  const uint8_t thunk[VDSO_THUNK_SIZE] = {
      0xb8,
      (uint8_t)(sysnum),
      (uint8_t)(sysnum >> 8),
      (uint8_t)(sysnum >> 16),
      (uint8_t)(sysnum >> 24),
      0x0f,
      0x05,
      0xc3,
  };
  replace_vdso_entry(module, table, name, symbol, thunk, sizeof(thunk));
}

/*
 * Replace `__vdso_getrandom(buffer, len, flags, opaque_state, opaque_len)`.
 * The kernel's version keys a userspace ChaCha20 state with one getrandom
 * syscall and re-keys it whenever the host kernel reseeds its crng, at
 * host-time-dependent points (https://github.com/rrnewton/reverie/issues/841).
 * This is the same stub as reverie-ptrace/src/vdso.rs: the parameter query
 * (NULL, 0, 0, params, ~0UL) returns -ENOSYS without writing `params`, so
 * glibc 2.41+ never sizes a state and calls the getrandom syscall directly;
 * any other call is the getrandom syscall on the first three arguments.
 */
static void neutralize_vdso_getrandom(
    const module_data_t* module,
    const vdso_symtab_t* table,
    const char* name,
    const Elf64_Sym* symbol) {
  static const uint8_t stub[36] = {
      0x49, 0x83, 0xf8, 0xff, /* cmp $-1, %r8 */
      0x75, 0x16, /* jne syscall_path */
      0x48, 0x85, 0xff, /* test %rdi, %rdi */
      0x75, 0x11, /* jne syscall_path */
      0x48, 0x85, 0xf6, /* test %rsi, %rsi */
      0x75, 0x0c, /* jne syscall_path */
      0x85, 0xd2, /* test %edx, %edx */
      0x75, 0x08, /* jne syscall_path */
      0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff, /* mov $-ENOSYS, %rax */
      0xc3, /* ret */
      /* syscall_path: */
      0xb8, 0x3e, 0x01, 0x00, 0x00, /* mov $SYS_getrandom, %eax */
      0x0f, 0x05, /* syscall */
      0xc3, /* ret */
  };
  replace_vdso_entry(module, table, name, symbol, stub, sizeof(stub));
}

/*
 * The classification of the entry point at `symbol`: the reverie_vdso_symbols
 * entry of a name exported at its address, or NULL if none is listed. The
 * x86_64 vDSO exports most functions twice (`clock_gettime` beside
 * `__vdso_clock_gettime`); listed names at one address that disagree exit the
 * runtime tree, as reverie-ptrace refuses such a vDSO.
 */
static const struct reverie_vdso_symbol* vdso_classify(
    const vdso_symtab_t* table,
    const Elf64_Sym* symbol) {
  const struct reverie_vdso_symbol* known = NULL;
  for (Elf64_Word index = 0; index < table->count; index++) {
    const Elf64_Sym* other = &table->symbols[index];
    if (!vdso_is_entry_point(other) || other->st_value != symbol->st_value)
      continue;
    const struct reverie_vdso_symbol* entry =
        reverie_vdso_symbol_lookup(table->strings + other->st_name);
    if (entry == NULL)
      continue;
    if (known != NULL &&
        (known->handling != entry->handling ||
         known->syscall != entry->syscall)) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: vdso exports %s and %s at one address, but they need "
          "different stubs\n",
          known->name,
          entry->name);
      exit_runtime_tree(101);
    }
    known = entry;
  }
  return known;
}

/* Is no earlier entry point in `table` at the address of symbol `index`? */
static bool vdso_first_at_address(const vdso_symtab_t* table, Elf64_Word index) {
  for (Elf64_Word other = 0; other < index; other++) {
    if (vdso_is_entry_point(&table->symbols[other]) &&
        table->symbols[other].st_value == table->symbols[index].st_value)
      return false;
  }
  return true;
}

/*
 * Replace every vDSO entry point as reverie-core classifies it
 * (reverie_vdso_symbols.h, generated from `VdsoSymbol::class`): a syscall fast
 * path with a stub that issues the syscall, any other function with
 * `mov $-ENOSYS, %rax; ret`, except those the classification leaves native.
 * A name the table does not list is reported and replaced with -ENOSYS, so no
 * entry point keeps running the kernel's code unobserved.
 */
static void neutralize_vdso(
    const module_data_t* module,
    const vdso_symtab_t* table) {
  static const uint8_t enosys[VDSO_THUNK_SIZE] = {
      0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff, /* mov $-ENOSYS, %rax */
      0xc3, /* ret */
  };
  for (Elf64_Word index = 0; index < table->count; index++) {
    const Elf64_Sym* symbol = &table->symbols[index];
    if (!vdso_is_entry_point(symbol) || !vdso_first_at_address(table, index))
      continue;
    const char* name = table->strings + symbol->st_name;
    const struct reverie_vdso_symbol* known = vdso_classify(table, symbol);
    if (known == NULL) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: replacing unknown vdso entry point %s with -ENOSYS\n",
          name);
      replace_vdso_entry(module, table, name, symbol, enosys, sizeof(enosys));
      continue;
    }
    switch (known->handling) {
      case REVERIE_VDSO_SYSCALL:
        if (known->syscall == SYS_getrandom)
          neutralize_vdso_getrandom(module, table, name, symbol);
        else
          neutralize_vdso_syscall(module, table, name, symbol, known->syscall);
        break;
      case REVERIE_VDSO_ENOSYS:
        replace_vdso_entry(module, table, name, symbol, enosys, sizeof(enosys));
        break;
      case REVERIE_VDSO_NATIVE:
        break;
    }
  }
}

static void
module_load(void* drcontext, const module_data_t* module, bool loaded) {
  const char* module_name = dr_module_preferred_name(module);
  if (module_name == NULL || strcmp(module_name, VDSO_SONAME) != 0) {
    if (dr_get_proc_address(module->handle, "__vdso_clock_gettime") != NULL) {
      /* Not recognized as the vDSO, so it would be left unpatched. */
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: module %s exports __vdso_clock_gettime but is not %s\n",
          module_name == NULL ? "(unnamed)" : module_name,
          VDSO_SONAME);
      exit_runtime_tree(101);
    }
    return;
  }
  vdso_symtab_t table;
  if (!vdso_find_symtab(module->start, &table)) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: the vdso has no DT_HASH symbol table to enumerate\n");
    exit_runtime_tree(101);
    return;
  }
  neutralize_vdso(module, &table);
}

static bool fd_matches_stdin(void* drcontext, int fd) {
#ifdef SYS_fstat
  struct stat candidate_stat = {0};
  uint64_t stat_args[6] = {(uint64_t)fd, (uint64_t)(uintptr_t)&candidate_stat};
  if (!task_state->initial_stdin_valid)
    return false;
  if (invoke_syscall((uintptr_t)drcontext, SYS_fstat, stat_args) < 0)
    return false;
  return task_state->initial_stdin.st_dev ==
      candidate_stat.st_dev &&
      task_state->initial_stdin.st_ino == candidate_stat.st_ino &&
      task_state->initial_stdin.st_rdev == candidate_stat.st_rdev;
#else
  return false;
#endif
}

static bool
syscall_reads_stdin(void* drcontext, int sysnum, const uint64_t* args) {
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

static bool filter_syscall(void* drcontext, int sysnum) {
  return true;
}

static void ensure_runtime_background(void);
static void runtime_background_init(void* argument);

static bool is_exec_syscall(int sysnum) {
  return sysnum == SYS_execve
#ifdef SYS_execveat
      || sysnum == SYS_execveat
#endif
      ;
}

// TODO-HUMAN-REVIEW(PR-131): Review clone metadata and registration ordering.
static bool thread_clone_metadata(
    void* drcontext,
    int sysnum,
    uint64_t* flags,
    uint64_t* child_tid_addr) {
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
      read_app(
          (const void*)dr_syscall_get_param(drcontext, 0),
          clone3_args,
          sizeof(clone3_args)) &&
      (clone3_args[0] & CLONE_THREAD) != 0) {
    *flags = clone3_args[0];
    *child_tid_addr = clone3_args[2];
    return true;
  }
#endif
  return false;
}

static void zero_wait_rusage(void* address) {
  if (address != NULL) {
    struct rusage usage = {0};
    write_app(address, &usage, sizeof(usage));
  }
}

static bool prepare_original_task_syscall(
    void* drcontext,
    prototype_counters_t* counters,
    int sysnum,
    const uint64_t* args,
    bool tail_injected) {
  uint64_t admitted[6];
  (void)tail_injected;
  memcpy(admitted, args, sizeof(admitted));
  if (!validate_task_arguments(sysnum, admitted)) {
    dr_syscall_set_result(drcontext,
        (reg_t)unknown_identity_error((uintptr_t)drcontext, sysnum, args));
    return false;
  }
  if (is_owner_syscall(sysnum, (uint32_t)args[1])) {
    dr_syscall_set_result(drcontext,
        (reg_t)execute_owner_syscall((uintptr_t)drcontext, sysnum, args));
    return false;
  }
  for (int i = 0; i != 6; ++i)
    if (admitted[i] != args[i])
      dr_syscall_set_param(drcontext, i, (reg_t)admitted[i]);
  if (is_exec_syscall(sysnum))
    retire_private_memory_for_exec();
  (void)prepare_clone_birth(counters, sysnum, admitted, CLONE_SYSCALL_ORIGINAL);
  return true;
}

// TODO-HUMAN-REVIEW(PR-66): Confirm wait-result normalization preserves wait
// semantics.
static void post_syscall(void* drcontext, int sysnum) {
  ptr_int_t syscall_result = (ptr_int_t)dr_syscall_get_result(drcontext);
  ptr_int_t host_syscall_result = syscall_result;
  int32_t completed_child_tid = 0;
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  DR_ASSERT(counters != NULL);

  if (is_clone_syscall(sysnum) && host_syscall_result == 0 &&
      !require_supported_child_pid_namespace())
    return;
  if (is_clone_syscall(sysnum) && host_syscall_result == 0 &&
      counters->pending_birth_token != 0) {
    publish_task_birth((int32_t)dr_get_process_id(),
        counters->pending_birth_token, true);
    publish_task_birth((int32_t)dr_get_thread_id(drcontext),
        counters->pending_birth_token, true);
    rebind_private_memory_after_clone(counters->pending_clone_flags);
  }

  if (reject_opened_proc_mem(
          (uintptr_t)drcontext, sysnum, host_syscall_result)) {
    dr_syscall_set_result(drcontext, (reg_t)-EPERM);
    return;
  }

  // Re-arm the guest-stack scrub (see `scrub_guest_stack_residue`). Servicing a
  // clone-family syscall is the second measured point -- after DynamoRIO's own
  // initialization -- at which a DynamoRIO address is left in the application's
  // dead stack: on `c-programs`-style fork probes the qword one frame below the
  // post-fork stack pointer holds a code-cache address whose per-run value made
  // exactly one `[stack]` hash differ. Re-arming here costs one scan per clone
  // rather than one per syscall, and it covers the child too, which returns
  // from the same syscall with the parent's latch inherited.
  //
  // The re-armed scan selects by ownership, not by position (see
  // `scrub_guest_stack_residue`). That distinction is what makes re-arming safe
  // at all: by this point the guest has run, and its own dead frames share the
  // range with DynamoRIO's residue. `stack_scrub_marker.c` is the bracket.
  if (is_clone_syscall(sysnum))
    atomic_store_explicit(&guest_stack_scrubbed, 0, memory_order_release);

  /* The measured delivery matrix reports both branches for fork and separate-VM
   * clone/clone3, but only the parent result for clone(CLONE_VM) and vfork.
   * Bind this callback to the actual clone-family post-event: CLONE_VM identity
   * handoff can remain pending briefly in shared state, and a later syscall
   * must not be misreported as another clone result. */
  if (!is_clone_syscall(sysnum) &&
      counters->pending_process_clone_result != 0) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: stale process-clone result state before syscall %d\n",
        sysnum);
    exit_runtime_tree(101);
  }
  if (is_clone_syscall(sysnum) && counters->pending_process_clone_result != 0) {
    if (!test_leave_process_clone_result_pending)
      counters->pending_process_clone_result = 0;
    if (host_syscall_result == 0 &&
        (counters->pending_process_clone_flags & CLONE_THREAD) == 0)
      evidence_initialize_fork_child_thread(counters);
    evidence_callback_enter();
    int32_t registration = reverie_dbt_runtime_process_clone_result(
        counters,
        drcontext,
        (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(),
        atomic_load_explicit(&branch_count, memory_order_relaxed),
        (int64_t)sysnum,
        host_syscall_result,
        host_syscall_result > 0 ? (int32_t)host_syscall_result
                               : (int32_t)dr_get_thread_id(drcontext),
        counters->pending_process_clone_ctid,
        counters->pending_process_clone_flags,
        (int32_t)counters->pending_process_clone_exit_signal,
        invoke_syscall,
        read_registers,
        write_registers);
    evidence_callback_leave();
    counters->pending_process_clone_flags = 0;
    counters->pending_process_clone_ctid = 0;
    counters->pending_process_clone_exit_signal = 0;
    if (registration < 0) {
      dr_fprintf(
          diagnostic_file, "reverie-dbt: process child registration failed\n");
      exit_runtime_tree(101);
      return;
    }
  }

  if (counters->pending_birth_token != 0 && is_clone_syscall(sysnum)) {
    completed_child_tid = complete_clone_birth(counters, syscall_result);
  }

  if (is_exec_syscall(sysnum) && evidence_is_enabled())
    require_evidence_flush(EVIDENCE_FRAME_EXEC_CANCEL);
  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process()))
    return;

  if (counters->pending_thread_clone != 0) {
    if (host_syscall_result >= 0) {
      evidence_callback_enter();
      int32_t registration = reverie_dbt_runtime_thread_created_v2(
          counters,
          drcontext,
          (int32_t)dr_get_thread_id(drcontext),
          (int32_t)dr_get_process_id(),
          atomic_load_explicit(&branch_count, memory_order_relaxed),
          (int32_t)host_syscall_result,
          completed_child_tid,
          counters->thread_clone_ctid,
          counters->thread_clone_flags,
          invoke_syscall,
          read_registers,
          write_registers);
      evidence_callback_leave();
      if (registration < 0) {
        dr_fprintf(
            diagnostic_file, "reverie-dbt: child thread registration failed\n");
        exit_runtime_tree(101);
        return;
      }
    }
    counters->pending_thread_clone = 0;
  }
  if (is_exec_syscall(sysnum)) {
    evidence_callback_enter();
    reverie_dbt_runtime_exec_failed(counters, (int32_t)dr_get_process_id());
    evidence_callback_leave();
    return;
  }

  if (syscall_result < 0)
    return;
  // AUTONOMOUS-BOT-IMPLEMENTED
  if (sysnum == SYS_wait4 && syscall_result > 0) {
    zero_wait_rusage((void*)dr_syscall_get_param(drcontext, 3));
    // AUTONOMOUS-BOT-IMPLEMENTED
  } else if (sysnum == SYS_waitid) {
    siginfo_t info;
    void* info_address = (void*)dr_syscall_get_param(drcontext, 2);
    if (info_address != NULL && read_app(info_address, &info, sizeof(info)) &&
        info.si_pid != 0) {
      info.si_utime = 0;
      info.si_stime = 0;
      write_app(info_address, &info, sizeof(info));
      zero_wait_rusage((void*)dr_syscall_get_param(drcontext, 4));
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

static void finalize_runtime_process(void) {
  evidence_sender_state_t* sender = NULL;
  if (evidence_is_enabled()) {
    dr_mutex_lock(evidence_lock);
    sender = evidence_sender_locked();
    if (sender == NULL) {
      dr_mutex_unlock(evidence_lock);
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: protected evidence finalization failed\n");
      exit_runtime_tree(101);
      return;
    }
    if (sender->finalization_started) {
      dr_mutex_unlock(evidence_lock);
      return;
    }
    sender->finalization_started = true;
    dr_mutex_unlock(evidence_lock);
  }
  if (!has_copied_runtime() ||
      (runtime_uses_external_global() && !is_copied_vfork_process())) {
    evidence_callback_enter();
    reverie_dbt_runtime_process_exit();
    evidence_callback_leave();
  }
  if (!evidence_is_enabled())
    return;

  if (!has_copied_runtime()) {
    int attempts = 0;
    int32_t state =
        atomic_load_explicit(&runtime_background_state, memory_order_acquire);
    while ((state == 1 || state == 2) && attempts++ != 5000) {
      dr_sleep(1);
      state =
          atomic_load_explicit(&runtime_background_state, memory_order_acquire);
    }
    if (state == 1 || state == 2) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: runtime background did not quiesce after shutdown\n");
      exit_runtime_tree(101);
      return;
    }
  }
  require_evidence_flush(EVIDENCE_FRAME_FINAL);
}

static bool evidence_current_process_finalized(void) {
  evidence_sender_state_t* sender;
  bool finalized;
  if (!evidence_is_enabled())
    return true;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  finalized = sender != NULL && sender->finalized;
  dr_mutex_unlock(evidence_lock);
  return finalized;
}

static void report_copied_unsupported_syscall(int sysnum) {
  if (unsupported_report_file != INVALID_FILE)
    dr_fprintf(unsupported_report_file, "@%d\n", sysnum);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review deterministic branch-count
// preemption. Runs at the first application instruction of every block (see
// `instrument_instruction`) when preemption is enabled. Once this thread has
// executed `preemption_quantum` counted app branches since its last preemption,
// it delivers a real `sched_yield` to the guest so a thread that busy-waits or
// tight-loops without reaching a syscall of its own still returns control to
// the deterministic scheduler and lets a co-runnable sibling proceed.
//
// SAFE-POINT delivery (this is the crux). The Detcore scheduler turn is an
// in-process RPC that allocates and can trigger the guest's own lazy PLT
// resolver, so it must NOT run synchronously from this clean call at an
// arbitrary instruction boundary: doing so re-enters non-reentrant guest
// libc/ld (observed as "undefined symbol getcwd" / GLIBC_PRIVATE, or a memchr
// panic from clobbered state). Instead, the ONLY place the turn runs is the
// existing `pre_syscall` handler, which is a proven-safe boundary for every
// real guest syscall (it is why the passing corpus passes). So this clean call
// does NO scheduler work: it captures the interrupted thread's full machine
// context and `dr_redirect_execution`s to a tiny generated stub whose sole
// instruction is a real `sched_yield` syscall. That syscall fires
// `pre_syscall`, Detcore's ordinary, already-deterministic `sched_yield`
// handler ends this thread's timeslice and reselects, and a clean call on the
// block after the stub syscall
// (`preempt_return`) restores the captured context and resumes the guest
// exactly where it was preempted. The injected syscall is thus fully
// transparent: rax, rip and the FP/SIMD state are all restored from the
// captured mcontext.
//
// Determinism: `branch_count` advances only at counted app branches (see
// `is_counted_branch`) and `preemption_quantum` is fixed, so the preemption
// points are a deterministic function of the executed instruction stream; both
// runs of `--verify` execute the same stream, take the same preemptions, and
// inject the same yields.
//
// SAFE-POINT gate refinement: we additionally require the interrupted PC to lie
// in the guest's MAIN EXECUTABLE (its own code). The busy-wait/tight loop that
// starves the scheduler spins there, not inside libc; restricting delivery to
// the guest's own code keeps the redirect/return away from partially-executed
// libc/ld sequences. We cache the main module's address range once.
static app_pc main_module_start;
static app_pc main_module_end;
static bool main_module_resolved;

static bool pc_in_main_executable(app_pc pc) {
  if (!main_module_resolved) {
    module_data_t* main_module = dr_get_main_module();
    if (main_module == NULL)
      return false;
    main_module_start = main_module->start;
    main_module_end = main_module->end;
    main_module_resolved = true;
    dr_free_module_data(main_module);
  }
  return pc >= main_module_start && pc < main_module_end;
}

static void maybe_preempt(app_pc pc) {
  if (!preemption_enabled || preempt_stub == NULL)
    return;
  void* drcontext = dr_get_current_drcontext();
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  if (counters == NULL || counters->preempt_mcontext == NULL)
    return;
  // An injected sched_yield is already in flight for this thread (we are
  // between the redirect to the stub and `preempt_return`); never nest a
  // preemption.
  if (counters->preempt_pending != 0 || counters->signal_token != 0)
    return;
  // Only preempt a thread that actually drives the Reverie tool this turn.
  // Mirror the guards used around the syscall dispatch: the runtime image must
  // be ready, and a copied child only runs the tool when it is an
  // external-global (RPC-connected) non-vfork process. A copied child under a
  // prototype runtime, or a vfork stand-in, runs no scheduler turn, so skip it.
  if (!reverie_dbt_runtime_ready(
          atomic_load_explicit(&image_generation, memory_order_acquire)))
    return;
  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process()))
    return;
  uint64_t branches = atomic_load_explicit(&branch_count, memory_order_relaxed);
  if (branches - counters->last_yield_branch < preemption_quantum)
    return;
  // Defer until the quantum elapses AND the interrupted PC is in the guest's
  // own code. Do NOT advance last_yield_branch when deferring, so delivery
  // lands at the first main-executable block after the quantum -- a
  // deterministic function of the deterministic instruction stream.
  if (preempt_gate_main_only && !pc_in_main_executable(pc))
    return;
  counters->last_yield_branch = branches;
  // Capture the full interrupted context (integer + control + FP/SIMD) so
  // `preempt_return` can resume the guest transparently after the yield. Force
  // the resume PC to `pc` (the block's application PC); the mcontext `pc` field
  // is not a reliable output of `dr_get_mcontext` in a clean call.
  dr_mcontext_t* saved = counters->preempt_mcontext;
  saved->size = sizeof(*saved);
  saved->flags = DR_MC_ALL;
  if (!dr_get_mcontext(drcontext, saved))
    return;
  saved->pc = pc;
  counters->preempt_pending = 1;
  // Redirect into the stub with rax set to the sched_yield syscall number; the
  // rest of the machine state is the guest's own captured state.
  dr_mcontext_t redirect = *saved;
  redirect.xax = (reg_t)SYS_sched_yield;
  redirect.pc = preempt_stub;
  dr_redirect_execution(&redirect);
  // dr_redirect_execution does not return on success.
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the safe-point preemption return
// path. Clean call inserted on the block immediately after the stub's
// `sched_yield` (see `instrument_instruction`). The injected syscall has by now
// flowed through `pre_syscall` and Detcore has performed the deterministic
// yield/reselect. We resume the guest at the captured preemption point,
// restoring its rax, rip and FP/SIMD state so the injected syscall is invisible
// to the guest.
static void preempt_return(void) {
  void* drcontext = dr_get_current_drcontext();
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  if (counters == NULL || counters->preempt_mcontext == NULL ||
      counters->preempt_pending == 0)
    return; // unreachable in normal flow; the stub's ud2 traps if we fall
            // through
  counters->preempt_pending = 0;
  dr_redirect_execution(counters->preempt_mcontext);
  // dr_redirect_execution does not return on success.
}

// The x86-64 SysV red zone: the 128 bytes below `rsp` that a leaf function may
// use without adjusting the stack pointer. Everything below it is dead by the
// ABI -- the kernel and signal delivery may clobber it at any moment -- so it
// is the only safe floor for the scrub below.
#define GUEST_STACK_RED_ZONE_BYTES 128

static const char* parse_hex_prefix(const char* text, uintptr_t* value) {
  uintptr_t parsed = 0;
  const char* cursor = text;
  for (; *cursor != '\0'; ++cursor) {
    unsigned digit;
    if (*cursor >= '0' && *cursor <= '9')
      digit = (unsigned)(*cursor - '0');
    else if (*cursor >= 'a' && *cursor <= 'f')
      digit = (unsigned)(*cursor - 'a') + 10;
    else if (*cursor >= 'A' && *cursor <= 'F')
      digit = (unsigned)(*cursor - 'A') + 10;
    else
      break;
    parsed = (parsed << 4) | digit;
  }
  if (cursor == text)
    return NULL;
  *value = parsed;
  return cursor;
}

// Locates the `[stack]` VMA in `/proc/self/maps`. Detcore selects the region it
// hashes by the very same `[stack]` pathname tag (`procmaps::MMapPath::Stack`),
// so resolving it the same way binds the scrub to exactly the bytes the hash
// covers instead of to a correlated guess at where the stack is. Uses
// DynamoRIO's file API, whose raw syscalls are DynamoRIO's own and therefore
// never surface as guest syscall events.
static bool find_guest_stack_vma(uintptr_t* start, uintptr_t* end) {
  file_t maps = dr_open_file("/proc/self/maps", DR_FILE_READ);
  if (maps == INVALID_FILE)
    return false;
  char chunk[4096];
  char line[512];
  size_t used = 0;
  bool found = false;
  ssize_t got;
  while (!found && (got = dr_read_file(maps, chunk, sizeof(chunk))) > 0) {
    for (ssize_t i = 0; i < got && !found; ++i) {
      if (chunk[i] != '\n') {
        // A `/proc/self/maps` line longer than the buffer can only be a long
        // pathname; the address range we need is at the front, so truncating
        // the tail is safe and the `[stack]` tag is never that far out.
        if (used + 1 < sizeof(line))
          line[used++] = chunk[i];
        continue;
      }
      line[used] = '\0';
      used = 0;
      if (strstr(line, "[stack]") == NULL)
        continue;
      uintptr_t low = 0;
      uintptr_t high = 0;
      const char* cursor = parse_hex_prefix(line, &low);
      if (cursor == NULL || *cursor != '-')
        continue;
      cursor = parse_hex_prefix(cursor + 1, &high);
      if (cursor == NULL || low >= high)
        continue;
      *start = low;
      *end = high;
      found = true;
    }
  }
  dr_close_file(maps);
  return found;
}

// Whether a word read out of the guest's dead stack is an address DynamoRIO
// allocated for itself. `dr_memory_is_dr_internal` is DynamoRIO's own
// `is_dynamo_address`, documented in `core/os_api.h` as "memory allocated by DR
// for its own purposes, and would not exist if the application were run
// natively" -- an observed ownership test on the value. It is a vmarea lookup,
// never a dereference, so an arbitrary stack word is a safe argument.
static bool is_dynamorio_owned_word(uintptr_t word) {
  if (word == 0)
    return false;
  return dr_memory_is_dr_internal((const byte*)word);
}

// Removes DynamoRIO's own footprint from the guest's dead stack.
//
// DynamoRIO initializes on the application's own initial stack before switching
// to its private dstack, and it never unwinds or clears those frames. The dead
// bytes it leaves behind hold DynamoRIO's private mapping addresses -- whose
// base is `-vm_base` plus a per-run random jitter drawn from DynamoRIO's PRNG
// (`core/heap.c` `vmm_place_vmcode`, seeded from the OS unless `-prng_seed` is
// set) -- and the raw host pid, in both binary and decimal-string form. Both
// change on every run of the same guest.
//
// Detcore's `--detlog-stack` hashes the WHOLE `[stack]` VMA, dead space
// included, so that residue makes every DBT stack hash differ run to run even
// though the guest's own stack bytes are bit-identical. Measured on
// `c-programs/kcmp-eperm` under `--strict --base-env minimal`: 38 of 38 stack
// hashes differ between two DBT runs, while ptrace differs in 0 of 38; at the
// byte level exactly 32 of 135168 `[stack]` bytes differ, all of them below the
// deepest byte the guest itself ever writes.
//
// Every other backend presents this region as the kernel left it: zero. Restore
// that at the source rather than adjusting what Detcore hashes: at the first
// application syscall after DynamoRIO has deposited state on the application
// stack -- the earliest point at which DynamoRIO is provably off that stack and
// the application's context is available -- zero the part of the `[stack]` VMA
// below the application's stack pointer minus the red zone. The hashed range is
// unchanged.
//
// TWO SCRUBS, TWO SELECTION RULES, because they face different memory.
//
// The FIRST scrub runs before the guest's own code has executed. Everything
// below the application's stack pointer at that moment was put there by
// DynamoRIO's initialization and the dynamic loader, so zeroing all of it is
// blunt but sound, and it has to be blunt: most of the run-varying residue is
// not a pointer. Dumping every nonzero word in the range across two runs shows
// 21 words differing, and only 8 of them are DynamoRIO addresses; the rest are
// the raw host pid packed several ways (`000ad552000ad552`, `ffffffff000ad552`)
// and its ASCII decimal rendering (`3037393930370020`). No ownership test on an
// address can catch a pid or a digit string, so a value-based rule here would
// leave the hash nondeterministic -- measured, 38 of 38 differing, i.e. no
// better than doing nothing.
//
// EVERY LATER scrub is re-armed by a clone (see `post_syscall`) and runs after
// the guest has executed. Its dead frames are now in the same range, and they
// are the guest's, not DynamoRIO's. Selecting by position here erases them:
// measured with a neutral marker planted in guest-owned dead stack, native and
// ptrace preserved it (90/90/90) while DBT zeroed it after a clone in 4 of 4
// runs -- a deterministic wrong answer, the failure mode a determinism tool is
// least able to notice. So the re-armed scrub selects by ownership instead,
// zeroing only words `is_dynamorio_owned_word` identifies. That is enough,
// because what a clone deposits IS a pointer: the qword one frame below the
// post-fork stack pointer holds a code-cache address. Measured on a forking
// guest: dropping the re-arm entirely leaves 1 of 42 hashes differing, and the
// ownership-only re-arm brings it back to 0 of 42 while preserving the marker.
//
// Deliberately latched rather than run on every syscall, so the cost is one
// scan per residue-depositing event rather than one per syscall. The latch is
// set after a scrub and cleared at the two measured points where DynamoRIO
// writes its own addresses into the dead stack: initialization (a fresh image
// starts with it clear) and clone-family syscall servicing.
//
// RESIDUAL RISK of the ownership rule, stated rather than hidden: a guest word
// that happens to equal an address inside DynamoRIO's private mappings is
// indistinguishable from residue and is zeroed. The guest cannot learn those
// addresses through any supported channel, and the word must also sit below the
// stack pointer minus the red zone, where the ABI already lets the kernel and
// signal delivery clobber it.
//
// KNOWN LIMIT, narrowed but not closed. The first scrub is still positional, so
// dead bytes the dynamic loader left below the stack pointer before the guest
// ran are zeroed under DBT and not under ptrace. That is a cross-backend
// difference in a region no correct program reads, and it is the price of
// removing non-pointer residue; the review's finding was about guest data
// written DURING execution, which the clone path now preserves. Separately,
// nothing prevents DynamoRIO from leaving residue at some third moment; that
// would reappear as a nondeterministic `[stack]` hash -- a visible failure, not
// a silent wrong answer.
static void scrub_guest_stack_residue(void* drcontext) {
  if (atomic_load_explicit(&guest_stack_scrubbed, memory_order_acquire) != 0)
    return;
  // Only the process's initial thread runs on the kernel-provided `[stack]`;
  // every other thread has its own mmap'd stack, which carries no `[stack]` tag
  // and is therefore not hashed. Checking that first keeps a sibling thread
  // from re-reading `/proc/self/maps` on each of its syscalls while the latch
  // is armed. The stack-pointer bounds check below, not this one, is what makes
  // the scrub correct; this only makes it cheap.
  if (dr_get_thread_id(drcontext) != dr_get_process_id())
    return;
  dr_mcontext_t context = {sizeof(context), DR_MC_CONTROL};
  if (!dr_get_mcontext(drcontext, &context))
    return;
  uintptr_t start = 0;
  uintptr_t end = 0;
  if (!find_guest_stack_vma(&start, &end))
    return;
  uintptr_t pointer = (uintptr_t)context.xsp;
  // Leave the latch clear if this thread is not in fact on the `[stack]` VMA,
  // so a thread that is will still scrub when it reaches its next syscall.
  if (pointer <= start || pointer > end)
    return;
  const bool initial =
      atomic_exchange_explicit(
          &guest_stack_initially_scrubbed, 1, memory_order_acq_rel) == 0;
  atomic_store_explicit(&guest_stack_scrubbed, 1, memory_order_release);
  if (pointer - start <= GUEST_STACK_RED_ZONE_BYTES)
    return;
  uintptr_t ceiling = pointer - GUEST_STACK_RED_ZONE_BYTES;
  ceiling &= ~(uintptr_t)(sizeof(uintptr_t) - 1);
  const uintptr_t page = (uintptr_t)dr_page_size();
  for (uintptr_t cursor = start; cursor < ceiling;) {
    uintptr_t next = (cursor / page + 1) * page;
    if (next > ceiling)
      next = ceiling;
    unsigned char* bytes = (unsigned char*)cursor;
    size_t length = (size_t)(next - cursor);
    size_t offset = 0;
    while (offset != length && bytes[offset] == 0)
      ++offset;
    // Reading a never-faulted page maps the shared zero page; writing one would
    // commit it. Skipping the all-zero pages keeps the scrub from inflating the
    // guest's resident set by the size of its unused stack.
    if (offset != length) {
      if (initial) {
        memset(bytes, 0, length);
      } else {
        for (size_t at = 0; at + sizeof(uintptr_t) <= length;
             at += sizeof(uintptr_t)) {
          uintptr_t word;
          memcpy(&word, bytes + at, sizeof(word));
          if (is_dynamorio_owned_word(word))
            memset(bytes + at, 0, sizeof(word));
        }
      }
    }
    cursor = next;
  }
}

/* `-test-compare-exchange` also answers
 * prctl(COMPARE_EXCHANGE_OUTSIDE_EVENT_PRCTL, address, expected, desired) by
 * running runtime_compare_exchange_u32 from a DynamoRIO client thread, which
 * is never inside a system-call event, and returning its status or the
 * observed value. The guest fixture uses it on a page DynamoRIO protects. */
#define COMPARE_EXCHANGE_OUTSIDE_EVENT_PRCTL 0x43415322u

typedef struct {
  uintptr_t address;
  uint32_t expected;
  uint32_t desired;
  int32_t status;
  uint32_t observed;
  _Atomic int done;
} compare_exchange_outside_event_t;

static void compare_exchange_outside_event(void* argument) {
  compare_exchange_outside_event_t* request =
      (compare_exchange_outside_event_t*)argument;
  request->status = runtime_compare_exchange_u32(
      request->address, request->expected, request->desired, &request->observed);
  atomic_store_explicit(&request->done, 1, memory_order_release);
}

static int64_t compare_exchange_from_client_thread(
    uintptr_t address,
    uint32_t expected,
    uint32_t desired) {
  compare_exchange_outside_event_t request = {
      .address = address, .expected = expected, .desired = desired};
  if (!dr_create_client_thread(compare_exchange_outside_event, &request))
    return -EAGAIN;
  while (!atomic_load_explicit(&request.done, memory_order_acquire))
    dr_thread_yield();
  return request.status < 0 ? request.status : (int64_t)request.observed;
}

// See `instrument_instruction`. Runs once, before the guest's first
// application instruction.
static void scrub_guest_stack_before_first_instruction(void) {
  scrub_guest_stack_residue(dr_get_current_drcontext());
}

static bool pre_syscall(void* drcontext, int sysnum) {
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  DR_ASSERT(counters != NULL);
  /* A vfork child can reach its first syscall without thread_init or a child
   * post-event. Its copied birth latch is still live; the parent cannot reach
   * another application syscall until vfork completion clears that latch. */
  if (counters->pending_birth_token != 0 &&
      (counters->pending_clone_flags & CLONE_VFORK) != 0 &&
      !require_supported_child_pid_namespace())
    return false;
  if (has_copied_runtime() && counters->pending_birth_token != 0) {
    publish_task_birth((int32_t)dr_get_process_id(),
        counters->pending_birth_token, true);
    publish_task_birth((int32_t)dr_get_thread_id(drcontext),
        counters->pending_birth_token, true);
    rebind_private_memory_after_clone(counters->pending_clone_flags);
  }
  // At the first system call rather than in thread_init: the self-test starts
  // and waits for a client thread, which cannot initialize while thread_init
  // holds DynamoRIO's thread lock.
  if (test_compare_exchange &&
      !atomic_flag_test_and_set(&compare_exchange_self_tested))
    run_compare_exchange_self_test();
  if (test_controller_capture &&
      !atomic_flag_test_and_set(&controller_capture_self_tested))
    run_controller_capture_self_test();
  if (test_compare_exchange && sysnum == SYS_prctl &&
      dr_syscall_get_param(drcontext, 0) ==
          COMPARE_EXCHANGE_OUTSIDE_EVENT_PRCTL) {
    dr_syscall_set_result(
        drcontext,
        (reg_t)compare_exchange_from_client_thread(
            (uintptr_t)dr_syscall_get_param(drcontext, 1),
            (uint32_t)dr_syscall_get_param(drcontext, 2),
            (uint32_t)dr_syscall_get_param(drcontext, 3)));
    return false;
  }
  if (counters->signal_token != 0 && counters->signal_phase == 1) {
    if (native_runtime_entries != 0 || counters->preempt_pending != 0 ||
        sysnum != SYS_gettid ||
        counters->signal_owner_tid != dr_get_thread_id(drcontext) ||
        counters->signal_owner_pid != dr_get_process_id() ||
        counters->signal_image_generation !=
            atomic_load_explicit(&image_generation, memory_order_acquire)) {
      dr_fprintf(diagnostic_file, "reverie-dbt: invalid signal continuation owner\n");
      exit_runtime_tree(101);
      return false;
    }
    // The private syscall is a safe entry boundary, never a Tool syscall or
    // extra scheduler turn. Drop all Rust ownership before the native commit.
    counters->signal_phase = 2;
    evidence_callback_enter();
    counters->signal_action = reverie_dbt_runtime_signal_event(
        drcontext, counters, (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(), counters->signal_image_generation,
        atomic_load_explicit(&branch_count, memory_order_relaxed),
        &counters->signal_event, invoke_syscall, read_registers, write_registers,
        read_memory, write_memory, reverie_dbt_emit);
    evidence_callback_leave();
    if (counters->signal_action < 0 || counters->signal_action > 2 ||
        native_runtime_entries != 0) {
      exit_runtime_tree(101);
      return false;
    }
    if (counters->signal_action == 2) {
      // Returning native syscalls need a different continuation. The shared
      // signal hook uses this terminal path for cancellation.
      dbt_signal_event_t* event = &counters->signal_event;
      if (event->deferred_sysnum != SYS_exit &&
          event->deferred_sysnum != SYS_exit_group) {
        dr_fprintf(diagnostic_file,
                   "reverie-dbt: nonterminal signal tail-injection is unsupported\n");
        exit_runtime_tree(101);
        return false;
      }
      counters->signal_phase = 3;
      dr_syscall_set_sysnum(drcontext, (int)event->deferred_sysnum);
      for (int i = 0; i != 6; ++i)
        dr_syscall_set_param(drcontext, i, (reg_t)event->deferred_args[i]);
      complete_runtime_thread_exit(
          counters,
          drcontext,
          event->deferred_sysnum == SYS_exit,
          event->deferred_sysnum == SYS_exit_group);
      return true;
    }
    dr_syscall_set_result(drcontext, 0);
    return false;
  }
  if (fail_if_process_clone_result_pending(counters, sysnum))
    return false;

  // Retained as a FALLBACK, not as the initial-scrub site. Normally the latch
  // is already set by the first-instruction hook above and this returns
  // immediately; it still runs the ownership-based scrub each time a clone
  // re-arms it. If some guest ever reached a syscall without executing an
  // application instruction, this would take the initial path exactly as
  // before, so the change degrades to the old behaviour rather than to no
  // scrub at all.
  scrub_guest_stack_residue(drcontext);
  if (((uint32_t)sysnum & X32_SYSCALL_BIT) != 0) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: x32-marked syscalls are unsupported\n");
    exit_runtime_tree(102);
    return false;
  }
  bool decoded_compat_gateway =
      drmgr_get_tls_field(drcontext, compat_gateway_index) != NULL;
  DR_ASSERT(drmgr_set_tls_field(drcontext, compat_gateway_index, NULL));
  if (decoded_compat_gateway) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: compat int 0x80 syscalls are unsupported\n");
    exit_runtime_tree(102);
    return false;
  }
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-84): Review process-group mutation refusal in isolated
  // runtimes. Group containment does not rely on mutable gateway bytes: copied
  // runtimes reject the ambiguous i386 raw numbers even if gateway proof races.
  // Only where the launcher contains the run by its process group: as a PID
  // namespace's init (Hermit's container) it contains the run by the
  // namespace, so a guest's setsid and setpgid go to the Tool like any other
  // call (slice B3a-4c of https://github.com/rrnewton/hermit/issues/4266).
  if (contain_by_process_group &&
      (sysnum == SYS_setsid || sysnum == SYS_setpgid ||
       (has_copied_runtime() &&
        (sysnum == X86_32_SYS_SETPGID || sysnum == X86_32_SYS_SETSID)))) {
    dr_syscall_set_result(drcontext, (reg_t)-EPERM);
    return false;
  }

  uint64_t args[6];
  int64_t result = 0;
  int i;
  // TODO-HUMAN-REVIEW(PR-134): Review post-application runtime bootstrap.
  if (!has_copied_runtime())
    ensure_runtime_background();
  if (test_wait_for_background && !has_copied_runtime()) {
    while (atomic_load_explicit(
               &runtime_background_state, memory_order_acquire) != 3)
      dr_sleep(1);
  }

  /* A delayed entry-block flush is not synchronous.  If a native child reaches
   * a syscall through an inherited fragment, start it here after the
   * thread-init event has returned so the parent post-clone callback can
   * register it. */
  // TODO-HUMAN-REVIEW(PR-134): Confirm the syscall entry fallback.
  if (counters->pending_thread_start != 0) {
    start_pending_thread();
  }

  for (i = 0; i != 6; ++i)
    args[i] = (uint64_t)dr_syscall_get_param(drcontext, i);

  capture_observe_lifecycle(sysnum, args);

  uint64_t copied_clone_flags = 0;
  bool copied_vfork_clone = has_copied_runtime() &&
      clone_identity_flags(sysnum, args, &copied_clone_flags) &&
      (copied_clone_flags & CLONE_THREAD) == 0 &&
      (copied_clone_flags & CLONE_VFORK) != 0;

  if (protect_evidence_socket_syscall(
          (uintptr_t)drcontext, sysnum, args, &result)) {
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }

  /* DynamoRIO can continue a vfork child without a new thread-init event.  At
   * its first syscall, the shared pending clone state is the only boundary
   * available before the copied-process external-runtime initialization below.
   */
  if (has_copied_runtime() && runtime_uses_external_global() &&
      !copied_vfork_clone &&
      copied_process_runtime_pid != dr_get_process_id() &&
      counters->pending_birth_token != 0 &&
      (counters->pending_clone_flags & CLONE_VFORK) != 0) {
    atomic_store_explicit(
        &copied_vfork_pid, (int32_t)dr_get_process_id(), memory_order_release);
    release_clone_identity_handoff(counters->pending_birth_token);
  }

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-255): Review copied-process Detcore state rebasing.
  if (has_copied_runtime() && runtime_uses_external_global() &&
      !copied_vfork_clone && !is_copied_vfork_process() &&
      copied_process_runtime_pid != dr_get_process_id()) {
    bind_capture_owner(counters);
    evidence_callback_enter();
    int32_t initialized = reverie_dbt_runtime_thread_init(
        counters,
        drcontext,
        (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(),
        in_tree_parent_pid(),
        atomic_load_explicit(&branch_count, memory_order_relaxed),
        0,
        invoke_syscall,
        read_registers,
        write_registers);
    evidence_callback_leave();
    if (initialized != 0) {
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: copied process state initialization failed\n");
      exit_runtime_tree(101);
      return false;
    }
    copied_process_runtime_pid = dr_get_process_id();
  }

  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process() ||
       copied_vfork_clone)) {
    // Prepare the real process's birth owner before entering the callback. A
    // vfork/CLONE_VM child cannot use the inherited runtime_process_control.
    process_control_t* process = NULL;
    if (runtime_process_group != 0 &&
        runtime_process_group != dr_get_process_id())
      process = process_control_for((int32_t)dr_get_process_id());
    evidence_callback_enter();
    int32_t copied_action =
        reverie_dbt_runtime_copied_syscall((int64_t)sysnum, args);
    evidence_callback_leave();
    if (test_copied_backend_failure && sysnum == SYS_sched_getscheduler)
      copied_action = 1;
    // Negative actions are deterministic errno values synthesized by the
    // copied-child policy. They avoid executing a host-dependent syscall while
    // preserving the error that the instrumented root observes.
    if (copied_action < 0) {
      dr_syscall_set_result(drcontext, (reg_t)copied_action);
      return false;
    }
    if (copied_action == 1) {
      dr_fprintf(
          diagnostic_file,
          "detcore-dbt: unsupported syscall %d in copied child\n",
          sysnum);
      exit_copied_syscall_failure(process);
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
    if (preserve_internal_descriptors(
            (uintptr_t)drcontext, sysnum, args, &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    /* The client keeps no clock or resource-limit table of its own. A copied
     * child runs no Rust Tool, so its clock and rlimit calls are the
     * runtime's to decide in reverie_dbt_runtime_copied_syscall above:
     * Detcore's runtime refuses them by name, and the prototype runtime lets
     * them reach the host as its forwarding tools do. */
    if (sysnum == SYS_exit || sysnum == SYS_exit_group)
      complete_runtime_thread_exit(
          counters, drcontext, sysnum == SYS_exit, sysnum == SYS_exit_group);
    bool execute = prepare_original_task_syscall(
        drcontext, counters, sysnum, args, false);
    if (execute && is_exec_syscall(sysnum)) {
      require_evidence_flush(EVIDENCE_FRAME_EXEC);
    }
    return execute;
  }
  while (!reverie_dbt_runtime_ready(
      atomic_load_explicit(&image_generation, memory_order_acquire)))
    dr_sleep(1);
  if (test_backend_failure) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: requested backend failure for testing\n");
    exit_runtime_tree(101);
    return false;
  }
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
  evidence_callback_enter();
  int32_t action = reverie_dbt_runtime_pre_syscall(
      drcontext,
      counters,
      (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(),
      atomic_load_explicit(&image_generation, memory_order_acquire),
      (int64_t)sysnum,
      args,
      atomic_load_explicit(&branch_count, memory_order_relaxed),
      &result,
      &deferred_sysnum,
      deferred_args,
      invoke_syscall,
      read_registers,
      write_registers,
      read_memory,
      write_memory,
      reverie_dbt_emit);
  evidence_callback_leave();
  DR_ASSERT(evidence_callback_depth == 0);
  if (counters->syscall_interruption != 0) {
    uint64_t token = counters->syscall_interruption;
    bool owner = native_runtime_entries == 0 &&
        counters->syscall_interruption_pid == dr_get_process_id() &&
        counters->syscall_interruption_tid == dr_get_thread_id(drcontext) &&
        counters->syscall_interruption_generation ==
            atomic_load_explicit(&image_generation, memory_order_acquire);
    bool terminal = action == 2 &&
        (deferred_sysnum == SYS_exit || deferred_sysnum == SYS_exit_group);
    bool resolved = owner &&
        (terminal ? dr_cancel_syscall_interruption(drcontext, token)
                  : action == 1 && dr_complete_syscall_interruption(
                        drcontext, token, (reg_t)result));
    if (!resolved) {
      dr_fprintf(diagnostic_file,
                 "reverie-dbt: interrupted syscall final outcome refused\n");
      exit_runtime_tree(101);
      return false;
    }
    counters->syscall_interruption = 0;
  }
  if (action != 0 && counters->pending_thread_clone != 0)
    counters->pending_thread_clone = 0;

  if (action < 0 || action > 2) {
    exit_runtime_tree(101);
    return false;
  }
  if (action == 1) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(#77): Confirm pipe EAGAIN retry preserves signal and
    // short-I/O semantics.
    // Detcore owns blocking retries and logs the completed I/O result. Preserve
    // that result, including EAGAIN and short transfers, without native retries.
    // A completed Tool answer is final, including own-identity getters.
    // Suppress installs this value without further native syscall policy.
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }
  if (action == 2) {
    uint64_t clone_flags = 0;
    uint64_t clone_ctid = 0;
    int i;
    sysnum = (int)deferred_sysnum;
    memcpy(args, deferred_args, sizeof(args));
    capture_observe_lifecycle(sysnum, args);
    dr_syscall_set_sysnum(drcontext, sysnum);
    for (i = 0; i != 6; ++i)
      dr_syscall_set_param(drcontext, i, (reg_t)args[i]);
    if (protect_evidence_socket_syscall(
            (uintptr_t)drcontext, sysnum, args, &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    if (thread_clone_metadata(drcontext, sysnum, &clone_flags, &clone_ctid)) {
      counters->pending_thread_clone = 1;
      counters->thread_clone_flags = clone_flags;
      counters->thread_clone_ctid = clone_ctid;
    }
    if (preserve_internal_descriptors(
            (uintptr_t)drcontext, sysnum, args, &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
    if (sysnum == SYS_exit || sysnum == SYS_exit_group)
      complete_runtime_thread_exit(
          counters, drcontext, sysnum == SYS_exit, sysnum == SYS_exit_group);
    bool execute = prepare_original_task_syscall(
        drcontext, counters, sysnum, args, true);
    if (execute && is_exec_syscall(sysnum)) {
      require_evidence_flush(EVIDENCE_FRAME_EXEC);
    }
    return execute;
  }

  /* A runtime that declines a call leaves it to the host. The client keeps
   * no clock or resource-limit table: under Hermit, Detcore owns the
   * complete syscall policy and answers these above. */
  if (sysnum == SYS_exit || sysnum == SYS_exit_group)
    complete_runtime_thread_exit(
        counters, drcontext, sysnum == SYS_exit, sysnum == SYS_exit_group);
  bool execute = prepare_original_task_syscall(
      drcontext, counters, sysnum, args, false);
  if (execute && is_exec_syscall(sysnum)) {
    require_evidence_flush(EVIDENCE_FRAME_EXEC);
  }
  return execute;
}

/* The contended half of the self-test: two threads each add one to the same
 * word this many times through compare_exchange_word, the exchange that
 * runtime_compare_exchange_u32 performs after its access checks, as a retry
 * loop. Only an atomic compare-and-exchange keeps every increment. The access
 * checks, which cost far more than the exchange, are left out so that the
 * two threads collide often enough to expose a non-atomic exchange. */
#define COMPARE_EXCHANGE_CONTENDED_INCREMENTS 200000

typedef struct {
  uint32_t* word;
  _Atomic int contender_ready;
  _Atomic int start;
  _Atomic int finished;
} compare_exchange_contest_t;

static void compare_exchange_increment_many(
    compare_exchange_contest_t* contest) {
  while (!atomic_load_explicit(&contest->start, memory_order_acquire))
    ;
  for (int i = 0; i < COMPARE_EXCHANGE_CONTENDED_INCREMENTS; ++i) {
    uint32_t value = __atomic_load_n(contest->word, __ATOMIC_RELAXED);
    for (;;) {
      uint32_t observed = compare_exchange_word(contest->word, value, value + 1);
      if (observed == value)
        break;
      value = observed;
    }
  }
}

static void compare_exchange_contender(void* argument) {
  compare_exchange_contest_t* contest = (compare_exchange_contest_t*)argument;
  atomic_store_explicit(&contest->contender_ready, 1, memory_order_release);
  compare_exchange_increment_many(contest);
  atomic_store_explicit(&contest->finished, 1, memory_order_release);
}

/* Races a DynamoRIO client thread against the calling thread, both
 * incrementing one word; true when no increment was lost. */
static bool compare_exchange_survives_contention(uint32_t* word) {
  compare_exchange_contest_t contest = {.word = word};
  *word = 0;
  if (!dr_create_client_thread(compare_exchange_contender, &contest))
    return false;
  // Start both loops only once the client thread runs, so they overlap.
  while (!atomic_load_explicit(&contest.contender_ready, memory_order_acquire))
    dr_thread_yield();
  atomic_store_explicit(&contest.start, 1, memory_order_release);
  compare_exchange_increment_many(&contest);
  while (!atomic_load_explicit(&contest.finished, memory_order_acquire))
    dr_thread_yield();
  return __atomic_load_n(word, __ATOMIC_SEQ_CST) ==
      2u * COMPARE_EXCHANGE_CONTENDED_INCREMENTS;
}

/* `-test-compare-exchange`: checks runtime_compare_exchange_u32's outcomes on
 * client-owned memory once, at the first system call, and reports them on the
 * diagnostic stream for reverie-dbt's live tests. */
static void run_compare_exchange_self_test(void) {
  size_t page = dr_page_size();
  uint32_t* writable =
      (uint32_t*)dr_nonheap_alloc(page, DR_MEMPROT_READ | DR_MEMPROT_WRITE);
  uint32_t* read_only =
      (uint32_t*)dr_nonheap_alloc(page, DR_MEMPROT_READ | DR_MEMPROT_WRITE);
  DR_ASSERT(writable != NULL && read_only != NULL);
  writable[0] = 7;
  read_only[0] = 7;
  DR_ASSERT(dr_memory_protect(read_only, page, DR_MEMPROT_READ));
  uint32_t observed = 0;
  uint64_t core_calls_before =
      atomic_load_explicit(&compare_exchange_word_calls, memory_order_relaxed);
  int matched = runtime_compare_exchange_u32(
                    (uintptr_t)writable, 7, 9, &observed) == 0 &&
      observed == 7 && writable[0] == 9;
  int mismatched = runtime_compare_exchange_u32(
                       (uintptr_t)writable, 7, 11, &observed) == 0 &&
      observed == 9 && writable[0] == 9;
  int through_core =
      atomic_load_explicit(&compare_exchange_word_calls, memory_order_relaxed) -
          core_calls_before ==
      2;
  int misaligned = runtime_compare_exchange_u32(
                       (uintptr_t)writable + 1, 9, 1, &observed) == -EINVAL &&
      writable[0] == 9;
  int unmapped =
      runtime_compare_exchange_u32((uintptr_t)8, 0, 1, &observed) == -EFAULT;
  int unwritable = runtime_compare_exchange_u32(
                       (uintptr_t)read_only, 7, 9, &observed) == -EFAULT &&
      read_only[0] == 7;
  int contended = compare_exchange_survives_contention(writable + 16);
  dr_fprintf(
      diagnostic_file,
      "reverie-dbt: compare-exchange self-test matched=%d mismatched=%d "
      "core=%d misaligned=%d unmapped=%d unwritable=%d contended=%d\n",
      matched,
      mismatched,
      through_core,
      misaligned,
      unmapped,
      unwritable,
      contended);
  DR_ASSERT(
      dr_memory_protect(read_only, page, DR_MEMPROT_READ | DR_MEMPROT_WRITE));
  dr_nonheap_free(writable, page);
  dr_nonheap_free(read_only, page);
}

/* Component controls use a private scratch owner, not synthetic live process
 * identities. No production owner or TLS admission is substituted or reset. */
static void reset_capture_test_owner(task_state_t* scratch, int32_t pid) {
  memset(scratch, 0, sizeof(*scratch));
  scratch->magic = TASK_STATE_MAGIC;
  atomic_flag_clear(&scratch->lock);
  atomic_init(&scratch->capture_uncertain, false);
  atomic_init(&scratch->process_control_count, 0);
  scratch->external_global = true;
  scratch->capture_procfs_valid = true;
  scratch->capture_procfs_device = 17;
  scratch->capture_procfs_inode = 29;
  scratch->root_pid = pid;
  scratch->root_birth_token = 100;
  scratch->task_count = 1;
  scratch->tasks[0] = (task_membership_t){pid, 100};
  initialize_process_control_locked(
      scratch, &scratch->process_controls[0], pid, 100, false);
  atomic_store_explicit(&scratch->process_control_count, 1, memory_order_release);
}

static bool capture_test_query(
    task_state_t* scratch, capture_owner_t* owner, int32_t pid, bool ready) {
  controller_capture_fact_t out;
  memset(&out, 0xa5, sizeof(out));
  int result = controller_capture_from_owner(scratch, owner, pid, pid, 0, true, &out);
  if (ready)
    return result == 1 && out.physical_pid == pid && out.physical_tid == pid &&
        out.procfs_device == 17 && out.procfs_inode == 29;
  controller_capture_fact_t zero = {0};
  return result == 0 && memcmp(&out, &zero, sizeof(out)) == 0;
}

/* Failed attempts must not consume the bounded process-owner table. This
 * also checks the full-capacity boundary without creating any kernel tasks. */
static bool capture_test_canceled_capacity(task_state_t* scratch, int32_t pid) {
  reset_capture_test_owner(scratch, pid);
  capture_owner_t root = {&scratch->process_controls[0], 100, pid};
  for (int32_t i = 0; i < MAX_TASK_MEMBERSHIPS + 1; ++i) {
    int32_t birth = 1000 + i;
    reserve_capture_admission_locked(scratch, birth);
    if (atomic_load(&scratch->process_control_count) != 2 ||
        scratch->process_controls[1].birth_token != birth ||
        !atomic_load(&scratch->process_controls[1].capture_pending_admission))
      return false;
    cancel_failed_capture_admission_locked(scratch, birth);
  }
  if (!capture_test_query(scratch, &root, pid, true))
    return false;

  reserve_capture_admission_locked(scratch, 30000);
  scratch->tasks[1] = (task_membership_t){pid + 1, 30000};
  scratch->task_count = 2;
  scratch->process_controls[1].kernel_pid = pid + 1;
  capture_owner_t child = {&scratch->process_controls[1], 30000, 0};
  controller_capture_fact_t out;
  if (controller_capture_from_owner(
          scratch, &child, pid + 1, pid + 1, 1, true, &out) != 1 ||
      scratch->process_controls[1].kernel_pid != pid + 1 ||
      atomic_load(&scratch->process_controls[1].capture_pending_admission))
    return false;

  for (size_t i = 2; i < MAX_TASK_MEMBERSHIPS; ++i)
    initialize_process_control_locked(scratch, &scratch->process_controls[i],
        pid + (int32_t)i, 40000 + (int32_t)i, false);
  atomic_store_explicit(
      &scratch->process_control_count, MAX_TASK_MEMBERSHIPS, memory_order_release);
  process_control_t* pending = &scratch->process_controls[2];
  pending->kernel_pid = 0;
  atomic_store(&pending->capture_pending_admission, true);
  process_control_t* published = &scratch->process_controls[3];
  atomic_store(&published->capture_pending_admission, true);
  atomic_store(&published->image_epoch, 73);
  const private_memory_snapshot_t saved_memory = {
      .owner = {17, 29, 3, 73}, .version = 91, .state = 1, .count = 1,
      .ranges = {{0x1000, 0x3000}}};
  published->private_memory = saved_memory;
  published->memory_published = 1;
  // An owner whose identity is unavailable still cannot donate a published
  // memory-token slot to the canceled-create reservation pool.
  process_control_t* memory_owner = &scratch->process_controls[4];
  memory_owner->kernel_pid = 0;
  memory_owner->private_memory = saved_memory;
  memory_owner->memory_published = 1;
  process_control_t* canceled = &scratch->process_controls[MAX_TASK_MEMBERSHIPS - 1];
  canceled->kernel_pid = 0;
  atomic_store(&canceled->capture_pending_admission, true);
  cancel_failed_capture_admission_locked(scratch, canceled->birth_token);
  reserve_capture_admission_locked(scratch, 60000);
  bool reused = atomic_load(&scratch->process_control_count) == MAX_TASK_MEMBERSHIPS &&
      canceled->birth_token == 60000 && canceled->kernel_pid == 0 &&
      atomic_load(&canceled->capture_pending_admission) &&
      scratch->process_controls[0].kernel_pid == pid &&
      scratch->process_controls[0].birth_token == 100 &&
      scratch->process_controls[1].kernel_pid == pid + 1 &&
      scratch->process_controls[1].birth_token == 30000 &&
      pending->kernel_pid == 0 && pending->birth_token == 40002 &&
      atomic_load(&pending->capture_pending_admission) &&
      published->kernel_pid == pid + 3 && published->birth_token == 40003 &&
      atomic_load(&published->capture_pending_admission) &&
      atomic_load(&published->image_epoch) == 73 &&
      published->memory_published == 1 && published->memory_retired == 0 &&
      memcmp(&published->private_memory, &saved_memory, sizeof(saved_memory)) == 0 &&
      memory_owner->kernel_pid == 0 && memory_owner->birth_token == 40004 &&
      memory_owner->memory_published == 1 && memory_owner->memory_retired == 0 &&
      memcmp(&memory_owner->private_memory, &saved_memory, sizeof(saved_memory)) == 0 &&
      !atomic_load(&scratch->capture_uncertain);
  // With no canceled slot left, retain every owner and withdraw certainty.
  reserve_capture_admission_locked(scratch, 60001);
  reused &= atomic_load(&scratch->process_control_count) == MAX_TASK_MEMBERSHIPS &&
      canceled->birth_token == 60000 && atomic_load(&scratch->capture_uncertain);
  cancel_failed_capture_admission_locked(scratch, 60000);
  reserve_capture_admission_locked(scratch, 60002);
  return reused && canceled->birth_token == 60002 &&
      atomic_load(&canceled->capture_pending_admission) &&
      atomic_load(&scratch->capture_uncertain);
}

static void run_controller_capture_self_test(void) {
  const int32_t pid = 37;
  task_state_t* scratch = dr_global_alloc(sizeof(*scratch));
  DR_ASSERT(scratch != NULL);
  reset_capture_test_owner(scratch, pid);
  capture_owner_t root = {&scratch->process_controls[0], 100, 0};
  controller_capture_fact_t out;
  bool fresh = capture_test_query(scratch, &root, pid, false) &&
      controller_capture_from_owner(scratch, &root, pid, pid, 1, true, &out) == 1 &&
      capture_test_query(scratch, &root, pid, true);

  reserve_capture_admission_locked(scratch, 200);
  bool pending = capture_test_query(scratch, &root, pid, false);
  scratch->process_controls[1].kernel_pid = pid + 1;
  capture_owner_t child = {&scratch->process_controls[1], 201, 0};
  bool wrong_birth = controller_capture_from_owner(
          scratch, &child, pid + 1, pid + 1, 1, true, &out) == 0 &&
      controller_capture_from_owner(scratch, &root, pid, pid, 1, true, &out) == 1 &&
      atomic_load(&scratch->process_controls[1].capture_pending_admission) &&
      capture_test_query(scratch, &root, pid, false);
  child.birth = 200;
  bool wrong_pid = controller_capture_from_owner(
          scratch, &child, pid, pid, 1, true, &out) == 0 &&
      controller_capture_from_owner(
          scratch, &root, pid + 1, pid + 1, 1, true, &out) == 0 &&
      atomic_load(&scratch->process_controls[1].capture_pending_admission) &&
      capture_test_query(scratch, &root, pid, false);
  bool admitted = controller_capture_from_owner(
          scratch, &child, pid + 1, pid + 1, 1, true, &out) == 1 &&
      !atomic_load(&scratch->process_controls[1].capture_pending_admission) &&
      capture_test_query(scratch, &root, pid, true);

  reserve_capture_admission_locked(scratch, 300);
  reserve_capture_admission_locked(scratch, 400);
  cancel_failed_capture_admission_locked(scratch, 300);
  bool exact_failure = !atomic_load(&scratch->process_controls[2].capture_pending_admission) &&
      atomic_load(&scratch->process_controls[3].capture_pending_admission) &&
      capture_test_query(scratch, &root, pid, false);
  cancel_failed_capture_admission_locked(scratch, 400);
  exact_failure &= capture_test_query(scratch, &root, pid, true);

  atomic_store(&scratch->process_controls[0].pending_thread_clones, 1);
  bool thread_pending = capture_test_query(scratch, &root, pid, false);
  atomic_store(&scratch->process_controls[0].pending_thread_clones, 0);
  thread_pending &= capture_test_query(scratch, &root, pid, true);

  // Hold the unrelated membership lock through BOTH operations. Old try-lock
  // query and deferred acknowledgment fail this positive correctness control.
  atomic_flag_test_and_set(&scratch->lock);
  bool contention = capture_test_query(scratch, &root, pid, true);
  root.mediated_pid = 0;
  atomic_store(&root.entry->capture_pending_admission, true);
  contention &= capture_test_query(scratch, &root, pid, false) &&
      controller_capture_from_owner(scratch, &root, pid, pid, 1, true, &out) == 1 &&
      !atomic_load(&root.entry->capture_pending_admission) &&
      capture_test_query(scratch, &root, pid, true);
  capture_owner_t unknown = {0};
  contention &= capture_test_query(scratch, &unknown, pid, false);
  // A publisher that died with an unresolved reservation remains unavailable,
  // regardless of the held lock. There is no inferred cancellation on death.
  atomic_store(&scratch->process_controls[2].capture_pending_admission, true);
  contention &= capture_test_query(scratch, &root, pid, false);
  atomic_store(&scratch->process_controls[2].capture_pending_admission, false);
  atomic_flag_clear(&scratch->lock);
  contention &= capture_test_query(scratch, &root, pid, true);

  uint64_t arguments[6] = {CLONE_VM | CLONE_VFORK | SIGCHLD, 0, 0, 0, 0, 0};
  if (capture_lifecycle_is_uncertain(SYS_clone, arguments))
    capture_mark_owner_uncertain(scratch);
  atomic_flag_test_and_set(&scratch->lock);
  bool sticky = capture_test_query(scratch, &root, pid, false) &&
      controller_capture_from_owner(scratch, &root, pid, pid, 1, true, &out) == 1 &&
      capture_test_query(scratch, &root, pid, false);
  atomic_flag_clear(&scratch->lock);
  if (capture_lifecycle_is_uncertain(SYS_exit, arguments))
    capture_mark_owner_uncertain(scratch);
  sticky &= capture_test_query(scratch, &root, pid, false);

  reset_capture_test_owner(scratch, pid);
  root = (capture_owner_t){&scratch->process_controls[0], 100, pid};
  bool lost = controller_capture_from_owner(
          scratch, &root, pid, pid, 0, false, &out) == 0 &&
      atomic_load(&scratch->capture_uncertain);
  lost &= capture_test_query(scratch, &root, pid, false);
  bool exec_loss = capture_may_initialize(true, false) &&
      !capture_may_initialize(true, true) &&
      !capture_may_initialize(false, false) &&
      !capture_may_initialize(false, true);

  bool capacity = capture_test_canceled_capacity(scratch, pid);
  dr_global_free(scratch, sizeof(*scratch));
  dr_fprintf(diagnostic_file,
      "CONTROLLER_CAPTURE_TEST fresh=%d pending=%d wrong_birth=%d wrong_pid=%d "
      "admitted=%d exact_failure=%d thread_pending=%d contention=%d sticky=%d "
      "lost=%d exec_loss=%d capacity=%d\n",
      fresh, pending, wrong_birth, wrong_pid, admitted, exact_failure,
      thread_pending, contention, sticky, lost, exec_loss, capacity);
  if (!(fresh && pending && wrong_birth && wrong_pid && admitted && exact_failure &&
        thread_pending && contention && sticky && lost && exec_loss && capacity))
    exit_runtime_tree(101);
}

/* The registered system-call events: mark the thread as inside one for
 * runtime_compare_exchange_u32, around the real handlers. */
static void set_in_syscall_event(void* drcontext, bool value) {
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  if (counters != NULL)
    counters->in_syscall_event = value;
}

static bool pre_syscall_event(void* drcontext, int sysnum) {
  set_in_syscall_event(drcontext, true);
  bool execute = pre_syscall(drcontext, sysnum);
  set_in_syscall_event(drcontext, false);
  return execute;
}

static void post_syscall_event(void* drcontext, int sysnum) {
  set_in_syscall_event(drcontext, true);
  post_syscall(drcontext, sysnum);
  set_in_syscall_event(drcontext, false);
}

static void thread_init(void* drcontext) {
  prototype_counters_t* counters =
      (prototype_counters_t*)dr_thread_alloc(drcontext, sizeof(*counters));
  int32_t host_tid = (int32_t)dr_get_thread_id(drcontext);
  int32_t pending_child =
      atomic_load_explicit(&pending_clone_birth_token, memory_order_acquire);
  if (pending_child != 0 && !require_supported_child_pid_namespace())
    return;
  int32_t clone_creator = pending_child != 0
      ? atomic_load_explicit(&pending_clone_creator_pid, memory_order_relaxed)
      : 0;
  if ((int32_t)dr_get_process_id() == clone_creator)
    pending_child = 0;
  uint64_t clone_flags = pending_child != 0
      ? atomic_load_explicit(&pending_clone_flags, memory_order_relaxed)
      : 0;
  bool is_thread = (clone_flags & CLONE_THREAD) != 0;
  if (pending_child != 0) {
    if (!is_thread)
      publish_task_birth((int32_t)dr_get_process_id(), pending_child, true);
    publish_task_birth(host_tid, pending_child, true);
    rebind_private_memory_after_clone(clone_flags);
  }
  DR_ASSERT(counters != NULL);
  memset(counters, 0, sizeof(*counters));
  DR_ASSERT(drmgr_set_tls_field(drcontext, thread_state_index, counters));

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review safe-point preemption per-thread
  // state. When preemption is enabled, give this thread a persistent mcontext
  // buffer for `maybe_preempt` to capture into and `preempt_return` to resume
  // from. Freed in `thread_exit`.
  if (preemption_enabled) {
    counters->preempt_mcontext =
        (dr_mcontext_t*)dr_thread_alloc(drcontext, sizeof(dr_mcontext_t));
    DR_ASSERT(counters->preempt_mcontext != NULL);
  }
  counters->signal_mcontext =
      (dr_mcontext_t*)dr_thread_alloc(drcontext, sizeof(dr_mcontext_t));
  DR_ASSERT(counters->signal_mcontext != NULL);

  int32_t pending_thread_start =
      dr_get_thread_id(drcontext) != dr_get_process_id() &&
      (has_copied_runtime() ||
       reverie_dbt_runtime_ready(
           atomic_load_explicit(&image_generation, memory_order_acquire)));

  // Publish kernel IDs before Rust. A new thread's ID remains zero until
  // its parent publishes admission for this incarnation.
  counters->kernel_pid = (int32_t)dr_get_process_id();
  counters->kernel_ppid = (int32_t)dr_get_parent_id();
  counters->kernel_tid = pending_thread_start ? 0 : host_tid;
  if (pending_child == 0 && !pending_thread_start)
    ensure_task_membership(host_tid);
  counters->pending_birth_token = 0;
  counters->pending_clone_flags = pending_child != 0 ? clone_flags : 0;

  bind_capture_owner(counters);
  evidence_thread_enter(counters);
  evidence_callback_enter();
  evidence_emit_image_initialization();
  int32_t init_result = reverie_dbt_runtime_thread_init(
      counters,
      drcontext,
      (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(),
      in_tree_parent_pid(),
      atomic_load_explicit(&branch_count, memory_order_relaxed),
      1,
      invoke_syscall,
      read_registers,
      write_registers);
  evidence_callback_leave();
  DR_ASSERT(evidence_callback_depth == 0);
  if (init_result < 0) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: runtime thread initialization failed\n");
    exit_runtime_tree(101);
    return;
  }
  if (pending_child != 0) {
    if (!is_thread && (clone_flags & CLONE_VFORK) != 0)
      atomic_store_explicit(
          &copied_vfork_pid,
          (int32_t)dr_get_process_id(),
          memory_order_release);
    release_clone_identity_handoff(pending_child);
  }

  set_pending_thread_start(counters, (uint64_t)pending_thread_start);
}

/* The exchange itself: one lock cmpxchg on a word the caller has already
 * found readable and writable. Returns the value the word held. */
static uint32_t compare_exchange_word(
    uint32_t* word,
    uint32_t expected,
    uint32_t desired) {
  atomic_fetch_add_explicit(&compare_exchange_word_calls, 1, memory_order_relaxed);
  uint32_t value = expected;
  __atomic_compare_exchange_n(
      word, &value, desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return value;
}

/* Atomically replaces the aligned guest word at `address` with `desired` if it
 * holds `expected`, as Linux's futex_cmpxchg_value_locked does, and stores the
 * value the word held at `observed`. Returns 0, -EINVAL for a misaligned
 * address, -EFAULT for a word that is not mapped readable and writable, or
 * -ENOSYS on a thread DynamoRIO does not know. This is the runtime's
 * MemoryAccess::compare_exchange_u32 (ABI version 8).
 *
 * The word's access is decided from DynamoRIO's view of the guest mapping
 * before the exchange, not by catching a fault: a fault caught with
 * DR_TRY_EXCEPT cannot be told apart from a user-sent SIGSEGV, which it would
 * then swallow, possibly after the exchange had stored. So a word on an
 * unmapped, unreadable or read-only page is -EFAULT without being touched.
 *
 * A writable page that DynamoRIO has made read-only because it holds
 * translated code (DR_MEMPROT_PRETEND_WRITE) is writable for the guest.
 * DynamoRIO recovers a client write to such a page, flushing the code and
 * re-executing the write, but only from a pre- or post-system-call event with
 * no locks held (see DR_MEMPROT_PRETEND_WRITE in os_api.h). Outside those
 * events such a word is -EFAULT, reported on the diagnostic stream. Detcore's
 * owner-death stores run inside system-call events.
 *
 * With no try/except, a fault on the exchange itself aborts the run
 * (DynamoRIO's client-fault handler, core/unix/signal.c). The checks and the
 * safe read just before it leave only a concurrent change to the mapping
 * between them and the exchange, which Hermit's sequentialized turns rule
 * out: no other thread of the guest runs during the tool's turn. */
static int32_t runtime_compare_exchange_u32(
    uintptr_t address,
    uint32_t expected,
    uint32_t desired,
    uint32_t* observed) {
  if (address % sizeof(uint32_t) != 0)
    return -EINVAL;
  void* drcontext = dr_get_current_drcontext();
  if (drcontext == NULL)
    return -ENOSYS;
  dr_mem_info_t info;
  if (!dr_query_memory_ex((const byte*)address, &info) ||
      info.type == DR_MEMTYPE_FREE ||
      (info.prot & (DR_MEMPROT_READ | DR_MEMPROT_WRITE)) !=
          (DR_MEMPROT_READ | DR_MEMPROT_WRITE))
    return -EFAULT;
  if ((info.prot & DR_MEMPROT_PRETEND_WRITE) != 0) {
    prototype_counters_t* counters =
        (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
    if (counters == NULL || !counters->in_syscall_event) {
      // Not silent: the caller loses a store Linux would have made. For a
      // runtime memory store this remains an explicit access failure.
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: compare-exchange refused outside a system-call event "
          "on a page DynamoRIO made read-only (address %p)\n",
          (void*)address);
      return -EFAULT;
    }
    if (test_compare_exchange)
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: compare-exchange on a page DynamoRIO made read-only\n");
  }
  // A word the mapping calls readable may still fault, for example in a
  // shared mapping past the end of its file; read it safely first.
  uint32_t current;
  if (!read_app((const void*)address, &current, sizeof(current)))
    return -EFAULT;
  *observed = compare_exchange_word((uint32_t*)address, expected, desired);
  return 0;
}

static void complete_runtime_thread_exit(
    prototype_counters_t* counters,
    void* drcontext,
    bool explicit_exit,
    bool exit_group) {
  (void)exit_group;
  bool owns_runtime;
  if (namespace_admission_refused)
    return;
  if (counters->runtime_thread_exit_called != 0)
    return;
  counters->runtime_thread_exit_called = 1;
  owns_runtime = !has_copied_runtime() ||
      (runtime_uses_external_global() && !is_copied_vfork_process());
  if (owns_runtime) {
    evidence_callback_enter();
    reverie_dbt_runtime_thread_exit(
        counters, drcontext, dr_get_thread_id(drcontext), invoke_syscall);
    evidence_callback_leave();
    if (test_thread_exit_evidence && explicit_exit && evidence_is_enabled() &&
        counters->evidence_thread_process == dr_get_process_id()) {
      static const char record[] =
          "1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: "
          "explicit SYS_exit thread callback completed\n";
      evidence_callback_enter();
      reverie_dbt_emit_evidence(record, sizeof(record) - 1);
      evidence_callback_leave();
    }
  }
}

static void thread_exit(void* drcontext) {
  if (namespace_admission_refused)
    return;
  prototype_counters_t* counters =
      (prototype_counters_t*)drmgr_get_tls_field(drcontext, thread_state_index);
  if (counters != NULL) {
    bool owns_runtime = !has_copied_runtime() ||
        (runtime_uses_external_global() && !is_copied_vfork_process());
    complete_runtime_thread_exit(counters, drcontext, false, false);
    evidence_thread_leave(counters);
    if (owns_runtime) {
      if (counters->signal_mcontext != NULL)
        dr_thread_free(drcontext, counters->signal_mcontext, sizeof(dr_mcontext_t));
      if (counters->preempt_mcontext != NULL)
        dr_thread_free(
            drcontext, counters->preempt_mcontext, sizeof(dr_mcontext_t));
      dr_thread_free(drcontext, counters, sizeof(*counters));
    }
  }
}

// Wire-v1 stats record layout (must byte-match src/backend_stats.rs):
//   header(24) + 15 little-endian u64 fields(120) = 144 bytes.
// Header: magic[8]="RVDBTSTA", version u16=1, record_len u16=144, flags u32,
//         runtime_kind u8, 7 reserved bytes (u64 alignment padding).
#define STATS_WIRE_RECORD_LEN 144
#define STATS_WIRE_VERSION 1
#define STATS_WIRE_FLAG_DR_STATS_PRESENT 1u
// Set when this image ended through exit_runtime_tree. Without an isolated
// process group that path ends only this process, so the record is how the
// launcher's caller learns a child failed (backend_stats.rs,
// WIRE_FLAG_BACKEND_FAILURE).
#define STATS_WIRE_FLAG_BACKEND_FAILURE 2u

static void stats_put_u64_le(unsigned char* out, uint64_t value) {
  for (int byte = 0; byte < 8; ++byte)
    out[byte] = (unsigned char)((value >> (8 * byte)) & 0xff);
}

// Emits one fixed-size stats record for this runtime image to `stats_path`.
// The file is opened per-image in append mode and the whole record is written by a single
// dr_write_file, so concurrent images append their 144-byte records atomically
// without interleaving.
// Appends this image's record to the run's stats file. A copied (pre-exec)
// runtime passes include_counters=false: its counters were copied from the
// parent, so it records only its identity and flags, which keeps a terminal
// failure in a forked child visible without counting the parent's work twice.
static void emit_stats_record(bool include_counters) {
  uint64_t branches = 0;
  uint64_t syscalls = 0;
  uint64_t rewritten = 0;
  uint64_t memory_hash = 0;
  uint64_t stdin_reads = 0;
  if (include_counters) {
    reverie_dbt_runtime_totals(&branches, &syscalls, &rewritten, &memory_hash);
    stdin_reads = atomic_load_explicit(&stdin_read_count, memory_order_relaxed);
  }
  uint64_t generation =
      atomic_load_explicit(&image_generation, memory_order_acquire);

  dr_stats_t dr_stats;
  dr_stats.size = sizeof(dr_stats);
  bool dr_stats_present = include_counters && dr_get_stats(&dr_stats);

  unsigned char record[STATS_WIRE_RECORD_LEN];
  memset(record, 0, sizeof(record));
  memcpy(record, "RVDBTSTA", 8);
  record[8] = (unsigned char)(STATS_WIRE_VERSION & 0xff);
  record[9] = (unsigned char)((STATS_WIRE_VERSION >> 8) & 0xff);
  record[10] = (unsigned char)(STATS_WIRE_RECORD_LEN & 0xff);
  record[11] = (unsigned char)((STATS_WIRE_RECORD_LEN >> 8) & 0xff);
  uint32_t flags = dr_stats_present ? STATS_WIRE_FLAG_DR_STATS_PRESENT : 0u;
  if (atomic_load_explicit(&runtime_backend_failure, memory_order_acquire))
    flags |= STATS_WIRE_FLAG_BACKEND_FAILURE;
  record[12] = (unsigned char)(flags & 0xff);
  record[13] = (unsigned char)((flags >> 8) & 0xff);
  record[14] = (unsigned char)((flags >> 16) & 0xff);
  record[15] = (unsigned char)((flags >> 24) & 0xff);
  record[16] = reverie_dbt_runtime_kind_code();
  // record[17..24] stay zero (reserved alignment padding).

  size_t offset = 24;
  stats_put_u64_le(record + offset, generation);
  offset += 8;
  stats_put_u64_le(
      record + offset,
      (uint64_t)(uint32_t)(include_counters ? runtime_process_id
                                          : (int32_t)dr_get_process_id()));
  offset += 8;
  stats_put_u64_le(
      record + offset,
      (uint64_t)(uint32_t)(include_counters ? runtime_parent_process_id
                                          : (int32_t)dr_get_parent_id()));
  offset += 8;
  stats_put_u64_le(record + offset, branches);
  offset += 8;
  stats_put_u64_le(record + offset, syscalls);
  offset += 8;
  stats_put_u64_le(record + offset, rewritten);
  offset += 8;
  stats_put_u64_le(record + offset, stdin_reads);
  offset += 8;
  stats_put_u64_le(record + offset, memory_hash);
  offset += 8;
  stats_put_u64_le(
      record + offset, dr_stats_present ? dr_stats.basic_block_count : 0);
  offset += 8;
  stats_put_u64_le(
      record + offset, dr_stats_present ? dr_stats.num_threads_created : 0);
  offset += 8;
  stats_put_u64_le(
      record + offset, dr_stats_present ? dr_stats.synchs_not_at_safe_spot : 0);
  offset += 8;
  stats_put_u64_le(
      record + offset, dr_stats_present ? dr_stats.num_native_signals : 0);
  offset += 8;
  stats_put_u64_le(
      record + offset, dr_stats_present ? dr_stats.num_cache_exits : 0);
  offset += 8;
  stats_put_u64_le(
      record + offset, dr_stats_present ? dr_stats.peak_num_threads : 0);
  offset += 8;
  stats_put_u64_le(
      record + offset,
      dr_stats_present ? dr_stats.peak_vmm_blocks_reach_cache : 0);
  offset += 8;
  DR_ASSERT(offset == STATS_WIRE_RECORD_LEN);

  file_t stats_file = dr_open_file(stats_path, DR_FILE_WRITE_APPEND);
  if (stats_file == INVALID_FILE) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: failed to open stats sink for append\n");
    return;
  }
  // One append keeps the record whole among other images' appends; a retry
  // could interleave with them. A short or failed write is reported, because
  // a missing record can hide this image's backend failure from the launcher's
  // caller (a partial record makes the whole stream undecodable instead).
  ssize_t written = dr_write_file(stats_file, record, sizeof(record));
  if (written != (ssize_t)sizeof(record))
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: could not append the stats record (%d of %d bytes)%s\n",
        (int)written,
        (int)sizeof(record),
        atomic_load_explicit(&runtime_backend_failure, memory_order_acquire)
            ? "; this process ended on a backend failure"
            : "");
  dr_close_file(stats_file);
}

static void publish_copied_terminal_stats(process_control_t* process) {
  if (stats_path[0] == 0)
    return;
  uint32_t expected = 0;
  if (atomic_compare_exchange_strong_explicit(
          &process->terminal_stats_state, &expected, 1,
          memory_order_acq_rel, memory_order_acquire)) {
    emit_stats_record(false);
    // Even a short/failed append completes the attempt. Retrying could
    // interleave records; the decoder must refuse a missing or partial stream.
    atomic_store_explicit(&process->terminal_stats_state, 2, memory_order_release);
    return;
  }
  // Another failing thread must not kill the root before the publisher has
  // finished. Bound the wait; a stalled transport is itself a loud failure.
  for (int attempt = 0; attempt < 1000; ++attempt) {
    if (atomic_load_explicit(&process->terminal_stats_state, memory_order_acquire) == 2)
      return;
    dr_sleep(1);
  }
  dr_fprintf(diagnostic_file,
      "reverie-dbt: terminal failure stats publication did not finish\n");
}

static void event_exit(void) {
  if (namespace_admission_refused)
    return;
  if (dr_get_process_id() == runtime_memory_owner_pid) {
    retire_private_memory();
    dr_set_private_reservation_retirement_callback(NULL);
  }
  if (test_reused_tid)
    dr_fprintf(
        diagnostic_file,
        "REUSED_TID_TEST exercised=%d\n",
        atomic_load_explicit(&test_reused_tid_exercised, memory_order_acquire)
            ? 1
            : 0);
  finalize_runtime_process();
  uint64_t branches;
  uint64_t syscalls;
  uint64_t rewritten;
  uint64_t stdin_reads;
  uint64_t memory_hash;

  if (report_summary && !has_copied_runtime()) {
    reverie_dbt_runtime_totals(&branches, &syscalls, &rewritten, &memory_hash);
    stdin_reads = atomic_load_explicit(&stdin_read_count, memory_order_relaxed);
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: tool=%s branches=%llu syscalls=%llu "
        "rewritten=%llu stdin_reads=%llu memory_hash=%016llx\n",
        reverie_dbt_runtime_name(),
        branches,
        syscalls,
        rewritten,
        stdin_reads,
        memory_hash);
  }
  if (stats_path[0] != 0) {
    if (!has_copied_runtime())
      emit_stats_record(true);
    else if (atomic_load_explicit(
                 &runtime_backend_failure, memory_order_acquire)) {
      process_control_t* process =
          existing_process_control((int32_t)dr_get_process_id());
      if (process == NULL || atomic_load_explicit(
              &process->terminal_stats_state, memory_order_acquire) == 0)
        emit_stats_record(false);
    }
  }
  if (unsupported_report_file != INVALID_FILE) {
    dr_close_file(unsupported_report_file);
    unsupported_report_file = INVALID_FILE;
  }
  if (evidence_is_enabled() && !is_copied_vfork_process() &&
      evidence_current_process_finalized()) {
    dr_global_free(evidence_buffer, EVIDENCE_BUFFER_CAPACITY);
    evidence_buffer = NULL;
    dr_global_free(
        evidence_senders,
        sizeof(evidence_sender_state_t) * EVIDENCE_MAX_SENDERS);
    evidence_senders = NULL;
    dr_mutex_destroy(evidence_lock);
    evidence_lock = NULL;
  }
  drwrap_exit();
  drx_exit();
  drmgr_unregister_tls_field(compat_gateway_index);
  drmgr_unregister_tls_field(thread_state_index);
  DR_ASSERT(dr_raw_tls_cfree(admission_state_tls_offset, 1));
  drreg_exit();
  drmgr_exit();
}

static dr_signal_action_t event_signal(void* drcontext, dr_siginfo_t* info) {
  (void)drcontext;
  (void)info;
  return DR_SIGNAL_DELIVER;
}

static dr_signal_admission_status_t signal_admission_event(
    void* drcontext, const dr_signal_admission_t* event, dr_mcontext_t* redirect) {
  prototype_counters_t* counters =
      drmgr_get_tls_field(drcontext, thread_state_index);
  if (event == NULL) {
    if (counters == NULL ||
        !reverie_dbt_runtime_ready(
            atomic_load_explicit(&image_generation, memory_order_acquire)) ||
        (has_copied_runtime() &&
         (!runtime_uses_external_global() || is_copied_vfork_process())))
      return DR_SIGNAL_ADMISSION_BYPASS;
    if (native_runtime_entries != 0 || counters->preempt_pending != 0 ||
        counters->signal_token != 0 || counters->pending_thread_start != 0 ||
        counters->pending_process_clone_result != 0)
      return DR_SIGNAL_ADMISSION_WAIT;
    return DR_SIGNAL_ADMISSION_START;
  }
  if (counters == NULL || event->token == 0 || native_runtime_entries != 0 ||
      counters->preempt_pending != 0 || counters->signal_token != 0) {
    dr_fprintf(diagnostic_file, "reverie-dbt: signal admission ownership violation\n");
    exit_runtime_tree(101);
    return DR_SIGNAL_ADMISSION_WAIT;
  }
  counters->signal_token = event->token;
  counters->signal_owner_tid = dr_get_thread_id(drcontext);
  counters->signal_owner_pid = dr_get_process_id();
  counters->signal_image_generation =
      atomic_load_explicit(&image_generation, memory_order_acquire);
  counters->signal_phase = 1;
  counters->signal_registers_changed = false;
  *counters->signal_mcontext = *event->mcontext;
  memset(&counters->signal_event, 0, sizeof(counters->signal_event));
  counters->signal_event.signal = event->sig;
  counters->signal_event.delivered_signal = event->sig;
  memcpy(counters->signal_event.signal_info, event->siginfo, sizeof(event->siginfo));
  redirect->pc = signal_stub;
  redirect->xax = SYS_gettid;
  return DR_SIGNAL_ADMISSION_START;
}

static void signal_admission_return(void) {
  void* drcontext = dr_get_current_drcontext();
  prototype_counters_t* counters =
      drmgr_get_tls_field(drcontext, thread_state_index);
  if (counters == NULL || counters->signal_token == 0 ||
      counters->signal_phase != 2 || native_runtime_entries != 0 ||
      counters->signal_owner_tid != dr_get_thread_id(drcontext) ||
      counters->signal_owner_pid != dr_get_process_id() ||
      counters->signal_image_generation !=
          atomic_load_explicit(&image_generation, memory_order_acquire)) {
    dr_fprintf(diagnostic_file, "reverie-dbt: stale signal return continuation\n");
    exit_runtime_tree(101);
    return;
  }
  uint64_t token = counters->signal_token;
  int signal = counters->signal_action == 1
      ? 0 : counters->signal_event.delivered_signal;
  const byte* replacement = counters->signal_event.signal_info_changed
      ? counters->signal_event.signal_info : NULL;
  const dr_mcontext_t* registers = counters->signal_registers_changed
      ? counters->signal_mcontext : NULL;
  counters->signal_token = 0;
  counters->signal_phase = 0;
  if (!dr_signal_admission_resume(drcontext, token, signal, replacement, registers)) {
    dr_fprintf(diagnostic_file, "reverie-dbt: signal commit refused\n");
    exit_runtime_tree(101);
  }
}

static void runtime_idle(void) {
  if (!runtime_retirement_requested &&
      atomic_load_explicit(
          &runtime_process_control->image_epoch, memory_order_acquire) !=
          runtime_process_epoch) {
    runtime_retirement_requested = true;
    reverie_dbt_runtime_process_exit();
  }
  dr_sleep(1);
}

static void runtime_background_init(void* argument) {
  (void)argument;
  runtime_process_control->helper_pid = (int32_t)getpid();
  publish_helper_membership(runtime_process_control->helper_pid);
  if (!evidence_process_start_time(
          (process_id_t)runtime_process_control->helper_pid,
          &runtime_process_control->helper_start_time)) {
    dr_fprintf(
        diagnostic_file, "reverie-dbt: could not identify runtime helper\n");
    exit_runtime_tree(101);
    return;
  }
  atomic_store_explicit(&runtime_background_state, 2, memory_order_release);
  evidence_callback_enter();
  evidence_emit_image_initialization();
  // Only the initialized, inherited per-image state supplies mode authority.
  // An absent or invalid mapping must not become standalone by default.
  if (task_state == NULL ||
      task_state->magic != TASK_STATE_MAGIC) {
    evidence_callback_leave();
    dr_fprintf(diagnostic_file, "reverie-dbt: native startup mode is uninitialized\n");
    exit_runtime_tree(CLIENT_THREAD_START_FAILURE_EXIT_CODE);
    return;
  }
  uint32_t native_mode = runtime_uses_external_global()
      ? REVERIE_DBT_STARTUP_COORDINATED
      : REVERIE_DBT_STARTUP_STANDALONE;
  int32_t startup_status = reverie_dbt_runtime_background_init_v3(
      &runtime_callbacks_page.value, native_mode);
  evidence_callback_leave();
  if (startup_status != 0) {
    dr_fprintf(diagnostic_file, "reverie-dbt: runtime startup was refused\n");
    exit_runtime_tree(CLIENT_THREAD_START_FAILURE_EXIT_CODE);
    return;
  }
  // DynamoRIO implements a client thread as a distinct process sharing the
  // application address space. Protected evidence emitted by the external
  // scheduler is therefore admitted under this process's SO_PEERCRED identity,
  // not the application process identity. No application thread-exit or
  // process-exit callback runs when this entry point returns, so complete this
  // sender explicitly before the client process exits.
  require_evidence_flush(EVIDENCE_FRAME_FINAL);
  atomic_store_explicit(&runtime_background_state, 3, memory_order_release);
  atomic_store_explicit(
      &runtime_process_control->finished_helper_epoch,
      runtime_process_epoch,
      memory_order_release);
  if (test_delay_exec_helper_exit && runtime_process_epoch == 1) {
    // This fixture must exec once. Hold its first helper (and shared FDs)
    // until the successor claims its image, then expose the window between
    // acknowledged FINAL and kernel exit. Later images exit normally.
    while (atomic_load_explicit(
               &runtime_process_control->image_epoch, memory_order_acquire) ==
           runtime_process_epoch)
      dr_sleep(1);
    dr_sleep(1000);
  }
}

static void ensure_runtime_background(void) {
  int32_t expected = 0;
  if (!atomic_compare_exchange_strong_explicit(
          &runtime_background_state,
          &expected,
          1,
          memory_order_acq_rel,
          memory_order_acquire))
    return;

  // TODO-HUMAN-REVIEW(PR-134): Review fail-fast native runtime bootstrap.
  if (!dr_create_client_thread(
          runtime_background_init, (void*)reverie_dbt_emit)) {
    atomic_store_explicit(&runtime_background_state, 0, memory_order_release);
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: failed to start background client thread\n");
    exit_runtime_tree(CLIENT_THREAD_START_FAILURE_EXIT_CODE);
  }
}

extern char** environ;

// DynamoRIO removes its own variables and the launcher's HERMIT_DBT_* ones from
// the application's initial environment once this client is initialized, so a
// guest sees the environment it was given (its private libc's `environ` was the
// application's array). The runtime reads some of them later (the coordinator
// socket, Detcore's configuration), also in fork children, so it keeps a copy.
static void keep_private_environment(void) {
  size_t count = 0;
  while (environ[count] != NULL)
    ++count;
  char** copy = (char**)dr_global_alloc(sizeof(char*) * (count + 1));
  for (size_t i = 0; i < count; ++i) {
    size_t size = strlen(environ[i]) + 1;
    copy[i] = (char*)dr_global_alloc(size);
    memcpy(copy[i], environ[i], size);
  }
  copy[count] = NULL;
  environ = copy;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  drreg_options_t register_options = {sizeof(register_options), 1, false};
  bool external_global = false;
  bool test_direct_evidence_entry = false;
  bool test_runtime_abi_mismatch = false;
  bool evidence_socket_seen = false;
  bool evidence_token_seen = false;
  unsigned char evidence_address[EVIDENCE_ADDRESS_LEN] = {0};
  unsigned char evidence_token[EVIDENCE_TOKEN_LEN] = {0};

  keep_private_environment();
  diagnostic_file = STDERR;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-external-global") == 0)
      external_global = true;
    else if (strcmp(argv[i], "-test-direct-evidence-entry") == 0)
      test_direct_evidence_entry = true;
    else if (strcmp(argv[i], "-test-runtime-abi-mismatch") == 0)
      test_runtime_abi_mismatch = true;
    else if (strcmp(argv[i], "-test-wait-for-background") == 0)
      test_wait_for_background = true;
    else if (strcmp(argv[i], "-test-delay-exec-helper-exit") == 0)
      test_delay_exec_helper_exit = true;
    else if (strcmp(argv[i], "-test-kill-announced-child") == 0)
      test_kill_announced_child = true;
    else if (strcmp(argv[i], "-test-thread-exit-evidence") == 0)
      test_thread_exit_evidence = true;
    else if (strcmp(argv[i], "-test-leave-process-clone-result-pending") == 0)
      test_leave_process_clone_result_pending = true;
    else if (strcmp(argv[i], "-test-backend-failure") == 0)
      test_backend_failure = true;
    else if (strcmp(argv[i], "-test-copied-backend-failure") == 0)
      test_copied_backend_failure = true;
    else if (strcmp(argv[i], "-test-skip-terminal-cleanup") == 0)
      test_skip_terminal_cleanup = true;
    else if (strcmp(argv[i], "-test-backend-failure-sender-lookup-miss") == 0)
      test_backend_failure_sender_lookup_miss = true;
    else if (strcmp(argv[i], "-test-private-memory") == 0) {
      if (++i >= argc) {
        dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_TEST missing-mode\n");
        dr_exit_process(101);
        return;
      }
      if (strcmp(argv[i], "ready") == 0)
        test_private_memory = PRIVATE_MEMORY_TEST_READY;
      else if (strcmp(argv[i], "retire") == 0)
        test_private_memory = PRIVATE_MEMORY_TEST_RETIRE;
      else if (strcmp(argv[i], "lost-exec") == 0)
        test_private_memory = PRIVATE_MEMORY_TEST_LOST_EXEC;
      else if (strcmp(argv[i], "routes") == 0)
        test_private_memory = PRIVATE_MEMORY_TEST_ROUTES;
      else {
        dr_fprintf(diagnostic_file, "PRIVATE_MEMORY_TEST invalid-mode\n");
        dr_exit_process(101);
        return;
      }
    } else if (strcmp(argv[i], "-test-compare-exchange") == 0)
      test_compare_exchange = true;
    else if (strcmp(argv[i], "-test-controller-capture") == 0)
      test_controller_capture = true;
    else if (strcmp(argv[i], "-test-reused-tid") == 0)
      test_reused_tid = true;
    else if (strcmp(argv[i], "-test-thread-clone-process-exit") == 0)
      test_thread_clone_process_exit = true;
    else if (strcmp(argv[i], "-test-stalled-thread-start") == 0)
      test_stalled_thread_start = true;
    else if (strcmp(argv[i], "-test-thread-start-write") == 0) {
      test_thread_start_write = true;
      test_reused_tid = true;
    } else if (strcmp(argv[i], "-diagnostic_fd") == 0) {
      int fd;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%d", &fd) == 1);
      DR_ASSERT(fd >= 0);
      diagnostic_file = (file_t)fd;
    } else if (strcmp(argv[i], "-evidence-socket") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(
          decode_hex(argv[i], evidence_address, sizeof(evidence_address)));
      evidence_socket_seen = true;
    } else if (strcmp(argv[i], "-evidence-token") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(decode_hex(argv[i], evidence_token, sizeof(evidence_token)));
      evidence_token_seen = true;
    } else if (strcmp(argv[i], "-evidence-log-level") == 0) {
      int level;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%d", &level) == 1);
      DR_ASSERT(level >= 0 && level <= 5);
      runtime_callbacks_page.value.evidence_log_level = level;
    }
  }
  uint32_t runtime_abi_version = reverie_dbt_runtime_abi_version();
  if (test_runtime_abi_mismatch)
    // Both historical ABI-10 tables had the same size but incompatible final
    // slots. Reject version 10 even with the current runtime's correct size.
    runtime_abi_version = 10;
  if (runtime_abi_version != REVERIE_DBT_RUNTIME_ABI_VERSION ||
      reverie_dbt_runtime_callbacks_size() != sizeof(runtime_callbacks_t)) {
    dr_fprintf(
        diagnostic_file,
        "reverie-dbt: native/runtime ABI version or callback size mismatch\n");
    dr_exit_process(101);
    return;
  }
  DR_ASSERT(evidence_socket_seen == evidence_token_seen);
  DR_ASSERT(dr_page_size() == EVIDENCE_CONFIG_PAGE_SIZE);
  evidence_config_page.value.enabled =
      (unsigned char)(evidence_socket_seen && evidence_token_seen);
  memcpy(
      evidence_config_page.value.address,
      evidence_address,
      sizeof(evidence_address));
  memcpy(
      evidence_config_page.value.token, evidence_token, sizeof(evidence_token));
  DR_ASSERT(dr_memory_protect(
      &evidence_config_page, sizeof(evidence_config_page), DR_MEMPROT_READ));
  runtime_callbacks_page.value.emit_evidence =
      evidence_is_enabled() ? reverie_dbt_emit_evidence : reverie_dbt_emit;
  runtime_callbacks_page.value.controller_capture_control =
      controller_capture_control;
  if (!evidence_is_enabled())
    runtime_callbacks_page.value.evidence_log_level = 0;
  atomic_store_explicit(&runtime_background_state, 0, memory_order_release);
  atomic_store_explicit(
      &test_reused_tid_exercised, false, memory_order_relaxed);
  atomic_store_explicit(&test_reused_tid_waited, false, memory_order_relaxed);
  runtime_owner_pid = dr_get_process_id();
  initialize_task_state(external_global);
  initialize_evidence_transport();
  if (test_direct_evidence_entry) {
    static const char record[] =
        "1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: "
        "direct entry must be refused\n";
    DR_ASSERT(evidence_is_enabled());
    reverie_dbt_emit_evidence(record, sizeof(record) - 1);
    DR_ASSERT(false);
  }
  runtime_process_id = (int32_t)runtime_owner_pid;
  runtime_parent_process_id = (int32_t)dr_get_parent_id();
  ensure_task_membership(runtime_process_id);
  if (!claim_runtime_image())
    return;
  atomic_store_explicit(
      pending_thread_clones_for(runtime_process_id), 0, memory_order_release);
  atomic_store_explicit(
      &image_generation,
      reverie_dbt_runtime_image_init(),
      memory_order_release);

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-summary") == 0)
      report_summary = true;
    else if (
        strcmp(argv[i], "-diagnostic_fd") == 0 ||
        strcmp(argv[i], "-evidence-socket") == 0 ||
        strcmp(argv[i], "-evidence-token") == 0 ||
        strcmp(argv[i], "-evidence-log-level") == 0)
      ++i;
    else if (strcmp(argv[i], "-stats_path") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(strlen(argv[i]) < sizeof(stats_path));
      dr_snprintf(stats_path, sizeof(stats_path), "%s", argv[i]);
    } else if (strcmp(argv[i], "-unsupported-report-path") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(strlen(argv[i]) < sizeof(unsupported_report_path));
      dr_snprintf(
          unsupported_report_path,
          sizeof(unsupported_report_path),
          "%s",
          argv[i]);
    } else if (strcmp(argv[i], "-panic-on-unsupported-syscalls") == 0)
      runtime_callbacks_page.value.panic_on_unsupported_syscalls = 1;
    else if (strcmp(argv[i], "-test-direct-evidence-entry") == 0) {
      /* Handled before application initialization. */
    } else if (strcmp(argv[i], "-test-runtime-abi-mismatch") == 0) {
      /* Handled before application initialization. */
    } else if (strcmp(argv[i], "-test-private-memory") == 0) {
      ++i; /* Mode was checked before application initialization. */
    } else if (
        strcmp(argv[i], "-test-wait-for-background") == 0 ||
        strcmp(argv[i], "-test-delay-exec-helper-exit") == 0 ||
        strcmp(argv[i], "-test-kill-announced-child") == 0 ||
        strcmp(argv[i], "-test-thread-exit-evidence") == 0 ||
        strcmp(argv[i], "-test-reused-tid") == 0 ||
        strcmp(argv[i], "-test-thread-clone-process-exit") == 0 ||
        strcmp(argv[i], "-test-stalled-thread-start") == 0 ||
        strcmp(argv[i], "-test-thread-start-write") == 0 ||
        strcmp(argv[i], "-test-leave-process-clone-result-pending") == 0 ||
        strcmp(argv[i], "-test-backend-failure") == 0 ||
        strcmp(argv[i], "-test-backend-failure-sender-lookup-miss") == 0 ||
        strcmp(argv[i], "-test-compare-exchange") == 0) {
      /* Used only by native lifecycle regression tests. */
    } else if (strcmp(argv[i], "-launcher-pid") == 0) {
      unsigned long long launcher = 0;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%llu", &launcher) == 1);
      runtime_process_group = launch_root_below((process_id_t)launcher);
    } else if (strcmp(argv[i], "-contain-by-process-group") == 0)
      contain_by_process_group = true;
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review branch-count preemption
    // argument.
    else if (strcmp(argv[i], "-preemption-quantum") == 0) {
      unsigned long long quantum = 0;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%llu", &quantum) == 1);
      preemption_quantum = (uint64_t)quantum;
      preemption_enabled = quantum > 0;
    }
  }

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the injected-syscall stub
  // allocation. When preemption is enabled, allocate the tiny redirect stub
  // whose bytes are `syscall; ud2`. `maybe_preempt` redirects here with rax =
  // SYS_sched_yield to deliver a real yield at a safe point; the block starting
  // at the `ud2` carries a `preempt_return` clean call, so the `ud2` only
  // executes (and traps) if the return path is ever bypassed.
  if (preemption_enabled && getenv("HERMIT_DBT_PREEMPT_ANYPC") != NULL)
    preempt_gate_main_only = false;

  if (preemption_enabled) {
    preempt_stub = (byte*)dr_nonheap_alloc(
        dr_page_size(), DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
    DR_ASSERT(preempt_stub != NULL);
    preempt_stub[0] = 0x0f; // syscall
    preempt_stub[1] = 0x05;
    preempt_stub[2] = 0x0f; // ud2
    preempt_stub[3] = 0x0b;
  }
  signal_stub = (byte*)dr_nonheap_alloc(
      dr_page_size(), DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
  DR_ASSERT(signal_stub != NULL);
  signal_stub[0] = 0x0f;
  signal_stub[1] = 0x05;
  signal_stub[2] = 0x0f;
  signal_stub[3] = 0x0b;
  initialize_private_memory(preempt_stub, signal_stub, dr_page_size());
  runtime_callbacks_page.value.runtime_private_memory = runtime_private_memory;
  if (!run_private_memory_self_test())
    return;

  if (unsupported_report_path[0] != 0) {
    unsupported_report_file =
        dr_open_file(unsupported_report_path, DR_FILE_WRITE_ONLY);
    if (unsupported_report_file == INVALID_FILE)
      dr_fprintf(
          diagnostic_file,
          "reverie-dbt: failed to open private unsupported-syscall report\n");
  }
  runtime_callbacks_page.value.unsupported_report_fd =
      (int32_t)unsupported_report_file;
  DR_ASSERT(dr_memory_protect(
      &runtime_callbacks_page,
      sizeof(runtime_callbacks_page),
      DR_MEMPROT_READ));

  dr_set_client_name(
      "Reverie DynamoRIO backend prototype",
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
  if (!dr_raw_tls_calloc(
          &admission_state_tls_register, &admission_state_tls_offset, 1, 0))
    DR_ASSERT(false);
  drmgr_register_exit_event(event_exit);
  if (!drmgr_register_module_load_event(module_load) ||
      !drmgr_register_thread_init_event(thread_init) ||
      !drmgr_register_thread_exit_event(thread_exit) ||
      !drmgr_register_bb_app2app_event(rewrite_cpuid, NULL) ||
      !drmgr_register_bb_app2app_event(rewrite_rdtsc, NULL) ||
      !drmgr_register_bb_instrumentation_event(
          analyze_syscall_gateway, instrument_instruction, NULL) ||
      !drmgr_register_filter_syscall_event(filter_syscall) ||
      !drmgr_register_pre_syscall_event(pre_syscall_event) ||
      !drmgr_register_post_syscall_event(post_syscall_event) ||
      !drmgr_register_signal_event(event_signal) ||
      !dr_register_signal_admission_event(signal_admission_event))
    DR_ASSERT(false);
}
