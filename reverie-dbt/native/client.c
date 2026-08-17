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
#include <stddef.h>
#include <stdatomic.h>
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
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review branch-count preemption bookkeeping.
  // Branch count observed at this thread's most recent synthetic sched_yield
  // preemption. Appended at the end of the struct so the existing field layout
  // (mirrored by detcore-dbt `NativeThreadScratch` and the prototype
  // `PrototypeCounters` prefix view) is unchanged; the `memset` in `thread_init`
  // zero-initializes it for every runtime.
  uint64_t last_yield_branch;
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review safe-point preemption thread state.
  // Client-only safe-point preemption state, appended AFTER the fields the Rust
  // `NativeThreadScratch` mirrors. Rust writes only that shorter prefix, and the
  // client `dr_thread_alloc`s + `memset`s the full `prototype_counters_t`, so
  // these are zero-initialized and never touched by the Rust side.
  // 1 while an injected sched_yield is in flight (between the redirect to the
  // stub and `preempt_return`); prevents nesting a second preemption.
  uint64_t preempt_pending;
  // Saved interrupted machine context (integer + control + FP/SIMD) captured by
  // `maybe_preempt` and restored by `preempt_return` so the injected syscall is
  // transparent to the guest. Allocated per thread when preemption is enabled.
  dr_mcontext_t *preempt_mcontext;
  // Process identity whose protected-evidence thread count includes this
  // client-owned thread state. Fork-child duplicate exit callbacks retain the
  // parent's identity and therefore cannot decrement the child's count.
  process_id_t evidence_thread_process;
  // One-shot guard for the runtime thread-exit hook. Some exit syscalls do not
  // receive a DynamoRIO thread_exit callback; others can receive both paths.
  uint64_t runtime_thread_exit_called;
} prototype_counters_t;

#define VIRTUAL_ROOT_PID INT32_C(3)
#define VIRTUAL_INIT_PID INT32_C(1)
#define VIRTUAL_IDENTITY_FD 197
#define CLIENT_THREAD_START_FAILURE_EXIT_CODE 125
#define DBT_DIAGNOSTIC_FD 198
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
#define REVERIE_DBT_RUNTIME_ABI_VERSION 2u
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
  // Structured tracing records use a distinct authenticated transport. Raw
  // lifecycle and unsupported-syscall diagnostics remain on `emit`.
  reverie_emit_fn_t emit_evidence;
  // DbtEvidenceLogLevel discriminant: off/error/warn/info/debug/trace = 0..5.
  int32_t evidence_log_level;
} runtime_callbacks_t;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#90): Confirm diagnostic fd ownership across exec.
// Inherited from the launcher so guest stderr redirections cannot capture it.
static file_t diagnostic_file;
static char unsupported_report_path[4096];
static file_t unsupported_report_file = INVALID_FILE;
static void reverie_dbt_emit(const char *buf, size_t len) {
  dr_write_file(diagnostic_file, buf, len);
}
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-162): Review the native stdout emit path.
// Emits pre-formatted bytes to real stdout via DynamoRIO's own I/O. Like
// `reverie_dbt_emit`, this avoids re-entering the syscall interception path that
// an app-level `write(1, ...)` would trigger, and works even after the guest has
// closed its own stdout.
static void reverie_dbt_emit_stdout(const char *buf, size_t len) {
  dr_write_file(STDOUT, buf, len);
}
static void reverie_dbt_emit_evidence(const char *buf, size_t len);
static void runtime_idle(void);

// TODO-HUMAN-REVIEW(PR-131): Review the native thread lifecycle callback ABI.
extern int32_t reverie_dbt_runtime_thread_init(
    prototype_counters_t *counters, void *context, int32_t tid, int32_t pid,
    int32_t in_tree_ppid, uint64_t branches, int32_t defer_runtime,
    syscall_invoker_t invoke_syscall, register_reader_t read_registers,
    register_writer_t write_registers);
extern uint32_t reverie_dbt_runtime_abi_version(void);
extern size_t reverie_dbt_runtime_callbacks_size(void);
extern int32_t reverie_dbt_runtime_thread_created_v2(
    prototype_counters_t *counters, void *context, int32_t parent_tid,
    int32_t pid, uint64_t branches, int32_t child_tid,
    int32_t virtual_child_tid, uint64_t child_tid_addr, uint64_t flags,
    syscall_invoker_t invoke_syscall,
    register_reader_t read_registers, register_writer_t write_registers);

extern void reverie_dbt_runtime_thread_exit(prototype_counters_t *counters,
                                            void *context, int32_t tid,
                                            syscall_invoker_t invoke_syscall);
extern uint64_t reverie_dbt_runtime_image_init(void);
extern void reverie_dbt_runtime_exec_failed(prototype_counters_t *counters,
                                            int32_t pid);
extern void reverie_dbt_runtime_background_init_v2(void *argument);
extern int32_t reverie_dbt_runtime_ready(uint64_t image_generation);
extern void reverie_dbt_runtime_process_exit(void);
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-219): Review copied-child argument and errno policy ABI.
extern int32_t reverie_dbt_runtime_copied_syscall(int64_t sysnum,
                                                  const uint64_t *args);
// TODO-HUMAN-REVIEW(PR-154): Review the deferred lifecycle syscall callback ABI.
extern int32_t reverie_dbt_runtime_pre_syscall(
    void *context, prototype_counters_t *counters, int32_t tid, int32_t pid,
    uint64_t image_generation, int64_t sysnum, const uint64_t *args,
    uint64_t branches, int64_t *result, int64_t *deferred_sysnum,
    uint64_t *deferred_args, syscall_invoker_t invoke_syscall,
    register_reader_t read_registers, register_writer_t write_registers,
    memory_reader_t read_memory, memory_writer_t write_memory,
    reverie_emit_fn_t emit);
extern const char *reverie_dbt_runtime_name(void);
extern uint8_t reverie_dbt_runtime_kind_code(void);
extern void reverie_dbt_runtime_totals(uint64_t *branches, uint64_t *syscalls,
                                       uint64_t *rewritten,
                                       uint64_t *memory_hash);

static _Atomic uint64_t branch_count __attribute__((aligned(64)));
static _Atomic uint64_t stdin_read_count;
static _Atomic uint64_t pending_thread_starts;
static _Atomic int32_t runtime_background_state;
static _Atomic uint64_t virtual_time_ns = UINT64_C(1000000000);
static _Atomic uint64_t image_generation;
static int thread_state_index;
static int compat_gateway_index;
static ptr_uint_t cpuid_marker_note;
static ptr_uint_t rdtsc_marker_note;
static ptr_uint_t rdtscp_marker_note;
static bool report_summary;
static bool test_wait_for_background;
static bool test_kill_announced_child;
static bool test_thread_exit_evidence;
// Typed backend-statistics sink path. When the launcher passes
// `-stats_path <path>`, each real runtime image appends exactly one fixed-size
// binary record to this file at `event_exit`, using DynamoRIO's own
// append-mode file I/O (O_APPEND, so concurrent process images append their
// 144-byte records atomically without interleaving). The launcher decodes and
// commutatively aggregates every record in the process tree (see
// src/backend_stats.rs). An empty path means stats collection is off. Using a
// shared path instead of an inherited fd avoids the drrun->guest exec fd
// inheritance problem that the diagnostic fd works around.
static char stats_path[4096];
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review branch-count preemption configuration.
// Deterministic branch-count preemption. When `preemption_enabled` (set from the
// `-preemption-quantum N` client arg with N > 0), the client injects a synthetic
// sched_yield scheduler turn every `preemption_quantum` counted app branches so a
// running guest thread returns control to Detcore's scheduler between syscalls.
// Both default to the disabled state, so guests run unchanged unless the quantum
// is supplied.
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
static void complete_runtime_thread_exit(prototype_counters_t *counters,
                                         void *drcontext,
                                         bool explicit_exit);
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
#define EVIDENCE_CONFIG_PAGE_SIZE 4096

static const unsigned char evidence_channel_magic[8] = {'R', 'V', 'D', 'B',
                                                        'T', 'E', '2', 0};
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
_Static_assert(sizeof(runtime_callbacks_page_t) == EVIDENCE_CONFIG_PAGE_SIZE,
               "runtime callback page must occupy exactly one page");

// The guest and client share one address space, and this client loads at a
// stable preferred address. Keep every callback and policy field on a dedicated
// page, finish initialization in `dr_client_main`, and seal it before the first
// application instruction. Otherwise a syscall-free guest entry point could
// replace `emit_evidence` before the first syscall starts the background
// runtime, then forge records while the callback-depth gate is legitimately
// active.
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
  bool initialization_record_sent;
  uint32_t active_threads;
} evidence_sender_state_t;

static unsigned char *evidence_buffer;
static size_t evidence_buffer_length;
static void *evidence_lock;
static evidence_sender_state_t *evidence_senders;
static _Thread_local uint32_t evidence_callback_depth;

static bool evidence_is_enabled(void) {
  return evidence_config_page.value.enabled != 0;
}

static void evidence_callback_enter(void) { ++evidence_callback_depth; }

static void evidence_callback_leave(void) {
  DR_ASSERT(evidence_callback_depth != 0);
  --evidence_callback_depth;
}

static bool decode_hex(const char *encoded, unsigned char *out, size_t out_len) {
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

static void put_u32_le(unsigned char *out, uint32_t value) {
  out[0] = (unsigned char)(value & 0xff);
  out[1] = (unsigned char)((value >> 8) & 0xff);
  out[2] = (unsigned char)((value >> 16) & 0xff);
  out[3] = (unsigned char)((value >> 24) & 0xff);
}

static void put_u64_le(unsigned char *out, uint64_t value) {
  int byte;
  for (byte = 0; byte != 8; ++byte)
    out[byte] = (unsigned char)((value >> (byte * 8)) & 0xff);
}

static uint64_t evidence_hash_update(uint64_t hash,
                                     const unsigned char *bytes,
                                     size_t length) {
  while (length-- != 0)
    hash = (hash ^ *bytes++) * UINT64_C(0x00000100000001b3);
  return hash;
}

static uint64_t evidence_frame_hash(uint64_t seed, unsigned char kind,
                                    size_t payload_length, uint64_t sequence,
                                    const unsigned char *payload) {
  unsigned char encoded_length[4];
  unsigned char encoded_sequence[8];
  put_u32_le(encoded_length, (uint32_t)payload_length);
  put_u64_le(encoded_sequence, sequence);
  seed = evidence_hash_update(seed, &kind, 1);
  seed = evidence_hash_update(seed, encoded_length, sizeof(encoded_length));
  seed = evidence_hash_update(seed, encoded_sequence, sizeof(encoded_sequence));
  return evidence_hash_update(seed, payload, payload_length);
}

static bool evidence_write_all(int descriptor, const unsigned char *buffer,
                               size_t length) {
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

static bool evidence_send_frame(unsigned char kind, const unsigned char *payload,
                                size_t payload_length, uint64_t sequence) {
  struct sockaddr_un address;
  unsigned char header[EVIDENCE_CHANNEL_HEADER_LEN] = {0};
  socklen_t address_length;
  const struct timeval timeout = {.tv_sec = 0, .tv_usec = 250000};
  int attempt;

  if (payload_length > EVIDENCE_BUFFER_CAPACITY)
    return false;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, evidence_config_page.value.address,
         sizeof(evidence_config_page.value.address));
  address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                               sizeof(evidence_config_page.value.address));

  memcpy(header, evidence_channel_magic, sizeof(evidence_channel_magic));
  memcpy(header + 8, evidence_config_page.value.token,
         sizeof(evidence_config_page.value.token));
  header[40] = kind;
  put_u32_le(header + 48, (uint32_t)payload_length);
  put_u64_le(header + 56, sequence);
  put_u64_le(header + 64,
             evidence_frame_hash(UINT64_C(0xcbf29ce484222325), kind,
                                 payload_length, sequence, payload));
  put_u64_le(header + 72,
             evidence_frame_hash(UINT64_C(0x9e3779b97f4a7c15), kind,
                                 payload_length, sequence, payload));

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
    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
        connect(descriptor, (const struct sockaddr *)&address, address_length) !=
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

static bool evidence_process_start_time(process_id_t process,
                                        uint64_t *start_time) {
  char path[64];
  char stat_buffer[1024];
  char *cursor;
  char *end;
  int descriptor;
  int length;
  int field;
  uint64_t parsed = 0;
  length = dr_snprintf(path, sizeof(path), "/proc/%d/stat", (int)process);
  if (length <= 0 || (size_t)length >= sizeof(path))
    return false;
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0)
    return false;
  do {
    length = (int)read(descriptor, stat_buffer, sizeof(stat_buffer) - 1);
  } while (length < 0 && errno == EINTR);
  close(descriptor);
  if (length <= 0 || (size_t)length >= sizeof(stat_buffer))
    return false;
  stat_buffer[length] = 0;
  cursor = strrchr(stat_buffer, ')');
  if (cursor == NULL)
    return false;
  ++cursor;
  for (field = 3; field <= 22; ++field) {
    while (*cursor == ' ')
      ++cursor;
    if (*cursor == 0)
      return false;
    end = cursor;
    while (*end != 0 && *end != ' ')
      ++end;
    if (field == 22) {
      if (cursor == end)
        return false;
      while (cursor != end) {
        if (*cursor < '0' || *cursor > '9')
          return false;
        parsed = parsed * 10 + (uint64_t)(*cursor++ - '0');
      }
      *start_time = parsed;
      return true;
    }
    cursor = end;
  }
  return false;
}

static bool evidence_current_identity(process_id_t *process,
                                      uint64_t *start_time) {
  *process = (process_id_t)getpid();
  return evidence_process_start_time(*process, start_time);
}

static evidence_sender_state_t *evidence_sender_locked(void) {
  process_id_t process;
  uint64_t start_time;
  evidence_sender_state_t *empty = NULL;
  evidence_sender_state_t *reusable = NULL;
  size_t index;
  if (!evidence_current_identity(&process, &start_time))
    return NULL;
  for (index = 0; index != EVIDENCE_MAX_SENDERS; ++index) {
    evidence_sender_state_t *candidate = &evidence_senders[index];
    if (candidate->process == process && candidate->start_time == start_time)
      return candidate;
    if (candidate->process == 0 && empty == NULL)
      empty = candidate;
    if (candidate->finalized && reusable == NULL) {
      uint64_t observed_start_time;
      if (!evidence_process_start_time(candidate->process,
                                       &observed_start_time) ||
          observed_start_time != candidate->start_time)
        reusable = candidate;
    }
  }
  if (empty == NULL)
    empty = reusable;
  if (empty == NULL) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: evidence sender-state capacity exceeded\n");
    return NULL;
  }
  memset(empty, 0, sizeof(*empty));
  empty->process = process;
  empty->start_time = start_time;
  return empty;
}

static bool evidence_flush_locked(evidence_sender_state_t *sender,
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
    (void)evidence_send_frame(EVIDENCE_FRAME_ERROR, message,
                              sizeof(message) - 1, sender->sequence++);
    return false;
  }
  if (evidence_buffer_length != 0) {
    if (!evidence_send_frame(EVIDENCE_FRAME_DATA, evidence_buffer,
                             evidence_buffer_length, sender->sequence++))
      return false;
    evidence_buffer_length = 0;
  }
  if (terminal_kind != 0) {
    if (!evidence_send_frame(terminal_kind, NULL, 0, sender->sequence++))
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
  evidence_sender_state_t *sender;
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
  ok = !sender->transport_failed && evidence_flush_locked(sender, terminal_kind);
  if (!ok)
    sender->transport_failed = true;
  dr_mutex_unlock(evidence_lock);
  return ok;
}

static void require_evidence_flush(unsigned char terminal_kind) {
  if (!evidence_flush(terminal_kind)) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: protected evidence transport failed\n");
    exit_runtime_tree(101);
  }
}

static void reverie_dbt_emit_evidence(const char *buf, size_t len) {
  bool ok;
  evidence_sender_state_t *sender;
  if (!evidence_is_enabled()) {
    reverie_dbt_emit(buf, len);
    return;
  }
  if (test_kill_announced_child && runtime_process_group != 0 &&
      dr_get_process_id() != runtime_process_group)
    return;
  if (evidence_callback_depth == 0) {
    dr_fprintf(diagnostic_file,
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
    dr_fprintf(diagnostic_file,
               "reverie-dbt: protected evidence record send failed\n");
    exit_runtime_tree(101);
  }
}

static bool evidence_announce_child(process_id_t child) {
  unsigned char payload[12];
  evidence_sender_state_t *sender;
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
         evidence_send_frame(EVIDENCE_FRAME_CHILD, payload, sizeof(payload),
                             sender->sequence++);
  if (!ok && sender != NULL)
    sender->transport_failed = true;
  dr_mutex_unlock(evidence_lock);
  return ok;
}

static void require_evidence_child(process_id_t child) {
  if (!evidence_announce_child(child)) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: protected child evidence announcement failed\n");
    exit_runtime_tree(101);
  }
}

static void evidence_thread_enter(prototype_counters_t *counters) {
  evidence_sender_state_t *sender;
  if (!evidence_is_enabled())
    return;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender == NULL || sender->active_threads == UINT32_MAX) {
    dr_mutex_unlock(evidence_lock);
    dr_fprintf(diagnostic_file,
               "reverie-dbt: protected evidence thread count failed\n");
    exit_runtime_tree(101);
    return;
  }
  ++sender->active_threads;
  counters->evidence_thread_process = dr_get_process_id();
  dr_mutex_unlock(evidence_lock);
}

static void evidence_count_fork_child_thread(prototype_counters_t *counters) {
  evidence_sender_state_t *sender;
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
    dr_fprintf(diagnostic_file,
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
  evidence_sender_state_t *sender;
  bool emit = false;
  if (!evidence_is_enabled() ||
      runtime_callbacks_page.value.evidence_log_level < 3)
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
      dr_fprintf(diagnostic_file,
                 "reverie-dbt: protected evidence image initialization failed\n");
      exit_runtime_tree(101);
    }
    return;
  }
  reverie_dbt_emit_evidence(record, sizeof(record) - 1);
}

static void evidence_thread_leave(prototype_counters_t *counters) {
  evidence_sender_state_t *sender;
  bool last_thread;
  process_id_t process = dr_get_process_id();
  if (!evidence_is_enabled() || counters->evidence_thread_process != process)
    return;
  dr_mutex_lock(evidence_lock);
  sender = evidence_sender_locked();
  if (sender == NULL || sender->active_threads == 0) {
    dr_mutex_unlock(evidence_lock);
    dr_fprintf(diagnostic_file,
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
  evidence_buffer =
      (unsigned char *)dr_global_alloc(EVIDENCE_BUFFER_CAPACITY);
  evidence_senders = (evidence_sender_state_t *)dr_global_alloc(
      sizeof(evidence_sender_state_t) * EVIDENCE_MAX_SENDERS);
  DR_ASSERT(evidence_lock != NULL && evidence_buffer != NULL &&
            evidence_senders != NULL);
  memset(evidence_senders, 0,
         sizeof(evidence_sender_state_t) * EVIDENCE_MAX_SENDERS);
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

  descriptor = (int)syscall(SYS_memfd_create, "reverie-dbt-pids", 0);
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

  evidence_callback_enter();
  int32_t init_result = reverie_dbt_runtime_thread_init(
      counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(), in_tree_parent_pid(),
      atomic_load_explicit(&branch_count, memory_order_relaxed), 0,
      invoke_syscall, read_registers, write_registers);
  evidence_callback_leave();
  // TODO-HUMAN-REVIEW(PR-134): Confirm retryable native child startup.
  if (init_result > 0) {
    counters->pending_thread_start = 2;
    return;
  }
  if (init_result < 0) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: runtime thread initialization failed\n");
    exit_runtime_tree(101);
    return;
  }
  counters->pending_thread_start = 0;
  atomic_fetch_sub_explicit(&pending_thread_starts, 1, memory_order_release);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the branch-count preemption hook.
// Defined below, after the runtime-readiness predicates it consults.
static void maybe_preempt(app_pc pc);
static void preempt_return(void);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the injected-syscall stub.
// A tiny generated code region used as the redirect target that delivers a real
// `sched_yield` to the guest at a safe point. Its bytes are `syscall; ud2`: the
// `syscall` (with rax preloaded to SYS_sched_yield by the redirect) flows
// through the ordinary `pre_syscall` handler and Detcore's deterministic
// sched_yield path; the block starting at the trailing `ud2` carries a
// `preempt_return` clean call that redirects back to the captured guest context,
// so the `ud2` never actually executes (it is only a trap if the return path is
// somehow bypassed). Allocated once when preemption is enabled.
#define PREEMPT_STUB_SYSCALL_LEN 2 /* bytes of `syscall` (0F 05) */
#define PREEMPT_STUB_LEN 4         /* syscall (2) + ud2 (2) */
static byte *preempt_stub;

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
      atomic_load_explicit(&guest_stack_initially_scrubbed,
                           memory_order_acquire) == 0) {
    dr_insert_clean_call_ex(drcontext, bb, instruction,
                            (void *)scrub_guest_stack_before_first_instruction,
                            DR_CLEANCALL_READS_APP_CONTEXT, 0);
  }
  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the branch-count preemption hook.
  // Mirrors the `start_pending_thread` hook above: at the first application
  // instruction of a block, invoke `maybe_preempt`, which injects a synthetic
  // sched_yield scheduler turn once the per-thread branch quantum elapses. Gated
  // at instrumentation time on `preemption_enabled` (a `dr_client_main` constant)
  // so disabled runs incur zero added instrumentation.
  if (preemption_enabled && preempt_stub != NULL && instr_is_app(instruction) &&
      instruction == instrlist_first_app(bb)) {
    app_pc block_pc = instr_get_app_pc(instruction);
    // Blocks inside the injected-syscall stub are handled specially and never
    // carry the ordinary preemption hook. The block starting at the trailing
    // `ud2` gets the `preempt_return` clean call that resumes the guest; the
    // stub's `syscall` block needs no preemption instrumentation (it flows
    // through `pre_syscall` like any syscall).
    if (block_pc >= preempt_stub && block_pc < preempt_stub + PREEMPT_STUB_LEN) {
      if (block_pc == preempt_stub + PREEMPT_STUB_SYSCALL_LEN) {
        dr_insert_clean_call(drcontext, bb, instruction, (void *)preempt_return,
                             /*save_fpstate=*/false, 0);
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
    dr_insert_clean_call(drcontext, bb, instruction, (void *)maybe_preempt,
                         /*save_fpstate=*/true, 1,
                         OPND_CREATE_INTPTR(block_pc));
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

static bool is_exec_syscall(int sysnum);

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
      (fd == VIRTUAL_IDENTITY_FD || fd == DBT_DIAGNOSTIC_FD)) {
    *result = 0;
    return true;
  }
  if (sysnum == SYS_fcntl &&
      (fd == VIRTUAL_IDENTITY_FD || fd == DBT_DIAGNOSTIC_FD) &&
      args[1] == F_SETFD) {
    *result = 0;
    return true;
  }
  if ((sysnum == SYS_dup2 || sysnum == SYS_dup3) &&
      ((int)args[1] == VIRTUAL_IDENTITY_FD ||
       (int)args[1] == DBT_DIAGNOSTIC_FD)) {
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
    if ((flags & CLONE_THREAD) == 0) {
      require_evidence_child((process_id_t)result);
      if (test_kill_announced_child && kill((pid_t)result, SIGKILL) != 0) {
        dr_fprintf(diagnostic_file,
                   "reverie-dbt: failed to kill announced test child\n");
        exit_runtime_tree(101);
      }
    }
    if ((flags & CLONE_THREAD) != 0 &&
        lookup_virtual_identity((int32_t)result, &mapped))
      virtual_child = mapped;
    else
      remember_virtual_identity((int32_t)result, virtual_child);
  } else if (result == 0) {
    int32_t host_tid = (int32_t)dr_get_thread_id(dr_get_current_drcontext());
    if ((flags & CLONE_THREAD) == 0)
      evidence_count_fork_child_thread(counters);
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

typedef struct {
  struct msghdr msg_hdr;
  unsigned int msg_len;
} evidence_mmsghdr_t;

static bool sockaddr_is_evidence(const void *address, size_t length) {
  struct sockaddr_un candidate;
  const size_t expected =
      offsetof(struct sockaddr_un, sun_path) + 1 + EVIDENCE_ADDRESS_LEN;
  if (!evidence_is_enabled() || address == NULL || length != expected ||
      !read_app(address, &candidate, expected))
    return false;
  return candidate.sun_family == AF_UNIX && candidate.sun_path[0] == 0 &&
         memcmp(candidate.sun_path + 1,
                evidence_config_page.value.address,
                EVIDENCE_ADDRESS_LEN) == 0;
}

static bool message_targets_evidence(const void *address) {
  struct msghdr message;
  return address != NULL && read_app(address, &message, sizeof(message)) &&
         sockaddr_is_evidence(message.msg_name, message.msg_namelen);
}

static bool proc_link_is_memory(const char *link, size_t length) {
  static const char prefix[] = "/proc/";
  static const char suffix[] = "/mem";
  return length >= sizeof(prefix) - 1 + sizeof(suffix) - 1 &&
         memcmp(link, prefix, sizeof(prefix) - 1) == 0 &&
         memcmp(link + length - (sizeof(suffix) - 1), suffix,
                sizeof(suffix) - 1) == 0;
}

static bool fd_is_proc_mem(uintptr_t context, int fd) {
  char descriptor_path[64];
  char target[4096];
  uint64_t arguments[6];
  int path_length = dr_snprintf(descriptor_path, sizeof(descriptor_path),
                                "/proc/self/fd/%d", fd);
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

static bool path_is_proc_mem(uintptr_t context, int directory_fd,
                             const void *path) {
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

static bool reject_opened_proc_mem(uintptr_t context, int sysnum,
                                   int64_t descriptor) {
  if (!evidence_is_enabled() || descriptor < 0 ||
      !syscall_returns_open_fd(sysnum) ||
      !fd_is_proc_mem(context, (int)descriptor))
    return false;
  const uint64_t close_arguments[6] = {(uint64_t)descriptor};
  (void)invoke_raw_syscall(context, SYS_close, close_arguments);
  return true;
}

static bool syscall_uses_proc_mem_fd(uintptr_t context, int sysnum,
                                     const uint64_t *args) {
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
    return args[4] != (uint64_t)-1 &&
           fd_is_proc_mem(context, (int)args[4]);
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

static bool range_overlaps_page(uint64_t address, uint64_t length,
                                const void *page, size_t page_length) {
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

static bool range_overlaps_protected_evidence_state(uint64_t address,
                                                    uint64_t length) {
  return range_overlaps_page(address, length, &evidence_config_page,
                             sizeof(evidence_config_page)) ||
         range_overlaps_page(address, length, &runtime_callbacks_page,
                             sizeof(runtime_callbacks_page));
}

static bool syscall_targets_protected_evidence_state(int sysnum,
                                                     const uint64_t *args) {
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
    // SHM_REMAP can replace an existing mapping and supplies no segment length
    // in the syscall arguments, so it cannot be range-validated safely here.
    return (args[2] & SHM_REMAP) != 0;
#endif
#if defined(SYS_io_uring_setup) || defined(SYS_io_uring_enter) ||             \
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

// Reject app-originated traffic to the evidence endpoint even if the guest has
// recovered the client arguments or token from shared address-space state. The
// native sender uses client-private libc syscalls while the guest is stopped,
// so it never traverses this application-syscall policy.
static bool protect_evidence_socket_syscall(uintptr_t context, int sysnum,
                                            const uint64_t *args,
                                            int64_t *result) {
  if (!evidence_is_enabled())
    return false;
  if (syscall_targets_protected_evidence_state(sysnum, args) ||
      syscall_uses_proc_mem_fd(context, sysnum, args))
    goto forbidden;
  switch (sysnum) {
  case SYS_connect:
    if (!sockaddr_is_evidence((const void *)(uintptr_t)args[1], args[2]))
      return false;
    break;
  case SYS_sendto:
    if (!sockaddr_is_evidence((const void *)(uintptr_t)args[4], args[5]))
      return false;
    break;
  case SYS_sendmsg:
    if (!message_targets_evidence((const void *)(uintptr_t)args[1]))
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
      if (!read_app((const void *)address, &message, sizeof(message)))
        return false;
      if (sockaddr_is_evidence(message.msg_hdr.msg_name,
                               message.msg_hdr.msg_namelen))
        goto forbidden;
    }
    return false;
  }
#endif
  case SYS_open:
  case SYS_creat:
    if (!path_is_proc_mem(context, AT_FDCWD,
                          (const void *)(uintptr_t)args[0]))
      return false;
    break;
  case SYS_openat:
#ifdef SYS_openat2
  case SYS_openat2:
#endif
    if (!path_is_proc_mem(context, (int)args[0],
                          (const void *)(uintptr_t)args[1]))
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
  *result = -EPERM;
  return true;
}

static int64_t invoke_syscall(uintptr_t context, int64_t sysnum,
                              const uint64_t *args) {
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      (void *)context, thread_state_index);
  uint64_t translated[6];
  int64_t result;
  bool is_clone;
  DR_ASSERT(counters != NULL);
  if (protect_evidence_socket_syscall(context, (int)sysnum, args, &result))
    return result;
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
  if (is_exec_syscall((int)sysnum))
    require_evidence_flush(EVIDENCE_FRAME_EXEC);
  if (sysnum == SYS_exit || sysnum == SYS_exit_group)
    complete_runtime_thread_exit(counters, (void *)context,
                                 sysnum == SYS_exit);
  result = invoke_raw_syscall(context, sysnum, translated);
  if (is_exec_syscall((int)sysnum) && result < 0)
    require_evidence_flush(EVIDENCE_FRAME_EXEC_CANCEL);
  if (reject_opened_proc_mem(context, (int)sysnum, result))
    return -EPERM;
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
// TODO-HUMAN-REVIEW(PR-167): Review the DBT guest register-write callback.
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

// TODO-HUMAN-REVIEW(PR-234): Review the fault-safe DBT memory-write callback ABI.
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
               "reverie-dbt: failed to unprotect vdso to neutralize %s\n", name);
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
  int32_t completed_virtual_child = 0;
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  DR_ASSERT(counters != NULL);

  if (reject_opened_proc_mem((uintptr_t)drcontext, sysnum,
                             host_syscall_result)) {
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

  if (counters->pending_virtual_child != 0 && is_clone_syscall(sysnum)) {
    int32_t virtual_child = complete_clone_identity(counters, syscall_result);
    completed_virtual_child = virtual_child;
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

  if (is_exec_syscall(sysnum) && evidence_is_enabled())
    require_evidence_flush(EVIDENCE_FRAME_EXEC_CANCEL);

  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process()))
    return;

  if (counters->pending_thread_clone != 0) {
    if (host_syscall_result >= 0) {
      evidence_callback_enter();
      int32_t registration = reverie_dbt_runtime_thread_created_v2(
          counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
          (int32_t)dr_get_process_id(),
          atomic_load_explicit(&branch_count, memory_order_relaxed),
          (int32_t)host_syscall_result, completed_virtual_child,
          counters->thread_clone_ctid, counters->thread_clone_flags,
          invoke_syscall, read_registers, write_registers);
      evidence_callback_leave();
      if (registration < 0) {
        dr_fprintf(diagnostic_file,
                   "reverie-dbt: child thread registration failed\n");
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

static void finalize_runtime_process(void) {
  evidence_sender_state_t *sender = NULL;
  if (evidence_is_enabled()) {
    dr_mutex_lock(evidence_lock);
    sender = evidence_sender_locked();
    if (sender == NULL) {
      dr_mutex_unlock(evidence_lock);
      dr_fprintf(diagnostic_file,
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
      dr_fprintf(diagnostic_file,
                 "reverie-dbt: runtime background did not quiesce after shutdown\n");
      exit_runtime_tree(101);
      return;
    }
  }
  require_evidence_flush(EVIDENCE_FRAME_FINAL);
}

static bool evidence_current_process_finalized(void) {
  evidence_sender_state_t *sender;
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
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review deterministic branch-count preemption.
// Runs at the first application instruction of every block (see
// `instrument_instruction`) when preemption is enabled. Once this thread has
// executed `preemption_quantum` counted app branches since its last preemption,
// it delivers a real `sched_yield` to the guest so a thread that busy-waits or
// tight-loops without reaching a syscall of its own still returns control to the
// deterministic scheduler and lets a co-runnable sibling proceed.
//
// SAFE-POINT delivery (this is the crux). The Detcore scheduler turn is an
// in-process RPC that allocates and can trigger the guest's own lazy PLT
// resolver, so it must NOT run synchronously from this clean call at an
// arbitrary instruction boundary: doing so re-enters non-reentrant guest
// libc/ld (observed as "undefined symbol getcwd" / GLIBC_PRIVATE, or a memchr
// panic from clobbered state). Instead, the ONLY place the turn runs is the
// existing `pre_syscall` handler, which is a proven-safe boundary for every real
// guest syscall (it is why the passing corpus passes). So this clean call does
// NO scheduler work: it captures the interrupted thread's full machine context
// and `dr_redirect_execution`s to a tiny generated stub whose sole instruction
// is a real `sched_yield` syscall. That syscall fires `pre_syscall`, Detcore's
// ordinary, already-deterministic `sched_yield` handler ends this thread's
// timeslice and reselects, and a clean call on the block after the stub syscall
// (`preempt_return`) restores the captured context and resumes the guest exactly
// where it was preempted. The injected syscall is thus fully transparent: rax,
// rip and the FP/SIMD state are all restored from the captured mcontext.
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
    module_data_t *main_module = dr_get_main_module();
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
  void *drcontext = dr_get_current_drcontext();
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  if (counters == NULL || counters->preempt_mcontext == NULL)
    return;
  // An injected sched_yield is already in flight for this thread (we are between
  // the redirect to the stub and `preempt_return`); never nest a preemption.
  if (counters->preempt_pending != 0)
    return;
  // Only preempt a thread that actually drives the Reverie tool this turn.
  // Mirror the guards used around the syscall dispatch: the runtime image must be
  // ready, and a copied child only runs the tool when it is an external-global
  // (RPC-connected) non-vfork process. A copied child under a prototype runtime,
  // or a vfork stand-in, runs no scheduler turn, so skip it.
  if (!reverie_dbt_runtime_ready(
          atomic_load_explicit(&image_generation, memory_order_acquire)))
    return;
  if (has_copied_runtime() &&
      (!runtime_uses_external_global() || is_copied_vfork_process()))
    return;
  uint64_t branches = atomic_load_explicit(&branch_count, memory_order_relaxed);
  if (branches - counters->last_yield_branch < preemption_quantum)
    return;
  // Defer until the quantum elapses AND the interrupted PC is in the guest's own
  // code. Do NOT advance last_yield_branch when deferring, so delivery lands at
  // the first main-executable block after the quantum -- a deterministic
  // function of the deterministic instruction stream.
  if (preempt_gate_main_only && !pc_in_main_executable(pc))
    return;
  counters->last_yield_branch = branches;
  // Capture the full interrupted context (integer + control + FP/SIMD) so
  // `preempt_return` can resume the guest transparently after the yield. Force
  // the resume PC to `pc` (the block's application PC); the mcontext `pc` field
  // is not a reliable output of `dr_get_mcontext` in a clean call.
  dr_mcontext_t *saved = counters->preempt_mcontext;
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
// TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the safe-point preemption return path.
// Clean call inserted on the block immediately after the stub's `sched_yield`
// (see `instrument_instruction`). The injected syscall has by now flowed through
// `pre_syscall` and Detcore has performed the deterministic yield/reselect. We
// resume the guest at the captured preemption point, restoring its rax, rip and
// FP/SIMD state so the injected syscall is invisible to the guest.
static void preempt_return(void) {
  void *drcontext = dr_get_current_drcontext();
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  if (counters == NULL || counters->preempt_mcontext == NULL ||
      counters->preempt_pending == 0)
    return; // unreachable in normal flow; the stub's ud2 traps if we fall through
  counters->preempt_pending = 0;
  dr_redirect_execution(counters->preempt_mcontext);
  // dr_redirect_execution does not return on success.
}

// The x86-64 SysV red zone: the 128 bytes below `rsp` that a leaf function may
// use without adjusting the stack pointer. Everything below it is dead by the
// ABI -- the kernel and signal delivery may clobber it at any moment -- so it
// is the only safe floor for the scrub below.
#define GUEST_STACK_RED_ZONE_BYTES 128

static const char *parse_hex_prefix(const char *text, uintptr_t *value) {
  uintptr_t parsed = 0;
  const char *cursor = text;
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
static bool find_guest_stack_vma(uintptr_t *start, uintptr_t *end) {
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
      const char *cursor = parse_hex_prefix(line, &low);
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
  return dr_memory_is_dr_internal((const byte *)word);
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
static void scrub_guest_stack_residue(void *drcontext) {
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
      atomic_exchange_explicit(&guest_stack_initially_scrubbed, 1,
                               memory_order_acq_rel) == 0;
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
    unsigned char *bytes = (unsigned char *)cursor;
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

// See `instrument_instruction`. Runs once, before the guest's first
// application instruction.
static void scrub_guest_stack_before_first_instruction(void) {
  scrub_guest_stack_residue(dr_get_current_drcontext());
}

static bool pre_syscall(void *drcontext, int sysnum) {
  // Retained as a FALLBACK, not as the initial-scrub site. Normally the latch
  // is already set by the first-instruction hook above and this returns
  // immediately; it still runs the ownership-based scrub each time a clone
  // re-arms it. If some guest ever reached a syscall without executing an
  // application instruction, this would take the initial path exactly as
  // before, so the change degrades to the old behaviour rather than to no
  // scrub at all.
  scrub_guest_stack_residue(drcontext);
  if (((uint32_t)sysnum & X32_SYSCALL_BIT) != 0) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: x32-marked syscalls are unsupported\n");
    exit_runtime_tree(102);
    return false;
  }
  bool decoded_compat_gateway =
      drmgr_get_tls_field(drcontext, compat_gateway_index) != NULL;
  DR_ASSERT(drmgr_set_tls_field(drcontext, compat_gateway_index, NULL));
  if (decoded_compat_gateway) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: compat int 0x80 syscalls are unsupported\n");
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
  if (test_wait_for_background && !has_copied_runtime()) {
    while (atomic_load_explicit(&runtime_background_state,
                                memory_order_acquire) != 3)
      dr_sleep(1);
  }

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

  if (protect_evidence_socket_syscall((uintptr_t)drcontext, sysnum, args,
                                      &result)) {
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-255): Review copied-process Detcore state rebasing.
  if (has_copied_runtime() && runtime_uses_external_global() &&
      !is_copied_vfork_process() &&
      copied_process_runtime_pid != dr_get_process_id()) {
    evidence_callback_enter();
    int32_t initialized = reverie_dbt_runtime_thread_init(
        counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
        (int32_t)dr_get_process_id(), in_tree_parent_pid(),
        atomic_load_explicit(&branch_count, memory_order_relaxed), 0,
        invoke_syscall, read_registers, write_registers);
    evidence_callback_leave();
    if (initialized != 0) {
      dr_fprintf(diagnostic_file,
                 "reverie-dbt: copied process state initialization failed\n");
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
    evidence_callback_enter();
    int32_t copied_action =
        reverie_dbt_runtime_copied_syscall((int64_t)sysnum, args);
    evidence_callback_leave();
    // Negative actions are deterministic errno values synthesized by the
    // copied-child policy. They avoid executing a host-dependent syscall while
    // preserving the error that the instrumented root observes.
    if (copied_action < 0) {
      dr_syscall_set_result(drcontext, (reg_t)copied_action);
      return false;
    }
    if (copied_action == 1) {
      dr_fprintf(diagnostic_file,
                 "detcore-dbt: unsupported syscall %d in copied child\n", sysnum);
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
    /* A copied child runs no Rust Tool (reverie_dbt_runtime_copied_syscall
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
    if (sysnum == SYS_exit || sysnum == SYS_exit_group)
      complete_runtime_thread_exit(counters, drcontext, sysnum == SYS_exit);
    bool execute =
        prepare_original_identity_syscall(drcontext, counters, sysnum, args);
    if (execute && is_exec_syscall(sysnum))
      require_evidence_flush(EVIDENCE_FRAME_EXEC);
    return execute;
  }
  while (!reverie_dbt_runtime_ready(
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
  evidence_callback_enter();
  int32_t action = reverie_dbt_runtime_pre_syscall(
      drcontext, counters, (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(),
      atomic_load_explicit(&image_generation, memory_order_acquire),
      (int64_t)sysnum, args,
      atomic_load_explicit(&branch_count, memory_order_relaxed), &result,
      &deferred_sysnum, deferred_args, invoke_syscall, read_registers,
      write_registers, read_memory, write_memory, reverie_dbt_emit);
  evidence_callback_leave();
  DR_ASSERT(evidence_callback_depth == 0);
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
    if (protect_evidence_socket_syscall((uintptr_t)drcontext, sysnum, args,
                                        &result)) {
      dr_syscall_set_result(drcontext, (reg_t)result);
      return false;
    }
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
    if (sysnum == SYS_exit || sysnum == SYS_exit_group)
      complete_runtime_thread_exit(counters, drcontext, sysnum == SYS_exit);
    bool execute =
        prepare_original_identity_syscall(drcontext, counters, sysnum, args);
    if (execute && is_exec_syscall(sysnum))
      require_evidence_flush(EVIDENCE_FRAME_EXEC);
    return execute;
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
  if (sysnum == SYS_exit || sysnum == SYS_exit_group)
    complete_runtime_thread_exit(counters, drcontext, sysnum == SYS_exit);
  bool execute =
      prepare_original_identity_syscall(drcontext, counters, sysnum, args);
  if (execute && is_exec_syscall(sysnum))
    require_evidence_flush(EVIDENCE_FRAME_EXEC);
  return execute;
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

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review safe-point preemption per-thread state.
  // When preemption is enabled, give this thread a persistent mcontext buffer for
  // `maybe_preempt` to capture into and `preempt_return` to resume from. Freed in
  // `thread_exit`.
  if (preemption_enabled) {
    counters->preempt_mcontext =
        (dr_mcontext_t *)dr_thread_alloc(drcontext, sizeof(dr_mcontext_t));
    DR_ASSERT(counters->preempt_mcontext != NULL);
  }

  // Publish stable virtual identities before entering Rust. Detcore consumes
  // these fields while constructing its thread state; host tid/pid remain
  // separate callback arguments for native targeting and pending-map lookup.
  counters->virtual_pid =
      pending_child != 0 && !is_thread ? pending_child : virtual_process_id;
  counters->virtual_ppid = pending_child != 0 && !is_thread
                               ? virtual_process_id
                               : virtual_parent_process_id;
  counters->virtual_tid =
      pending_child != 0 ? pending_child : ensure_virtual_identity(host_tid);
  counters->pending_virtual_child = 0;
  counters->pending_clone_flags = pending_child != 0 ? clone_flags : 0;

  int32_t pending_thread_start =
      !has_copied_runtime() && dr_get_thread_id(drcontext) != dr_get_process_id() &&
      reverie_dbt_runtime_ready(
          atomic_load_explicit(&image_generation, memory_order_acquire));
  evidence_thread_enter(counters);
  evidence_callback_enter();
  evidence_emit_image_initialization();
  int32_t init_result = reverie_dbt_runtime_thread_init(
      counters, drcontext, (int32_t)dr_get_thread_id(drcontext),
      (int32_t)dr_get_process_id(), in_tree_parent_pid(),
      atomic_load_explicit(&branch_count, memory_order_relaxed), 1, invoke_syscall,
      read_registers, write_registers);
  evidence_callback_leave();
  DR_ASSERT(evidence_callback_depth == 0);
  if (init_result < 0) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: runtime thread initialization failed\n");
    exit_runtime_tree(101);
    return;
  }
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

static void complete_runtime_thread_exit(prototype_counters_t *counters,
                                         void *drcontext,
                                         bool explicit_exit) {
  bool owns_runtime;
  if (counters->runtime_thread_exit_called != 0)
    return;
  counters->runtime_thread_exit_called = 1;
  owns_runtime = !has_copied_runtime() ||
                 (runtime_uses_external_global() &&
                  !is_copied_vfork_process());
  if (owns_runtime) {
    evidence_callback_enter();
    reverie_dbt_runtime_thread_exit(counters, drcontext,
                                    dr_get_thread_id(drcontext),
                                    invoke_syscall);
    evidence_callback_leave();
    if (test_thread_exit_evidence && explicit_exit &&
        evidence_is_enabled() &&
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

static void thread_exit(void *drcontext) {
  prototype_counters_t *counters = (prototype_counters_t *)drmgr_get_tls_field(
      drcontext, thread_state_index);
  if (counters != NULL) {
    bool owns_runtime =
        !has_copied_runtime() ||
        (runtime_uses_external_global() && !is_copied_vfork_process());
    complete_runtime_thread_exit(counters, drcontext, false);
    evidence_thread_leave(counters);
    if (owns_runtime) {
      if (counters->preempt_mcontext != NULL)
        dr_thread_free(drcontext, counters->preempt_mcontext,
                       sizeof(dr_mcontext_t));
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

static void stats_put_u64_le(unsigned char *out, uint64_t value) {
  for (int byte = 0; byte < 8; ++byte)
    out[byte] = (unsigned char)((value >> (8 * byte)) & 0xff);
}

// Emits one fixed-size stats record for this runtime image to `stats_path`.
// Called only for a real runtime owner (never a copied/vfork runtime), so the
// totals read here belong to exactly this process image. The file is opened
// per-image in append mode and the whole record is written by a single
// dr_write_file, so concurrent images append their 144-byte records atomically
// without interleaving.
static void emit_stats_record(void) {
  uint64_t branches = 0;
  uint64_t syscalls = 0;
  uint64_t rewritten = 0;
  uint64_t memory_hash = 0;
  reverie_dbt_runtime_totals(&branches, &syscalls, &rewritten, &memory_hash);
  uint64_t stdin_reads =
      atomic_load_explicit(&stdin_read_count, memory_order_relaxed);
  uint64_t generation =
      atomic_load_explicit(&image_generation, memory_order_acquire);

  dr_stats_t dr_stats;
  dr_stats.size = sizeof(dr_stats);
  bool dr_stats_present = dr_get_stats(&dr_stats);

  unsigned char record[STATS_WIRE_RECORD_LEN];
  memset(record, 0, sizeof(record));
  memcpy(record, "RVDBTSTA", 8);
  record[8] = (unsigned char)(STATS_WIRE_VERSION & 0xff);
  record[9] = (unsigned char)((STATS_WIRE_VERSION >> 8) & 0xff);
  record[10] = (unsigned char)(STATS_WIRE_RECORD_LEN & 0xff);
  record[11] = (unsigned char)((STATS_WIRE_RECORD_LEN >> 8) & 0xff);
  uint32_t flags = dr_stats_present ? STATS_WIRE_FLAG_DR_STATS_PRESENT : 0u;
  record[12] = (unsigned char)(flags & 0xff);
  record[13] = (unsigned char)((flags >> 8) & 0xff);
  record[14] = (unsigned char)((flags >> 16) & 0xff);
  record[15] = (unsigned char)((flags >> 24) & 0xff);
  record[16] = reverie_dbt_runtime_kind_code();
  // record[17..24] stay zero (reserved alignment padding).

  size_t offset = 24;
  stats_put_u64_le(record + offset, generation);
  offset += 8;
  stats_put_u64_le(record + offset, (uint64_t)(uint32_t)virtual_process_id);
  offset += 8;
  stats_put_u64_le(record + offset,
                   (uint64_t)(uint32_t)virtual_parent_process_id);
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
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.basic_block_count : 0);
  offset += 8;
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.num_threads_created : 0);
  offset += 8;
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.synchs_not_at_safe_spot : 0);
  offset += 8;
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.num_native_signals : 0);
  offset += 8;
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.num_cache_exits : 0);
  offset += 8;
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.peak_num_threads : 0);
  offset += 8;
  stats_put_u64_le(record + offset,
                   dr_stats_present ? dr_stats.peak_vmm_blocks_reach_cache : 0);
  offset += 8;
  DR_ASSERT(offset == STATS_WIRE_RECORD_LEN);

  file_t stats_file = dr_open_file(stats_path, DR_FILE_WRITE_APPEND);
  if (stats_file == INVALID_FILE) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: failed to open stats sink for append\n");
    return;
  }
  dr_write_file(stats_file, record, sizeof(record));
  dr_close_file(stats_file);
}

static void event_exit(void) {
  finalize_runtime_process();
  uint64_t branches;
  uint64_t syscalls;
  uint64_t rewritten;
  uint64_t stdin_reads;
  uint64_t memory_hash;

  if (report_summary && !has_copied_runtime()) {
    reverie_dbt_runtime_totals(&branches, &syscalls, &rewritten, &memory_hash);
    stdin_reads = atomic_load_explicit(&stdin_read_count, memory_order_relaxed);
    dr_fprintf(diagnostic_file,
               "reverie-dbt: tool=%s branches=%llu syscalls=%llu "
               "rewritten=%llu stdin_reads=%llu memory_hash=%016llx\n",
               reverie_dbt_runtime_name(), branches, syscalls, rewritten,
               stdin_reads, memory_hash);
  }
  if (stats_path[0] != 0 && !has_copied_runtime())
    emit_stats_record();
  if (unsupported_report_file != INVALID_FILE) {
    dr_close_file(unsupported_report_file);
    unsupported_report_file = INVALID_FILE;
  }
  if (evidence_is_enabled() && !is_copied_vfork_process() &&
      evidence_current_process_finalized()) {
    dr_global_free(evidence_buffer, EVIDENCE_BUFFER_CAPACITY);
    evidence_buffer = NULL;
    dr_global_free(evidence_senders,
                   sizeof(evidence_sender_state_t) * EVIDENCE_MAX_SENDERS);
    evidence_senders = NULL;
    dr_mutex_destroy(evidence_lock);
    evidence_lock = NULL;
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

static void runtime_background_init(void *argument) {
  (void)argument;
  atomic_store_explicit(&runtime_background_state, 2, memory_order_release);
  evidence_callback_enter();
  reverie_dbt_runtime_background_init_v2(&runtime_callbacks_page.value);
  evidence_callback_leave();
  atomic_store_explicit(&runtime_background_state, 3, memory_order_release);
}

static void ensure_runtime_background(void) {
  int32_t expected = 0;
  if (!atomic_compare_exchange_strong_explicit(
          &runtime_background_state, &expected, 1, memory_order_acq_rel,
          memory_order_acquire))
    return;

  // TODO-HUMAN-REVIEW(PR-134): Review fail-fast native runtime bootstrap.
  if (!dr_create_client_thread(runtime_background_init,
                               (void *)reverie_dbt_emit)) {
    atomic_store_explicit(&runtime_background_state, 0, memory_order_release);
    dr_fprintf(diagnostic_file,
               "reverie-dbt: failed to start background client thread\n");
    dr_exit_process(CLIENT_THREAD_START_FAILURE_EXIT_CODE);
  }
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  drreg_options_t register_options = {sizeof(register_options), 1, false};
  bool external_global = false;
  bool test_direct_evidence_entry = false;
  bool test_runtime_abi_mismatch = false;
  bool evidence_socket_seen = false;
  bool evidence_token_seen = false;
  unsigned char evidence_address[EVIDENCE_ADDRESS_LEN] = {0};
  unsigned char evidence_token[EVIDENCE_TOKEN_LEN] = {0};

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
    else if (strcmp(argv[i], "-test-kill-announced-child") == 0)
      test_kill_announced_child = true;
    else if (strcmp(argv[i], "-test-thread-exit-evidence") == 0)
      test_thread_exit_evidence = true;
    else if (strcmp(argv[i], "-diagnostic_fd") == 0) {
      int fd;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%d", &fd) == 1);
      DR_ASSERT(fd >= 0);
      diagnostic_file = (file_t)fd;
    } else if (strcmp(argv[i], "-evidence-socket") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(decode_hex(argv[i], evidence_address,
                           sizeof(evidence_address)));
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
    ++runtime_abi_version;
  if (runtime_abi_version != REVERIE_DBT_RUNTIME_ABI_VERSION ||
      reverie_dbt_runtime_callbacks_size() != sizeof(runtime_callbacks_t)) {
    dr_fprintf(diagnostic_file,
               "reverie-dbt: native/runtime ABI version or callback size mismatch\n");
    dr_exit_process(101);
    return;
  }
  DR_ASSERT(evidence_socket_seen == evidence_token_seen);
  DR_ASSERT(dr_page_size() == EVIDENCE_CONFIG_PAGE_SIZE);
  evidence_config_page.value.enabled =
      (unsigned char)(evidence_socket_seen && evidence_token_seen);
  memcpy(evidence_config_page.value.address, evidence_address,
         sizeof(evidence_address));
  memcpy(evidence_config_page.value.token, evidence_token,
         sizeof(evidence_token));
  DR_ASSERT(dr_memory_protect(&evidence_config_page,
                              sizeof(evidence_config_page),
                              DR_MEMPROT_READ));
  runtime_callbacks_page.value.emit_evidence =
      evidence_is_enabled() ? reverie_dbt_emit_evidence : reverie_dbt_emit;
  if (!evidence_is_enabled())
    runtime_callbacks_page.value.evidence_log_level = 0;
  atomic_store_explicit(&runtime_background_state, 0, memory_order_release);
  runtime_owner_pid = dr_get_process_id();
  initialize_evidence_transport();
  if (test_direct_evidence_entry) {
    static const char record[] =
        "1970-01-01T00:00:00.000000Z INFO reverie_dbt::evidence: "
        "direct entry must be refused\n";
    DR_ASSERT(evidence_is_enabled());
    reverie_dbt_emit_evidence(record, sizeof(record) - 1);
    DR_ASSERT(false);
  }
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
  atomic_store_explicit(&image_generation, reverie_dbt_runtime_image_init(),
                        memory_order_release);
  resource_lock = dr_mutex_create();
  DR_ASSERT(resource_lock != NULL);
  init_virtual_limits();

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-summary") == 0)
      report_summary = true;
    else if (strcmp(argv[i], "-diagnostic_fd") == 0 ||
             strcmp(argv[i], "-evidence-socket") == 0 ||
             strcmp(argv[i], "-evidence-token") == 0 ||
             strcmp(argv[i], "-evidence-log-level") == 0)
      ++i;
    else if (strcmp(argv[i], "-stats_path") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(strlen(argv[i]) < sizeof(stats_path));
      dr_snprintf(stats_path, sizeof(stats_path), "%s", argv[i]);
    }
    else if (strcmp(argv[i], "-unsupported-report-path") == 0) {
      DR_ASSERT(++i < argc);
      DR_ASSERT(strlen(argv[i]) < sizeof(unsupported_report_path));
      dr_snprintf(unsupported_report_path, sizeof(unsupported_report_path),
                  "%s", argv[i]);
    }
    else if (strcmp(argv[i], "-panic-on-unsupported-syscalls") == 0)
      runtime_callbacks_page.value.panic_on_unsupported_syscalls = 1;
    else if (strcmp(argv[i], "-test-direct-evidence-entry") == 0) {
      /* Handled before application initialization. */
    }
    else if (strcmp(argv[i], "-test-runtime-abi-mismatch") == 0) {
      /* Handled before application initialization. */
    }
    else if (strcmp(argv[i], "-test-wait-for-background") == 0 ||
             strcmp(argv[i], "-test-kill-announced-child") == 0 ||
             strcmp(argv[i], "-test-thread-exit-evidence") == 0) {
      /* Used only by native lifecycle regression tests. */
    }
    else if (strcmp(argv[i], "-isolated-process-group") == 0)
      runtime_process_group = (process_id_t)getpgrp();
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review branch-count preemption argument.
    else if (strcmp(argv[i], "-preemption-quantum") == 0) {
      unsigned long long quantum = 0;
      DR_ASSERT(++i < argc);
      DR_ASSERT(dr_sscanf(argv[i], "%llu", &quantum) == 1);
      preemption_quantum = (uint64_t)quantum;
      preemption_enabled = quantum > 0;
    }
  }

  // AUTONOMOUS-BOT-IMPLEMENTED
  // TODO-HUMAN-REVIEW(PR-dbi-preempt): Review the injected-syscall stub allocation.
  // When preemption is enabled, allocate the tiny redirect stub whose bytes are
  // `syscall; ud2`. `maybe_preempt` redirects here with rax = SYS_sched_yield to
  // deliver a real yield at a safe point; the block starting at the `ud2` carries
  // a `preempt_return` clean call, so the `ud2` only executes (and traps) if the
  // return path is ever bypassed.
  if (preemption_enabled && getenv("HERMIT_DBT_PREEMPT_ANYPC") != NULL)
    preempt_gate_main_only = false;

  if (preemption_enabled) {
    preempt_stub = (byte *)dr_nonheap_alloc(
        dr_page_size(), DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
    DR_ASSERT(preempt_stub != NULL);
    preempt_stub[0] = 0x0f; // syscall
    preempt_stub[1] = 0x05;
    preempt_stub[2] = 0x0f; // ud2
    preempt_stub[3] = 0x0b;
  }

  if (unsupported_report_path[0] != 0) {
    unsupported_report_file =
        dr_open_file(unsupported_report_path, DR_FILE_WRITE_ONLY);
    if (unsupported_report_file == INVALID_FILE)
      dr_fprintf(diagnostic_file,
                 "reverie-dbt: failed to open private unsupported-syscall report\n");
  }
  runtime_callbacks_page.value.unsupported_report_fd =
      (int32_t)unsupported_report_file;
  DR_ASSERT(dr_memory_protect(&runtime_callbacks_page,
                              sizeof(runtime_callbacks_page),
                              DR_MEMPROT_READ));

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
