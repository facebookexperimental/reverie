/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <time.h>

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

// Emits a pre-formatted line of tool output through DynamoRIO's own I/O. The
// simple observation tools (syscall histogram, strace) call back through this
// rather than writing to fd 2 directly: the guest can close its stderr before
// exit, and app-level writes re-enter the syscall interception path.
typedef void (*reverie_emit_fn_t)(const char *buf, size_t len);
static void reverie_dbi_emit(const char *buf, size_t len) {
  dr_write_file(STDERR, buf, len);
}

extern void reverie_dbi_runtime_thread_init(prototype_counters_t *counters);
extern int32_t reverie_dbi_runtime_pre_syscall(
    void *context, prototype_counters_t *counters, int32_t tid, int32_t pid,
    int64_t sysnum, const uint64_t *args, uint64_t branches, int64_t *result,
    syscall_invoker_t invoke_syscall, register_reader_t read_registers,
    reverie_emit_fn_t emit);
extern void reverie_dbi_runtime_totals(uint64_t *branches, uint64_t *syscalls,
                                       uint64_t *rewritten);

static _Atomic uint64_t branch_count __attribute__((aligned(64)));
static _Atomic uint64_t virtual_time_ns = UINT64_C(1000000000);
static int thread_state_index;
static ptr_uint_t cpuid_marker_note;
static bool report_summary;

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

static void wrap_vdso_clock_gettime(void *wrapcxt, void **user_data) {
  uint64_t args[6] = {
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 0),
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 1),
  };
  int64_t result = -ENOSYS;
  DR_ASSERT(handle_virtual_clock(0, SYS_clock_gettime, args, &result));
  DR_ASSERT(drwrap_skip_call(wrapcxt, (void *)(ptr_int_t)result, 0));
}

static void wrap_vdso_clock_getres(void *wrapcxt, void **user_data) {
  uint64_t args[6] = {
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 0),
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 1),
  };
  int64_t result = -ENOSYS;
  DR_ASSERT(handle_virtual_clock(0, SYS_clock_getres, args, &result));
  DR_ASSERT(drwrap_skip_call(wrapcxt, (void *)(ptr_int_t)result, 0));
}

static void wrap_vdso_gettimeofday(void *wrapcxt, void **user_data) {
  uint64_t args[6] = {
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 0),
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 1),
  };
  int64_t result = -ENOSYS;
  DR_ASSERT(handle_virtual_clock(0, SYS_gettimeofday, args, &result));
  DR_ASSERT(drwrap_skip_call(wrapcxt, (void *)(ptr_int_t)result, 0));
}

#ifdef SYS_time
static void wrap_vdso_time(void *wrapcxt, void **user_data) {
  uint64_t args[6] = {
      (uint64_t)(uintptr_t)drwrap_get_arg(wrapcxt, 0),
  };
  int64_t result = -ENOSYS;
  DR_ASSERT(handle_virtual_clock(0, SYS_time, args, &result));
  DR_ASSERT(drwrap_skip_call(wrapcxt, (void *)(ptr_int_t)result, 0));
}
#endif

static void wrap_vdso_symbol(const module_data_t *module, const char *name,
                             void (*callback)(void *, void **)) {
  app_pc address = (app_pc)dr_get_proc_address(module->handle, name);
  if (address != NULL)
    DR_ASSERT(drwrap_wrap(address, callback, NULL));
}

static void module_load(void *drcontext, const module_data_t *module,
                        bool loaded) {
  wrap_vdso_symbol(module, "__vdso_clock_gettime", wrap_vdso_clock_gettime);
  wrap_vdso_symbol(module, "__vdso_clock_getres", wrap_vdso_clock_getres);
  wrap_vdso_symbol(module, "__vdso_gettimeofday", wrap_vdso_gettimeofday);
#ifdef SYS_time
  wrap_vdso_symbol(module, "__vdso_time", wrap_vdso_time);
#endif
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

  if (handle_virtual_clock((uintptr_t)drcontext, sysnum, args, &result) ||
      handle_virtual_resource(sysnum, args, &result)) {
    counters->branches =
        atomic_load_explicit(&branch_count, memory_order_relaxed);
    counters->observed_syscalls += 1;
    counters->rewritten_syscalls += 1;
    dr_syscall_set_result(drcontext, (reg_t)result);
    return false;
  }

  if (reverie_dbi_runtime_pre_syscall(
          drcontext, counters, (int32_t)dr_get_thread_id(drcontext),
          (int32_t)dr_get_process_id(), (int64_t)sysnum, args,
          atomic_load_explicit(&branch_count, memory_order_relaxed), &result,
          invoke_syscall, read_registers, reverie_dbi_emit)) {
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

  if (report_summary) {
    reverie_dbi_runtime_totals(&branches, &syscalls, &rewritten);
    dr_fprintf(
        STDERR,
        "reverie-dbi: branches=%llu syscalls=%llu rewritten_writes=%llu\n",
        branches, syscalls, rewritten);
  }
  dr_mutex_destroy(resource_lock);
  drwrap_exit();
  drx_exit();
  drmgr_unregister_tls_field(thread_state_index);
  drreg_exit();
  drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  drreg_options_t register_options = {sizeof(register_options), 1, false};

  resource_lock = dr_mutex_create();
  DR_ASSERT(resource_lock != NULL);
  init_virtual_limits();

  for (int i = 1; i < argc; ++i)
    if (strcmp(argv[i], "-summary") == 0)
      report_summary = true;

  dr_set_client_name("Reverie DynamoRIO backend prototype",
                     "https://github.com/rrnewton/reverie");
  if (!drmgr_init() || !drwrap_init() || !drx_init() ||
      drreg_init(&register_options) != DRREG_SUCCESS)
    DR_ASSERT(false);
  cpuid_marker_note = drmgr_reserve_note_range(1);
  if (cpuid_marker_note == DRMGR_NOTE_NONE)
    DR_ASSERT(false);
  thread_state_index = drmgr_register_tls_field();
  if (thread_state_index == -1)
    DR_ASSERT(false);

  drmgr_register_exit_event(event_exit);
  if (!drmgr_register_module_load_event(module_load) ||
      !drmgr_register_thread_init_event(thread_init) ||
      !drmgr_register_thread_exit_event(thread_exit) ||
      !drmgr_register_bb_app2app_event(rewrite_cpuid, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL, instrument_instruction,
                                               NULL) ||
      !drmgr_register_filter_syscall_event(filter_syscall) ||
      !drmgr_register_pre_syscall_event(pre_syscall))
    DR_ASSERT(false);
}
