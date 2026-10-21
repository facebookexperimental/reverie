/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Included by client.c after its ownership helpers. All storage and states
 * below belong to this actual image; fork copies never become eligible. */
#include "mapping_capture_test_signals.h"
#include "mapping_capture_test_topology.h"
#define MAPPING_CAPTURE_REQUEST_CAPACITY (64U * 1024U)
#define MAPPING_CAPTURE_RESPONSE_CAPACITY (2U * 1024U * 1024U + 64U * 1024U)
#define MAPPING_CAPTURE_ACQUIRE_NS UINT64_C(5000000000)
#define MAPPING_CAPTURE_RESTORE_NS UINT64_C(2000000000)
enum {
  MAPPING_IDLE, MAPPING_REQUESTED, MAPPING_ENTERING, MAPPING_PARKED,
  MAPPING_RELEASE_REQUESTED, MAPPING_RESTORED, MAPPING_FAILED
};
enum {
  MAPPING_UNAVAILABLE = 0, MAPPING_READY = 1, MAPPING_INVALID = -1,
  MAPPING_TIMEOUT = -2, MAPPING_TRANSPORT = -3, MAPPING_OWNER_CHANGED = -4,
  MAPPING_UNAUTHORIZED = -5
};

typedef struct {
  _Atomic uint32_t state;
  _Atomic bool eligible;
  _Atomic bool transaction_active;
  _Atomic bool helper_permit;
  void* application_context;
  void* helper_context;
  thread_id_t helper_tid;
  uint64_t image;
  uint64_t generation;
  uint64_t last_nonce;
  uint64_t authorized_nonce;
  uint64_t requests_started;
  uint64_t caller_mask;
  uint64_t helper_mask;
  bool test_extra_completed;
  bool test_flag_clear;
  bool test_storage_owned;
  _Atomic bool test_role_checked;
  bool test_role_refused;
  bool test_registry_held;
  bool test_final_flag_held;
  uint64_t test_control_seen;
  uint32_t test_control_blocked;
  uint32_t test_received_length;
  uint32_t test_fault_value;
  bool test_control_injected;
  uintptr_t caller_stack_start, caller_stack_end;
  uintptr_t helper_stack_start, helper_stack_end;
  _Atomic bool test_observer_active;
  _Atomic uint64_t test_memory_events[4];
  uint64_t test_send_calls;
  uint64_t test_recv_calls;
  uint64_t test_send_success;
  uint64_t test_recv_success;
  uint64_t test_send_bytes;
  uint64_t test_recv_bytes;
  size_t test_max_send;
  size_t test_max_recv;
  ptr_int_t test_last_transfer;
  mapping_capture_topology_test_t topology;
  mapping_capture_signal_test_t caller_signals;
  mapping_capture_signal_test_t helper_signals;
  bool test_caller_full_mask;
  bool test_helper_full_mask;
  bool test_caller_signals_restored;
  bool test_helper_signals_restored;
  private_memory_snapshot_t before;
  private_memory_snapshot_t after;
  unsigned char request_header[4];
  unsigned char response_header[4];
  unsigned char request[MAPPING_CAPTURE_REQUEST_CAPACITY];
  unsigned char response[MAPPING_CAPTURE_RESPONSE_CAPACITY];
} mapping_capture_slot_t;

/* Never freed by cancellation, a copied child, or an unfinished generation.
 * Successful exec destroys the actual old MM after its existing helper exit
 * protocol. Ordinary process teardown owns the private arena. */
static mapping_capture_slot_t* mapping_capture_slot;

static bool mapping_capture_test_signals(void) {
  return test_mapping_capture == MAPPING_TEST_MASK_PENDING ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_EPIPE;
}

static bool mapping_capture_test_observer(void) {
  return test_mapping_capture == MAPPING_TEST_CLOSED_OBSERVER ||
      test_mapping_capture == MAPPING_TEST_CLOSED_ALLOCATION;
}

/* Installed only for the explicit private observer controls. Counts actual
 * SDK allocation/free and map/protection entry paths, not a stand-alone model.
 * The fixed Closed call graph uses these SDK functions or the raw control leaf;
 * arbitrary private-libc/direct syscalls are outside this finite observer. */
static void mapping_capture_memory_event(dr_mapping_capture_memory_kind_t kind) {
  mapping_capture_slot_t* slot = mapping_capture_slot;
  if (slot != NULL && (unsigned int)kind < 4 &&
      atomic_load_explicit(&slot->test_observer_active, memory_order_acquire))
    atomic_fetch_add_explicit(&slot->test_memory_events[kind], 1, memory_order_relaxed);
}

static bool mapping_capture_active(void) {
  if (mapping_capture_slot == NULL)
    return false;
  return atomic_load_explicit(&mapping_capture_slot->transaction_active, memory_order_acquire);
}

static void mapping_capture_terminal(void) {
  if (mapping_capture_slot != NULL)
    atomic_store_explicit(&mapping_capture_slot->state, MAPPING_FAILED, memory_order_release);
  // Pending remains registered at the external controller. No DR cleanup,
  // flush, allocator, logger or Rust unwinder is safe against a masked helper.
  dr_mapping_capture_control(DR_MAPPING_CAPTURE_EXIT, 125, 0, 0);
  for (;;)
    __asm__ volatile("pause" ::: "memory");
}

static void mapping_capture_withdraw(void) {
  if (mapping_capture_slot != NULL)
    atomic_store_explicit(&mapping_capture_slot->eligible, false, memory_order_release);
}

static void mapping_capture_withdraw_for_syscall(int sysnum) {
  if (is_clone_syscall(sysnum) || sysnum == SYS_unshare || sysnum == SYS_setns) {
    mapping_capture_withdraw();
    if (test_mapping_capture == MAPPING_TEST_BIRTH_DOMAIN && mapping_capture_slot != NULL &&
        !mapping_capture_active())
      dr_fprintf(diagnostic_file,
          "MAPPING_CAPTURE_TEST phase=birth-withdraw syscall=%d requested=%llu\n",
          sysnum, (unsigned long long)mapping_capture_slot->requests_started);
  }
}

static void mapping_capture_birth(void* parent, void (*entry)(void*), void* argument) {
  mapping_capture_slot_t* slot = mapping_capture_slot;
  if (slot == NULL)
    return;
  bool permitted = true;
  if (parent == slot->application_context && entry == runtime_background_init &&
      argument == (void*)reverie_dbt_emit &&
      atomic_compare_exchange_strong_explicit(&slot->helper_permit, &permitted, false,
          memory_order_acq_rel, memory_order_acquire))
    return;
  mapping_capture_withdraw();
}

/* Never use runtime_private_memory here: its spinning acquisition is not a
 * bounded capture operation. Every success and mismatch releases the flag. */
static bool mapping_capture_copy_owner(private_memory_snapshot_t* output) {
  if (task_state == NULL || !task_state_identity_valid || task_state_identity_lost ||
      atomic_flag_test_and_set_explicit(&task_state->lock, memory_order_acquire))
    return false;
  bool valid = runtime_memory_owner_slot < task_state->process_control_count;
  if (valid) {
    process_control_t* entry = &task_state->process_controls[runtime_memory_owner_slot];
    valid = entry->memory_published != 0 && entry->memory_retired == 0 &&
        atomic_load_explicit(&entry->image_epoch, memory_order_relaxed) == runtime_memory_owner_epoch &&
        entry->private_memory.state == 1 && entry->private_memory.count > 0 &&
        entry->private_memory.count <= DR_PRIVATE_RESERVATION_MAX &&
        entry->private_memory.owner[0] == task_state_device &&
        entry->private_memory.owner[1] == task_state_inode &&
        entry->private_memory.owner[2] == runtime_memory_owner_slot &&
        entry->private_memory.owner[3] == runtime_memory_owner_epoch;
    if (valid)
      *output = entry->private_memory;
  }
  task_state_unlock();
  return valid;
}

static bool mapping_capture_private(const private_memory_snapshot_t* owner,
    const void* bytes, size_t length) {
  uintptr_t start = (uintptr_t)bytes;
  if (length == 0 || start > UINTPTR_MAX - length)
    return false;
  uintptr_t end = start + length;
  for (uint32_t i = 0; i < owner->count; ++i) {
    if (owner->ranges[i].end <= start)
      continue;
    if (owner->ranges[i].start > start)
      return false;
    if (owner->ranges[i].end >= end)
      return true;
    start = owner->ranges[i].end;
  }
  return false;
}

static bool mapping_capture_prefault_stack(void* context,
    const private_memory_snapshot_t* owner) {
  byte* start = NULL;
  size_t size = 0;
  if (!dr_mapping_capture_stack(context, &start, &size) ||
      !mapping_capture_private(owner, start, size))
    return false;
  if (mapping_capture_slot != NULL) {
    if (context == mapping_capture_slot->application_context) {
      mapping_capture_slot->caller_stack_start = (uintptr_t)start;
      mapping_capture_slot->caller_stack_end = (uintptr_t)start + size;
    } else if (context == mapping_capture_slot->helper_context) {
      mapping_capture_slot->helper_stack_start = (uintptr_t)start;
      mapping_capture_slot->helper_stack_end = (uintptr_t)start + size;
    }
  }
  // Only the current executor touches its own complete allocated DR stack.
  // Read/write the same byte to materialize writable backing before masking.
  for (size_t offset = 0; offset < size; offset += 4096) {
    volatile byte* page = start + offset;
    *page = *page;
  }
  return true;
}

/* Test-only check at each actual initiating-executor control leaf. The helper's
 * futex may run concurrently with the caller's short owner copy; it does not
 * own that flag and is deliberately not asserted to observe global vacancy.
 * Normal operation goes straight to the existing fixed raw shim. */
static ptr_int_t mapping_capture_caller_control(dr_mapping_capture_operation_t operation,
    uintptr_t a, uintptr_t b, uintptr_t c) {
  mapping_capture_slot_t* slot = mapping_capture_slot;
  bool checked = slot != NULL &&
      (test_mapping_capture == MAPPING_TEST_RAW_FLAG_CLEAR ||
       test_mapping_capture == MAPPING_TEST_RAW_FLAG_HELD ||
       test_mapping_capture == MAPPING_TEST_TRANSPORT_STALL) &&
      atomic_load_explicit(&slot->transaction_active, memory_order_acquire) &&
      (operation == DR_MAPPING_CAPTURE_SEND || operation == DR_MAPPING_CAPTURE_RECEIVE ||
       operation == DR_MAPPING_CAPTURE_POLL || operation == DR_MAPPING_CAPTURE_CLOCK ||
       operation == DR_MAPPING_CAPTURE_WAIT || operation == DR_MAPPING_CAPTURE_WAKE);
  if (checked) {
    slot->test_control_seen |= UINT64_C(1) << operation;
    bool injected = test_mapping_capture == MAPPING_TEST_RAW_FLAG_HELD &&
        operation == DR_MAPPING_CAPTURE_SEND && !slot->test_control_injected &&
        atomic_load_explicit(&slot->state, memory_order_acquire) == MAPPING_PARKED;
    bool held = injected &&
        !atomic_flag_test_and_set_explicit(&task_state->lock, memory_order_acquire);
    if (injected)
      slot->test_control_injected = true;
    if (atomic_flag_test_and_set_explicit(&task_state->lock, memory_order_acquire)) {
      slot->test_flag_clear = false;
      slot->test_control_blocked = (uint32_t)operation + 1;
      if (held)
        task_state_unlock();
      return -EBUSY;
    }
    task_state_unlock();
  }
  return dr_mapping_capture_control(operation, a, b, c);
}

static uint64_t mapping_capture_now(void) {
  struct timespec now;
  if (mapping_capture_caller_control(DR_MAPPING_CAPTURE_CLOCK, (uintptr_t)&now, 0, 0) != 0 ||
      now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
      (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / UINT64_C(1000000000))
    return UINT64_MAX;
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint64_t mapping_capture_deadline(uint64_t interval) {
  uint64_t now = mapping_capture_now();
  return now <= UINT64_MAX - interval ? now + interval : 0;
}

static bool mapping_capture_before(uint64_t deadline) {
  return deadline != 0 && mapping_capture_now() < deadline;
}

static void mapping_capture_wait(mapping_capture_slot_t* slot, uint32_t state) {
  const struct timespec interval = { .tv_sec = 0, .tv_nsec = 1000000 };
  mapping_capture_caller_control(DR_MAPPING_CAPTURE_WAIT,
      (uintptr_t)&slot->state, state, (uintptr_t)&interval);
}

static void mapping_capture_wake(mapping_capture_slot_t* slot) {
  mapping_capture_caller_control(DR_MAPPING_CAPTURE_WAKE, (uintptr_t)&slot->state, 0, 0);
}

static void mapping_capture_helper_wait(mapping_capture_slot_t* slot, uint32_t state) {
  const struct timespec interval = { .tv_sec = 0, .tv_nsec = 1000000 };
  dr_mapping_capture_control(DR_MAPPING_CAPTURE_WAIT,
      (uintptr_t)&slot->state, state, (uintptr_t)&interval);
}

static void mapping_capture_helper_idle(void) {
  mapping_capture_slot_t* slot = mapping_capture_slot;
  if (slot == NULL || slot->helper_context != dr_get_current_drcontext() ||
      slot->helper_tid != dr_get_thread_id(slot->helper_context))
    return;
  if (test_mapping_capture == MAPPING_TEST_APP_ROLE &&
      !atomic_load_explicit(&slot->test_role_checked, memory_order_acquire))
    return; // Let the application call this exact role-guarded entry first.
  if (test_mapping_capture == MAPPING_TEST_CANCEL_REQUESTED)
    return; // Exercise the real unclaimed-request cancellation CAS.
  uint32_t expected = MAPPING_REQUESTED;
  if (!atomic_compare_exchange_strong_explicit(&slot->state, &expected, MAPPING_ENTERING,
          memory_order_acq_rel, memory_order_acquire))
    return;
  uint64_t generation = slot->generation;
  if (mapping_capture_test_signals() &&
      !mapping_capture_signal_test_prepare(&slot->helper_signals,
          (int32_t)slot->helper_tid, runtime_process_id))
    mapping_capture_terminal();
  if (test_mapping_capture == MAPPING_TEST_REGISTRY_BUSY) {
    slot->test_registry_held = dr_mapping_capture_test_registry_lock(true);
    if (!slot->test_registry_held)
      mapping_capture_terminal();
  }
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_BLOCK_SIGNALS,
          (uintptr_t)&slot->helper_mask, 0, 0) != 0)
    mapping_capture_terminal();
  if (mapping_capture_test_signals()) {
    slot->test_helper_full_mask =
        mapping_capture_signal_test_blocked(&slot->helper_signals);
    if (!slot->test_helper_full_mask) {
      mapping_capture_signal_test_report_mask_mismatch(
          &slot->helper_signals, diagnostic_file);
      mapping_capture_terminal();
    }
  }
  if (test_mapping_capture == MAPPING_TEST_CANCEL_ENTERING) {
    // Real helper, real mask: caller must cancel Entering and observe restore.
    while (atomic_load_explicit(&slot->state, memory_order_acquire) == MAPPING_ENTERING)
      mapping_capture_helper_wait(slot, MAPPING_ENTERING);
  }
  expected = MAPPING_ENTERING;
  if (atomic_compare_exchange_strong_explicit(&slot->state, &expected, MAPPING_PARKED,
          memory_order_acq_rel, memory_order_acquire)) {
    dr_mapping_capture_control(DR_MAPPING_CAPTURE_WAKE, (uintptr_t)&slot->state, 0, 0);
    while (atomic_load_explicit(&slot->state, memory_order_acquire) == MAPPING_PARKED)
      mapping_capture_helper_wait(slot, MAPPING_PARKED);
  }
  if (test_mapping_capture == MAPPING_TEST_FAIL_RELEASE) {
    // Hold the actual masked executor. The caller's fixed restoration grace
    // must end via raw exit and launcher cleanup, never DR synchronization.
    for (;;)
      mapping_capture_helper_wait(slot, MAPPING_RELEASE_REQUESTED);
  }
  if (test_mapping_capture == MAPPING_TEST_HELPER_EXIT) {
    static const char note[] = "MAPPING_CAPTURE_TEST phase=helper-exit\n";
    dr_mapping_capture_control(DR_MAPPING_CAPTURE_TEST_WRITE,
        diagnostic_file, (uintptr_t)note, sizeof(note) - 1);
    // Real helper exits without removing its DR record. Only the caller's
    // bounded restore wait and the authenticated launcher containment remain.
    dr_mapping_capture_control(DR_MAPPING_CAPTURE_EXIT, 125, 0, 0);
    for (;;)
      __asm__ volatile("pause" ::: "memory");
  }
  if (slot->test_registry_held)
    dr_mapping_capture_test_registry_lock(false);
  if (generation != slot->generation ||
      atomic_load_explicit(&slot->state, memory_order_acquire) != MAPPING_RELEASE_REQUESTED ||
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_RESTORE_SIGNALS,
          test_mapping_capture == MAPPING_TEST_HELPER_MASK_FAILURE
              ? UINTPTR_MAX : (uintptr_t)&slot->helper_mask, 0, 0) != 0)
    mapping_capture_terminal();
  if (mapping_capture_test_signals()) {
    slot->test_helper_signals_restored =
        mapping_capture_signal_test_finish(&slot->helper_signals);
    if (!slot->test_helper_signals_restored)
      mapping_capture_terminal();
  }
  atomic_store_explicit(&slot->state, MAPPING_RESTORED, memory_order_release);
  dr_mapping_capture_control(DR_MAPPING_CAPTURE_WAKE, (uintptr_t)&slot->state, 0, 0);
}

static bool mapping_capture_transfer(mapping_capture_slot_t* slot, int fd,
    unsigned char* bytes, size_t length, bool sending, uint64_t deadline, bool parked) {
  size_t offset = 0;
  while (offset < length && mapping_capture_before(deadline)) {
    if (parked && test_mapping_capture != MAPPING_TEST_NONE) {
      if (atomic_flag_test_and_set_explicit(&task_state->lock, memory_order_acquire)) {
        slot->test_flag_clear = false;
        return false;
      }
      task_state_unlock();
    }
    size_t requested = length - offset;
    if (parked && test_mapping_capture == MAPPING_TEST_PARTIAL_FRAMES && requested > 7)
      requested = 7;
    ptr_int_t result = mapping_capture_caller_control(
        sending ? DR_MAPPING_CAPTURE_SEND : DR_MAPPING_CAPTURE_RECEIVE,
        fd, (uintptr_t)(bytes + offset), requested);
    if (parked) {
      if (sending)
        ++slot->test_send_calls;
      else
        ++slot->test_recv_calls;
      slot->test_last_transfer = result;
    }
    if (result > 0 && (size_t)result <= requested) {
      if (parked) {
        if (sending) {
          ++slot->test_send_success;
          slot->test_send_bytes += (size_t)result;
          if ((size_t)result > slot->test_max_send)
            slot->test_max_send = (size_t)result;
        } else {
          ++slot->test_recv_success;
          slot->test_recv_bytes += (size_t)result;
          if ((size_t)result > slot->test_max_recv)
            slot->test_max_recv = (size_t)result;
        }
      }
      offset += (size_t)result;
    } else if (result == -EINTR) {
      continue;
    } else if (result == -EAGAIN) {
      struct pollfd pollfd = { .fd = fd, .events = sending ? POLLOUT : POLLIN };
      result = mapping_capture_caller_control(DR_MAPPING_CAPTURE_POLL,
          (uintptr_t)&pollfd, 1, 0);
      if (result < 0 && result != -EINTR)
        return false;
    } else {
      return false;
    }
    if (parked && atomic_load_explicit(&slot->state, memory_order_acquire) != MAPPING_PARKED)
      return false;
  }
  return offset == length && mapping_capture_before(deadline);
}

static bool mapping_capture_exchange(mapping_capture_slot_t* slot,
    mapping_capture_arguments_t* args, uint64_t deadline, bool parked) {
  uint32_t length = (uint32_t)args->request_length;
  if (parked && test_mapping_capture == MAPPING_TEST_TRANSPORT_STALL) {
    // The real connected primary has no outstanding request. Receive/poll
    // therefore exercises the existing bounded EAGAIN/deadline path.
    return mapping_capture_transfer(slot, args->fd, slot->response_header, 4,
        false, deadline, true);
  }
  for (size_t i = 0; i < 4; ++i)
    slot->request_header[i] = (unsigned char)(length >> ((3 - i) * 8));
  if (!mapping_capture_transfer(slot, args->fd, slot->request_header, 4, true, deadline, parked) ||
      !mapping_capture_transfer(slot, args->fd, slot->request, length, true, deadline, parked) ||
      !mapping_capture_transfer(slot, args->fd, slot->response_header, 4, false, deadline, parked))
    return false;
  length = 0;
  for (size_t i = 0; i < 4; ++i)
    length = (length << 8) | slot->response_header[i];
  if (parked)
    slot->test_received_length = length;
  if (parked && test_mapping_capture == MAPPING_TEST_TRANSPORT_OVERSIZE) {
    length = MAPPING_CAPTURE_RESPONSE_CAPACITY + 1;
    slot->test_fault_value = length;
  }
  if (length > MAPPING_CAPTURE_RESPONSE_CAPACITY ||
      !mapping_capture_transfer(slot, args->fd, slot->response, length, false, deadline, parked))
    return false;
  if (parked && test_mapping_capture == MAPPING_TEST_TRANSPORT_MALFORMED && length > 0) {
    slot->test_fault_value = slot->response[0];
    slot->response[0] = 0xff; // Actual complete response; post-restore decode must refuse.
  }
  args->response_length = length;
  return true;
}

static void mapping_capture_initialize(void) {
  mapping_capture_slot = dr_global_alloc(sizeof(*mapping_capture_slot));
  if (mapping_capture_slot == NULL)
    return;
  memset(mapping_capture_slot, 0, sizeof(*mapping_capture_slot));
  mapping_capture_slot->application_context = dr_get_current_drcontext();
  mapping_capture_slot->image = runtime_process_epoch;
  bool valid = runtime_is_root && runtime_uses_external_global() &&
      mapping_capture_copy_owner(&mapping_capture_slot->before) &&
      mapping_capture_private(&mapping_capture_slot->before,
          mapping_capture_slot, sizeof(*mapping_capture_slot));
  if (!valid) {
    dr_global_free(mapping_capture_slot, sizeof(*mapping_capture_slot));
    mapping_capture_slot = NULL;
    return;
  }
  atomic_init(&mapping_capture_slot->eligible, true);
  atomic_init(&mapping_capture_slot->transaction_active, false);
  atomic_init(&mapping_capture_slot->helper_permit, false);
  atomic_init(&mapping_capture_slot->state, MAPPING_IDLE);
  atomic_init(&mapping_capture_slot->test_observer_active, false);
  atomic_init(&mapping_capture_slot->test_role_checked, false);
  for (size_t i = 0; i < 4; ++i)
    atomic_init(&mapping_capture_slot->test_memory_events[i], 0);
  dr_set_mapping_capture_birth_observer(mapping_capture_birth);
  if (mapping_capture_test_observer())
    dr_set_mapping_capture_memory_observer(mapping_capture_memory_event);
}

static void mapping_capture_helper_enter(void) {
  mapping_capture_slot_t* slot = mapping_capture_slot;
  if (slot == NULL)
    return;
  slot->helper_context = dr_get_current_drcontext();
  slot->helper_tid = dr_get_thread_id(slot->helper_context);
  if (!mapping_capture_prefault_stack(slot->helper_context, &slot->before))
    mapping_capture_withdraw();
}

// These controls are reachable only through explicit private native test
// arguments. They create a real extra executor and reap that exact child before
// capture; a transient registry-count check cannot substitute for withdrawal.
static _Atomic int32_t mapping_capture_test_extra_pid;

static void mapping_capture_test_extra(void* unused) {
  (void)unused;
  atomic_store_explicit(&mapping_capture_test_extra_pid, (int32_t)getpid(),
      memory_order_release);
}

static bool mapping_capture_test_retired_helper(mapping_capture_slot_t* slot) {
  slot->test_extra_completed = true;
  bool created = dr_create_client_thread(mapping_capture_test_extra, NULL);
  uint64_t deadline = mapping_capture_deadline(MAPPING_CAPTURE_ACQUIRE_NS);
  int32_t pid = 0;
  bool retired = false;
  while (created && mapping_capture_before(deadline)) {
    pid = atomic_load_explicit(&mapping_capture_test_extra_pid, memory_order_acquire);
    if (pid > 0) {
      int status = 0;
      pid_t reaped = waitpid((pid_t)pid, &status, WNOHANG | __WALL);
      if (reaped == (pid_t)pid) {
        retired = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        break;
      }
      if (reaped < 0 && errno != EINTR)
        break;
    }
    dr_sleep(1);
  }
  dr_fprintf(diagnostic_file,
      "MAPPING_CAPTURE_TEST phase=extra-helper retired=%d caller=%d helper=%d\n",
      retired, (int)dr_get_thread_id(slot->application_context), pid);
  return retired;
}

static int32_t runtime_mapping_capture(uintptr_t context, uint32_t operation,
    mapping_capture_arguments_t* args) {
  mapping_capture_slot_t* slot = mapping_capture_slot;
  if (slot != NULL && operation == 0 && !slot->test_extra_completed &&
      test_mapping_capture == MAPPING_TEST_EXTRA_HELPER &&
      !mapping_capture_test_retired_helper(slot))
    return MAPPING_INVALID;
  if (slot == NULL || args == NULL || context != (uintptr_t)slot->application_context ||
      dr_get_current_drcontext() != slot->application_context ||
      runtime_process_id != (int32_t)dr_get_process_id() || !runtime_is_root ||
      runtime_process_epoch != slot->image ||
      !atomic_load_explicit(&slot->eligible, memory_order_acquire) ||
      atomic_load_explicit(&runtime_background_state, memory_order_acquire) != 2) {
    if (operation == 0 && test_mapping_capture == MAPPING_TEST_PRIVATE_SPLIT &&
        !mapping_capture_active())
      dr_fprintf(diagnostic_file,
          "MAPPING_CAPTURE_TEST phase=private-split-refused operation=0 native=0 "
          "reason=eligibility step=%u\n", slot == NULL ? 0 : slot->topology.phase + 1);
    if (operation == 0 && test_mapping_capture == MAPPING_TEST_BIRTH_DOMAIN &&
        slot != NULL && !mapping_capture_active())
      dr_fprintf(diagnostic_file,
          "MAPPING_CAPTURE_TEST phase=birth-refused requested=%llu\n",
          (unsigned long long)slot->requests_started);
    return MAPPING_UNAVAILABLE;
  }
  uint32_t state = atomic_load_explicit(&slot->state, memory_order_acquire);
  if (state != MAPPING_IDLE && state != MAPPING_RESTORED) {
    if (operation == 0 && test_mapping_capture == MAPPING_TEST_PRIVATE_SPLIT &&
        !mapping_capture_active())
      dr_fprintf(diagnostic_file,
          "MAPPING_CAPTURE_TEST phase=private-split-refused operation=0 native=0 "
          "reason=state state=%u step=%u\n", state, slot->topology.phase + 1);
    return MAPPING_UNAVAILABLE;
  }
  if (operation == 0) {
    if (test_mapping_capture == MAPPING_TEST_PRIVATE_SPLIT) {
      slot->topology.stage = 0;
      if (!mapping_capture_copy_owner(&slot->after) ||
          !mapping_capture_topology_test_prepare(
              &slot->topology, &slot->after, mapping_capture_private)) {
        // Test-only, before masks/Requested. Report the existing observations;
        // do not query again or change any topology assertion on failure.
        mapping_capture_topology_extent_t* view =
            slot->topology.observed[slot->topology.phase < 3 ? slot->topology.phase : 2];
        mapping_capture_topology_extent_t* initial = &slot->topology.observed[0][0];
        dr_fprintf(diagnostic_file,
            "MAPPING_CAPTURE_TEST phase=private-split-refused operation=0 native=-1 "
            "step=%u stage=%u "
            "initial_start=%llu initial_end=%llu initial_prot=%u "
            "left_start=%llu left_end=%llu left_prot=%u left_query=%u "
            "middle_start=%llu middle_end=%llu middle_prot=%u middle_query=%u "
            "right_start=%llu right_end=%llu right_prot=%u right_query=%u\n",
            slot->topology.phase + 1, slot->topology.stage,
            (unsigned long long)initial->start, (unsigned long long)initial->end,
            initial->protection,
            (unsigned long long)view[0].start, (unsigned long long)view[0].end,
            view[0].protection, view[0].query_status,
            (unsigned long long)view[1].start, (unsigned long long)view[1].end,
            view[1].protection, view[1].query_status,
            (unsigned long long)view[2].start, (unsigned long long)view[2].end,
            view[2].protection, view[2].query_status);
        return MAPPING_INVALID;
      }
    }
    args->request = slot->request;
    args->request_capacity = sizeof(slot->request);
    args->response = slot->response;
    args->response_capacity = sizeof(slot->response);
    args->response_length = 0;
    return MAPPING_READY;
  }
  if (operation == 2) {
    // Authenticate Pending/containment through the already-connected primary
    // before masks or Requested. The fixed ACK must echo this entire tuple.
    const unsigned char request_prefix[8] = { 255, 255, 255, 255, 'M', 'C', 1, 0 };
    const unsigned char ack_prefix[8] = { 255, 255, 255, 255, 'M', 'C', 1, 1 };
    uint64_t token_nonce = 0;
    int32_t process = 0, thread = 0;
    if (args->request != slot->request || args->response != slot->response ||
        args->fd < 0 || args->request_length != 80 || args->nonce == 0 ||
        args->nonce <= slot->last_nonce || slot->authorized_nonce != 0 ||
        memcmp(slot->request, request_prefix, sizeof(request_prefix)) != 0)
      return MAPPING_UNAUTHORIZED;
    memcpy(&token_nonce, slot->request + 8, 8);
    memcpy(&process, slot->request + 16, 4);
    memcpy(&thread, slot->request + 20, 4);
    if (token_nonce != args->nonce || process != runtime_process_id || thread != process ||
        process != args->root_pid ||
        memcmp(slot->request + 40, args->expected.owner, sizeof(args->expected.owner)) != 0 ||
        memcmp(slot->request + 72, &args->expected.version, sizeof(args->expected.version)) != 0)
      return MAPPING_UNAUTHORIZED;
    if (test_mapping_capture == MAPPING_TEST_FORGED_TOKEN)
      slot->request[8] ^= 0x80; // Validly framed, unregistered Pending nonce.
    bool authorized = mapping_capture_exchange(slot, args,
        mapping_capture_deadline(MAPPING_CAPTURE_ACQUIRE_NS), false) &&
        args->response_length == 80 &&
        memcmp(slot->response, ack_prefix, sizeof(ack_prefix)) == 0 &&
        memcmp(slot->response + 8, slot->request + 8, 72) == 0;
    if (!authorized) {
      if (test_mapping_capture == MAPPING_TEST_FORGED_TOKEN)
        dr_fprintf(diagnostic_file,
            "MAPPING_CAPTURE_TEST phase=authorization-refused requested=%llu\n",
            (unsigned long long)slot->requests_started);
      return MAPPING_UNAUTHORIZED;
    }
    slot->authorized_nonce = args->nonce;
    return MAPPING_READY;
  }
  // These private controls perturb the actual precondition inputs after a
  // genuine authorization. None may reach masking or Requested.
  const char* preflight_fault = NULL;
  bool owner_flag_held = false;
  if (operation == 1 && test_mapping_capture == MAPPING_TEST_STALE_NONCE) {
    slot->last_nonce = args->nonce;
    preflight_fault = "stale-nonce";
  } else if (operation == 1 && test_mapping_capture == MAPPING_TEST_GENERATION_EXHAUSTED) {
    slot->generation = UINT64_MAX;
    preflight_fault = "generation-exhausted";
  } else if (operation == 1 && test_mapping_capture == MAPPING_TEST_OWNER_BUSY) {
    owner_flag_held =
        !atomic_flag_test_and_set_explicit(&task_state->lock, memory_order_acquire);
    preflight_fault = "owner-busy";
  }
  bool invalid = operation != 1 || args->nonce == 0 || args->nonce <= slot->last_nonce ||
      args->nonce != slot->authorized_nonce ||
      slot->generation == UINT64_MAX || args->root_pid != runtime_process_id ||
      args->fd < 0 || args->request != slot->request || args->response != slot->response ||
      args->request_capacity != sizeof(slot->request) ||
      args->response_capacity != sizeof(slot->response) ||
      args->request_length > sizeof(slot->request) || args->release_lease == NULL ||
      !mapping_capture_copy_owner(&slot->before) ||
      memcmp(&slot->before, &args->expected, sizeof(slot->before)) != 0 ||
      !mapping_capture_private(&slot->before, slot, sizeof(*slot)) ||
      !mapping_capture_private(&slot->before, args, sizeof(*args)) ||
      !mapping_capture_prefault_stack((void*)context, &slot->before);
  if (owner_flag_held)
    task_state_unlock();
  if (invalid) {
    if (preflight_fault != NULL)
      dr_fprintf(diagnostic_file,
          "MAPPING_CAPTURE_TEST phase=preflight-refused requested=%llu reason=%s\n",
          (unsigned long long)slot->requests_started, preflight_fault);
    return MAPPING_INVALID;
  }
  slot->test_storage_owned = true; // All slot/args/stack checks above succeeded.
  slot->test_send_calls = slot->test_recv_calls = 0;
  slot->test_send_success = slot->test_recv_success = 0;
  slot->test_send_bytes = slot->test_recv_bytes = 0;
  slot->test_max_send = slot->test_max_recv = 0;
  slot->test_last_transfer = 0;
  slot->test_control_seen = 0;
  slot->test_control_blocked = 0;
  slot->test_control_injected = false;
  slot->test_received_length = 0;
  slot->test_fault_value = 0;
  if ((test_mapping_capture == MAPPING_TEST_TRANSPORT_EPIPE ||
       test_mapping_capture == MAPPING_TEST_TRANSPORT_EOF) &&
      dr_mapping_capture_control(DR_MAPPING_CAPTURE_TEST_SHUTDOWN, args->fd,
          test_mapping_capture == MAPPING_TEST_TRANSPORT_EPIPE ? 1 /* SHUT_WR */ : 0,
          0) != 0)
    return MAPPING_INVALID;
  uint64_t started = mapping_capture_now();
  uint64_t deadline = started <= UINT64_MAX - MAPPING_CAPTURE_ACQUIRE_NS
      ? started + MAPPING_CAPTURE_ACQUIRE_NS : 0;
  uint64_t acquired = started;
  uint64_t exchanged = started;
  if (deadline == 0)
    return MAPPING_INVALID;
  slot->authorized_nonce = 0;
  slot->test_flag_clear = true;
  ++slot->generation;
  slot->last_nonce = args->nonce;
  args->response_length = 0;
  atomic_store_explicit(&slot->transaction_active, true, memory_order_release);
  if (mapping_capture_test_signals() &&
      !mapping_capture_signal_test_prepare(&slot->caller_signals,
          runtime_process_id, runtime_process_id))
    mapping_capture_terminal();
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_BLOCK_SIGNALS,
          (uintptr_t)&slot->caller_mask, 0, 0) != 0)
    mapping_capture_terminal();
  ++slot->requests_started;
  atomic_store_explicit(&slot->state, MAPPING_REQUESTED, memory_order_release);
  if (test_mapping_capture == MAPPING_TEST_APP_ROLE) {
    mapping_capture_helper_idle(); // Actual application executor, not a model.
    slot->test_role_refused =
        atomic_load_explicit(&slot->state, memory_order_acquire) == MAPPING_REQUESTED;
    if (!slot->test_role_refused)
      mapping_capture_terminal();
    atomic_store_explicit(&slot->test_role_checked, true, memory_order_release);
  }
  int32_t result = MAPPING_TIMEOUT;
  while (mapping_capture_before(deadline)) {
    state = atomic_load_explicit(&slot->state, memory_order_acquire);
    if (state == MAPPING_PARKED)
      break;
    if (state == MAPPING_FAILED)
      mapping_capture_terminal();
    mapping_capture_wait(slot, state);
  }
  acquired = mapping_capture_now();
  exchanged = acquired;
  if (state == MAPPING_PARKED) {
    if (mapping_capture_test_signals()) {
      slot->test_caller_full_mask =
          mapping_capture_signal_test_blocked(&slot->caller_signals);
      if (!slot->test_caller_full_mask || !slot->test_helper_full_mask ||
          !mapping_capture_signal_test_arrivals(runtime_process_id) ||
          !mapping_capture_signal_test_arrivals((int32_t)slot->helper_tid))
        mapping_capture_terminal();
    }
    result = MAPPING_OWNER_CHANGED;
    if (atomic_load_explicit(&slot->eligible, memory_order_acquire) &&
        dr_mapping_capture_registry((void*)context, slot->helper_context, slot->helper_tid) &&
        mapping_capture_copy_owner(&slot->after) &&
        memcmp(&slot->before, &slot->after, sizeof(slot->before)) == 0) {
      if (mapping_capture_test_observer()) {
        for (size_t i = 0; i < 4; ++i)
          atomic_store_explicit(&slot->test_memory_events[i], 0, memory_order_relaxed);
        atomic_store_explicit(&slot->test_observer_active, true, memory_order_release);
      }
      if (test_mapping_capture == MAPPING_TEST_CLOSED_ALLOCATION) {
        // Deliberate real SDK allocation while the helper is parked. The
        // observer, not a manually set counter, must reject this capture.
        void* allocation = dr_global_alloc(16);
        if (allocation != NULL)
          dr_global_free(allocation, 16);
      }
      result = MAPPING_TRANSPORT;
      if (mapping_capture_exchange(slot, args, deadline, true)) {
        if (test_mapping_capture == MAPPING_TEST_FAIL_PARKED)
          mapping_capture_terminal();
        if (test_mapping_capture == MAPPING_TEST_STALE_GENERATION)
          ++slot->generation; // The real helper retained the earlier generation.
        result = MAPPING_OWNER_CHANGED;
        bool final_registry =
            dr_mapping_capture_registry((void*)context, slot->helper_context, slot->helper_tid);
        if (test_mapping_capture == MAPPING_TEST_OWNER_FINAL_BUSY)
          slot->test_final_flag_held =
              !atomic_flag_test_and_set_explicit(&task_state->lock, memory_order_acquire);
        bool final_owner = final_registry && mapping_capture_copy_owner(&slot->after);
        if (slot->test_final_flag_held)
          task_state_unlock();
        uint64_t original_image = slot->image;
        if (test_mapping_capture == MAPPING_TEST_IMAGE_CHANGED)
          slot->image ^= 1;
        // Corrupt only the returned copy, after a real controller observation.
        // The ordinary comparison must reject it and restore before returning.
        if (final_owner && test_mapping_capture == MAPPING_TEST_OWNER_FINAL_CHANGED)
          slot->after.version ^= 1;
        if (final_owner &&
            atomic_load_explicit(&slot->eligible, memory_order_acquire) &&
            runtime_process_epoch == slot->image &&
            memcmp(&slot->before, &slot->after, sizeof(slot->before)) == 0)
          result = MAPPING_READY;
        slot->image = original_image;
      }
      if (mapping_capture_test_observer()) {
        atomic_store_explicit(&slot->test_observer_active, false, memory_order_release);
        for (size_t i = 0; i < 4; ++i)
          if (atomic_load_explicit(&slot->test_memory_events[i], memory_order_relaxed) != 0)
            result = MAPPING_OWNER_CHANGED;
      }
    }
  }
  exchanged = mapping_capture_now();
  // Cancel only an unclaimed request without a helper ACK. Every other state
  // requires observed restoration, even when acquisition itself timed out.
  uint32_t expected = MAPPING_REQUESTED;
  if (!atomic_compare_exchange_strong_explicit(&slot->state, &expected, MAPPING_RESTORED,
          memory_order_acq_rel, memory_order_acquire)) {
    if (expected == MAPPING_FAILED)
      mapping_capture_terminal();
    while (expected == MAPPING_ENTERING || expected == MAPPING_PARKED) {
      if (atomic_compare_exchange_weak_explicit(&slot->state, &expected,
              MAPPING_RELEASE_REQUESTED, memory_order_acq_rel, memory_order_acquire))
        break;
    }
    if (expected == MAPPING_FAILED)
      mapping_capture_terminal();
    mapping_capture_wake(slot);
    uint64_t restore_deadline = mapping_capture_deadline(MAPPING_CAPTURE_RESTORE_NS);
    while (atomic_load_explicit(&slot->state, memory_order_acquire) != MAPPING_RESTORED) {
      if (!mapping_capture_before(restore_deadline) ||
          atomic_load_explicit(&slot->state, memory_order_acquire) == MAPPING_FAILED)
        mapping_capture_terminal();
      mapping_capture_wait(slot, MAPPING_RELEASE_REQUESTED);
    }
  }
  args->release_lease(args->lease, result == MAPPING_READY ? 1 : 0);
  if (dr_mapping_capture_control(DR_MAPPING_CAPTURE_RESTORE_SIGNALS,
          test_mapping_capture == MAPPING_TEST_CALLER_MASK_FAILURE
              ? UINTPTR_MAX : (uintptr_t)&slot->caller_mask, 0, 0) != 0)
    mapping_capture_terminal();
  if (mapping_capture_test_signals()) {
    slot->test_caller_signals_restored =
        mapping_capture_signal_test_finish(&slot->caller_signals);
    if (!slot->test_caller_signals_restored)
      mapping_capture_terminal();
  }
  atomic_store_explicit(&slot->transaction_active, false, memory_order_release);
  if (mapping_capture_test_signals())
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=signal-masks caller_full=%d helper_full=%d "
        "caller_restored=%d helper_restored=%d caller_pending=%d helper_pending=%d "
        "caller_original_mask=%llu caller_baseline_mask=%llu caller_blocked_mask=%llu "
        "caller_restored_mask=%llu caller_final_mask=%llu caller_pending_before=%llu "
        "caller_pending_after=%llu helper_original_mask=%llu helper_baseline_mask=%llu "
        "helper_blocked_mask=%llu helper_restored_mask=%llu helper_final_mask=%llu "
        "helper_pending_before=%llu helper_pending_after=%llu "
        "caller_initial_pending=%llu caller_prepared_pending=%llu caller_consumed=%llu "
        "helper_initial_pending=%llu helper_prepared_pending=%llu helper_consumed=%llu\n",
        slot->test_caller_full_mask, slot->test_helper_full_mask,
        slot->caller_signals.restored, slot->helper_signals.restored,
        slot->caller_signals.pending, slot->helper_signals.pending,
        (unsigned long long)slot->caller_signals.original_mask,
        (unsigned long long)slot->caller_signals.baseline_mask,
        (unsigned long long)slot->caller_signals.blocked_mask,
        (unsigned long long)slot->caller_signals.restored_mask,
        (unsigned long long)slot->caller_signals.final_mask,
        (unsigned long long)slot->caller_signals.pending_before,
        (unsigned long long)slot->caller_signals.pending_after,
        (unsigned long long)slot->helper_signals.original_mask,
        (unsigned long long)slot->helper_signals.baseline_mask,
        (unsigned long long)slot->helper_signals.blocked_mask,
        (unsigned long long)slot->helper_signals.restored_mask,
        (unsigned long long)slot->helper_signals.final_mask,
        (unsigned long long)slot->helper_signals.pending_before,
        (unsigned long long)slot->helper_signals.pending_after,
        (unsigned long long)slot->caller_signals.initial_pending,
        (unsigned long long)slot->caller_signals.prepared_pending,
        (unsigned long long)slot->caller_signals.consumed,
        (unsigned long long)slot->helper_signals.initial_pending,
        (unsigned long long)slot->helper_signals.prepared_pending,
        (unsigned long long)slot->helper_signals.consumed);
  if (test_mapping_capture != MAPPING_TEST_NONE) {
    uint64_t restored = mapping_capture_now();
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=restored result=%d acquire_ns=%llu exchange_ns=%llu "
        "restore_ns=%llu caller=%d helper=%d flag_clear=%d\n",
        result, (unsigned long long)(acquired - started),
        (unsigned long long)(exchanged - acquired),
        (unsigned long long)(restored - exchanged),
        (int)dr_get_thread_id(slot->application_context), (int)slot->helper_tid,
        slot->test_flag_clear);
  }
  if (test_mapping_capture == MAPPING_TEST_TRANSPORT_OVERSIZE ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_MALFORMED)
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=transport-fault kind=%s received_length=%u "
        "fault_value=%u response_length=%llu\n",
        test_mapping_capture == MAPPING_TEST_TRANSPORT_OVERSIZE ? "oversize" : "malformed",
        slot->test_received_length, slot->test_fault_value,
        (unsigned long long)args->response_length);
  if (test_mapping_capture == MAPPING_TEST_APP_ROLE)
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=app-role refused=%d\n", slot->test_role_refused);
  if (test_mapping_capture == MAPPING_TEST_OWNER_FINAL_BUSY ||
      test_mapping_capture == MAPPING_TEST_REGISTRY_BUSY ||
      test_mapping_capture == MAPPING_TEST_IMAGE_CHANGED)
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=final-input owner_held=%d registry_held=%d image_changed=%d\n",
        slot->test_final_flag_held, slot->test_registry_held,
        test_mapping_capture == MAPPING_TEST_IMAGE_CHANGED);
  if (test_mapping_capture == MAPPING_TEST_RAW_FLAG_CLEAR ||
      test_mapping_capture == MAPPING_TEST_RAW_FLAG_HELD ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_STALL)
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=raw-leaves seen=%llu blocked=%u injected=%d "
        "caller_stack_start=%llu caller_stack_end=%llu "
        "helper_stack_start=%llu helper_stack_end=%llu storage_owned=%d\n",
        (unsigned long long)slot->test_control_seen, slot->test_control_blocked,
        slot->test_control_injected,
        (unsigned long long)slot->caller_stack_start, (unsigned long long)slot->caller_stack_end,
        (unsigned long long)slot->helper_stack_start, (unsigned long long)slot->helper_stack_end,
        slot->test_storage_owned);
  if (test_mapping_capture == MAPPING_TEST_PARTIAL_FRAMES ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_EPIPE ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_EOF ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_STALL ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_OVERSIZE ||
      test_mapping_capture == MAPPING_TEST_TRANSPORT_MALFORMED)
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=transport send_calls=%llu recv_calls=%llu "
        "partial=%d last_result=%lld send_success=%llu recv_success=%llu "
        "send_bytes=%llu recv_bytes=%llu max_send=%llu max_recv=%llu\n",
        (unsigned long long)slot->test_send_calls,
        (unsigned long long)slot->test_recv_calls,
        test_mapping_capture == MAPPING_TEST_PARTIAL_FRAMES,
        (long long)slot->test_last_transfer,
        (unsigned long long)slot->test_send_success,
        (unsigned long long)slot->test_recv_success,
        (unsigned long long)slot->test_send_bytes,
        (unsigned long long)slot->test_recv_bytes,
        (unsigned long long)slot->test_max_send,
        (unsigned long long)slot->test_max_recv);
  if (mapping_capture_test_observer())
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=closed-observer allocations=%llu frees=%llu "
        "mappings=%llu protections=%llu storage_owned=%d\n",
        (unsigned long long)atomic_load_explicit(&slot->test_memory_events[0], memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&slot->test_memory_events[1], memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&slot->test_memory_events[2], memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&slot->test_memory_events[3], memory_order_relaxed),
        slot->test_storage_owned);
  if (test_mapping_capture == MAPPING_TEST_PRIVATE_SPLIT && slot->topology.phase > 0) {
    mapping_capture_topology_extent_t* view =
        slot->topology.observed[slot->topology.phase - 1];
    dr_fprintf(diagnostic_file,
        "MAPPING_CAPTURE_TEST phase=private-split step=%u address=%llu page_size=%llu "
        "owned=%d left_start=%llu left_end=%llu left_prot=%u "
        "middle_start=%llu middle_end=%llu middle_prot=%u "
        "right_start=%llu right_end=%llu right_prot=%u\n",
        slot->topology.phase, (unsigned long long)(uintptr_t)slot->topology.pointer,
        (unsigned long long)slot->topology.page, slot->topology.owned,
        (unsigned long long)view[0].start, (unsigned long long)view[0].end, view[0].protection,
        (unsigned long long)view[1].start, (unsigned long long)view[1].end, view[1].protection,
        (unsigned long long)view[2].start, (unsigned long long)view[2].end, view[2].protection);
  }
  if (result != MAPPING_READY)
    args->response_length = 0;
  return result;
}
