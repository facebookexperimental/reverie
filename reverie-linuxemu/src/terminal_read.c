/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "terminal_read.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

struct rvk_read {
  /* Immutable from preparation until destruction. No borrowed Rust objects. */
  int fd;
  uintptr_t address;
  size_t count;

  /* Child publication never takes this sender-admission mutex. */
  pthread_mutex_t send_mutex;
  pthread_cond_t send_drained;
  pthread_t thread;
  enum rvk_read_state state;
  bool terminal;
  bool handle_published;
  uint64_t senders;
  int join_error;

  /* One C publisher writes result/errno before the release outcome store.
   * The event lock is independent of send admission and of every Rust lock. */
  _Atomic unsigned outcome;
  ssize_t result;
  int read_errno;
  _Atomic uint64_t first_error;
  pthread_mutex_t event_mutex;
  pthread_cond_t event;
  _Atomic uint64_t epoch;

#ifdef RVK_READ_TEST
  _Atomic int fail_create;
  _Atomic int fail_cancel;
  _Atomic int fail_join;
#endif
};

#ifdef RVK_READ_TEST
#define TEST_HOOK(op, event) rvk_read_test_hook((op), (event))
#else
#define TEST_HOOK(op, event) ((void)0)
#endif

static int remember_error(struct rvk_read* op, unsigned phase, int error) {
  if (error != 0) {
    uint64_t empty = 0;
    uint64_t value = ((uint64_t)phase << 32) | (uint32_t)error;
    atomic_compare_exchange_strong_explicit(
        &op->first_error,
        &empty,
        value,
        memory_order_release,
        memory_order_relaxed);
  }
  return error;
}

static int lock(struct rvk_read* op, pthread_mutex_t* mutex) {
  return remember_error(op, RVK_READ_ERROR_SYNC, pthread_mutex_lock(mutex));
}

static int unlock(struct rvk_read* op, pthread_mutex_t* mutex) {
  return remember_error(op, RVK_READ_ERROR_SYNC, pthread_mutex_unlock(mutex));
}

uint64_t rvk_read_epoch(struct rvk_read* op) {
  return atomic_load_explicit(&op->epoch, memory_order_acquire);
}

int rvk_read_wake(struct rvk_read* op) {
  int error = lock(op, &op->event_mutex);
  if (error != 0) {
    return error;
  }
  atomic_fetch_add_explicit(&op->epoch, 1, memory_order_release);
  error = remember_error(
      op, RVK_READ_ERROR_SYNC, pthread_cond_broadcast(&op->event));
  int unlock_error = unlock(op, &op->event_mutex);
  return error != 0 ? error : unlock_error;
}

int rvk_read_wait(struct rvk_read* op, uint64_t observed_epoch) {
  int error = lock(op, &op->event_mutex);
  if (error != 0) {
    return error;
  }
  while (rvk_read_epoch(op) == observed_epoch && error == 0) {
    error = remember_error(
        op,
        RVK_READ_ERROR_SYNC,
        pthread_cond_wait(&op->event, &op->event_mutex));
  }
  int unlock_error = unlock(op, &op->event_mutex);
  return error != 0 ? error : unlock_error;
}

static void publish(struct rvk_read* op, enum rvk_read_outcome outcome) {
  atomic_store_explicit(&op->outcome, outcome, memory_order_release);
  rvk_read_wake(op);
  TEST_HOOK(op, RVK_READ_TEST_AFTER_OUTCOME);
}

static void canceled(void* opaque) {
  struct rvk_read* op = opaque;
  remember_error(
      op,
      RVK_READ_ERROR_CANCEL_STATE,
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
  /* No errno, retry, or claim about kernel progress is derived from this. */
  publish(op, RVK_READ_CANCELED);
}

static void* reader(void* opaque) {
  /* Newly created pthreads start with deferred cancellation. Before the first
   * cancellation point, disable it and install a C-only cleanup stack. */
  int error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  struct rvk_read* op = opaque;
  if (error != 0) {
    remember_error(op, RVK_READ_ERROR_CANCEL_STATE, error);
    publish(op, RVK_READ_NOT_STARTED);
    return NULL;
  }

  pthread_cleanup_push(canceled, op);
  error = remember_error(
      op,
      RVK_READ_ERROR_CANCEL_TYPE,
      pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL));
  if (error == 0) {
    TEST_HOOK(op, RVK_READ_TEST_BEFORE_ENABLE);
    error = remember_error(
        op,
        RVK_READ_ERROR_CANCEL_STATE,
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL));
  }
  if (error == 0) {
    TEST_HOOK(op, RVK_READ_TEST_BEFORE_READ);
    ssize_t result = read(op->fd, (void*)op->address, op->count);
    int read_errno = errno;
    /* The test hook uses only atomics/pause here, never a cancellation point.
     * Production has no hook or intervening call before cancellation disable.
     * A public read return survives a late deferred cancellation request. */
    TEST_HOOK(op, RVK_READ_TEST_AFTER_READ);
    remember_error(
        op,
        RVK_READ_ERROR_CANCEL_STATE,
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
    op->result = result;
    op->read_errno = read_errno;
    publish(op, RVK_READ_RETURNED);
  } else {
    publish(op, RVK_READ_NOT_STARTED);
  }
  pthread_cleanup_pop(0);
  return NULL;
}

struct rvk_read*
rvk_read_new(int fd, uintptr_t address, size_t count, int* error) {
  *error = 0;
  if (count != 0) {
    *error = EINVAL;
    return NULL;
  }
  struct rvk_read* op = calloc(1, sizeof(*op));
  if (op == NULL) {
    *error = ENOMEM;
    return NULL;
  }
  op->fd = fd;
  op->address = address;
  op->count = count;
  op->state = RVK_READ_PREPARED;
  atomic_init(&op->outcome, RVK_READ_PENDING);
  atomic_init(&op->first_error, 0);
  atomic_init(&op->epoch, 0);
#ifdef RVK_READ_TEST
  atomic_init(&op->fail_create, 0);
  atomic_init(&op->fail_cancel, 0);
  atomic_init(&op->fail_join, 0);
#endif
  *error = pthread_mutex_init(&op->send_mutex, NULL);
  if (*error != 0) {
    free(op);
    return NULL;
  }
  *error = pthread_cond_init(&op->send_drained, NULL);
  if (*error != 0) {
    pthread_mutex_destroy(&op->send_mutex);
    free(op);
    return NULL;
  }
  *error = pthread_mutex_init(&op->event_mutex, NULL);
  if (*error != 0) {
    pthread_cond_destroy(&op->send_drained);
    pthread_mutex_destroy(&op->send_mutex);
    free(op);
    return NULL;
  }
  *error = pthread_cond_init(&op->event, NULL);
  if (*error != 0) {
    pthread_mutex_destroy(&op->event_mutex);
    pthread_cond_destroy(&op->send_drained);
    pthread_mutex_destroy(&op->send_mutex);
    free(op);
    return NULL;
  }
  return op;
}

int rvk_read_start(struct rvk_read* op) {
  int error = lock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  if (op->state != RVK_READ_PREPARED) {
    unlock(op, &op->send_mutex);
    return EALREADY;
  }
  if (op->terminal) {
    op->state = RVK_READ_NO_THREAD;
    unlock(op, &op->send_mutex);
    publish(op, RVK_READ_NOT_STARTED);
    return 0;
  }
  op->state = RVK_READ_CREATING;
  error = unlock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }

  TEST_HOOK(op, RVK_READ_TEST_BEFORE_CREATE);
  pthread_t thread;
#ifdef RVK_READ_TEST
  error = atomic_exchange(&op->fail_create, 0);
  if (error == 0)
#endif
    error = pthread_create(&thread, NULL, reader, op);
  if (error != 0) {
    remember_error(op, RVK_READ_ERROR_CREATE, error);
    int lock_error = lock(op, &op->send_mutex);
    if (lock_error != 0) {
      return lock_error;
    }
    op->state = RVK_READ_NO_THREAD;
    unlock(op, &op->send_mutex);
    publish(op, RVK_READ_NOT_STARTED);
    return error;
  }
  /* Creation ownership exists before public send admission. While CREATING,
   * only this creator accesses thread; publication synchronizes later users. */
  op->thread = thread;
  TEST_HOOK(op, RVK_READ_TEST_AFTER_CREATE);

  error = lock(op, &op->send_mutex);
  if (error != 0) {
    /* Retain storage; the owner must not infer that creation failed. */
    return error;
  }
  op->handle_published = true;
  op->state = RVK_READ_CALLABLE;
  bool cancel = op->terminal &&
      atomic_load_explicit(&op->outcome, memory_order_acquire) ==
          RVK_READ_PENDING;
  error = unlock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  /* request_cancel rechecks outcome under admission synchronization. An early
   * child completion never opens a fresh send window on handle publication. */
  return cancel ? rvk_read_request_cancel(op) : 0;
}

int rvk_read_request_cancel(struct rvk_read* op) {
  int error = lock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  op->terminal = true;
  bool send = op->state == RVK_READ_CALLABLE && op->handle_published &&
      atomic_load_explicit(&op->outcome, memory_order_acquire) ==
          RVK_READ_PENDING;
  pthread_t thread;
  if (send) {
    ++op->senders;
    thread = op->thread;
  }
  error = unlock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  if (!send) {
    return rvk_read_wake(op);
  }

  TEST_HOOK(op, RVK_READ_TEST_BEFORE_CANCEL);
#ifdef RVK_READ_TEST
  error = atomic_exchange(&op->fail_cancel, 0);
  if (error == 0)
#endif
    error = pthread_cancel(thread);
  remember_error(op, RVK_READ_ERROR_CANCEL, error);
  TEST_HOOK(op, RVK_READ_TEST_AFTER_CANCEL);
  int lock_error = lock(op, &op->send_mutex);
  if (lock_error != 0) {
    /* The lease remains counted on a synchronization failure. */
    return lock_error;
  }
  --op->senders;
  int signal_error = remember_error(
      op, RVK_READ_ERROR_SYNC, pthread_cond_broadcast(&op->send_drained));
  int unlock_error = unlock(op, &op->send_mutex);
  int wake_error = rvk_read_wake(op);
  return error != 0       ? error
      : signal_error != 0 ? signal_error
      : unlock_error != 0 ? unlock_error
                          : wake_error;
}

int rvk_read_snapshot(struct rvk_read* op, struct rvk_read_snapshot* snapshot) {
  int error = lock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  snapshot->outcome = atomic_load_explicit(&op->outcome, memory_order_acquire);
  snapshot->result = snapshot->outcome == RVK_READ_RETURNED ? op->result : 0;
  snapshot->read_errno =
      snapshot->outcome == RVK_READ_RETURNED ? op->read_errno : 0;
  snapshot->senders = op->senders;
  snapshot->state = op->state;
  snapshot->terminal = op->terminal;
  snapshot->handle_published = op->handle_published;
  uint64_t first_error =
      atomic_load_explicit(&op->first_error, memory_order_acquire);
  snapshot->error_phase = first_error >> 32;
  snapshot->error_number = (int32_t)(uint32_t)first_error;
  return unlock(op, &op->send_mutex);
}

int rvk_read_finish(struct rvk_read* op) {
  int error = lock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  if (op->state == RVK_READ_PREPARED) {
    op->state = RVK_READ_NO_THREAD;
    unlock(op, &op->send_mutex);
    publish(op, RVK_READ_NOT_STARTED);
    return 0;
  }
  if (op->state == RVK_READ_JOINED || op->state == RVK_READ_NO_THREAD) {
    return unlock(op, &op->send_mutex);
  }
  if (op->state == RVK_READ_JOIN_FAILED) {
    error = op->join_error;
    unlock(op, &op->send_mutex);
    return error;
  }
  if (op->state != RVK_READ_CALLABLE ||
      atomic_load_explicit(&op->outcome, memory_order_acquire) ==
          RVK_READ_PENDING) {
    unlock(op, &op->send_mutex);
    return EBUSY;
  }
  op->state = RVK_READ_DISARMED;
  error = unlock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  TEST_HOOK(op, RVK_READ_TEST_DISARMED);

  error = lock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  while (op->senders != 0 && error == 0) {
    error = remember_error(
        op,
        RVK_READ_ERROR_SYNC,
        pthread_cond_wait(&op->send_drained, &op->send_mutex));
  }
  if (error != 0) {
    unlock(op, &op->send_mutex);
    return error;
  }
  op->state = RVK_READ_JOINING;
  pthread_t thread = op->thread;
  error = unlock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  TEST_HOOK(op, RVK_READ_TEST_BEFORE_JOIN);
#ifdef RVK_READ_TEST
  error = atomic_exchange(&op->fail_join, 0);
  if (error == 0)
#endif
    error = pthread_join(thread, NULL);
  remember_error(op, RVK_READ_ERROR_JOIN, error);
  TEST_HOOK(op, RVK_READ_TEST_AFTER_JOIN);

  int lock_error = lock(op, &op->send_mutex);
  if (lock_error != 0) {
    return lock_error;
  }
  op->join_error = error;
  op->state = error == 0 ? RVK_READ_JOINED : RVK_READ_JOIN_FAILED;
  int unlock_error = unlock(op, &op->send_mutex);
  return error != 0 ? error : unlock_error;
}

int rvk_read_destroy(struct rvk_read* op) {
  int error = lock(op, &op->send_mutex);
  if (error != 0) {
    return error;
  }
  bool safe = op->senders == 0 &&
      (op->state == RVK_READ_PREPARED || op->state == RVK_READ_NO_THREAD ||
       op->state == RVK_READ_JOINED);
  error = unlock(op, &op->send_mutex);
  if (error != 0 || !safe) {
    return error != 0 ? error : EBUSY;
  }
  /* The caller has retired all users, not only cancel senders. On any destroy
   * error, retain the allocation; it must never be used or freed thereafter. */
  error =
      remember_error(op, RVK_READ_ERROR_SYNC, pthread_cond_destroy(&op->event));
  if (error == 0) {
    error = remember_error(
        op, RVK_READ_ERROR_SYNC, pthread_cond_destroy(&op->send_drained));
  }
  if (error == 0) {
    error = remember_error(
        op, RVK_READ_ERROR_SYNC, pthread_mutex_destroy(&op->event_mutex));
  }
  if (error == 0) {
    error = remember_error(
        op, RVK_READ_ERROR_SYNC, pthread_mutex_destroy(&op->send_mutex));
  }
  if (error == 0) {
    free(op);
  }
  return error;
}

#ifdef RVK_READ_TEST
void rvk_read_test_fail(
    struct rvk_read* op,
    enum rvk_read_error_phase phase,
    int error) {
  switch (phase) {
    case RVK_READ_ERROR_CREATE:
      atomic_store(&op->fail_create, error);
      break;
    case RVK_READ_ERROR_CANCEL:
      atomic_store(&op->fail_cancel, error);
      break;
    case RVK_READ_ERROR_JOIN:
      atomic_store(&op->fail_join, error);
      break;
    default:
      abort();
  }
}
#endif
