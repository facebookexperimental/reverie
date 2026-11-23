/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Two stores to one global word: the worker thread's first, then the main
 * thread's after it joins the worker. The GDB tests set one hardware
 * watchpoint on the word and require both stores to stop. The stores and
 * the word are global symbols; the test builds this file with -no-pie,
 * so their symbol values are their run-time addresses.
 */

#include <pthread.h>
#include <stdint.h>

volatile uint64_t reverie_watched;
/* Set by the main thread to let the worker store: the frozen-sibling test
 * holds the worker spinning here while gdb holds the main thread's stop. */
volatile uint64_t reverie_release_worker;

static void *worker(void *unused) {
  (void)unused;
  while (!reverie_release_worker) {
  }
  __asm__ volatile(
      ".globl reverie_worker_store\n"
      "reverie_worker_store:\n"
      "  movq $1, reverie_watched(%%rip)\n"
      ".globl reverie_after_worker_store\n"
      "reverie_after_worker_store:\n"
      "  nop\n"
      :
      :
      : "memory");
  return 0;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) {
    return 2;
  }
  __asm__ volatile(
      ".globl reverie_main_before_release\n"
      "reverie_main_before_release:\n"
      "  nop\n"
      :
      :
      : "memory");
  reverie_release_worker = 1;
  if (pthread_join(thread, 0) != 0) {
    return 3;
  }
  __asm__ volatile(
      ".globl reverie_main_store\n"
      "reverie_main_store:\n"
      "  movq $2, reverie_watched(%%rip)\n"
      ".globl reverie_after_main_store\n"
      "reverie_after_main_store:\n"
      "  nop\n"
      :
      :
      : "memory");
  return reverie_watched == 2 ? 0 : 1;
}
