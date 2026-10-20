/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * The main thread starts a second thread, waits for it, then reaches a place
 * to set a software breakpoint and exits 0.
 *
 * Reverie neither delivers nor reports a SIGTRAP that no breakpoint accounts
 * for, so a stray int3 left at the site makes the guest run on from the byte
 * after it, 0x1f, an invalid opcode: the guest dies of SIGILL rather than
 * exiting 0.
 *
 * The label is a global symbol. The test builds this file with -no-pie, so
 * its symbol value is its run-time address.
 */

#include <pthread.h>

static void* body(void* arg) {
  return arg;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, 0, body, 0) != 0) {
    return 2;
  }
  if (pthread_join(thread, 0) != 0) {
    return 3;
  }
  __asm__ volatile(
      ".globl reverie_bkpt_main\n"
      "reverie_bkpt_main:\n"
      "  .byte 0x0f, 0x1f, 0x00\n" /* nopl (%rax) */
      "  .byte 0x0f, 0x1f, 0x00\n" /* nopl (%rax) */
  );
  return 0;
}
