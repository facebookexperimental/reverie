/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Negative control for the DBI guest-stack scrub (`scrub_guest_stack_residue`
 * in `reverie-dbi/native/client.c`): the scrub must not erase the guest's own
 * dead stack.
 *
 * The scrub removes DynamoRIO's addresses from the dead part of the guest's
 * `[stack]` VMA, because they are re-randomized every run and make Detcore's
 * `--detlog-stack` hash differ run to run. The hazard is that "dead" is a
 * property of the ABI, not a statement of ownership: the guest's own popped
 * frames live in the same range. An earlier revision selected bytes by position
 * -- every nonzero byte below the stack pointer minus the red zone -- and so
 * deleted guest data. Measured then: native and ptrace preserved a planted
 * marker (90/90/90) while DBI zeroed it after a clone in 4 of 4 runs.
 *
 * The clone is the load-bearing part. Servicing a clone-family syscall re-arms
 * the scrub, so the parent's next syscall runs a full scan at a point where the
 * guest has already accumulated dead frames. A plant with no clone after it
 * never reaches that path, which is why the original mutation bracket missed
 * this.
 *
 * Deliberately backend-agnostic and free of any DynamoRIO knowledge: it plants,
 * clones, and reads back. The same binary is the native and ptrace control.
 * Note it must not consult `/proc/self/maps` to find its stack -- the DBI
 * client virtualizes that file for the guest -- so the marker is anchored off
 * the running frame's own address instead.
 *
 * Output, one line, parsed by the driving script:
 *
 *   stack-scrub-marker before=<n> after_plain=<n> after_clone=<n>
 *
 * Exit status: 0 when all three counts equal MARKER_WORDS, 42 when any marker
 * word was modified (the product failure this brackets), 2 on harness trouble
 * so a broken environment is never read as a product failure.
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define HARNESS_FAILURE 2
#define MARKER_MISMATCH 42

/* How far below the running frame the marker is planted.
 *
 * Deep enough that no libc frame reaches it -- `printf` and `fork` are the
 * hungriest calls here and use on the order of a kilobyte -- and shallow enough
 * to stay inside the 64 KiB + 256 B window below the stack pointer that every
 * Linux version will auto-grow the main stack for. */
#define MARKER_DEPTH_BYTES 32768
#define MARKER_WORDS 90
/* Neutral: not a pointer, not zero, not a value DynamoRIO deals in. */
#define MARKER_BYTE 0x5a

/* Counts how many planted words still hold the marker pattern. `volatile` so
 * the compiler cannot decide the region is dead and skip the reads: that
 * memory is precisely what is under test. */
static int surviving_marker_words(volatile const unsigned char *marker) {
  int intact = 0;
  for (int word = 0; word < MARKER_WORDS; ++word) {
    bool whole = true;
    for (size_t at = 0; at < sizeof(uintptr_t); ++at) {
      if (marker[(size_t)word * sizeof(uintptr_t) + at] != MARKER_BYTE)
        whole = false;
    }
    if (whole)
      ++intact;
  }
  return intact;
}

int main(void) {
  /* Anchor off this frame, so the marker is below the stack pointer and thus
   * dead by the ABI -- inside the range the scrub is allowed to consider. */
  unsigned char here = 0;
  uintptr_t anchor = (uintptr_t)&here;
  if (anchor <= MARKER_DEPTH_BYTES) {
    fprintf(stderr, "stack-scrub-marker: implausible stack address\n");
    return HARNESS_FAILURE;
  }
  volatile unsigned char *marker =
      (volatile unsigned char *)(anchor - MARKER_DEPTH_BYTES);

  for (size_t at = 0; at < (size_t)MARKER_WORDS * sizeof(uintptr_t); ++at)
    marker[at] = MARKER_BYTE;
  int before = surviving_marker_words(marker);

  /* An ordinary syscall. The scrub runs in the client's pre-syscall hook, so
   * this separates "a scrub erased it" from "the plant never took", and shows
   * the un-re-armed path is already quiet. */
  (void)getpid();
  int after_plain = surviving_marker_words(marker);

  /* The path under test: servicing a clone re-arms the scrub, so the parent's
   * next syscall runs a full scan with the guest's dead frames -- this marker
   * among them -- already in place. */
  fflush(stdout);
  pid_t child = fork();
  if (child < 0) {
    fprintf(stderr, "stack-scrub-marker: fork failed\n");
    return HARNESS_FAILURE;
  }
  if (child == 0)
    _exit(0);
  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    fprintf(stderr, "stack-scrub-marker: waitpid failed\n");
    return HARNESS_FAILURE;
  }
  (void)getpid();
  int after_clone = surviving_marker_words(marker);

  printf("stack-scrub-marker before=%d after_plain=%d after_clone=%d\n", before,
         after_plain, after_clone);

  if (before != MARKER_WORDS || after_plain != MARKER_WORDS ||
      after_clone != MARKER_WORDS)
    return MARKER_MISMATCH;
  return 0;
}
