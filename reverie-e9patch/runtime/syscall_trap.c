/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Build.rs is the single source of truth for these cross-language constants. */
#ifndef REVERIE_E9PATCH_AOT_PAGE
#error "missing REVERIE_E9PATCH_AOT_PAGE"
#endif
#ifndef REVERIE_E9PATCH_AOT_MAGIC
#error "missing REVERIE_E9PATCH_AOT_MAGIC"
#endif
#ifndef REVERIE_E9PATCH_TRAP_ENTRY
#error "missing REVERIE_E9PATCH_TRAP_ENTRY"
#endif

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)

/*
 * Keep the legacy ptrace fallback first in .text. The injected-trap ABI binds
 * this entry to 0x70001000 and recognizes the magic RAX value at the int3.
 */
// TODO-HUMAN-REVIEW(PR-102): Review the rewritten-syscall trap payload.
__attribute__((naked, used, section(".text.000_trap"))) void
reverie_e9patch_syscall(void *state __attribute__((unused))) {
  __asm__ volatile("movabs $0x7265766539653970, %rax\n\t"
                   "int3\n\t"
                   "ret\n\t");
}

/*
 * E9tool's clean-call trampoline passes its writable STATE frame in RDI. When
 * the preload constructor has published the shared-dispatch callback, call it
 * in ordinary guest context. Otherwise jump to the byte-for-byte legacy ptrace
 * trap above, preserving the existing correctness fallback.
 */
// TODO-HUMAN-REVIEW(PR-pending): Review AOT trampoline routing through the
// shared reverie-preload dispatcher.
// AUTONOMOUS-BOT-IMPLEMENTED
__attribute__((naked, used, section(".text.100_dispatch"))) void
reverie_e9patch_dispatch(void *state __attribute__((unused))) {
  __asm__ volatile(
      /* Capture flags before the provenance checks below modify them. */
      "pushfq\n\t"
      "pop %rsi\n\t"
      "movabs $" STRINGIFY(REVERIE_E9PATCH_AOT_PAGE) ", %rax\n\t"
      "movabs $" STRINGIFY(REVERIE_E9PATCH_AOT_MAGIC) ", %rdx\n\t"
      "cmp %rdx, (%rax)\n\t"
      "jne 1f\n\t"
      "mov 8(%rax), %rax\n\t"
      "test %rax, %rax\n\t"
      "je 1f\n\t"
      /* SysV requires RSP to be 16-byte aligned before the nested call. */
      "sub $8, %rsp\n\t"
      "call *%rax\n\t"
      "add $8, %rsp\n\t"
      "ret\n\t"
      "1:\n\t"
      "movabs $" STRINGIFY(REVERIE_E9PATCH_TRAP_ENTRY) ", %rax\n\t"
      "jmp *%rax\n\t");
}
