/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* Build.rs is the single source of truth for these cross-language constants. */
#ifndef REVERIE_E9PATCH_HANDOFF_PAGE
#error "missing REVERIE_E9PATCH_HANDOFF_PAGE"
#endif
#ifndef REVERIE_E9PATCH_AOT_MAGIC
#error "missing REVERIE_E9PATCH_AOT_MAGIC"
#endif

/*
 * Keep the legacy ptrace fallback first in .text. Writing this as assembly,
 * rather than a compiler-generated naked function, prevents toolchain hardening
 * prefixes from moving the injected-trap ABI at 0x70001000.
 */
/* TODO-HUMAN-REVIEW(PR-102): Review the rewritten-syscall trap payload. */
.section .text.000_trap,"ax",@progbits
.global reverie_e9patch_syscall
.type reverie_e9patch_syscall,@function
reverie_e9patch_syscall:
    movabs $0x7265766539653970, %rax
    int3
    ret
.size reverie_e9patch_syscall, .-reverie_e9patch_syscall

/*
 * E9tool's clean-call trampoline passes its writable STATE frame in RDI. When
 * the preload constructor has published the shared-dispatch callback, call it
 * in ordinary guest context. Otherwise jump to the byte-for-byte legacy ptrace
 * trap above, preserving the existing correctness fallback.
 */
/* TODO-HUMAN-REVIEW(PR-264): Review AOT trampoline routing through the shared
 * reverie-preload dispatcher. */
/* AUTONOMOUS-BOT-IMPLEMENTED */
.section .text.100_dispatch,"ax",@progbits
.global reverie_e9patch_dispatch
.type reverie_e9patch_dispatch,@function
reverie_e9patch_dispatch:
    /* Capture flags before the provenance checks below modify them. */
    pushfq
    pop %rsi
    lea reverie_e9patch_aot_page(%rip), %rax
    movabs $REVERIE_E9PATCH_AOT_MAGIC, %rdx
    cmp %rdx, (%rax)
    jne .Lfallback
    mov 8(%rax), %rax
    test %rax, %rax
    je .Lfallback

    /*
     * E9Tool's clean ABI neither aligns RSP for a System V call nor preserves
     * extended state. Save the callee-saved scratch registers, allocate an
     * aligned XSAVE area when the kernel enables XSAVE, and fall back to the
     * architectural FXSAVE area on older x86-64 hosts.
     */
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    push %rdi
    push %rsi
    push $0
    mov %rsp, %r12
    mov %rax, %r13

    mov $1, %eax
    cpuid
    mov %ecx, %eax
    and $0x0c000000, %eax
    cmp $0x0c000000, %eax
    jne .Lfxsave

    xor %ecx, %ecx
    xgetbv
    mov %eax, %r14d
    mov %edx, %r15d
    mov $0x0d, %eax
    xor %ecx, %ecx
    cpuid
    and $-64, %rsp
    sub %rbx, %rsp
    and $-64, %rsp
    /* XSAVE leaves reserved header bytes untouched; XRSTOR requires zero. */
    movq $0, 512(%rsp)
    movq $0, 520(%rsp)
    movq $0, 528(%rsp)
    movq $0, 536(%rsp)
    movq $0, 544(%rsp)
    movq $0, 552(%rsp)
    movq $0, 560(%rsp)
    movq $0, 568(%rsp)
    mov %r14d, %eax
    mov %r15d, %edx
    xsave64 (%rsp)
    cld
    call *%r13
    mov %rax, (%r12)
    mov %r14d, %eax
    mov %r15d, %edx
    xrstor64 (%rsp)
    jmp .Lrestore

.Lfxsave:
    and $-16, %rsp
    sub $512, %rsp
    fxsave64 (%rsp)
    cld
    call *%r13
    mov %rax, (%r12)
    fxrstor64 (%rsp)

.Lrestore:
    mov %r12, %rsp
    pop %rax
    pop %rcx
    pop %rdi
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    cmp $2, %rax
    je .Lrestore_flags_and_sigreturn
    test %rax, %rax
    je .Lrestore_flags_and_fallback
    push %rcx
    popfq
    ret
.Lrestore_flags_and_fallback:
    push %rcx
    popfq
.Lfallback:
    jmp reverie_e9patch_syscall
.Lrestore_flags_and_sigreturn:
    push %rcx
    popfq
    mov 128(%rdi), %rsp
    mov $15, %eax
    syscall
    ud2
.size reverie_e9patch_dispatch, .-reverie_e9patch_dispatch

/*
 * E9patch calls this hook after mapping all payload segments. A preload
 * constructor cannot write the embedded page directly because constructors run
 * before the e9patch loader; instead it publishes into the fixed handoff page.
 * Probe that page with mincore, copy a valid callback into the embedded page,
 * seal the embedded page read-only again, and consume the handoff mapping.
 */
.section .text.200_init,"ax",@progbits
.global init
.type init,@function
init:
    sub $8, %rsp
    movabs $REVERIE_E9PATCH_HANDOFF_PAGE, %rdi
    mov $4096, %esi
    mov %rsp, %rdx
    mov $27, %eax
    syscall
    test %rax, %rax
    je .Linit_mapped
    cmp $-12, %rax
    je .Linit_done
    jmp .Linit_fatal
.Linit_mapped:
    movabs $REVERIE_E9PATCH_HANDOFF_PAGE, %rax
    movabs $REVERIE_E9PATCH_AOT_MAGIC, %rdx
    cmp %rdx, (%rax)
    jne .Linit_fatal
    mov 8(%rax), %r8
    test %r8, %r8
    je .Linit_fatal

    lea reverie_e9patch_aot_page(%rip), %rdi
    mov $4096, %esi
    mov $3, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    jne .Linit_fatal
    mov %r8, 8(%rdi)
    mov $1, %edx
    mov $10, %eax
    syscall
    test %rax, %rax
    je .Linit_consume_handoff
    movq $0, 8(%rdi)
    jmp .Linit_fatal

.Linit_consume_handoff:
    movabs $REVERIE_E9PATCH_HANDOFF_PAGE, %rdi
    mov $4096, %esi
    mov $11, %eax
    syscall
.Linit_done:
    add $8, %rsp
    ret
.Linit_fatal:
    mov $127, %edi
    mov $231, %eax
    syscall
    ud2
.size init, .-init

/*
 * This isolated read-only page travels with every rewritten payload, so the
 * default no-preload path safely observes a null callback and uses ptrace.
 */
.section .rodata.100_aot_dispatch,"a",@progbits
.balign 4096
.global reverie_e9patch_aot_page
.type reverie_e9patch_aot_page,@object
reverie_e9patch_aot_page:
    .quad REVERIE_E9PATCH_AOT_MAGIC
    .quad 0
    .zero 4080
.size reverie_e9patch_aot_page, .-reverie_e9patch_aot_page

.section .note.GNU-stack,"",@progbits
