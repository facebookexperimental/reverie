/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the repository root LICENSE.
 *
 * Native observation/seeding bridge retained from the bounded continuation
 * experiment. The syscall crosses a cache line so production must use fallback.
 * No guest-stack read occurs after its rights/protection are changed.
 */
.globl owned_frame_enter_guest
.type owned_frame_enter_guest,@function
owned_frame_enter_guest:
    mov %rsp,0(%rdi)
    mov %rbx,8(%rdi)
    mov %rbp,16(%rdi)
    mov %r12,24(%rdi)
    mov %r13,32(%rdi)
    mov %r14,40(%rdi)
    mov %r15,48(%rdi)
    mov %rdi,%r15
    fninit
    fld1
    fldpi
    fldl2e
    fldcw 376(%r15)
    ldmxcsr 368(%r15)
    movdqu 448(%r15),%xmm0
    movdqu 448(%r15),%xmm1
    movdqu 448(%r15),%xmm2
    movdqu 448(%r15),%xmm3
    movdqu 448(%r15),%xmm4
    movdqu 448(%r15),%xmm5
    movdqu 448(%r15),%xmm6
    movdqu 448(%r15),%xmm7
    movdqu 448(%r15),%xmm8
    movdqu 448(%r15),%xmm9
    movdqu 448(%r15),%xmm10
    movdqu 448(%r15),%xmm11
    movdqu 448(%r15),%xmm12
    movdqu 448(%r15),%xmm13
    movdqu 448(%r15),%xmm14
    movdqu 448(%r15),%xmm15
    cmpq $0,152(%r15)
    je .Lseed_done
    vmovdqu 448(%r15),%ymm0
    vmovdqu 448(%r15),%ymm1
    vmovdqu 448(%r15),%ymm2
    vmovdqu 448(%r15),%ymm3
    vmovdqu 448(%r15),%ymm4
    vmovdqu 448(%r15),%ymm5
    vmovdqu 448(%r15),%ymm6
    vmovdqu 448(%r15),%ymm7
    vmovdqu 448(%r15),%ymm8
    vmovdqu 448(%r15),%ymm9
    vmovdqu 448(%r15),%ymm10
    vmovdqu 448(%r15),%ymm11
    vmovdqu 448(%r15),%ymm12
    vmovdqu 448(%r15),%ymm13
    vmovdqu 448(%r15),%ymm14
    vmovdqu 448(%r15),%ymm15
    cmpq $0,160(%r15)
    je .Lseed_done
    vmovdqu64 448(%r15),%zmm0
    vmovdqu64 448(%r15),%zmm1
    vmovdqu64 448(%r15),%zmm2
    vmovdqu64 448(%r15),%zmm3
    vmovdqu64 448(%r15),%zmm4
    vmovdqu64 448(%r15),%zmm5
    vmovdqu64 448(%r15),%zmm6
    vmovdqu64 448(%r15),%zmm7
    vmovdqu64 448(%r15),%zmm8
    vmovdqu64 448(%r15),%zmm9
    vmovdqu64 448(%r15),%zmm10
    vmovdqu64 448(%r15),%zmm11
    vmovdqu64 448(%r15),%zmm12
    vmovdqu64 448(%r15),%zmm13
    vmovdqu64 448(%r15),%zmm14
    vmovdqu64 448(%r15),%zmm15
    vmovdqu64 448(%r15),%zmm16
    vmovdqu64 448(%r15),%zmm17
    vmovdqu64 448(%r15),%zmm18
    vmovdqu64 448(%r15),%zmm19
    vmovdqu64 448(%r15),%zmm20
    vmovdqu64 448(%r15),%zmm21
    vmovdqu64 448(%r15),%zmm22
    vmovdqu64 448(%r15),%zmm23
    vmovdqu64 448(%r15),%zmm24
    vmovdqu64 448(%r15),%zmm25
    vmovdqu64 448(%r15),%zmm26
    vmovdqu64 448(%r15),%zmm27
    vmovdqu64 448(%r15),%zmm28
    vmovdqu64 448(%r15),%zmm29
    vmovdqu64 448(%r15),%zmm30
    vmovdqu64 448(%r15),%zmm31
    movabs $0x123456789abcdef0,%rax
    kmovq %rax,%k0
    kmovq %rax,%k1
    kmovq %rax,%k2
    kmovq %rax,%k3
    kmovq %rax,%k4
    kmovq %rax,%k5
    kmovq %rax,%k6
    kmovq %rax,%k7
.Lseed_done:
    /* Seed arithmetic flags and DF; IF remains user-enabled, TF/RF excluded. */
    pushq $0xed7
    popfq
    mov 120(%r15),%rsp
    mov 136(%r15),%eax
    mov $0,%ecx
    mov $0,%edx
    wrpkru
    lfence
    /* r15 is on the accessible observation key, even with key zero denied. */
    mov 64(%r15),%rax
    mov 72(%r15),%rdi
    mov 80(%r15),%rsi
    mov 88(%r15),%rdx
    mov 96(%r15),%r10
    mov 104(%r15),%r8
    mov 112(%r15),%r9
    movabs $0x1212121212121212,%r12
    movabs $0x1313131313131313,%r13
    movabs $0x1414141414141414,%r14
    movabs $0xb0b0b0b0b0b0b0b0,%rbp
    movabs $0xb1b1b1b1b1b1b1b1,%rbx
    movabs $0xcccccccccccccccc,%rcx
    movabs $0x1111111111111111,%r11
.balign 64, 0x90
.fill 63, 1, 0x90
.globl owned_frame_guest_syscall
owned_frame_guest_syscall:
    syscall
.globl owned_frame_guest_resume
owned_frame_guest_resume:
    mov %r8,192(%r15)
    mov %r9,200(%r15)
    mov %r10,208(%r15)
    mov %r11,216(%r15)
    mov %r12,224(%r15)
    mov %r13,232(%r15)
    mov %r14,240(%r15)
    mov %r15,248(%r15)
    mov %rdi,256(%r15)
    mov %rsi,264(%r15)
    mov %rbp,272(%r15)
    mov %rbx,280(%r15)
    mov %rdx,288(%r15)
    mov %rax,296(%r15)
    mov %rcx,304(%r15)
    mov %rsp,312(%r15)
    lea owned_frame_guest_resume(%rip),%rax
    mov %rax,320(%r15)
    /* The original RSP has been observed; it is never dereferenced. */
    mov 128(%r15),%rsp
    pushfq
    pop %rax
    mov %rax,328(%r15)
    cld
    xor %eax,%eax
    mov %ss,%ax
    shl $16,%rax
    mov %fs,%ax
    shl $16,%rax
    mov %gs,%ax
    shl $16,%rax
    mov %cs,%ax
    mov %rax,336(%r15)
    xor %ecx,%ecx
    rdpkru
    mov %rax,344(%r15)
    mov 56(%r15),%rax
    mov %rax,%rdx
    shr $32,%rdx
    xsave64 512(%r15)
    movq $1,352(%r15)
    /* Measurement is complete. Both native and mediated controls now leave
     * guest observation and restore harness rights before touching its stack. */
    mov 144(%r15),%eax
    xor %ecx,%ecx
    xor %edx,%edx
    wrpkru
    lfence
    fninit
    movl $0x1f80,368(%r15)
    ldmxcsr 368(%r15)
    mov 0(%r15),%rsp
    mov 8(%r15),%rbx
    mov 16(%r15),%rbp
    mov 24(%r15),%r12
    mov 32(%r15),%r13
    mov 40(%r15),%r14
    mov 48(%r15),%r15
    ret
.size owned_frame_enter_guest,.-owned_frame_enter_guest

.globl owned_frame_clobber_guest_fp
.type owned_frame_clobber_guest_fp,@function
owned_frame_clobber_guest_fp:
    /* Ordinary owned stack; deliberately clobber MXCSR as well as vectors. */
    sub $8,%rsp
    movl $0x1f80,(%rsp)
    ldmxcsr (%rsp)
    add $8,%rsp
    fninit
    pxor %xmm0,%xmm0
    pxor %xmm1,%xmm1
    pxor %xmm2,%xmm2
    pxor %xmm3,%xmm3
    pxor %xmm4,%xmm4
    pxor %xmm5,%xmm5
    pxor %xmm6,%xmm6
    pxor %xmm7,%xmm7
    pxor %xmm8,%xmm8
    pxor %xmm9,%xmm9
    pxor %xmm10,%xmm10
    pxor %xmm11,%xmm11
    pxor %xmm12,%xmm12
    pxor %xmm13,%xmm13
    pxor %xmm14,%xmm14
    pxor %xmm15,%xmm15
    test %edi,%edi
    jz .Lclobber_done
    vzeroall
    test %esi,%esi
    jz .Lclobber_done
    vpxord %zmm0,%zmm0,%zmm0
    vpxord %zmm1,%zmm1,%zmm1
    vpxord %zmm2,%zmm2,%zmm2
    vpxord %zmm3,%zmm3,%zmm3
    vpxord %zmm4,%zmm4,%zmm4
    vpxord %zmm5,%zmm5,%zmm5
    vpxord %zmm6,%zmm6,%zmm6
    vpxord %zmm7,%zmm7,%zmm7
    vpxord %zmm8,%zmm8,%zmm8
    vpxord %zmm9,%zmm9,%zmm9
    vpxord %zmm10,%zmm10,%zmm10
    vpxord %zmm11,%zmm11,%zmm11
    vpxord %zmm12,%zmm12,%zmm12
    vpxord %zmm13,%zmm13,%zmm13
    vpxord %zmm14,%zmm14,%zmm14
    vpxord %zmm15,%zmm15,%zmm15
    vpxord %zmm16,%zmm16,%zmm16
    vpxord %zmm17,%zmm17,%zmm17
    vpxord %zmm18,%zmm18,%zmm18
    vpxord %zmm19,%zmm19,%zmm19
    vpxord %zmm20,%zmm20,%zmm20
    vpxord %zmm21,%zmm21,%zmm21
    vpxord %zmm22,%zmm22,%zmm22
    vpxord %zmm23,%zmm23,%zmm23
    vpxord %zmm24,%zmm24,%zmm24
    vpxord %zmm25,%zmm25,%zmm25
    vpxord %zmm26,%zmm26,%zmm26
    vpxord %zmm27,%zmm27,%zmm27
    vpxord %zmm28,%zmm28,%zmm28
    vpxord %zmm29,%zmm29,%zmm29
    vpxord %zmm30,%zmm30,%zmm30
    vpxord %zmm31,%zmm31,%zmm31
    kxorq %k0,%k0,%k0
    kxorq %k1,%k1,%k1
    kxorq %k2,%k2,%k2
    kxorq %k3,%k3,%k3
    kxorq %k4,%k4,%k4
    kxorq %k5,%k5,%k5
    kxorq %k6,%k6,%k6
    kxorq %k7,%k7,%k7
.Lclobber_done:
    ret
.size owned_frame_clobber_guest_fp,.-owned_frame_clobber_guest_fp
.section .note.GNU-stack,"",@progbits
