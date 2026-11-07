.text
.globl probe_state
.type probe_state,@function
probe_state:
  push %rbx
  push %r12
  push %r13
  push %r14
  push %r15
  mov %rdi,%r12
  mov %rsi,%r13
  mov %rdx,%r15
  mov probe_vector_level(%rip),%r14d
  cmpl $0,probe_use_xsave(%rip)
  je 1f
  mov probe_xsave_mask(%rip),%eax
  xor %edx,%edx
  xsave64 probe_original(%rip)
  jmp 2f
1:
  fxsave64 probe_original(%rip)
2:
  fninit
  fldcw probe_fcw(%rip)
  ldmxcsr probe_mxcsr(%rip)
  fldt probe_x87+0(%rip)
  fldt probe_x87+10(%rip)
  fldt probe_x87+20(%rip)
  fldt probe_x87+30(%rip)
  fldt probe_x87+40(%rip)
  fldt probe_x87+50(%rip)
  fldt probe_x87+60(%rip)
  fldt probe_x87+70(%rip)
  cmp $2,%r14d
  je 4f
  cmp $1,%r14d
  je 3f
  movdqu probe_seed+0(%rip),%xmm0
  movdqu probe_seed+64(%rip),%xmm1
  movdqu probe_seed+128(%rip),%xmm2
  movdqu probe_seed+192(%rip),%xmm3
  movdqu probe_seed+256(%rip),%xmm4
  movdqu probe_seed+320(%rip),%xmm5
  movdqu probe_seed+384(%rip),%xmm6
  movdqu probe_seed+448(%rip),%xmm7
  movdqu probe_seed+512(%rip),%xmm8
  movdqu probe_seed+576(%rip),%xmm9
  movdqu probe_seed+640(%rip),%xmm10
  movdqu probe_seed+704(%rip),%xmm11
  movdqu probe_seed+768(%rip),%xmm12
  movdqu probe_seed+832(%rip),%xmm13
  movdqu probe_seed+896(%rip),%xmm14
  movdqu probe_seed+960(%rip),%xmm15
  jmp 5f
3:
  vmovdqu probe_seed+0(%rip),%ymm0
  vmovdqu probe_seed+64(%rip),%ymm1
  vmovdqu probe_seed+128(%rip),%ymm2
  vmovdqu probe_seed+192(%rip),%ymm3
  vmovdqu probe_seed+256(%rip),%ymm4
  vmovdqu probe_seed+320(%rip),%ymm5
  vmovdqu probe_seed+384(%rip),%ymm6
  vmovdqu probe_seed+448(%rip),%ymm7
  vmovdqu probe_seed+512(%rip),%ymm8
  vmovdqu probe_seed+576(%rip),%ymm9
  vmovdqu probe_seed+640(%rip),%ymm10
  vmovdqu probe_seed+704(%rip),%ymm11
  vmovdqu probe_seed+768(%rip),%ymm12
  vmovdqu probe_seed+832(%rip),%ymm13
  vmovdqu probe_seed+896(%rip),%ymm14
  vmovdqu probe_seed+960(%rip),%ymm15
  jmp 5f
4:
  vmovdqu64 probe_seed+0(%rip),%zmm0
  vmovdqu64 probe_seed+64(%rip),%zmm1
  vmovdqu64 probe_seed+128(%rip),%zmm2
  vmovdqu64 probe_seed+192(%rip),%zmm3
  vmovdqu64 probe_seed+256(%rip),%zmm4
  vmovdqu64 probe_seed+320(%rip),%zmm5
  vmovdqu64 probe_seed+384(%rip),%zmm6
  vmovdqu64 probe_seed+448(%rip),%zmm7
  vmovdqu64 probe_seed+512(%rip),%zmm8
  vmovdqu64 probe_seed+576(%rip),%zmm9
  vmovdqu64 probe_seed+640(%rip),%zmm10
  vmovdqu64 probe_seed+704(%rip),%zmm11
  vmovdqu64 probe_seed+768(%rip),%zmm12
  vmovdqu64 probe_seed+832(%rip),%zmm13
  vmovdqu64 probe_seed+896(%rip),%zmm14
  vmovdqu64 probe_seed+960(%rip),%zmm15
  vmovdqu64 probe_seed+1024(%rip),%zmm16
  vmovdqu64 probe_seed+1088(%rip),%zmm17
  vmovdqu64 probe_seed+1152(%rip),%zmm18
  vmovdqu64 probe_seed+1216(%rip),%zmm19
  vmovdqu64 probe_seed+1280(%rip),%zmm20
  vmovdqu64 probe_seed+1344(%rip),%zmm21
  vmovdqu64 probe_seed+1408(%rip),%zmm22
  vmovdqu64 probe_seed+1472(%rip),%zmm23
  vmovdqu64 probe_seed+1536(%rip),%zmm24
  vmovdqu64 probe_seed+1600(%rip),%zmm25
  vmovdqu64 probe_seed+1664(%rip),%zmm26
  vmovdqu64 probe_seed+1728(%rip),%zmm27
  vmovdqu64 probe_seed+1792(%rip),%zmm28
  vmovdqu64 probe_seed+1856(%rip),%zmm29
  vmovdqu64 probe_seed+1920(%rip),%zmm30
  vmovdqu64 probe_seed+1984(%rip),%zmm31
  mov $257,%eax
  kmovw %eax,%k0
  mov $514,%eax
  kmovw %eax,%k1
  mov $771,%eax
  kmovw %eax,%k2
  mov $1028,%eax
  kmovw %eax,%k3
  mov $1285,%eax
  kmovw %eax,%k4
  mov $1542,%eax
  kmovw %eax,%k5
  mov $1799,%eax
  kmovw %eax,%k6
  mov $2056,%eax
  kmovw %eax,%k7
5:
  fxsave64 (%r12)
  cmp $2,%r14d
  je .Lzmm_before
  cmp $1,%r14d
  jne .Ldone_before
  vmovdqu %ymm0,512(%r12)
  vmovdqu %ymm1,576(%r12)
  vmovdqu %ymm2,640(%r12)
  vmovdqu %ymm3,704(%r12)
  vmovdqu %ymm4,768(%r12)
  vmovdqu %ymm5,832(%r12)
  vmovdqu %ymm6,896(%r12)
  vmovdqu %ymm7,960(%r12)
  vmovdqu %ymm8,1024(%r12)
  vmovdqu %ymm9,1088(%r12)
  vmovdqu %ymm10,1152(%r12)
  vmovdqu %ymm11,1216(%r12)
  vmovdqu %ymm12,1280(%r12)
  vmovdqu %ymm13,1344(%r12)
  vmovdqu %ymm14,1408(%r12)
  vmovdqu %ymm15,1472(%r12)
  jmp .Ldone_before
.Lzmm_before:
  vmovdqu64 %zmm0,512(%r12)
  vmovdqu64 %zmm1,576(%r12)
  vmovdqu64 %zmm2,640(%r12)
  vmovdqu64 %zmm3,704(%r12)
  vmovdqu64 %zmm4,768(%r12)
  vmovdqu64 %zmm5,832(%r12)
  vmovdqu64 %zmm6,896(%r12)
  vmovdqu64 %zmm7,960(%r12)
  vmovdqu64 %zmm8,1024(%r12)
  vmovdqu64 %zmm9,1088(%r12)
  vmovdqu64 %zmm10,1152(%r12)
  vmovdqu64 %zmm11,1216(%r12)
  vmovdqu64 %zmm12,1280(%r12)
  vmovdqu64 %zmm13,1344(%r12)
  vmovdqu64 %zmm14,1408(%r12)
  vmovdqu64 %zmm15,1472(%r12)
  vmovdqu64 %zmm16,1536(%r12)
  vmovdqu64 %zmm17,1600(%r12)
  vmovdqu64 %zmm18,1664(%r12)
  vmovdqu64 %zmm19,1728(%r12)
  vmovdqu64 %zmm20,1792(%r12)
  vmovdqu64 %zmm21,1856(%r12)
  vmovdqu64 %zmm22,1920(%r12)
  vmovdqu64 %zmm23,1984(%r12)
  vmovdqu64 %zmm24,2048(%r12)
  vmovdqu64 %zmm25,2112(%r12)
  vmovdqu64 %zmm26,2176(%r12)
  vmovdqu64 %zmm27,2240(%r12)
  vmovdqu64 %zmm28,2304(%r12)
  vmovdqu64 %zmm29,2368(%r12)
  vmovdqu64 %zmm30,2432(%r12)
  vmovdqu64 %zmm31,2496(%r12)
  kmovw %k0,%eax
  mov %rax,2560(%r12)
  kmovw %k1,%eax
  mov %rax,2568(%r12)
  kmovw %k2,%eax
  mov %rax,2576(%r12)
  kmovw %k3,%eax
  mov %rax,2584(%r12)
  kmovw %k4,%eax
  mov %rax,2592(%r12)
  kmovw %k5,%eax
  mov %rax,2600(%r12)
  kmovw %k6,%eax
  mov %rax,2608(%r12)
  kmovw %k7,%eax
  mov %rax,2616(%r12)
.Ldone_before:
  mov $14,%eax # SYS_rt_sigprocmask
  mov $1,%edi # SIG_UNBLOCK
  mov %r15,%rsi
  xor %edx,%edx
  mov $8,%r10d
  syscall
  mov %rax,%rbx
  fxsave64 (%r13)
  cmp $2,%r14d
  je .Lzmm_after
  cmp $1,%r14d
  jne .Ldone_after
  vmovdqu %ymm0,512(%r13)
  vmovdqu %ymm1,576(%r13)
  vmovdqu %ymm2,640(%r13)
  vmovdqu %ymm3,704(%r13)
  vmovdqu %ymm4,768(%r13)
  vmovdqu %ymm5,832(%r13)
  vmovdqu %ymm6,896(%r13)
  vmovdqu %ymm7,960(%r13)
  vmovdqu %ymm8,1024(%r13)
  vmovdqu %ymm9,1088(%r13)
  vmovdqu %ymm10,1152(%r13)
  vmovdqu %ymm11,1216(%r13)
  vmovdqu %ymm12,1280(%r13)
  vmovdqu %ymm13,1344(%r13)
  vmovdqu %ymm14,1408(%r13)
  vmovdqu %ymm15,1472(%r13)
  jmp .Ldone_after
.Lzmm_after:
  vmovdqu64 %zmm0,512(%r13)
  vmovdqu64 %zmm1,576(%r13)
  vmovdqu64 %zmm2,640(%r13)
  vmovdqu64 %zmm3,704(%r13)
  vmovdqu64 %zmm4,768(%r13)
  vmovdqu64 %zmm5,832(%r13)
  vmovdqu64 %zmm6,896(%r13)
  vmovdqu64 %zmm7,960(%r13)
  vmovdqu64 %zmm8,1024(%r13)
  vmovdqu64 %zmm9,1088(%r13)
  vmovdqu64 %zmm10,1152(%r13)
  vmovdqu64 %zmm11,1216(%r13)
  vmovdqu64 %zmm12,1280(%r13)
  vmovdqu64 %zmm13,1344(%r13)
  vmovdqu64 %zmm14,1408(%r13)
  vmovdqu64 %zmm15,1472(%r13)
  vmovdqu64 %zmm16,1536(%r13)
  vmovdqu64 %zmm17,1600(%r13)
  vmovdqu64 %zmm18,1664(%r13)
  vmovdqu64 %zmm19,1728(%r13)
  vmovdqu64 %zmm20,1792(%r13)
  vmovdqu64 %zmm21,1856(%r13)
  vmovdqu64 %zmm22,1920(%r13)
  vmovdqu64 %zmm23,1984(%r13)
  vmovdqu64 %zmm24,2048(%r13)
  vmovdqu64 %zmm25,2112(%r13)
  vmovdqu64 %zmm26,2176(%r13)
  vmovdqu64 %zmm27,2240(%r13)
  vmovdqu64 %zmm28,2304(%r13)
  vmovdqu64 %zmm29,2368(%r13)
  vmovdqu64 %zmm30,2432(%r13)
  vmovdqu64 %zmm31,2496(%r13)
  kmovw %k0,%eax
  mov %rax,2560(%r13)
  kmovw %k1,%eax
  mov %rax,2568(%r13)
  kmovw %k2,%eax
  mov %rax,2576(%r13)
  kmovw %k3,%eax
  mov %rax,2584(%r13)
  kmovw %k4,%eax
  mov %rax,2592(%r13)
  kmovw %k5,%eax
  mov %rax,2600(%r13)
  kmovw %k6,%eax
  mov %rax,2608(%r13)
  kmovw %k7,%eax
  mov %rax,2616(%r13)
.Ldone_after:
  cmpl $0,probe_use_xsave(%rip)
  je 6f
  mov probe_xsave_mask(%rip),%eax
  xor %edx,%edx
  xrstor64 probe_original(%rip)
  jmp 7f
6:
  fxrstor64 probe_original(%rip)
7:
  mov %rbx,%rax
  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %rbx
  ret
.size probe_state,.-probe_state
.globl probe_read, probe_read_instruction, probe_read_after
.type probe_read,@function
probe_read:
  xor %eax,%eax
.type probe_read_instruction,@function
probe_read_instruction:
  syscall
.type probe_read_after,@function
probe_read_after:
  ret
.size probe_read,.-probe_read

.globl probe_sigsuspend, probe_mask_after, probe_mask_alternate
.type probe_sigsuspend,@function
probe_sigsuspend:
  mov $130,%eax
  mov $8,%esi
  syscall
.type probe_mask_after,@function
probe_mask_after:
  movl $1,probe_mask_path(%rip)
  ret
.type probe_mask_alternate,@function
probe_mask_alternate:
  movl $2,probe_mask_path(%rip)
  ret
.size probe_sigsuspend,.-probe_sigsuspend

.globl probe_handler_entry
.type probe_handler_entry,@function
probe_handler_entry:
  mov %rax,probe_handler_rax(%rip)
  jmp probe_handler_body
.size probe_handler_entry,.-probe_handler_entry
.section .rodata
.p2align 4
probe_fcw: .short 0x077f
probe_mxcsr: .long 0x3f80
probe_x87:
  .tfloat 1.125
  .tfloat 2.125
  .tfloat 3.125
  .tfloat 4.125
  .tfloat 5.125
  .tfloat 6.125
  .tfloat 7.125
  .tfloat 8.125
.section .note.GNU-stack,"",@progbits
