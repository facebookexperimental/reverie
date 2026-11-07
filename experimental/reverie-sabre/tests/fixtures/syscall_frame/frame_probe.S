#include "frame_probe.h"
  .text
  .globl frame_probe
  .type frame_probe,@function
frame_probe:
  push %rbp
  push %rbx
  push %r12
  push %r13
  push %r14
  push %r15
  mov %rdi,%r15
  mov %rsp,SLOT(ORIGINAL_RSP)(%r15)
  pushq SLOT(EXPECTED_FLAGS)(%r15)
  popfq
  pushfq
  pop %r11
  movabs $0x718293a4b5c6d7e8,%rax
  .irp distance,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128
  mov %rax,-\distance(%rsp)
  .endr
  mov $0xb0b0,%ebp
  mov $0xbbbb,%ebx
  mov $0x1212,%r12d
  mov $0x3131,%r13d
  mov $0x1414,%r14d
  mov $0x9999,%r9d
  mov $0x8888,%r8d
  mov $0xaaaa,%r10d
  mov $17,%edi
  mov $0,%esi
  mov $0,%edx
  # Same entry contract as the real rewriter: reserve red zone, push scratch
  # continuation and architectural return, and enter the actual wrapper.
  # These instructions deliberately leave the selected flags unchanged.
  lea -0x80(%rsp),%rsp
  lea probe_scratch(%rip),%rcx
  push %rcx
  lea probe_after(%rip),%rcx
  push %rcx
  mov $56,%eax
  jmp *probe_handler(%rip)
  .globl probe_scratch
probe_scratch:
  lea 0x80(%rsp),%rsp
  movq $1,SLOT(SCRATCH_SEEN)(%r15)
  # A displaced instruction that must execute exactly once.
  lea 0x10(%r12),%r12
  .globl probe_after
probe_after:
  mov %rax,SLOT(RESULT_RAX)(%r15)
  mov %rsp,SLOT(RETURNED_RSP)(%r15)
  mov %r11,SLOT(RESULT_R11)(%r15)
  mov %r12,SLOT(RESULT_R12)(%r15)
  mov %rbp,SLOT(RESULT_RBP)(%r15)
  mov %r15,SLOT(RESULT_R15)(%r15)
  mov %r13,SLOT(RESULT_R13)(%r15)
  mov %rcx,SLOT(RESULT_RCX)(%r15)
  mov SLOT(ORIGINAL_RSP)(%r15),%rcx
  # Read the whole protected red zone before PUSHFQ consumes one stack word.
  .set probe_index,0
  .irp distance,128,120,112,104,96,88,80,72,64,56,48,40,32,24,16,8
  mov -\distance(%rcx),%rax
  mov %rax,(SLOT(REDZONE_START)+probe_index*8)(%r15)
  .set probe_index,probe_index+1
  .endr
  pushfq
  pop %rax
  mov %rax,SLOT(RESULT_FLAGS)(%r15)
  cld
  # Always recover the fixture's own caller stack so a wrong child offset is
  # an explicit failed observation, rather than hiding it in a secondary RET.
  mov SLOT(ORIGINAL_RSP)(%r15),%rsp
  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %rbx
  pop %rbp
  ret
  .size frame_probe,.-frame_probe
  .section .note.GNU-stack,"",@progbits
