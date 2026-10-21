/* Shared freestanding leaves. The normal runner is a GNU PIE; these functions
 * use no FS/GS-relative storage. The native scalar ABI is seven SysV scalars.
 */
.text
.p2align 4
.globl private_native_syscall
.hidden private_native_syscall
.type private_native_syscall,@function
private_native_syscall:
    endbr64
    push %r12
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 16(%rsp), %r9
    lea .Lnative_return(%rip), %r12
#ifdef EXEC_PRIVATE_BOOTSTRAP_IMAGE
    movabs $fixed_native_entry, %rcx
#else
    movabs $0x50000000007c, %rcx
#endif
    jmp *%rcx
.Lnative_return:
    endbr64
    pop %r12
    ret
.size private_native_syscall, .-private_native_syscall

.p2align 4
.globl private_native_terminal
.hidden private_native_terminal
.type private_native_terminal,@function
private_native_terminal:
    endbr64
    mov $231, %eax
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    lea .Lterminal_returned(%rip), %r12
#ifdef EXEC_PRIVATE_BOOTSTRAP_IMAGE
    movabs $fixed_native_entry, %rcx
#else
    movabs $0x50000000007c, %rcx
#endif
    jmp *%rcx
.Lterminal_returned:
    endbr64
    ud2
.size private_native_terminal, .-private_native_terminal

.p2align 4
.globl private_enter_tool_loader
.hidden private_enter_tool_loader
.type private_enter_tool_loader,@function
private_enter_tool_loader:
    endbr64
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    lfence
    cmpq $1, 0(%rdi)
    jne .Lbad_loader_entry
    cmpq $3520, 8(%rdi)
    jne .Lbad_loader_entry
    cmpq $1, 16(%rdi)
    jne .Lbad_loader_entry
    mov 152(%rdi), %rax
    mov (%rax), %rsp  /* bootstrap stored exact synthetic initial RSP here */
    mov 168(%rdi), %rax
    xor %edx, %edx
    jmp *%rax
.Lbad_loader_entry:
    mov $79, %edi
    jmp private_native_terminal
.size private_enter_tool_loader, .-private_enter_tool_loader

.p2align 4
.globl private_runner_resume
.hidden private_runner_resume
.type private_runner_resume,@function
private_runner_resume:
    endbr64
    /* Open rights before reading control or touching the private return stack.
     * This experiment does not activate keyed Tool storage.
     */
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    lfence
    mov %rdi, %r15
    cmpq $1, 0(%r15)
    jne .Lbad_resume
    cmpq $3520, 8(%r15)
    jne .Lbad_resume
    cmpq $2, 16(%r15)
    jne .Lbad_resume
    cmpq $1, 72(%r15)
    jne .Lbad_resume
    sub $8, %rsp          /* SysV alignment before the final C helper */
    call private_restore_kernel_state
    test %eax, %eax
    jne .Lbad_resume

    /* Preload everything needed after changing FS. No C, TLS, stack reads,
     * or protected-control reads follow the final PKRU restore.
     */
    mov 40(%r15), %r14
    mov 48(%r15), %r13
    mov 24(%r15), %rbx
    mov 360(%r15), %ebp
    mov $158, %eax
    mov $0x1002, %edi
    mov %rbx, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    lea .Lresume_fs_return(%rip), %r12
    movabs $0x50000000007c, %rcx
    jmp *%rcx
.Lresume_fs_return:
    endbr64
    test %rax, %rax
    jne .Lbad_resume_native
    /* Ordinary signals were still blocked while FS changed. Once mask restore
     * can deliver them, both phase and FS are Guest and RSP is original.
     */
    movq $3, 16(%r15)
    mov %r14, %rsp
    mov $14, %eax
    mov $2, %edi          /* SIG_SETMASK */
    lea 352(%r15), %rsi
    xor %edx, %edx
    mov $8, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    lea .Lresume_mask_return(%rip), %r12
    movabs $0x50000000007c, %rcx
    jmp *%rcx
.Lresume_mask_return:
    endbr64
    test %rax, %rax
    jne .Lbad_resume_native
    /* This branch is selected by actual protected native input, not argv/env.
     * Old HLIINIT1 keeps its original final instruction sequence below.
     */
    push %rbx
    mov 56(%r15), %rbx
    movabs $0x31434558454e4c48, %rax /* HLNEXEC1 */
    cmp %rax, (%rbx)
    je .Lnative_record_resume
    pop %rbx
    mov %ebp, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    lfence
    /* Interpreter entry has no inherited fini callback. Stock guest ld.so
     * creates its own real RDX callback when it enters the unchanged target.
     */
    jmp *%r13
.Lnative_record_resume:
    movabs $0x530000003000, %rbx
    movabs $0x3130474552584c48, %rax /* HLXREG01 */
    cmp %rax, 0(%rbx)
    jne .Lbad_resume_native
    cmpq $1, 8(%rbx)
    jne .Lbad_resume_native
    cmpq $256, 16(%rbx)
    jne .Lbad_resume_native
    mov 120(%r15), %rax
    cmp %rax, 24(%rbx)
    jne .Lbad_resume_native
    mov 40(%r15), %rax
    cmp %rax, 184(%rbx)
    jne .Lbad_resume_native
    mov 48(%r15), %rax
    cmp %rax, 160(%rbx)
    jne .Lbad_resume_native
    mov 248(%rbx), %eax
    test $1, %eax /* actual key0 read access required; all other rights retained */
    jne .Lbad_resume_native
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    lfence
    /* No Tool stack reads after restoring guest rights. The record is key0,
     * immutable and protected by the actual owner until final handoff.
     */
    mov 184(%rbx), %rsp
    pushq 176(%rbx)
    popfq
    pushq 160(%rbx) /* ret restores the original RSP exactly */
    mov 32(%rbx), %r15
    mov 40(%rbx), %r14
    mov 48(%rbx), %r13
    mov 56(%rbx), %r12
    mov 64(%rbx), %rbp
    mov 80(%rbx), %r11
    mov 88(%rbx), %r10
    mov 96(%rbx), %r9
    mov 104(%rbx), %r8
    mov 112(%rbx), %rax
    mov 120(%rbx), %rcx
    mov 128(%rbx), %rdx
    mov 136(%rbx), %rsi
    mov 144(%rbx), %rdi
    mov 72(%rbx), %rbx
    ret
.Lbad_resume:
    mov $80, %edi
    jmp private_native_terminal
.Lbad_resume_native:
    mov $81, %edi
    jmp private_native_terminal
.size private_runner_resume, .-private_runner_resume
.section .note.GNU-stack,"",@progbits
