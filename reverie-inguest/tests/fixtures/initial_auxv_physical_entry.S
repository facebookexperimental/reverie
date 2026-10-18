/* Test-only interpreter/checker entry. No libc, TLS, constructor or Tool. */
.text
.globl _start
.type _start,@function
_start:
    /* Capture the actual loader-entry state before any flag-changing opcode,
     * syscall or use of the original kernel stack. The parent audits this
     * frame while the libc-free peer waits for its one STATE response. */
    mov %rax, initial_auxv_fixture_frame+0(%rip)
    mov %rbx, initial_auxv_fixture_frame+8(%rip)
    mov %rcx, initial_auxv_fixture_frame+16(%rip)
    mov %rdx, initial_auxv_fixture_frame+24(%rip)
    mov %rsi, initial_auxv_fixture_frame+32(%rip)
    mov %rdi, initial_auxv_fixture_frame+40(%rip)
    mov %rbp, initial_auxv_fixture_frame+48(%rip)
    mov %rsp, initial_auxv_fixture_frame+56(%rip)
    mov %r8, initial_auxv_fixture_frame+64(%rip)
    mov %r9, initial_auxv_fixture_frame+72(%rip)
    mov %r10, initial_auxv_fixture_frame+80(%rip)
    mov %r11, initial_auxv_fixture_frame+88(%rip)
    mov %r12, initial_auxv_fixture_frame+96(%rip)
    mov %r13, initial_auxv_fixture_frame+104(%rip)
    mov %r14, initial_auxv_fixture_frame+112(%rip)
    mov %r15, initial_auxv_fixture_frame+120(%rip)
    fxsave64 initial_auxv_fixture_fp(%rip)
    lea initial_auxv_fixture_stack_end(%rip), %rsp
    pushfq
    pop %rax
    mov %rax, initial_auxv_fixture_frame+128(%rip)
    cld
    mov $1, %eax
    mov $1, %edi
    lea entry_marker(%rip), %rsi
    mov $(entry_marker_end-entry_marker), %edx
    syscall
    cmp $(entry_marker_end-entry_marker), %rax
    jne .Lbad
    mov initial_auxv_fixture_frame+56(%rip), %rdi
    call initial_auxv_fixture
.Lbad:
    mov $231, %eax
    mov $99, %edi
    syscall
    ud2
.size _start,.-_start
.section .rodata
entry_marker:
#ifdef FD_CHECKER
    .ascii "EXEC_ENTERED\n"
#else
    .ascii "LOADER_ENTERED\n"
#endif
entry_marker_end:

.bss
.balign 16
.globl initial_auxv_fixture_frame
.hidden initial_auxv_fixture_frame
.type initial_auxv_fixture_frame,@object
initial_auxv_fixture_frame:
    .skip 136
.size initial_auxv_fixture_frame,.-initial_auxv_fixture_frame
.balign 16
.globl initial_auxv_fixture_fp
.hidden initial_auxv_fixture_fp
.type initial_auxv_fixture_fp,@object
initial_auxv_fixture_fp:
    .skip 512
.size initial_auxv_fixture_fp,.-initial_auxv_fixture_fp
.balign 16
.globl initial_auxv_fixture_stack
.hidden initial_auxv_fixture_stack
.type initial_auxv_fixture_stack,@object
initial_auxv_fixture_stack:
    .skip 32768
.size initial_auxv_fixture_stack,.-initial_auxv_fixture_stack
.globl initial_auxv_fixture_stack_end
.hidden initial_auxv_fixture_stack_end
initial_auxv_fixture_stack_end:
.section .note.GNU-stack,"",@progbits
