/* Distinct initial-only ET_DYN interpreter, no native filter or Tool entry. */
.text
.p2align 4
.globl seed_bootstrap_entry
.hidden seed_bootstrap_entry
.type seed_bootstrap_entry,@function
seed_bootstrap_entry:
    endbr64
    mov %rax, seed_frame+0(%rip)
    mov %rbx, seed_frame+8(%rip)
    mov %rcx, seed_frame+16(%rip)
    mov %rdx, seed_frame+24(%rip)
    mov %rsi, seed_frame+32(%rip)
    mov %rdi, seed_frame+40(%rip)
    mov %rbp, seed_frame+48(%rip)
    mov %rsp, seed_frame+56(%rip)
    mov %r8, seed_frame+64(%rip)
    mov %r9, seed_frame+72(%rip)
    mov %r10, seed_frame+80(%rip)
    mov %r11, seed_frame+88(%rip)
    mov %r12, seed_frame+96(%rip)
    mov %r13, seed_frame+104(%rip)
    mov %r14, seed_frame+112(%rip)
    mov %r15, seed_frame+120(%rip)
    lea seed_stack_end(%rip), %rsp
    pushfq
    pop %rax
    mov %rax, seed_frame+128(%rip)
    cld
    lea seed_frame(%rip), %rdi
    call seed_bootstrap_start
    ud2
.size seed_bootstrap_entry, .-seed_bootstrap_entry

.p2align 4
.globl seed_syscall6
.hidden seed_syscall6
.type seed_syscall6,@function
seed_syscall6:
    endbr64
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    syscall
    ret
.size seed_syscall6, .-seed_syscall6

.p2align 4
.globl seed_relocate
.hidden seed_relocate
.type seed_relocate,@function
seed_relocate:
    endbr64
    mov %rdi, %rax
    mov %rsi, %rsp
    and $-16, %rsp
    sub $8, %rsp
    movq $0, (%rsp) /* relocated C entry is noreturn */
    mov %rdx, %rdi
    jmp *%rax
.size seed_relocate, .-seed_relocate

.p2align 4
.globl seed_bootstrap_resume
.hidden seed_bootstrap_resume
.type seed_bootstrap_resume,@function
seed_bootstrap_resume:
    endbr64
    /* The last C call is noreturn. Preserve only the original guest frame and
     * the public loader entry while erasing every other active writable byte,
     * including this call's live stack and return address. No call, push or
     * syscall may follow the wipe. Linker assertions bound all three spans. */
    mov %rsi, seed_transfer_entry(%rip)
    cld
    xor %eax, %eax
    lea seed_data_start(%rip), %rdi
    lea seed_frame(%rip), %rcx
    sub %rdi, %rcx
    rep stosb
    lea seed_frame+136(%rip), %rdi
    lea seed_transfer_entry(%rip), %rcx
    sub %rdi, %rcx
    rep stosb
    lea seed_transfer_entry+8(%rip), %rdi
    lea seed_image_active_end(%rip), %rcx
    sub %rdi, %rcx
    rep stosb

    /* Consume flags without pushing another saved copy into cleared memory.
     * From popfq through the final jump, use only flag-neutral MOVs and JMP.
     * RIP-relative slots let every GP register be restored and its slot erased;
     * restore the original guest RSP last, without writing to that stack. */
    lea seed_frame+128(%rip), %rsp
    popfq
    movq $0, seed_frame+128(%rip)
    mov seed_frame+0(%rip), %rax
    movq $0, seed_frame+0(%rip)
    mov seed_frame+8(%rip), %rbx
    movq $0, seed_frame+8(%rip)
    mov seed_frame+16(%rip), %rcx
    movq $0, seed_frame+16(%rip)
    mov seed_frame+24(%rip), %rdx
    movq $0, seed_frame+24(%rip)
    mov seed_frame+32(%rip), %rsi
    movq $0, seed_frame+32(%rip)
    mov seed_frame+40(%rip), %rdi
    movq $0, seed_frame+40(%rip)
    mov seed_frame+48(%rip), %rbp
    movq $0, seed_frame+48(%rip)
    mov seed_frame+64(%rip), %r8
    movq $0, seed_frame+64(%rip)
    mov seed_frame+72(%rip), %r9
    movq $0, seed_frame+72(%rip)
    mov seed_frame+80(%rip), %r10
    movq $0, seed_frame+80(%rip)
    mov seed_frame+88(%rip), %r11
    movq $0, seed_frame+88(%rip)
    mov seed_frame+96(%rip), %r12
    movq $0, seed_frame+96(%rip)
    mov seed_frame+104(%rip), %r13
    movq $0, seed_frame+104(%rip)
    mov seed_frame+112(%rip), %r14
    movq $0, seed_frame+112(%rip)
    mov seed_frame+120(%rip), %r15
    movq $0, seed_frame+120(%rip)
    mov seed_frame+56(%rip), %rsp
    movq $0, seed_frame+56(%rip)
    /* This sole nonzero writable word is AT_BASE plus the loader ELF entry,
     * not bootstrap authority. No seed storage is accessed after this jump. */
    jmp *seed_transfer_entry(%rip)
.size seed_bootstrap_resume, .-seed_bootstrap_resume

.bss
.balign 16
.globl seed_frame
.hidden seed_frame
.type seed_frame,@object
seed_frame:
    .skip 136
.size seed_frame, .-seed_frame
.balign 16
.globl seed_stack
.hidden seed_stack
seed_stack:
    .skip 32768
.globl seed_stack_end
.hidden seed_stack_end
seed_stack_end:
.balign 8
.globl seed_transfer_entry
.hidden seed_transfer_entry
.type seed_transfer_entry,@object
seed_transfer_entry:
    .skip 8
.size seed_transfer_entry, .-seed_transfer_entry
.section .note.GNU-stack,"",@progbits
