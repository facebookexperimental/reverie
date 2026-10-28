/* Preparation only: no build/run. Retained sentinel/LOOP plus one raw helper.
 * The client may wait in helper_getpid's pre-syscall callback, flush main's
 * selected fragment, then return true. Linux still executes the real getpid.
 * All dispatch/join choices use CMOV + unconditional control transfers.
 */
.text
.global _start
.global clock_control_branch
.global clone_syscall, main_after_clone, sentinel_setup
.global helper_entry, helper_getpid, helper_exit
.global main_join_poll, join_futex_syscall, main_join_complete, sentinel_output
.global main_tgid, helper_pid, helper_clone_result, helper_tid, helper_status
.global helper_stack, helper_stack_top, result
_start:
    /* Remember the real TGID before the raw thread clone. */
    mov $39, %eax
    syscall
    mov %rax, main_tgid(%rip)
    lea prepare_clone(%rip), %r11
    lea fail_main_pid(%rip), %r10
    cmp $1, %rax
    cmovl %r10, %r11
    jmp *%r11

prepare_clone:
    lea helper_stack_top-8(%rip), %rsi
    lea helper_entry(%rip), %rax
    mov %rax, (%rsi)
    /* VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|CHILD_CLEARTID.
     * parent_tid and child_tid deliberately name the same shared aligned word.
     */
    mov $0x350f00, %edi
    lea helper_tid(%rip), %rdx
    lea helper_tid(%rip), %r10
    xor %r8d, %r8d
    lea main_after_clone(%rip), %rax
    push %rax
    mov $56, %eax
clone_syscall:
    syscall
    ret

main_after_clone:
    mov %rax, helper_clone_result(%rip)
    lea sentinel_setup(%rip), %r11
    lea fail_clone(%rip), %r10
    cmp $1, %rax
    cmovl %r10, %r11
    jmp *%r11

sentinel_setup:
    mov $13, %eax
    mov $6, %edi
    lea action(%rip), %rsi
    xor %edx, %edx
    mov $8, %r10d
    syscall
    mov %rax, result(%rip)
    mov $2, %ecx
    mov %rsp, result+152(%rip)
    movabs $0x1122334455667700, %rax
    movabs $0x1122334455667701, %rbx
    movabs $0x1122334455667702, %rdx
    movabs $0x1122334455667703, %rsi
    movabs $0x1122334455667704, %rdi
    movabs $0x1122334455667705, %rbp
    movabs $0x1122334455667706, %r8
    movabs $0x1122334455667707, %r9
    movabs $0x1122334455667708, %r10
    movabs $0x1122334455667709, %r11
    movabs $0x112233445566770a, %r12
    movabs $0x112233445566770b, %r13
    movabs $0x112233445566770c, %r14
    movabs $0x112233445566770d, %r15
    pushq $0xad7
    popfq
clock_control_branch:
    loop clock_control_branch
    mov %rcx, result+8(%rip)
    mov %rax, result+32(%rip)
    mov %rbx, result+40(%rip)
    mov %rdx, result+48(%rip)
    mov %rsi, result+56(%rip)
    mov %rdi, result+64(%rip)
    mov %rbp, result+72(%rip)
    mov %r8, result+80(%rip)
    mov %r9, result+88(%rip)
    mov %r10, result+96(%rip)
    mov %r11, result+104(%rip)
    mov %r12, result+112(%rip)
    mov %r13, result+120(%rip)
    mov %r14, result+128(%rip)
    mov %r15, result+136(%rip)
    pushfq
    popq result+144(%rip)
    mov %rsp, result+160(%rip)
    /* The original full sentinel has already been saved. Join before writing
     * it or exiting: kernel clear_child_tid makes an exited helper observable.
     * Ordinary FUTEX_WAIT is required: exit's clear-child-TID wake is shared.
     */
main_join_poll:
    mov helper_tid(%rip), %edx
    lea main_join_wait(%rip), %r11
    lea fail_helper(%rip), %r10
    test %edx, %edx
    cmovs %r10, %r11
    lea main_join_complete(%rip), %r10
    cmovz %r10, %r11
    jmp *%r11

main_join_wait:
    lea helper_tid(%rip), %rdi
    xor %esi, %esi                 /* FUTEX_WAIT, no PRIVATE flag */
    xor %r10d, %r10d               /* no guest-side timeout */
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
join_futex_syscall:
    syscall
    lea fail_futex(%rip), %r11
    lea main_join_poll(%rip), %r10
    cmp $0, %rax
    cmove %r10, %r11
    cmp $-11, %rax                 /* EAGAIN: exit raced the wait */
    cmove %r10, %r11
    cmp $-4, %rax                  /* EINTR: recheck, never accept early */
    cmove %r10, %r11
    jmp *%r11

main_join_complete:
    lea sentinel_output(%rip), %r11
    lea fail_helper(%rip), %r10
    cmpl $0, helper_status(%rip)
    cmovne %r10, %r11
    mov helper_pid(%rip), %rax
    cmp main_tgid(%rip), %rax
    cmovne %r10, %r11
    jmp *%r11

sentinel_output:
    mov $1, %eax
    mov $1, %edi
    lea result(%rip), %rsi
    mov $168, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
    ud2

/* Own stack, no libc/TLS/allocation. Exactly one real helper getpid. */
helper_entry:
    mov $39, %eax
helper_getpid:
    syscall
    mov %rax, helper_pid(%rip)
    mov $93, %edi
    xor %edx, %edx
    cmp main_tgid(%rip), %rax
    cmove %edx, %edi
    mov %edi, helper_status(%rip)
    mov $60, %eax
helper_exit:
    syscall
    ud2

fail_main_pid:
    mov $90, %edi
    jmp fail_group
fail_clone:
    mov $91, %edi
    jmp fail_group
fail_futex:
    mov $92, %edi
    jmp fail_group
fail_helper:
    mov $94, %edi
fail_group:
    mov $231, %eax
    syscall
    ud2

handler:
    incq result+16(%rip)
    movslq 8(%rsi), %rax
    mov %rax, result+24(%rip)
    ret
restorer:
    mov $15, %eax
    syscall
    ud2

.data
.align 8
action:
    .quad handler, 0x04000004, restorer, 0
result:
    .zero 168

/* All lifecycle data is separate from the unchanged 168-byte result. */
.align 8
main_tgid: .quad 0
helper_pid: .quad 0
helper_clone_result: .quad 0
.align 4
helper_tid: .long -1
helper_status: .long -1

.bss
.balign 16
helper_stack:
    .skip 65536
helper_stack_top:
.section .note.GNU-stack,"",@progbits
