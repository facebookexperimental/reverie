/* Exact fixed-gate template plus kernel interpreter and bootstrap signal entry.
 * Only the frozen six syscall/return IPs belong in the launcher's filter.
 */
.intel_syntax noprefix
.section .gate,"ax",@progbits
.balign 4096
.global fixed_gate_template
.hidden fixed_gate_template
fixed_gate_template:
    .org 0x7c, 0xcc
.global fixed_native_entry
.hidden fixed_native_entry
fixed_native_entry:
    endbr64
    .org 0x80, 0xcc
    syscall
    .org 0x82, 0xcc
    jmp r12
    .org 0x100, 0xcc
    endbr64
    push r12
    push r13
    push r14
    push r15
    mov r12d, edx
    mov r13, rdi
    mov r14, [rsi + 16]
    mov rdi, [rsi]
    mov rdx, [rsi + 8]
    mov r10, [rsi + 24]
    mov r8, [rsi + 32]
    mov r9, [rsi + 40]
    mov rsi, rdx
    xor ecx, ecx
    rdpkru
    mov r15d, eax
    mov eax, r12d
    xor edx, edx
    wrpkru
    lfence
    mov rax, r13
    mov rdx, r14
    jmp .Lguest_syscall
    .org 0x200, 0xcc
.Lguest_syscall:
    syscall
    .org 0x202, 0xcc
    mov r12, rax
    xor ecx, ecx
    rdpkru
    mov r14d, eax
    mov eax, r15d
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rax, r12
    mov edx, r14d
    pop r15
    pop r14
    pop r13
    pop r12
    ret
    .org 0x300, 0xcc
.global fixed_signal_restorer
.hidden fixed_signal_restorer
fixed_signal_restorer:
    endbr64
    mov eax, 15
    .org 0x309, 0xcc
    syscall
    .org 0x30b, 0xcc
    ud2
    .org 4096, 0xcc
.global fixed_gate_template_end
.hidden fixed_gate_template_end
fixed_gate_template_end:
.att_syntax prefix

.text
.p2align 4
.globl _start
.type _start,@function
_start:
    endbr64
    mov %rsp, %r13
    xor %ecx, %ecx
    rdpkru
    mov %eax, %r14d
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    lfence
    lea private_boot_stack_end(%rip), %rsp
    and $-16, %rsp
    mov %r13, %rdi
    mov %r14, %rsi
    call private_bootstrap_prepare
    mov %rax, %rdi
    jmp private_enter_tool_loader
.size _start, .-_start

.p2align 4
.globl private_bootstrap_sigsys_entry
.hidden private_bootstrap_sigsys_entry
.type private_bootstrap_sigsys_entry,@function
private_bootstrap_sigsys_entry:
    endbr64
    /* Preserve all three signal arguments without a stack or control access. */
    mov %rdx, %r8
    xor %eax, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    wrpkru
    lfence
    mov %r8, %rdx
    jmp private_bootstrap_sigsys
.size private_bootstrap_sigsys_entry, .-private_bootstrap_sigsys_entry

.section .locator,"aw",@nobits
.balign 8
.globl exec_private_control
.hidden exec_private_control
.type exec_private_control,@object
exec_private_control:
    .zero 8
.size exec_private_control, 8

.bss
.balign 16
private_boot_stack:
    .skip 65536
private_boot_stack_end:
.section .note.GNU-stack,"",@progbits
