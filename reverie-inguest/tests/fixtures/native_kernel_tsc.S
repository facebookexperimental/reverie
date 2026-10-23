.text
.global _start
.type _start,@function
_start:
    mov %rsp,%rdi
    and $-16,%rsp
    call fixture_main
    mov %eax,%edi
    mov $231,%eax
    syscall
    ud2
.size _start,.-_start

/* Same seven-scalar C ABI, real kernel calls; fixed-page routing is modeled. */
.global private_native_syscall
.type private_native_syscall,@function
private_native_syscall:
    mov %rdi,%rax
    mov %rsi,%rdi
    mov %rdx,%rsi
    mov %rcx,%rdx
    mov %r8,%r10
    mov %r9,%r8
    mov 8(%rsp),%r9
    syscall
    ret
.size private_native_syscall,.-private_native_syscall
.global private_native_terminal
.type private_native_terminal,@function
private_native_terminal:
    mov $231,%eax
    syscall
    ud2
.size private_native_terminal,.-private_native_terminal
.section .note.GNU-stack,"",@progbits
