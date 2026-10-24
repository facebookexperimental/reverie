// Switch to an enabled key2 stack before denying keys0/1. Both native and
// intercepted cases use the same assembly, including exact PKRU restoration.
.text
.global pkey_buffer_syscall
.type pkey_buffer_syscall,@function
pkey_buffer_syscall:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsp
    mov rsp, [r12 + 40]
    and rsp, -16
    xor ecx, ecx
    rdpkru
    mov [r12 + 56], rax
    mov eax, [r12 + 32]
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rax, [r12]
    mov rdi, [r12 + 8]
    mov rsi, [r12 + 16]
    mov rdx, [r12 + 24]
    mov r10, [r12 + 72]
    mov r8, [r12 + 80]
    mov r9, [r12 + 88]
    syscall
    mov [r12 + 48], rax
    xor ecx, ecx
    rdpkru
    mov [r12 + 64], rax
    mov eax, [r12 + 56]
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rsp, r13
    pop r13
    pop r12
    ret
.size pkey_buffer_syscall, .-pkey_buffer_syscall
.section .note.GNU-stack,"",@progbits
