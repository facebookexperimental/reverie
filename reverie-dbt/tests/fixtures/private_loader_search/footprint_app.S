.global _start
.section .text
_start:
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    cmp $-4095, %rax
    jae .Lfailure
    mov %rax, %r12
    mov %rax, %r8
    lea mmap_line+22(%rip), %rdi
    lea digits(%rip), %r9
    mov $16, %ecx
.Lhex:
    mov %r8d, %edx
    and $15, %edx
    movb (%r9,%rdx), %al
    movb %al, (%rdi)
    shr $4, %r8
    dec %rdi
    loop .Lhex
    mov $1, %eax
    mov $1, %edi
    lea mmap_line(%rip), %rsi
    mov $24, %edx
    syscall
    cmp $24, %rax
    jne .Lfailure
    mov $11, %eax
    mov %r12, %rdi
    mov $4096, %esi
    syscall
    test %rax, %rax
    jne .Lfailure
    mov $60, %eax
    xor %edi, %edi
    syscall
.Lfailure:
    mov $1, %eax
    mov $2, %edi
    lea failure_line(%rip), %rsi
    mov $11, %edx
    syscall
    mov $60, %eax
    mov $90, %edi
    syscall
.section .rodata
digits:
    .ascii "0123456789abcdef"
failure_line:
    .ascii "MMAP_ERROR\n"
.section .data
mmap_line:
    .ascii "MMAP=0x0000000000000000\n"
.section .note.GNU-stack,"",@progbits
