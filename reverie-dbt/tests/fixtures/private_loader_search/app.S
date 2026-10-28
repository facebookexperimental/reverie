.global _start
.section .text
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.section .note.GNU-stack,"",@progbits
