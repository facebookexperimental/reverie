.global _start
.section .text.start,"ax",@progbits
_start:
    movabs $0x6f776e65722d6d6d, %rax
    cmp %rax, occupied_canary(%rip)
    jne .Lbad
    mov $1, %eax
    mov $1, %edi
    lea canary_ok(%rip), %rsi
    mov $(canary_end-canary_ok), %edx
    syscall
    cmp $(canary_end-canary_ok), %rax
    jne .Lbad
    xor %edi, %edi
    jmp .Lexit
.Lbad:
    mov $2, %edi
.Lexit:
    mov $60, %eax
    syscall
.section .rodata,"a",@progbits
canary_ok:
    .ascii "COLLISION_CANARY_OK\n"
canary_end:
.section .occupied,"aw",@progbits
occupied_canary:
    .quad 0x6f776e65722d6d6d
.section .note.GNU-stack,"",@progbits
