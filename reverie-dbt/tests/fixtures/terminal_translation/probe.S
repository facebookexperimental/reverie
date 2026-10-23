.section .text.translation_probe,"ax",@progbits
.p2align 12
.globl translation_probe
.type translation_probe,@function
translation_probe:
    xor %eax, %eax
.globl translation_branch
translation_branch:
    jz translation_target_one
    ud2
.size translation_probe, .-translation_probe
.p2align 12
.globl translation_target_one
.type translation_target_one,@function
translation_target_one:
    mov $1, %eax
    ret
.size translation_target_one, .-translation_target_one
.p2align 12
.globl translation_target_two
.type translation_target_two,@function
translation_target_two:
    mov $2, %eax
    ret
.size translation_target_two, .-translation_target_two
.p2align 12
.globl translation_truncate
.type translation_truncate,@function
translation_truncate:
    nop
    mov $3, %eax
    ret
.size translation_truncate, .-translation_truncate
.p2align 12
.section .note.GNU-stack,"",@progbits
