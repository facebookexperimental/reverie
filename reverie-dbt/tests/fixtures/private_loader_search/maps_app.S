/* Test-only raw /proc/self/maps snapshot. No libc, heap allocation, mmap,
 * environment read, or parsing. One identical executable serves all variants.
 * The 1MiB buffer is consumed input storage, using tool_answers_brk's bound. */
.global _start
.equ MAPS_CAPACITY, 1048576
.section .text
_start:
    mov $-1, %r12
    xor %r13d, %r13d
    lea maps_buffer(%rip), %r15
    /* The first syscall is the observation itself. */
    mov $257, %eax
    mov $-100, %rdi
    lea maps_path(%rip), %rsi
    mov $0x80000, %edx
    xor %r10d, %r10d
    syscall
    cmp $-4095, %rax
    jae .Lfailure
    mov %rax, %r12
.Lread:
    xor %eax, %eax
    mov %r12, %rdi
    lea (%r15,%r13), %rsi
    mov $(MAPS_CAPACITY-1), %edx
    sub %r13, %rdx
    syscall
    test %rax, %rax
    js .Lfailure
    jz .Leof
    add %rax, %r13
    cmp $(MAPS_CAPACITY-1), %r13
    jae .Lfailure
    jmp .Lread
.Leof:
    mov $3, %eax
    mov %r12, %rdi
    syscall
    mov $-1, %r12
    test %rax, %rax
    jne .Lfailure
    test %r13, %r13
    jz .Lfailure
    cmpb $10, -1(%r15,%r13)
    jne .Lfailure
    /* NUL cannot occur in a complete proc maps text stream. */
    xor %ecx, %ecx
.Lcheck:
    cmpb $0, (%r15,%rcx)
    je .Lfailure
    inc %rcx
    cmp %r13, %rcx
    jb .Lcheck
    mov %r13, %r8
    lea maps_count+15(%rip), %rdi
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
    lea maps_begin(%rip), %rsi
    mov $MAPS_BEGIN_LENGTH, %edx
    call .Lwrite_all
    mov %r15, %rsi
    mov %r13, %rdx
    call .Lwrite_all
    lea maps_end(%rip), %rsi
    mov $MAPS_END_LENGTH, %edx
    call .Lwrite_all
    mov $60, %eax
    xor %edi, %edi
    syscall
.Lwrite_all:
    mov $1, %eax
    mov $1, %edi
    syscall
    test %rax, %rax
    jle .Lfailure
    add %rax, %rsi
    sub %rax, %rdx
    jne .Lwrite_all
    ret
.Lfailure:
    cmp $-1, %r12
    je .Lreport_failure
    mov $3, %eax
    mov %r12, %rdi
    syscall
.Lreport_failure:
    mov $1, %eax
    mov $2, %edi
    lea failure_line(%rip), %rsi
    mov $FAILURE_LENGTH, %edx
    syscall
    mov $60, %eax
    mov $90, %edi
    syscall
.section .rodata
maps_path:
    .asciz "/proc/self/maps"
digits:
    .ascii "0123456789abcdef"
maps_end:
    .ascii "MAPS_END\n"
.equ MAPS_END_LENGTH, .-maps_end
failure_line:
    .ascii "MAPS_SNAPSHOT_ERROR\n"
.equ FAILURE_LENGTH, .-failure_line
.section .data
maps_begin:
    .ascii "MAPS_BEGIN bytes=0x"
maps_count:
    .ascii "0000000000000000\n"
.equ MAPS_BEGIN_LENGTH, .-maps_begin
.section .bss
.balign 16
maps_buffer:
    .skip MAPS_CAPACITY
.section .note.GNU-stack,"",@progbits
