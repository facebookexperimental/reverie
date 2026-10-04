 .global _start
 .section .text
_start:
 lea clear_tid(%rip), %rdi
 mov $218, %eax
 syscall
 mov %eax, clear_tid(%rip)
 mov $56, %eax
 mov $0x50f00, %edi
 lea child_stack_end(%rip), %rsi
 xor %edx, %edx
 xor %r10d, %r10d
 xor %r8d, %r8d
 syscall
 test %rax, %rax
 jz worker
 js failed
 mov $60, %eax
 mov $37, %edi
 syscall
 ud2
worker:
 mov clear_tid(%rip), %edx
 test %edx, %edx
 jz worker_after_leader
 lea clear_tid(%rip), %rdi
 xor %esi, %esi
 xor %r10d, %r10d
 mov $202, %eax
 syscall
 jmp worker
worker_after_leader:
 mov $1, %eax
 mov $1, %edi
 lea message(%rip), %rsi
 mov $message_len, %edx
 syscall
 mov $WORKER_EXIT, %eax
 mov $73, %edi
 syscall
 ud2
failed:
 mov $231, %eax
 mov $99, %edi
 syscall
 .section .rodata
message:
 .ascii "worker continued after leader exit\n"
 .equ message_len, .-message
 .section .bss
 .balign 8
clear_tid: .skip 8
 .balign 16
child_stack: .skip 65536
child_stack_end:
 .section .note.GNU-stack,"",@progbits
