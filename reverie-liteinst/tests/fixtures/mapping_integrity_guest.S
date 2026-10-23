/* A separate ordinary eight-byte syscall window; never edits an old fixture. */
.text
.p2align 4
.globl m6_guest_syscall
.type m6_guest_syscall,@function
m6_guest_syscall:
.cfi_startproc
 mov %rdi,%rax
 mov %rsi,%r11
 mov 0(%r11),%rdi
 mov 8(%r11),%rsi
 mov 16(%r11),%rdx
 mov 24(%r11),%r10
 mov 32(%r11),%r8
 mov 40(%r11),%r9
 .p2align 6,0x90
.globl m6_guest_syscall_site
m6_guest_syscall_site:
 syscall
 .fill 6,1,0x90
 ret
 .fill 16,1,0x90
.cfi_endproc
.size m6_guest_syscall,.-m6_guest_syscall
.section .note.GNU-stack,"",@progbits
