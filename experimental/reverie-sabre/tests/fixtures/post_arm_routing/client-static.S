/* A static client without libc: SaBRe's static-client path. */
.text
.globl _start
.type _start,@function
_start:
  mov $1, %eax
  mov $1, %edi
  lea ok(%rip), %rsi
  mov $10, %edx
  syscall
  mov $60, %eax
  xor %edi, %edi
  syscall
.size _start,.-_start
.section .rodata
ok: .ascii "STATIC_OK\n"
.section .note.GNU-stack,"",@progbits
