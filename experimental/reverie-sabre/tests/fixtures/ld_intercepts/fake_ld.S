/* A stand-in dynamic linker: it prints UNMONITORED and exits 0, so a client
 * that names it as its interpreter runs without SaBRe's plugin if the loader
 * lets it start. Built with NO_TEXT its code is in a section that is not
 * .text, so the loader cannot install intercepts in it; otherwise it has a
 * .text but none of the symbols the loader intercepts. */
#ifdef NO_TEXT
.section .code,"ax",@progbits
#else
.text
#endif
.globl _start
_start:
  mov $1, %eax
  mov $1, %edi
  lea message(%rip), %rsi
  mov $(message_end - message), %edx
  syscall
  mov $60, %eax
  xor %edi, %edi
  syscall
message:
  .ascii "UNMONITORED\n"
message_end:
.section .note.GNU-stack,"",@progbits
