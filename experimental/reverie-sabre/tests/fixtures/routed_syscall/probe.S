/* getppid with six caller-supplied arguments, through a site with room for a
 * jump rewrite and through a site too short for one (the UD0 marker). */
.text
.globl jump_getppid6
.type jump_getppid6,@function
jump_getppid6:
  mov %rcx, %r10
  mov $110, %eax
  nop
  nop
  nop
  syscall
  nop
  nop
  nop
  ret
.size jump_getppid6,.-jump_getppid6

.globl short_getppid6
.type short_getppid6,@function
short_getppid6:
  mov %rcx, %r10
  mov $110, %eax
  jmp short_site6
.size short_getppid6,.-short_getppid6

/* A branch target followed by RET: nothing around it can be relocated. */
.type short_site6,@function
short_site6:
  syscall
  ret
.size short_site6,.-short_site6
.section .note.GNU-stack,"",@progbits
