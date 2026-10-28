.text
.globl _start
.type _start,@function
_start:
  lea buffer(%rip), %rdi
  mov $4, %esi
  mov $0x1357, %edx
  call late_probe
  cmp $137, %rax
  jne fail
  cmpb $0xea, buffer(%rip)
  jne fail
  mov $1, %eax
  mov $1, %edi
  lea ok(%rip), %rsi
  mov $10, %edx
  syscall
  mov $60, %eax
  xor %edi, %edi
  syscall
fail:
  mov $60, %eax
  mov $91, %edi
  syscall
.size _start,.-_start
.globl late_probe
.type late_probe,@function
late_probe:
  .rept 32
  nop
  .endr
  movb $0x6a, (%rdi)
  mov $37, %eax
  ret
.size late_probe,.-late_probe
.section .rodata
ok: .ascii "STATIC_OK\n"
.data
buffer: .byte 0,1,2,3
.section .note.GNU-stack,"",@progbits
