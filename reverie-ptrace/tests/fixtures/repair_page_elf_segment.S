/* A static ELF with a read-write PT_LOAD segment of 0xa5 bytes at 0x71001000,
 * the page after Reverie's trampoline, where pre-init maps its sealed SIGTRAP
 * repair page if the address is free. It makes two getppid calls, checks
 * every byte of the segment, prints a line and exits 0 if all are intact, 40
 * if any changed (https://github.com/rrnewton/hermit/issues/4409). From the
 * Codex reviewer's qualifier for https://github.com/rrnewton/reverie/pull/1070. */
.global _start
.section .text
_start:
    mov $110, %eax
    syscall
    mov $110, %eax
    syscall
    lea guest_marker(%rip), %rsi
    mov $4096, %ecx
1:
    cmpb $0xa5, (%rsi)
    jne changed
    inc %rsi
    dec %ecx
    jnz 1b
    lea intact_message(%rip), %rsi
    mov $intact_size, %edx
    xor %r8d, %r8d
    jmp print_exit
changed:
    lea changed_message(%rip), %rsi
    mov $changed_size, %edx
    mov $40, %r8d
print_exit:
    mov $1, %eax
    mov $1, %edi
    syscall
    mov $60, %eax
    mov %r8d, %edi
    syscall
.section .rodata
intact_message:
    .ascii "native-ELF guest segment 0x71001000 intact=1\n"
.set intact_size, .-intact_message
changed_message:
    .ascii "ELF guest segment 0x71001000 changed=1\n"
.set changed_size, .-changed_message
.section .guest,"aw",@progbits
guest_marker:
    .fill 4096, 1, 0xa5
.section .note.GNU-stack,"",@progbits
