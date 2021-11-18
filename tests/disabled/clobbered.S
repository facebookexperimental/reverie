/**
 * clobbered.S: used by reverie *only*
 * to test inject/tail_inject wouldn't clobber any
 * syscall registers.
 * NB: %rcx is clobbered by `syscall`.
 */
	.text
	.global _start
	.type _start, @function
_start:
	sub $0x18, %rsp

	mov  $9, %eax     // mmap
	movq $0, %rdi
	movq $4096, %rsi
	movq $1, %rdx
	movq $0x22, %r10
	movq $-1, %r8
	movq $0, %r9
	syscall
	cmp    $0xfffffffffffff000,%rax
	ja panic

	movq %rax, 0x8(%rsp)

	cmpq $0, %rdi
	jne panic

	cmpq $4096, %rsi
	jne panic

	cmpq $1, %rdx
	jne panic

	cmpq $0x22, %r10
	jne panic

	cmpq $-1, %r8
	jne panic

	cmpq $0, %r9
	jne panic

	movq $0x12345678, %rdi
	movq $0x17654321, %rsi
	movq $0x42421234, %rdx
	movq $0x1234abab, %r10
	movq $0x12123434, %r8
	movq $0x78781212, %r9
	
	mov $39, %eax // getpid
	syscall

	cmpq $0x12345678, %rdi
	jne panic

	cmpq $0x17654321, %rsi
	jne panic

	cmpq $0x42421234, %rdx
	jne panic

	cmpq $0x1234abab, %r10
	jne panic

	cmpq $0x12123434, %r8
	jne panic

	cmpq $0x78781212, %r9
	jne panic

	mov $11, %eax  // munmap
	movq 8(%rsp), %rdi
	movq $4096, %rsi
	syscall
	cmp    $0xfffffffffffff000,%rax
	ja panic

	cmpq $0x42421234, %rdx
	jne panic

	cmpq $0x1234abab, %r10
	jne panic

	cmpq $0x12123434, %r8
	jne panic

	cmpq $0x78781212, %r9
	jne panic

	add $18, %rsp
	mov $0xe7, %eax  // exit_group
	mov $0, %rdi
	syscall

panic: 	add $18, %rsp
	mov $1, %rdi
	mov $0xe7, %eax
	syscall
	
