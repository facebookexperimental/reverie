/* Fixed x86-64 syscall windows. CFI describes each real caller frame. */
.text
.macro args stack=8
 mov %rdi,%rax
 mov %rsi,%rdi
 mov %rdx,%rsi
 mov %rcx,%rdx
 mov %r8,%r10
 mov %r9,%r8
 mov \stack(%rsp),%r9
.endm
.globl raw_call
.type raw_call,@function
raw_call:
.cfi_startproc
 args
 .p2align 6,0x90
raw_site:
 syscall
 ret
 .fill 16,1,0x90
.cfi_endproc
.size raw_call,.-raw_call

.globl split_call
.type split_call,@function
split_call:
.cfi_startproc
 args
 .p2align 6,0x90
 .fill 60,1,0x90
.globl split_site
split_site:
 /* Literal eight-byte original: syscall; xor ecx,ecx; xor edx,edx; nop; nop. */
 .byte 0x0f,0x05,0x31,0xc9,0x31,0xd2,0x90,0x90
 ret
 .fill 16,1,0x90
.globl split_end
split_end:
.cfi_endproc
.size split_call,.-split_call

.globl contrast_call
.type contrast_call,@function
contrast_call:
.cfi_startproc
 args
 .p2align 6,0x90
 .fill 60,1,0x90
.globl contrast_site
contrast_site:
 .byte 0x0f,0x05
 /* Real function entry inside any minimum-five-byte displacement. */
.globl contrast_entry
.type contrast_entry,@function
contrast_entry:
 .byte 0x31,0xc9,0x31,0xd2,0x90,0x90
 ret
 .fill 16,1,0x90
.globl contrast_end
contrast_end:
.cfi_endproc
.size contrast_call,.-contrast_call
.size contrast_entry,contrast_end-contrast_entry

/* A real direct branch additionally makes contrast_site+2 an incoming entry. */
.globl contrast_tail_call
.type contrast_tail_call,@function
contrast_tail_call:
.cfi_startproc
 mov $23,%eax
 jmp contrast_entry
.cfi_endproc
.size contrast_tail_call,.-contrast_tail_call

.globl guest_restorer
.type guest_restorer,@function
 guest_restorer:
.cfi_startproc
 mov $15,%eax
 syscall
 ud2
.cfi_endproc
.size guest_restorer,.-guest_restorer

.globl tail_call
.type tail_call,@function
tail_call:
.cfi_startproc
 push %r12
.cfi_def_cfa_offset 16
.cfi_offset %r12,-16
 mov 24(%rsp),%r12
 args 16
 .p2align 6,0x90
 .fill 60,1,0x90
.globl tail_site
tail_site:
 .byte 0x0f,0x05,0xba,0x11,0x00,0x00,0x00,0x90
 mov %edx,(%r12)
 pop %r12
.cfi_restore %r12
.cfi_def_cfa_offset 8
 ret
 .fill 16,1,0x90
.globl tail_end
tail_end:
.cfi_endproc
.size tail_call,.-tail_call

/* Dedicated pages make real mapping replacement safe for the rest of the
 * fixture. Neither the raw setup helper nor its C caller runs on these pages. */
.section .text.native_cache,"ax",@progbits
.p2align 12,0x90
.globl cache_page
cache_page:
.globl cache_call
.type cache_call,@function
cache_call:
.cfi_startproc
 args
 .p2align 6,0x90
 .fill 60,1,0x90
.globl cache_site
cache_site:
 .byte 0x0f,0x05,0x31,0xc9,0x31,0xd2,0x90,0x90
 ret
 .fill 16,1,0x90
.globl cache_end
cache_end:
.cfi_endproc
.size cache_call,.-cache_call
.p2align 12,0x90
.globl cache_page_end
cache_page_end:

/* The syscall itself ends the first page. Original+2 and the authenticated
 * ordinary tail live on the second page, outside the site's start address. */
.section .text.native_boundary,"ax",@progbits
.p2align 12,0x90
.globl boundary_page
boundary_page:
.globl boundary_call
.type boundary_call,@function
boundary_call:
.cfi_startproc
 args
 .fill 4094-(.-boundary_page),1,0x90
.globl boundary_site
boundary_site:
 .byte 0x0f,0x05,0x31,0xc9,0x31,0xd2,0x90,0x90
 ret
 .fill 16,1,0x90
.globl boundary_end
boundary_end:
.cfi_endproc
.size boundary_call,.-boundary_call
.p2align 12,0x90
.globl boundary_page_end
boundary_page_end:

.section .note.GNU-stack,"",@progbits
