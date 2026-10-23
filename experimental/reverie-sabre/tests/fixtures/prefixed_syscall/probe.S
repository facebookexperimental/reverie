/* getppid through a plain SYSCALL and through REX.W-prefixed SYSCALLs
 * (48 0F 05): one with room to relocate around it (a jump rewrite), and two
 * too short (the UD0 marker), the second with two prefixes (66 48 0F 05) at
 * byte ALIGNED_SITE_OFFSET of a 64-byte cache line. A SYSCALL with LOCK
 * after another prefix (#UD natively) and one longer
 * than the 15-byte instruction limit (#GP natively) are never executed and
 * must be left as they are. */
#ifndef ALIGNED_SITE_OFFSET
#define ALIGNED_SITE_OFFSET 0
#endif
.text
.globl plain_getppid
.type plain_getppid,@function
plain_getppid:
  mov $110, %eax
  nop
  nop
  nop
  syscall
  nop
  nop
  nop
  ret
.size plain_getppid,.-plain_getppid

.globl prefixed_getppid
.type prefixed_getppid,@function
prefixed_getppid:
.globl prefixed_getppid_code
prefixed_getppid_code:
  mov $110, %eax
  nop
  nop
  nop
  .byte 0x48, 0x0f, 0x05
  nop
  nop
  nop
  ret
.size prefixed_getppid,.-prefixed_getppid

/* The site starts a function and is followed by RET, so nothing around it
 * can be relocated: the rewriter must use the marker. */
.globl prefixed_short_getppid
.type prefixed_short_getppid,@function
prefixed_short_getppid:
  mov $110, %eax
  jmp prefixed_short_site
.size prefixed_short_getppid,.-prefixed_short_getppid

.globl prefixed_short_site
.type prefixed_short_site,@function
prefixed_short_site:
  .byte 0x48, 0x0f, 0x05
  ret
.size prefixed_short_site,.-prefixed_short_site

.globl lock_site
.type lock_site,@function
lock_site:
  .byte 0x66, 0xf0, 0x0f, 0x05
  ret
.size lock_site,.-lock_site

/* Fourteen DS prefixes and 0F 05: sixteen bytes. */
.globl overlong_site
.type overlong_site,@function
overlong_site:
  .byte 0x3e, 0x3e, 0x3e, 0x3e, 0x3e, 0x3e, 0x3e
  .byte 0x3e, 0x3e, 0x3e, 0x3e, 0x3e, 0x3e, 0x3e
  .byte 0x0f, 0x05
  ret
.size overlong_site,.-overlong_site

.globl aligned_short_getppid
.type aligned_short_getppid,@function
aligned_short_getppid:
  mov $110, %eax
  jmp aligned_short_site
.size aligned_short_getppid,.-aligned_short_getppid

/* At least 64 INT3 bytes in front of the site, so the rewriter's linear
 * decode is in step at the site whatever precedes the section. */
.section .text.aligned_site,"ax",@progbits
.balign 64
.skip 64 + ALIGNED_SITE_OFFSET, 0xcc
.globl aligned_short_site
.type aligned_short_site,@function
aligned_short_site:
  .byte 0x66, 0x48, 0x0f, 0x05
  ret
.size aligned_short_site,.-aligned_short_site
.section .note.GNU-stack,"",@progbits
