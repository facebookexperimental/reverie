/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

.file "handle_syscall_loader.s"
.text
.globl handle_syscall_loader
.internal handle_syscall_loader
.type handle_syscall_loader, @function

handle_syscall_loader:
	addi sp, sp, -232

	sd x1, 0(sp)
	sd x3, 8(sp)
	sd x4, 16(sp)
	sd x5, 24(sp)
	sd x6, 32(sp)
	sd x7, 40(sp)
	sd x8, 48(sp)
	sd x9, 56(sp)
	sd x10, 64(sp)
	sd x11, 72(sp)
	sd x12, 80(sp)
	sd x13, 88(sp)
	sd x14, 96(sp)
	sd x15, 104(sp)
	sd x16, 112(sp)
	sd x17, 120(sp)
	sd x18, 128(sp)
	sd x19, 136(sp)
	sd x20, 144(sp)
	sd x21, 152(sp)
	sd x22, 160(sp)
	sd x23, 168(sp)
	sd x24, 176(sp)
	sd x25, 184(sp)
	sd x26, 192(sp)
	sd x27, 200(sp)
	sd x28, 208(sp)
	sd x29, 216(sp)
	sd x30, 224(sp)
	sd x31, 232(sp)

    addi sp, sp, -8
    sd x8, 0(sp)
	addi x8, sp, 0


    # adjust the arguments
	add t0, a7, x0
	add a7, a6, x0
	add a6, a5, x0
	add a5, a4, x0
	add a4, a3, x0
	add a3, a2, x0
	add a2, a1, x0
	add a1, a0, x0
	add a0, t0, x0

	call ld_sc_handler

    # no need to adjust return value

	ld x8, 0(sp)
	addi sp, sp, 8

    ld  x1, 0(sp)
    ld  x3, 8(sp)
    ld  x4, 16(sp)
    ld  x5, 24(sp)
    ld  x6, 32(sp)
    ld  x7, 40(sp)
    ld  x8, 48(sp)
    ld  x9, 56(sp)
#ld  x10, 64(sp)
#   ld  x11, 72(sp)
    ld  x12, 80(sp)
    ld  x13, 88(sp)
    ld  x14, 96(sp)
    ld  x15, 104(sp)
    ld  x16, 112(sp)
    ld  x17, 120(sp)
    ld  x18, 128(sp)
    ld  x19, 136(sp)
    ld  x20, 144(sp)
    ld  x21, 152(sp)
    ld  x22, 160(sp)
    ld  x23, 168(sp)
    ld  x24, 176(sp)
    ld  x25, 184(sp)
    ld  x26, 192(sp)
    ld  x27, 200(sp)
    ld  x28, 208(sp)
    ld  x29, 216(sp)
    ld  x30, 224(sp)
    ld  x31, 232(sp)

	addi sp, sp, 232
	ret

.size handle_syscall_loader, .-handle_syscall_loader
.section .note.GNU-stack,"",@progbits
