/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef SABRE_INCLUDES_ARCH_SYSCALL_STACKFRAME_H_
#define SABRE_INCLUDES_ARCH_SYSCALL_STACKFRAME_H_

#include <stddef.h>

// Stack frame built by handle_syscall and in the patching code in rewriter.c
struct syscall_stackframe;

void *get_syscall_return_address(struct syscall_stackframe *stack_frame);
size_t get_offsetof_syscall_return_address(void);

#endif /* SABRE_INCLUDES_ARCH_SYSCALL_STACKFRAME_H_ */
