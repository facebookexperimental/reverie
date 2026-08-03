/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef SABRE_INCLUDES_ARCH_REWRITER_API_H_
#define SABRE_INCLUDES_ARCH_REWRITER_API_H_

#include "loader/rewriter.h"
#include "plugins/sbr_api_defs.h"
#include <stdbool.h>

extern const size_t JUMP_SIZE;

void patch_syscalls_in_range(struct library *lib, char *start, char *stop,
                             char **extra_space, int *extra_len, bool loader);
void api_detour_func(struct library *lib, char *start, char *end,
                     sbr_icept_callback_fn callback, bool copy_first_stack_arg,
                     char **extra_space, int *extra_len);
void detour_func(struct library *lib, char *start, char *end, int syscall_no,
                 char **extra_space, int *extra_len);

#endif /* SABRE_INCLUDES_ARCH_REWRITER_API_H_ */
