/* Copyright © 2010 The Chromium Authors. All rights reserved.
 * Copyright © 2019 Software Reliability Group, Imperial College London
 *
 * This file is part of SaBRe.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-3-Clause
 */

#ifndef X86_DECODER_H
#define X86_DECODER_H

#include <stdbool.h>

#include "compiler.h"

enum { REX_B = 0x01, REX_X = 0x02, REX_R = 0x04, REX_W = 0x08 };

unsigned short next_inst(const char **ip, bool is64bit, bool *has_prefix,
                         char **rex_ptr, char **mod_rm_ptr, char **sib_ptr,
                         bool *is_group) __internal;

#endif // X86_DECODER_H
