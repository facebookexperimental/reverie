/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PATHELF_H
#define PATHELF_H

#include <stdbool.h>

void inject_needed_lib(const char *elfpath, const char *pluginpath, int fd,
                       bool debug);

#endif /* !PATHELF_H */
