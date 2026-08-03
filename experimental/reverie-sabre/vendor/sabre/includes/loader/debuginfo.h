/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef DEBUGINFO_H
#define DEBUGINFO_H

// Lookup external debug info file for a given executable/library
char *debuginfo_lookup_external(const char *absolute_path);

#endif
