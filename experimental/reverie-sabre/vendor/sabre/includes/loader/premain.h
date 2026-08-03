/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PREMAIN_H
#define PREMAIN_H

#include "plugins/sbr_api_defs.h"

// Copied from:
// https://code.woboq.org/userspace/glibc/include/link.h.html#link_map
#define DT_THISPROCNUM 0
struct ld_link_map {
  ElfW(Addr) l_addr;
  char *l_name;
  ElfW(Dyn) * l_ld;
  struct link_map *l_next, *l_prev;
  struct link_map *l_real;
  Lmid_t l_ns;
  struct libname_list *l_libname;
  ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM +
                     DT_VALNUM + DT_ADDRNUM];
};

void setup_sbr_premain(sbr_icept_reg_fn);
void init_sbr_static_plugin(void);

#endif /* !PREMAIN_H */
