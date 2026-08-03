/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef LD_SC_HANDLER_H
#define LD_SC_HANDLER_H

void load_client_tls();
void load_sabre_tls();

long runtime_syscall_router(long, long, long, long, long, long, long, void *);
void_void_fn ld_vdso_callback(long, void_void_fn);
void setup_plugin_vdso(sbr_icept_vdso_callback_fn);

#endif /* !LD_SC_HANDLER_H */
