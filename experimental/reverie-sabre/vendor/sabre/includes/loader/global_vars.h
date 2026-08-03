/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef GLOBAL_VARS_H
#define GLOBAL_VARS_H

#include <limits.h>

#include "plugins/sbr_api_defs.h"

#define MAX_ICEPT_RECORDS 50
#define MAX_ICEPT_STRLEN 80

typedef struct {
  char lib_name[MAX_ICEPT_STRLEN];
  char fn_name[MAX_ICEPT_STRLEN];
  sbr_icept_callback_fn callback;
  bool copy_first_stack_arg;
} sbr_fn_icept_local_struct;

extern int plugin_argc;
extern char **plugin_argv;
extern char abs_sabre_path[PATH_MAX];
extern char abs_plugin_path[PATH_MAX];
extern char abs_client_path[PATH_MAX];

extern int registered_icept_cnt;
extern sbr_fn_icept_local_struct intercept_records[MAX_ICEPT_RECORDS];
extern sbr_icept_vdso_callback_fn vdso_callback;
extern sbr_sc_handler_fn plugin_sc_handler;
#ifdef __NX_INTERCEPT_RDTSC
extern sbr_rdtsc_handler_fn plugin_rdtsc_handler;
#endif
extern calling_from_plugin_fn calling_from_plugin;
extern enter_plugin_fn enter_plugin;
extern exit_plugin_fn exit_plugin;
extern is_vdso_ready_fn is_vdso_ready;

extern const char *known_syscall_libs[];

void register_function_intercepts(const sbr_fn_icept_struct *);
void register_function_intercept_with_stack_arg(const sbr_fn_icept_struct *);

#endif /* !GLOBAL_VARS_H */
