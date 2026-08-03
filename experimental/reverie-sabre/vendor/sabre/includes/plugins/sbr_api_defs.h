/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef SBR_API_DEFS_H
#define SBR_API_DEFS_H

#include <stdbool.h>

// Helper typedef to simplify definition of sbr_icept_callback_fn
typedef void (*void_void_fn)(void);
typedef void_void_fn (*sbr_icept_callback_fn)(void_void_fn);

/*
 * Structure passed to the loader by SaBRe (or any other plugin) during
 * initialisation (in sbr_init).
 *
 * It contains two strings (library name as well as the name of the function
 * to be intercepted) and a callback function that loader calls while
 * intercepting the function.
 *
 * The callback function takes a function as an argument (which points to
 * relocated head of the function being intercepted) and returns a function
 * that is actually called instead of the function being intercepted.
 */
typedef struct sbr_fn_icept {
  const char *lib_name;
  const char *fn_name;
  /*
   * This is ugly - typedefs might help, but oh well.  icept_callback is a
   * pointer to a function that takes a pointer to a function that takes
   * nothing ant returns nothing and returns a function that takes nothing and
   * returns nothing. Reason for that is intercepted functions will all have
   * different parameters anyway, so we might as well use ANY function pointer
   * to keep the compiler happy and cast them to whatever is required.
   */
  // void (*(*icept_callback)(void (*)(void)))(void);
  sbr_icept_callback_fn icept_callback;
} sbr_fn_icept_struct;

// Signature for the syscall handler
typedef long (*sbr_sc_handler_fn)(long, long, long, long, long, long, long,
                                  void *);

#ifdef __NX_INTERCEPT_RDTSC
// Signature for the RDTSC handler
typedef long (*sbr_rdtsc_handler_fn)();
#endif

// Signature for vDSO callback function
typedef void_void_fn (*sbr_icept_vdso_callback_fn)(long, void_void_fn);

// Signature for the callback registration function
typedef void (*sbr_icept_reg_fn)(const sbr_fn_icept_struct *);

typedef void (*sbr_post_load_fn)(bool);

typedef void_void_fn sbr_premain_fn;

// Signature for the sbr_init function
typedef void (*sbr_init_fn)(
    int *, char ***,
    // sbr_segfault_handler_fn *segfault_handler, // - TBD
    sbr_icept_reg_fn, sbr_icept_vdso_callback_fn *, sbr_sc_handler_fn *,
#ifdef __NX_INTERCEPT_RDTSC
    sbr_rdtsc_handler_fn *,
#endif
    sbr_post_load_fn *, char *, char *);

struct syscall_stackframe;
void *get_syscall_return_address(struct syscall_stackframe *stack_frame);

// SaBRe uses the recursion_protector shim to check if a syscall is made from
// the SaBRe plugin or the client.
typedef bool (*calling_from_plugin_fn)(void);
typedef void (*enter_plugin_fn)(void);
typedef void (*exit_plugin_fn)(void);
typedef bool (*is_vdso_ready_fn)(void);

#endif /* !SBR_API_DEFS_H */
