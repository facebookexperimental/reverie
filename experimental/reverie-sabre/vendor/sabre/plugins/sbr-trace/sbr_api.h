/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * This is a proposed API for Loader <-> Plugin interaction.
 * This header file should be imported by the plugin implementation.
 * TBD:
 * - What handles the errors - loader or plugin? i.e. do we use void return
 *   types in the plugin or do we use int or something similar?
 * - Segfault handler
 */
#ifndef SBR_API_H
#define SBR_API_H

// Includes
#include "sbr_api_defs.h"

/*
 * Protocol of plugin registration and startup:
 * 1. Loader is passed the path of the plugin (which is ELF Shared Object)
 * 2. Loader uses dlopen() to open the ELF and dlsym() to find sbr_init()
 * 3. Loader calls the sbr_init(), providing following arguments:
 *   a) pointers to argc and argv - both of them will be modified by the
 *      plugin
 *   b) pointer to segfault handler to be populated by the plugin
 *   c) pointer to interception callback registration function to be called by
 *      the plugin
 *   d) pointer to vDSO callback function to be populated by the plugin
 *   e) pointer to syscall handler function to be populated by the plugin
 *
 * Plugin side (in sbr_init()):
 * 4. the plugin parses arguments and leaves them in a state such that when
 *    sbr_init returns, argv[0] is the path of the ELF to be executed and
 *    consecutive arguments are standard arguments passed to the ELF
 * 5. the plugin populates segfault handler with appropriate function (optional)
 * 6. the plugin calls fn_icept_reg for each of the functions that need to be
 *    intercepted
 * 7. the plugin populates vdso_callback with appropriate function (optional)
 * 8. the plugin  populates syscall_handler with appropriate function (required)
 *
 * Loader side:
 * 9. the loader loads the ELF file
 * 10. the loader performs the interception of the functions registered:
 *   a) function is located and first few instructions are relocated to make
 *      room for unconditional jump - pointer to the first function is saved
 *      and an unconditional jump is injected at the end to connect these
 *      instructions to the rest of the function
 *   b) static code is injected that would divert the flow of control through
 *      a pointer returned by the callback (that has to be called with the
 *      pointer of the start of the original function - the first relocated
 *      instruction)
 *   c) the unconditional jump mentioned in a) now jumps to code in b)
 * 11. the loader performs the interception of vDSO if vdso_callback was
 *     populated in a similar way to 10.
 * 12. the loader transfers control to the entry point of the ELF
 */
void sbr_init(int *argc, char **argv[],
              // sbr_segfault_handler_fn *segfault_handler, // - TBD
              sbr_icept_reg_fn fn_icept_reg,
              sbr_icept_vdso_callback_fn *vdso_callback,
              sbr_sc_handler_fn *syscall_handler, sbr_post_load_fn *post_load);

// If the init above is used, nothing else is required from the API - loader
// knows what it needs to overwrite and what to overwrite it with.

#endif /* !SBR_API_H */
