/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <elf.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>

#include "elf_loading.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "loader/rewriter.h"
#include "maps.h"
#include "premain.h"

// From: https://code.woboq.org/userspace/glibc/elf/dl-init.c.html#_dl_init
typedef void (*_dl_init_fn)(struct ld_link_map *, int, char **, char **);
static _dl_init_fn real_dl_init;
// From: https://code.woboq.org/userspace/glibc/elf/dl-deps.c.html#_dl_map_object_deps
typedef void (*_dl_map_object_deps_fn)(struct ld_link_map *,
                                       struct ld_link_map **, unsigned int, int,
                                       int);
static _dl_map_object_deps_fn real_dl_map_object_deps;
// From: https://code.woboq.org/userspace/glibc/elf/dl-load.c.html#_dl_map_object
typedef void *(*_dl_map_object_fn)(struct link_map *, const char *, int, int,
                                   int, Lmid_t, void *);
static _dl_map_object_fn real_dl_map_object;
typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
static clock_gettime_fn real_clock_gettime;

// This is currently a huge and unstable hack. We intercept the loader in order
// to edit the internal representation of its link-map. More specifically we edit
// the preinit_array loaded from the client's elf file, by prepending our shim
// in this array. The advantage of function calls made by the .preinit_array is
// that we can safely use arbitrary function calls to client libraries as GOT
// and all that jazz is ready.
// TODO(andronat): Write a tests that check client always gets client argv.
static void init_sbr_plugin(bool switch_client_tls) {
  if (switch_client_tls)
    load_sabre_tls();

  uintptr_t lib_base = first_region(abs_plugin_path);
  if (lib_base == 0)
    errx(EXIT_FAILURE, "Couldn't find memory base of %s.", abs_plugin_path);

  bool valid = false;
  ElfW(Addr) sym_addr;
  // TODO(andronat): add vaddr?
  sym_addr = addr_of_elf_symbol(abs_plugin_path, "sbr_init", &valid);
  assert(valid == true && "No symbol 'sbr_init'");
  sbr_init_fn plugin_init = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "calling_from_plugin", &valid);
  assert(valid == true && "No symbol 'calling_from_plugin'");
  calling_from_plugin = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "enter_plugin", &valid);
  assert(valid == true && "No symbol 'enter_plugin'");
  enter_plugin = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "exit_plugin", &valid);
  assert(valid == true && "No symbol 'exit_plugin'");
  exit_plugin = (void *)lib_base + sym_addr;

  sym_addr = addr_of_elf_symbol(abs_plugin_path, "is_vdso_ready", &valid);
  assert(valid == true && "No symbol 'is_vdso_ready'");
  is_vdso_ready = (void *)lib_base + sym_addr;

  if (switch_client_tls)
    load_client_tls();

  // TODO(andronat): We need to split plugins into loadtime and runtime. In case
  // of splitting, how do we transfer state between loadtime and runtime
  // plugins?

  // TODO(andronat): Support client argv editing.
  enter_plugin();

  // char **orig_plugin_argv = plugin_argv; // Read below.
  sbr_post_load_fn post_load = NULL;
  sbr_icept_vdso_callback_fn plugin_vdso_callback = NULL;

  plugin_init(&plugin_argc, &plugin_argv, &register_function_intercepts,
              &plugin_vdso_callback, &plugin_sc_handler,
#ifdef __NX_INTERCEPT_RDTSC
              &plugin_rdtsc_handler,
#endif
              &post_load, abs_sabre_path, abs_client_path);

  if (post_load != NULL)
    post_load(!switch_client_tls);

  // Rewrite vDSO handlers as they cannot be switched dynamically.
  // TODO: Rewriting the vDSO functions for a second time didn't work. The
  // rewriter is not idempotent.
  if (plugin_vdso_callback != NULL)
    setup_plugin_vdso(plugin_vdso_callback);

  // TODO: To free `plugin_argv` we need to switch TLSs, it doesn't worth it.
  // load_sabre_tls();
  // free(orig_plugin_argv);
  // load_client_tls();

  exit_plugin();
}

static void preinit_shim_init_sbr_plugin(int argc, char **argv, char **env) {
  unreferenced_var(argc);
  unreferenced_var(argv);
  unreferenced_var(env);

  init_sbr_plugin(true);
}

void init_sbr_static_plugin(void) { init_sbr_plugin(false); }

static ElfW(Dyn) new_dyn_entries[2] = {{.d_tag = DT_PREINIT_ARRAY},
                                       {.d_tag = DT_PREINIT_ARRAYSZ}};
static bool sbr_preinit_done = false;

// Shared objects are not allowed to register preinit_array:
// https://github.com/bminor/binutils-gdb/blob/20ea3acc727f3be6322dfbd881e506873535231d/bfd/elflink.c#L7302
// So we have to intercept the loader and inject our initialization functions.
// The following mechanism of course is very fragile. If the loader changes,
// or if the internals of the loader change, then the following won't work.
// You might be tempted to replace the following with some elf rewriting library.
// Our experience has shown that this didn't work well because (e.g. patchelf)
// is changing the elf layout so significantly (e.g. moves LOAD segments around)
// that those changes create issues with loading debug symbols.
void sbr_dl_init(struct ld_link_map *main_map, int ac, char **av, char **e) {
  if (sbr_preinit_done)
    return real_dl_init(main_map, ac, av, e);

  // Make sure this function shouldn't use the %fs register. e.g. don't use
  // printf.
  assert(main_map != NULL);

  ElfW(Dyn) *preinit_array_p = main_map->l_info[DT_PREINIT_ARRAY];
  ElfW(Dyn) *preinit_array_size_p = main_map->l_info[DT_PREINIT_ARRAYSZ];
  if (preinit_array_p != NULL) {
    // Get the current size of preinit_array. Default is 0.
    new_dyn_entries[1].d_un.d_val = preinit_array_size_p->d_un.d_val;
  }

  // Copy the ElfW(Dyn) structs to our own space and update main_map.
  main_map->l_info[DT_PREINIT_ARRAY] = &new_dyn_entries[0];
  main_map->l_info[DT_PREINIT_ARRAYSZ] = &new_dyn_entries[1];

  // We will add one more entry to the preinit array.
  new_dyn_entries[1].d_un.d_val += sizeof(ElfW(Addr));

  // We need the newly allocated space to be after main_map->l_addr because
  // look here: https://code.woboq.org/userspace/glibc/elf/dl-init.c.html#102.
  // Memory addresses are unsigned integers and thus we need the
  // new_preinit_array to be allocated to a higher address than main_map->l_addr
  // or else there will be undefined behaviour with wrapping around unsigned
  // integer values.
  void *hint = (void *)main_map->l_addr;
  ElfW(Addr) *new_preinit_array = (ElfW(Addr) *)mmap(
      hint, new_dyn_entries[1].d_un.d_val, PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if ((void *)new_preinit_array < hint) {
    // Free the previous area.
    assert(munmap(new_preinit_array, new_dyn_entries[1].d_un.d_val) == 0);

    // Try again with a hint from the area just before the stack.
    load_sabre_tls();
    void *hint2 = (void *)end_of_stack_region();

    new_preinit_array = (ElfW(Addr) *)mmap(hint2, new_dyn_entries[1].d_un.d_val,
                                           PROT_READ | PROT_WRITE,
                                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert((void *)new_preinit_array >= hint2);
    load_client_tls();
  }

  // If there is a preinit_array already, append it.
  if (preinit_array_p != NULL) {
    ElfW(Addr) *preinit_array =
        (ElfW(Addr) *)(preinit_array_p->d_un.d_ptr + main_map->l_addr);
    memcpy(&new_preinit_array[0], preinit_array,
           preinit_array_size_p->d_un.d_val);
  }

  // Append our plugin so it initializes after pthreads and LLVM sanitizers.
  int pos = new_dyn_entries[1].d_un.d_val / sizeof(ElfW(Addr)) - 1;
  new_preinit_array[pos] = (ElfW(Addr))preinit_shim_init_sbr_plugin;

  new_dyn_entries[0].d_un.d_val =
      (ElfW(Addr))new_preinit_array - main_map->l_addr;

  // We need to make sure we won't call this again as there are cases were libc
  // might call _dl_init multiple times. e.g. when loading libnss.
  sbr_preinit_done = true;

  // Interesting Trivia: glibc initializes the pthread library first with a
  // dirty hack as shown here:
  // https://code.woboq.org/userspace/glibc/elf/dl-init.c.html#84.
  // DF_1_INITFIRST is a specialized flag available only to libpthread as
  // suggested here:
  // https://stackoverflow.com/questions/53001746/in-what-order-are-shared-libraries-initialized-and-finalized#comment92968938_53005162

  return real_dl_init(main_map, ac, av, e);
}

static bool ready_to_inject_plugin = false;
static int plugin_position = 0;

// Instead of hacking link-maps and replacing elf symbols in the l_ld, we could
// make sabre to call itself with LD_PRELOAD and execve. Though this method
// can be just portable and safe, the "problem" is that we change the order of
// library loading which again create issues with dynamically loaded ASan. We
// are already bounded to intercept the internals of the loader due to the
// preinit_array restriction, thus intercepting the loader again to inject our
// plugin as a DT_NEEDED, makes no difference to the already non-portability.
void sbr_dl_map_object_deps(struct ld_link_map *map,
                            struct ld_link_map **preloads,
                            unsigned int npreloads, int trace_mode,
                            int open_mode) {
  if (sbr_preinit_done)
    return real_dl_map_object_deps(map, preloads, npreloads, trace_mode,
                                   open_mode);

  int first_dt_needed = 0;
  for (; map->l_ld[first_dt_needed].d_tag != DT_NEEDED &&
         map->l_ld[first_dt_needed].d_tag != DT_NULL;
       first_dt_needed++)
    ;
  int last_dt_needed = first_dt_needed;
  for (; map->l_ld[last_dt_needed].d_tag == DT_NEEDED &&
         map->l_ld[first_dt_needed].d_tag != DT_NULL;
       last_dt_needed++)
    ;
  int l_ld_len = last_dt_needed;
  for (; map->l_ld[l_ld_len].d_tag != DT_NULL; l_ld_len++)
    ;

  ElfW(Dyn) *new_l_ld = malloc((l_ld_len + 2) * sizeof(ElfW(Dyn)));

  // We add the plugin library last, so we can avoid cases where ASan is loaded
  // dynamically. ASan expects to be loaded first, or it fails. We might want to
  // have it as a configurable strategy in the future, as the earlier the plugin
  // is, the more weak symbols it can intercept.

  // Copy up to the last DT_NEEDED.
  memcpy(new_l_ld, map->l_ld, last_dt_needed * sizeof(ElfW(Dyn)));

  // Leave 1 empty spot right after all DT_NEEDED and repeat the last entry.
  new_l_ld[last_dt_needed] = map->l_ld[last_dt_needed - 1];
  plugin_position = last_dt_needed - first_dt_needed;

  // If it is a dynamic binary but there are no dependencies, let's create one
  // for ourselves.
  if (new_l_ld[last_dt_needed].d_tag != DT_NEEDED) {
    new_l_ld[last_dt_needed].d_tag = DT_NEEDED;
    new_l_ld[last_dt_needed].d_un.d_val = 0;
    new_l_ld[last_dt_needed].d_un.d_ptr = 0;
    map->l_info[DT_NEEDED] = &new_l_ld[last_dt_needed];
  }

  // Copy everything left to the end.
  memcpy(&new_l_ld[last_dt_needed + 1], &map->l_ld[last_dt_needed],
         (l_ld_len - last_dt_needed + 1) * sizeof(ElfW(Dyn)));

  ElfW(Dyn) *old_l_ld = map->l_ld;
  map->l_ld = new_l_ld;

  ready_to_inject_plugin = true;

  real_dl_map_object_deps(map, preloads, npreloads, trace_mode, open_mode);

  // Let's put everything back before we break something important.
  map->l_info[DT_NEEDED] = NULL;
  map->l_ld = old_l_ld;
}

void *sbr_dl_map_object(struct link_map *loader, const char *name, int type,
                        int trace_mode, int mode, Lmid_t nsid, void *scope) {
  if (sbr_preinit_done)
    real_dl_map_object(loader, name, type, trace_mode, mode, nsid, scope);

  static int counter = 0;
  if (ready_to_inject_plugin) {
    if (counter == plugin_position) {
      name = abs_plugin_path;
      ready_to_inject_plugin = false;
    }
    counter++;
  }

  return real_dl_map_object(loader, name, type, trace_mode, mode, nsid, scope);
}

int sabre_clock_gettime(clockid_t clockid, struct timespec *tp) {
  if (is_vdso_ready())
    return real_clock_gettime(clockid, tp);
  return syscall(SYS_clock_gettime, clockid, tp);
}

static void_void_fn premain_icept_callback(void_void_fn r_dl_init) {
  real_dl_init = (_dl_init_fn)r_dl_init;
  return (void_void_fn)sbr_dl_init;
}
static void_void_fn elf_deps_icept_callback(void_void_fn r_dl_map_object_deps) {
  real_dl_map_object_deps = (_dl_map_object_deps_fn)r_dl_map_object_deps;
  return (void_void_fn)sbr_dl_map_object_deps;
}
static void_void_fn elf_deps_2_icept_callback(void_void_fn r_dl_map_object) {
  real_dl_map_object = (_dl_map_object_fn)r_dl_map_object;
  return (void_void_fn)sbr_dl_map_object;
}
static void_void_fn vdso_guard_icept_callback(void_void_fn r_clock_gettime) {
  real_clock_gettime = (clock_gettime_fn)r_clock_gettime;
  return (void_void_fn)sabre_clock_gettime;
}

void setup_sbr_premain(sbr_icept_reg_fn fn_icept_reg) {
  sbr_fn_icept_struct premain = {.lib_name = "ld",
                                 .fn_name = "_dl_init",
                                 .icept_callback = premain_icept_callback};
  fn_icept_reg(&premain);
  sbr_fn_icept_struct elf_deps = {.lib_name = "ld",
                                  .fn_name = "_dl_map_object_deps",
                                  .icept_callback = elf_deps_icept_callback};
  fn_icept_reg(&elf_deps);
  sbr_fn_icept_struct elf_deps_2 = {.lib_name = "ld",
                                    .fn_name = "_dl_map_object",
                                    .icept_callback =
                                        elf_deps_2_icept_callback};
  register_function_intercept_with_stack_arg(&elf_deps_2);
  sbr_fn_icept_struct vdso_guard = {.lib_name = "libc",
                                    .fn_name = "__clock_gettime",
                                    .icept_callback =
                                        vdso_guard_icept_callback};
  fn_icept_reg(&vdso_guard);
}
