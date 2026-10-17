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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>

#include "bootstrap.h"
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


/* Plugin ELF finalizers are tool work just like sbr_init. The dynamic linker
 * otherwise invokes them after main with the guest routing domain active.
 * Keep the original callbacks and their ELF ordering; only their domain changes.
 */
typedef void (*plugin_fini_fn)(void);
static struct ld_link_map *client_link_maps;
static struct ld_link_map *guarded_plugin_map;
static plugin_fini_fn *plugin_fini_array;
static size_t plugin_fini_count;
static plugin_fini_fn plugin_fini;
static ElfW(Dyn) guarded_fini_entry = {.d_tag = DT_FINI};

static void run_plugin_finalizers(void) {
  bool was_plugin = calling_from_plugin();
  enter_plugin();
  for (size_t i = plugin_fini_count; i > 0; --i)
    plugin_fini_array[i - 1]();
  if (plugin_fini != NULL)
    plugin_fini();
  if (was_plugin)
    enter_plugin();
  else
    exit_plugin();
}

static void guard_plugin_finalizers(struct ld_link_map *maps,
                                    uintptr_t plugin_base) {
  /* Match the actual mapped object, not a filename or a dependency prefix.
   * dl_init can receive a map in the middle of its namespace's list.
   */
  while (maps != NULL && maps->l_prev != NULL)
    maps = (struct ld_link_map *)maps->l_prev;
  struct ld_link_map *plugin_map = NULL;
  for (struct ld_link_map *map = maps; map != NULL;
       map = (struct ld_link_map *)map->l_next) {
    if (map->l_addr == plugin_base) {
      if (plugin_map != NULL)
        errx(EXIT_FAILURE, "ambiguous plugin finalizer map");
      plugin_map = map;
    }
  }
  if (plugin_map == NULL)
    errx(EXIT_FAILURE, "missing plugin finalizer map");
  if (guarded_plugin_map != NULL) {
    if (guarded_plugin_map != plugin_map)
      errx(EXIT_FAILURE, "plugin finalizer map changed");
    return;
  }
  guarded_plugin_map = plugin_map;

  ElfW(Dyn) *array = plugin_map->l_info[DT_FINI_ARRAY];
  ElfW(Dyn) *fini = plugin_map->l_info[DT_FINI];
  if (array != NULL) {
    ElfW(Dyn) *size = plugin_map->l_info[DT_FINI_ARRAYSZ];
    if (size == NULL || size->d_un.d_val % sizeof(plugin_fini_fn) != 0)
      errx(EXIT_FAILURE, "invalid plugin finalizer array");
    plugin_fini_count = size->d_un.d_val / sizeof(plugin_fini_fn);
    plugin_fini_array =
        (plugin_fini_fn *)(plugin_base + array->d_un.d_ptr);
  }
  if (fini != NULL)
    plugin_fini = (plugin_fini_fn)(plugin_base + fini->d_un.d_ptr);
  if (array == NULL && fini == NULL)
    return;

  /* glibc calls FINI_ARRAY in reverse order, then FINI. One replacement FINI
   * invokes that exact sequence, so it also covers objects with only one kind.
   * ElfW(Addr) arithmetic is unsigned, including a lower-address loader shim.
   */
  guarded_fini_entry.d_un.d_ptr =
      (ElfW(Addr))run_plugin_finalizers - plugin_map->l_addr;
  plugin_map->l_info[DT_FINI_ARRAY] = NULL;
  plugin_map->l_info[DT_FINI_ARRAYSZ] = NULL;
  plugin_map->l_info[DT_FINI] = &guarded_fini_entry;
}

/* A matching name may be an undefined reference or a data object. Neither
 * implements this optional ABI, and neither may become a callable address.
 */
static sbr_bootstrap_install_fn find_continuation_installer(const char *path,
                                                            uintptr_t base) {
  bool valid = false;
  GElf_Sym symbol = find_elf_symbol(
      path, "reverie_sabre_install_loader_continuation_v1", &valid);
  if (!valid || symbol.st_shndx == SHN_UNDEF ||
      symbol.st_shndx >= SHN_LORESERVE ||
      GELF_ST_TYPE(symbol.st_info) != STT_FUNC || symbol.st_value == 0 ||
      symbol.st_value > UINTPTR_MAX - base)
    return NULL;
  return (void *)(base + symbol.st_value);
}

/* Optional ABI, looked up like the continuation installer. A plugin that will
 * arm its own trap path for every syscall the loader did not rewrite reports
 * it from this function, which must make no syscall: the loader calls it once,
 * after sbr_init and before post_load, and from a nonzero report on routes
 * every rewritten-site call to the plugin (ld_sc_handler.c). A plugin without
 * the symbol, or one that reports zero, keeps the existing routing. */
typedef int (*sbr_post_arm_routing_fn)(void);
static sbr_post_arm_routing_fn find_post_arm_routing(const char *path,
                                                     uintptr_t base) {
  bool valid = false;
  GElf_Sym symbol =
      find_elf_symbol(path, "reverie_sabre_post_arm_routing_v1", &valid);
  if (!valid || symbol.st_shndx == SHN_UNDEF ||
      symbol.st_shndx >= SHN_LORESERVE ||
      GELF_ST_TYPE(symbol.st_info) != STT_FUNC || symbol.st_value == 0 ||
      symbol.st_value > UINTPTR_MAX - base)
    return NULL;
  return (void *)(base + symbol.st_value);
}

bool sbr_plugin_defines_post_arm_report(const char *path) {
  return find_post_arm_routing(path, 0) != NULL;
}

// This is currently a huge and unstable hack. We intercept the loader in order
// to edit the internal representation of its link-map. More specifically we edit
// the preinit_array loaded from the client's elf file, by appending our shim
// to this array. The advantage of function calls made by the .preinit_array is
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

  sbr_bootstrap_install_fn install_bootstrap = NULL;
  bool continuation = false;
  if (sbr_bootstrap_enabled()) {
    sym_addr = addr_of_elf_symbol(
        abs_plugin_path, "reverie_sabre_install_loader_bootstrap_v1", &valid);
    if (!valid)
      errx(EXIT_FAILURE, "plugin does not support loader bootstrap");
    install_bootstrap = (void *)lib_base + sym_addr;
  } else {
    /* A distinct optional symbol preserves existing plugins, including tools
     * that support initial bootstrap but never requested continuation.
     */
    install_bootstrap = find_continuation_installer(abs_plugin_path, lib_base);
    continuation = install_bootstrap != NULL;
  }

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
  /* Resolved here, with the loader's own TLS, like every other plugin symbol;
   * called after sbr_init. */
  sbr_post_arm_routing_fn post_arm_routing =
      find_post_arm_routing(abs_plugin_path, lib_base);

  if (switch_client_tls)
    load_client_tls();

  /* Static clients preload the plugin into the loader namespace; dynamic
   * clients use the namespace supplied by their intercepted dl_init. */
  guard_plugin_finalizers(switch_client_tls ? client_link_maps
                                             : (struct ld_link_map *)_r_debug.r_map,
                           lib_base);

  // TODO(andronat): We need to split plugins into loadtime and runtime. In case
  // of splitting, how do we transfer state between loadtime and runtime
  // plugins?

  // TODO(andronat): Support client argv editing.
  enter_plugin();

  /* Optional, separate symbol: the existing sbr_init ABI is unchanged, and
   * old loaders/plugins continue to work without the explicit opt-in.
   * This setter only installs a callback; it cannot construct the Rust tool.
   */
  if (continuation) {
    if (sbr_bootstrap_install_continuation(install_bootstrap) != 0)
      errx(EXIT_FAILURE, "plugin refused loader continuation callback");
  } else if (install_bootstrap != NULL &&
             install_bootstrap(sbr_bootstrap_take_state) != 0) {
    errx(EXIT_FAILURE, "plugin refused loader bootstrap callback");
  }

  // char **orig_plugin_argv = plugin_argv; // Read below.
  sbr_post_load_fn post_load = NULL;
  sbr_icept_vdso_callback_fn plugin_vdso_callback = NULL;

  plugin_init(&plugin_argc, &plugin_argv, &register_function_intercepts,
              &plugin_vdso_callback, &plugin_sc_handler,
#ifdef __NX_INTERCEPT_RDTSC
              &plugin_rdtsc_handler,
#endif
              &post_load, abs_sabre_path, abs_client_path);

  bool post_arm = post_arm_routing != NULL && post_arm_routing() != 0;
  /* The rewriter has already left this run's short syscall sites as they
   * are. Only a plugin that arms its own trap path for every unrewritten
   * syscall sees them; with any other they would run unmonitored. */
  if (sbr_rewriter_short_sites_raw() && !post_arm)
    errx(EXIT_FAILURE,
         "refused: %s=raw needs a plugin that reports post-arm routing "
         "(reverie_sabre_post_arm_routing_v1); its short syscall sites would "
         "otherwise run unmonitored",
         SBR_SHORT_SYSCALL_SITES_ENV);
  if (post_arm) {
    /* A static client's loader still rewrites its images and installs its
     * SIGILL handler natively after this point (loader.c); refuse rather
     * than let those syscalls reach the plugin's trap path. */
    if (!switch_client_tls)
      errx(EXIT_FAILURE, "SaBRe: post-arm routing does not support static "
                         "clients");
    sbr_enable_post_arm_routing();
  }
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
  client_link_maps = main_map;

  ElfW(Dyn) *preinit_array_p = main_map->l_info[DT_PREINIT_ARRAY];
  ElfW(Dyn) *preinit_array_size_p = main_map->l_info[DT_PREINIT_ARRAYSZ];
  /* The plugin's start is appended to this array, so the client's own
   * preinit functions would run first, before the plugin arms its trap path,
   * and their short syscall sites were left raw. Refuse, as the in-guest
   * runtime refuses such clients, before ld.so runs any of them. */
  if (sbr_rewriter_short_sites_raw() && preinit_array_p != NULL &&
      preinit_array_size_p != NULL && preinit_array_size_p->d_un.d_val > 0) {
    load_sabre_tls();
    errx(EXIT_FAILURE,
         "refused: %s=raw: the client has a DT_PREINIT_ARRAY, whose functions "
         "would run before the plugin arms its trap path",
         SBR_SHORT_SYSCALL_SITES_ENV);
  }
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

bool sbr_premain_installed(void) {
  return real_dl_init != NULL && real_dl_map_object_deps != NULL &&
         real_dl_map_object != NULL;
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
