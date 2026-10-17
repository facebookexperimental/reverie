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
#ifdef __x86_64__
#include <asm/processor-flags.h>
#endif
#include <dirent.h>
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <linux/binfmts.h>
#include <linux/limits.h>
#include <malloc.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch/handle_syscall.h"
#include "arch/rewriter_tools.h"
#include "bootstrap.h"
#include "compiler.h"
#include "elf_loading.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "loader/backend_stats.h"
#include "macros.h"
#include "maps.h"
#include "plugins/sbr_api_defs.h"
#include "premain.h"
#include "rewriter.h"
#ifdef __NX_INTERCEPT_RDTSC
#include "arch/handle_rdtsc.h"
#endif
#include "arch/syscall_stackframe.h"

#define MAX_BUF_SIZE PATH_MAX + 1024
#ifdef __x86_64__
#define SABRE_DYNAMIC_LINKER "/lib64/ld-linux-x86-64.so.2"
#endif

typedef uintptr_t __attribute__((may_alias)) stack_val_t;

// Global variables
int plugin_argc = 0;
char **plugin_argv = NULL;
char abs_sabre_path[PATH_MAX];
char abs_plugin_path[PATH_MAX];
char abs_client_path[PATH_MAX];
sbr_fn_icept_local_struct intercept_records[MAX_ICEPT_RECORDS];
int registered_icept_cnt = 0;
sbr_sc_handler_fn plugin_sc_handler = NULL;
sbr_icept_vdso_callback_fn vdso_callback = ld_vdso_callback;
#ifdef __NX_INTERCEPT_RDTSC
sbr_rdtsc_handler_fn plugin_rdtsc_handler;
#endif
calling_from_plugin_fn calling_from_plugin = NULL;
enter_plugin_fn enter_plugin = NULL;
exit_plugin_fn exit_plugin = NULL;
is_vdso_ready_fn is_vdso_ready = NULL;

#ifdef __x86_64__
static __attribute__((noreturn)) void
reexec_static_client_with_plugin(int argc, char **argv) {
  char **loader_argv = calloc((size_t)argc + 4, sizeof(*loader_argv));
  if (loader_argv == NULL)
    err(EXIT_FAILURE, "Failed to allocate static client loader arguments");

  loader_argv[0] = SABRE_DYNAMIC_LINKER;
  loader_argv[1] = "--preload";
  loader_argv[2] = abs_plugin_path;
  loader_argv[3] = abs_sabre_path;
  for (int i = 1; i < argc; ++i)
    loader_argv[i + 3] = argv[i];

  execv(SABRE_DYNAMIC_LINKER, loader_argv);
  err(EXIT_FAILURE, "Failed to restart SaBRe with the static client plugin");
}
#endif

static void register_function_intercept(const sbr_fn_icept_struct *r_struct,
                                        bool copy_first_stack_arg) {
  const struct intercept_tls_context *tls = NULL;
#ifdef __x86_64__
  struct intercept_tls_context context;
  if (calling_from_plugin != NULL && enter_intercept_loader_tls(&context))
    tls = &context;
#endif
  /* Registering an intercept patches code, and the loader's patching syscalls
   * would reach the plugin's trap path once post-arm routing is on. Checked
   * after the switch to the loader's TLS, which errx needs. */
  if (sbr_post_arm_routing())
    errx(EXIT_FAILURE,
         "SaBRe: function intercept registered after post-arm routing");
  assert(strlen(r_struct->lib_name) < MAX_ICEPT_STRLEN);
  assert(strlen(r_struct->fn_name) < MAX_ICEPT_STRLEN);

  for (int i = 0; i < registered_icept_cnt; ++i) {
    if (!strcmp(intercept_records[i].lib_name, r_struct->lib_name) &&
        !strcmp(intercept_records[i].fn_name, r_struct->fn_name)) {
      if (intercept_records[i].callback != r_struct->icept_callback ||
          intercept_records[i].copy_first_stack_arg != copy_first_stack_arg)
        errx(EXIT_FAILURE, "conflicting function intercept registration");
      goto done; // Never detour an already registered entry a second time.
    }
  }
  if (registered_icept_cnt == MAX_ICEPT_RECORDS)
    errx(EXIT_FAILURE, "function intercept table is full");

  strcpy(intercept_records[registered_icept_cnt].lib_name, r_struct->lib_name);
  strcpy(intercept_records[registered_icept_cnt].fn_name, r_struct->fn_name);
  intercept_records[registered_icept_cnt].callback = r_struct->icept_callback;
  intercept_records[registered_icept_cnt].copy_first_stack_arg =
      copy_first_stack_arg;

  int registered = registered_icept_cnt++;
  if (tls != NULL) {
    // Dynamic plugin registration follows dependency mapping. Static clients
    // retain their original full rewrite after plugin initialization.
    // Apply only this new function entry; syscall/vDSO rewrites are not
    // idempotent and must not be repeated on those existing mappings.
    memorymaps_patch_intercept(registered, tls);
  }
done:
  ;
#ifdef __x86_64__
  if (tls != NULL)
    load_intercept_tls(tls->caller);
#endif
}

void register_function_intercepts(const sbr_fn_icept_struct *r_struct) {
  register_function_intercept(r_struct, false);
}

void register_function_intercept_with_stack_arg(
    const sbr_fn_icept_struct *r_struct) {
  register_function_intercept(r_struct, true);
}

static void *find_auxv(void *argv) {
  char **search_ptr;

  for (search_ptr = (char **)argv; *search_ptr; ++search_ptr)
    ;

  for (++search_ptr; *search_ptr; ++search_ptr)
    ;

  return (void *)(search_ptr + 1);
}

#ifdef __x86_64__
static void sigill_handler(int sig __unused, siginfo_t *info, void *ucontext) {
  assert(sig == SIGILL);
  ucontext_t *ctx = ucontext;
  uint16_t faulting_insn = *(uint16_t *)info->si_addr;
  size_t instruction_len = 2;
  // WARNING endianness
  if (faulting_insn == 0xFF0F) { // syscall
    sbr_backend_stats_record_slow_path(
        sbr_backend_stats_is_rewrite_sigill_site(info->si_addr)
            ? SBR_SLOW_REWRITE_SIGILL_DISPATCH
            : SBR_SLOW_PTRACE_INSTALLED_SIGILL_DISPATCH);
    // call syscall handler with proper arguments
    greg_t *regs = ctx->uc_mcontext.gregs;
    uintptr_t ret_addr = regs[REG_RIP] + 2;
    // Fault delivery sets RF in the saved frame so the faulting instruction
    // can be resumed. It was not present in the guest's pre-SYSCALL flags.
    greg_t syscall_rflags = regs[REG_EFL] & ~X86_EFLAGS_RF;
    regs[REG_EFL] = syscall_rflags;
    // simulate a syscall stack frame, as would be built by handle_syscall
    void *wrapper_sp =
        (void *)((intptr_t)&ret_addr - get_offsetof_syscall_return_address());
    // The ptrace fallback can install this marker in a shared libc site. Route
    // through the normal recursion boundary so guest calls reach the plugin,
    // while syscalls made by the plugin itself execute natively.
    regs[REG_RAX] = runtime_sigill_syscall_router(
        regs[REG_RAX], regs[REG_RDI], regs[REG_RSI], regs[REG_RDX],
        regs[REG_R10], regs[REG_R8], regs[REG_R9], wrapper_sp);
    regs[REG_RCX] = ret_addr;
    regs[REG_R11] = syscall_rflags;
#ifdef __NX_INTERCEPT_RDTSC
    // TODO-HUMAN-REVIEW(PR-2): Review deterministic RDTSCP SIGILL restoration.
  } else if (faulting_insn == 0x0B0F || // RDTSC marker
             faulting_insn == 0x0C0F) { // RDTSCP marker
    sbr_backend_stats_record_slow_path(faulting_insn == 0x0B0F
                                           ? SBR_SLOW_RDTSC_SIGILL_DISPATCH
                                           : SBR_SLOW_RDTSCP_SIGILL_DISPATCH);
    greg_t *regs = ctx->uc_mcontext.gregs;
    uint64_t tsc = (uint64_t)runtime_rdtsc_router();
    regs[REG_RAX] = (uint32_t)tsc;
    regs[REG_RDX] = (uint32_t)(tsc >> 32);
    if (faulting_insn == 0x0C0F) {
      regs[REG_RCX] = 0;
      instruction_len = 3;
    }
#endif
  } else {
    // not from SaBRe, so use default handler
    const struct sigaction dfl_sa = {.sa_handler = SIG_DFL};
    sigaction(SIGILL, &dfl_sa, NULL);
    raise(SIGILL);

    // wait for SIGILL to be delivered
    sigset_t consume_mask;
    sigfillset(&consume_mask);
    sigdelset(&consume_mask, SIGILL);
    sigsuspend(&consume_mask);
  }

  // Skip UD insn to point to return address
  ctx->uc_mcontext.gregs[REG_RIP] += instruction_len;
}
#elif defined __riscv
static void sigill_handler(int sig __unused, siginfo_t *info, void *ucontext) {
  assert(sig == SIGILL);
  ucontext_t *ctx = ucontext;
  uint32_t faulting_insn = *(uint32_t *)info->si_addr;

  if (faulting_insn == 0) { // syscall
    // call syscall handler with proper arguments
    greg_t *regs = ctx->uc_mcontext.__gregs;
    uintptr_t ret_addr = regs[REG_PC] + 4;
    // simulate a syscall stack frame, as would be built by handle_syscall
    void *wrapper_sp =
        (void *)((intptr_t)&ret_addr - get_offsetof_syscall_return_address());
    // Keep marker traps consistent with rewritten syscall sites: the runtime
    // router bypasses the plugin when this syscall originated in its handler.
    regs[REG_A0] = runtime_sigill_syscall_router(
        regs[REG_A0 + 7], regs[REG_A0], regs[REG_A0 + 1], regs[REG_A0 + 2],
        regs[REG_A0 + 3], regs[REG_A0 + 4], regs[REG_A0 + 5], wrapper_sp);
  } else {
    // not from SaBRe, so use default handler
    const struct sigaction dfl_sa = {.sa_handler = SIG_DFL};
    sigaction(SIGILL, &dfl_sa, NULL);
    raise(SIGILL);

    // wait for SIGILL to be delivered
    sigset_t consume_mask;
    sigfillset(&consume_mask);
    sigdelset(&consume_mask, SIGILL);
    sigsuspend(&consume_mask);
  }

  // Skip illegal insn to point to return address
  ctx->uc_mcontext.__gregs[REG_PC] += 4;
}
#endif // __x86_64__ / __riscv

static void print_usage(void) {
  static const char *usage =
      "Usage:\n"
      "\tSaBRe <PLUGIN> [<PLUGIN_OPTIONS>] -- <CLIENT> [<CLIENT_OPTIONS>]\n"
      "<PLUGIN> is the full path to the desired plugin library\n"
      "<CLIENT> is the full path to the client binary to be run under SaBRe\n"
      "<PLUGIN_OPTIONS> and <CLIENT_OPTIONS> depend on the plugin and the "
      "client\n";
  puts(usage);
}

static size_t find_client_path_idx(char **argv) {
  for (size_t i = 0; argv[i] != NULL; i++) {
    if (strlen(argv[i]) == 2 && strncmp(argv[i], "--", 2) == 0)
      return ++i;
  }
  errx(EXIT_FAILURE, "Missing -- from CLI. Please check --help.");
}

// Parse the shebang line if present.
static int parse_shebang(const char *client_path,
                         char shebang_path[BINPRM_BUF_SIZE],
                         char shebang_arg[BINPRM_BUF_SIZE]) {
  if (access(client_path, X_OK) < 0) {
    _nx_fatal_printf("Provided client: %s, is not executable!\n", client_path);
  }
  FILE *f = fopen(client_path, "r");
  if (f == NULL) {
    return 0;
  }

  char shebang_buf[BINPRM_BUF_SIZE];
  char *rc = fgets(shebang_buf, BINPRM_BUF_SIZE, f);
  fclose(f);
  if (rc == NULL || memcmp(shebang_buf, "#!", 2) != 0) {
    return 0;
  }

  // Skip #!.
  char *shebang_line = shebang_buf + 2;

  // Get the tokens.
  char *token1 = strtok(shebang_line, " \n\r\t");
  memcpy(shebang_path, token1, strlen(token1));
  char *token2 = strtok(NULL, " \n\r\t");
  if (token2 != NULL) {
    memcpy(shebang_arg, token2, strlen(token2));
    return 2;
  }
  return 1;
}

/* A launch specification: how a launcher runs a client under SaBRe without
 * putting SaBRe on the client's command line or in its environment. The
 * kernel then builds the client's initial stack, /proc/self/cmdline and
 * /proc/self/environ from the client's own argv and environment, as for an
 * exec of the client itself.
 *
 * The launcher passes an inherited, sealed memfd holding SBR_LAUNCH_MAGIC
 * followed by NUL-terminated strings: the plugin path, the client path, then
 * any number of NAME=VALUE settings, ended by an empty string. The client
 * path names an ELF image: the launcher resolves a script's interpreter
 * first, as the kernel would, and passes the argv the kernel would give it.
 * The settings go to the plugin as its arguments after its path: SaBRe
 * loads the plugin into the client's own libc, so SaBRe's environment would
 * not reach it, and the client's would reach the guest. The loader also
 * reads its own two: the bootstrap option, which it consumes, and the stats
 * descriptor, which it shares with the plugin.
 */
#define SBR_LAUNCH_MAGIC "SABRE-LAUNCH-V1"
#define SBR_LAUNCH_MAX_BYTES (64 * 1024)

struct launch_spec {
  char *bytes;
  const char *plugin;
  const char *client;
  char **settings; /* NULL-terminated */
  int setting_count;
};

static bool read_launch_spec(struct launch_spec *spec) {
  DIR *directory = opendir("/proc/self/fd");
  if (directory == NULL)
    err(EXIT_FAILURE, "cannot list descriptors for a launch specification");
  int found = -1;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;
    long fd = strtol(entry->d_name, &end, 10);
    if (end == entry->d_name || *end != '\0' || fd <= STDERR_FILENO ||
        fd == dirfd(directory))
      continue;
    char magic[sizeof(SBR_LAUNCH_MAGIC)];
    struct stat metadata;
    if (fstat((int)fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        pread((int)fd, magic, sizeof(magic), 0) != (ssize_t)sizeof(magic) ||
        memcmp(magic, SBR_LAUNCH_MAGIC, sizeof(magic)) != 0)
      continue;
    if (found >= 0)
      errx(EXIT_FAILURE, "more than one launch specification");
    found = (int)fd;
  }
  closedir(directory);
  if (found < 0)
    return false;

  int seals = fcntl(found, F_GET_SEALS);
  struct stat metadata;
  if (seals < 0 ||
      (seals & (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW)) !=
          (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW) ||
      fstat(found, &metadata) != 0 || metadata.st_size <= 0 ||
      metadata.st_size > SBR_LAUNCH_MAX_BYTES)
    errx(EXIT_FAILURE, "launch specification is not a sealed, bounded file");
  size_t size = (size_t)metadata.st_size;
  char *bytes = malloc(size + 1);
  if (bytes == NULL || pread(found, bytes, size, 0) != (ssize_t)size)
    errx(EXIT_FAILURE, "cannot read the launch specification");
  close(found);
  bytes[size] = '\0';

  /* Walk the strings after the magic; every one must end inside the file. */
  size_t at = sizeof(SBR_LAUNCH_MAGIC);
  const char *strings[2] = {NULL, NULL};
  /* Each setting takes at least two bytes, so this bounds their number. */
  char **settings = calloc(size / 2 + 1, sizeof(*settings));
  if (settings == NULL)
    err(EXIT_FAILURE, "cannot allocate launch specification settings");
  int setting_count = 0;
  for (int index = 0;; ++index) {
    if (at >= size)
      errx(EXIT_FAILURE, "launch specification is truncated");
    const char *value = bytes + at;
    size_t length = strnlen(value, size - at);
    if (at + length >= size)
      errx(EXIT_FAILURE, "launch specification string is unterminated");
    at += length + 1;
    if (index < 2) {
      if (length == 0)
        errx(EXIT_FAILURE, "launch specification lacks a plugin or client");
      strings[index] = value;
      continue;
    }
    if (length == 0)
      break;
    if (strchr(value, '=') == NULL || value[0] == '=')
      errx(EXIT_FAILURE, "launch specification setting is not NAME=VALUE");
    if (strncmp(value, SBR_BOOTSTRAP_ENV "=", sizeof(SBR_BOOTSTRAP_ENV)) == 0) {
      sbr_bootstrap_option_from_launch(value + sizeof(SBR_BOOTSTRAP_ENV));
      continue;
    }
    /* The loader counts patches and dispatches on the same stats page as the
     * plugin, so both get this setting. */
    if (strncmp(value, SBR_BACKEND_STATS_ENV "=",
                sizeof(SBR_BACKEND_STATS_ENV)) == 0)
      sbr_backend_stats_option_from_launch(value +
                                           sizeof(SBR_BACKEND_STATS_ENV));
    settings[setting_count++] = (char *)value;
  }
  if (at != size)
    errx(EXIT_FAILURE, "launch specification has trailing bytes");
  spec->bytes = bytes;
  spec->plugin = strings[0];
  spec->client = strings[1];
  spec->settings = settings;
  spec->setting_count = setting_count;
  return true;
}

// Returns the address of entry point and also populates a pointer
// for the top of the new stack
void load(int argc, char *argv[], void **new_entry, void **new_stack_top) {
  /* The bytes stay allocated: the plugin's arguments point into them. */
  static struct launch_spec launch;
  // There 2 mallocs in memory because SaBRe loads 2 libcs (one for SaBRe) and
  // one for the client (which is intercepted). These two mallocs will overlap
  // their arenas as malloc uses brk(NULL) to initialize its arena, and this
  // brk(NULL) will always return the same pointer. To avoid this we force
  // SaBRe's malloc to completely skip the arena initialization and keep objects
  // into separate mmap() pages. This of course comes with a small performance
  // decrease, and the potential to OOM if we allocate too many items. It comes
  // first: reading the launch specification allocates (opendir).
  int ret = mallopt(M_MMAP_THRESHOLD, 0);
  assert(ret == 1);
  bool launched = read_launch_spec(&launch);
  if (!launched)
    sbr_bootstrap_configure();
  int process_argc = argc;
  char **process_argv = argv;
  if (!launched && argc < 4) {
    print_usage();
    exit(EXIT_FAILURE);
  }

  sbr_backend_stats_init();

  stack_val_t *argv_null = (stack_val_t *)&argv[argc];

  // Sort out the auxiliary vector stuff
  ElfW(auxv_t) *auxv = find_auxv(argv);
  ElfW(auxv_t) *av_entry = NULL;
  ElfW(auxv_t) *av_phdr = NULL;
  ElfW(auxv_t) *av_phnum = NULL;
  size_t pagesize = 0;

  ElfW(auxv_t) * av;
  for (av = auxv;
       av_entry == NULL || av_phdr == NULL || av_phnum == NULL || pagesize == 0;
       ++av) {
    switch (av->a_type) {
    case AT_NULL:
      _nx_fatal_printf(
          "Failed to find AT_ENTRY, AT_PHDR, AT_PHNUM, or AT_PAGESZ!");
      /*NOTREACHED*/
    case AT_ENTRY:
      av_entry = av;
      break;
    case AT_PAGESZ:
      pagesize = av->a_un.a_val;
      break;
    case AT_PHDR:
      av_phdr = av;
      break;
    case AT_PHNUM:
      av_phnum = av;
      break;
    }
  }

  const char *client_path;
  char *rv;
  if (launched) {
    /* The client's own argv, untouched: the kernel exec'd SaBRe with it. */
    rv = realpath("/proc/self/exe", abs_sabre_path);
    assert(rv != NULL);
    if (access(launch.plugin, F_OK) == -1)
      errx(EXIT_FAILURE, "Failed to find plugin file at: %s.", launch.plugin);
    rv = realpath(launch.plugin, abs_plugin_path);
    assert(rv != NULL);
    client_path = launch.client;
    setup_sbr_premain(&register_function_intercepts);
    plugin_argc = 1 + launch.setting_count;
    plugin_argv = (char **)malloc(sizeof(char *) * (plugin_argc + 1));
    plugin_argv[0] = abs_plugin_path;
    memcpy(plugin_argv + 1, launch.settings,
           sizeof(char *) * (launch.setting_count + 1));
    static char unused_path[BINPRM_BUF_SIZE];
    static char unused_arg[BINPRM_BUF_SIZE];
    if (parse_shebang(client_path, unused_path, unused_arg) > 0)
      errx(EXIT_FAILURE,
           "launch specification client %s is a script; the launcher resolves "
           "its interpreter",
           client_path);
  } else {
    rv = realpath(argv[0], abs_sabre_path);
    assert(rv != NULL);

    // Drop irrelevant args before passing them to the init
    --argc;
    ++argv;

    // Get the absolute path of the plugin so we can add it as DT_NEEDED
    // dependency in the client's elf file.
    if (access(argv[0], F_OK) == -1) {
      errx(EXIT_FAILURE, "Failed to find plugin file at: %s.", argv[0]);
    }
    rv = realpath(argv[0], abs_plugin_path);
    assert(rv != NULL);

    // Find client's path. It should be right after `--`.
    size_t client_path_idx = find_client_path_idx(argv);
    client_path = argv[client_path_idx];

    setup_sbr_premain(&register_function_intercepts);

    // Separate client and plugin arguments.
    plugin_argc = client_path_idx - 1;
    char *client_separator = argv[plugin_argc];
    argv[plugin_argc] = NULL;
    plugin_argv = (char **)malloc(sizeof(char *) * (plugin_argc + 1));
    memcpy(plugin_argv, argv, sizeof(char *) * (plugin_argc + 1));
    argv[plugin_argc] = client_separator;

    // Skip plugin arguments
    argv += client_path_idx;
    argc -= client_path_idx;

    // Check if our client_path is a script with a shebang line, and if yes, parse
    // it.
    // We need these vars static as we will return from this function.
    static char shebang_path[BINPRM_BUF_SIZE];
    static char shebang_arg[BINPRM_BUF_SIZE];
    int shebang_tokens_found =
        parse_shebang(client_path, shebang_path, shebang_arg);

    if (shebang_tokens_found > 0) {
      // Let's use the plugin slots on argv, as we don't need them anymore.
      argv -= shebang_tokens_found;
      argc += shebang_tokens_found;

      argv[0] = shebang_path;
      client_path = shebang_path;

      if (shebang_tokens_found == 2)
        argv[1] = shebang_arg;
    }
  }

  // Mask out loader and plugin
  binrw_rd_init_maps();

  // Store the full path so we can use it later.
  // TODO: Handle errors better here. We may also not want to resolve symlinks.
  rv = realpath(client_path, abs_client_path);
  assert(rv != NULL);

  int elf_fd = open(client_path, O_RDONLY, 0);

  ElfW(Ehdr) ehdr;
  if (elfld_getehdr(elf_fd, &ehdr) != 0)
    _nx_fatal_printf("Failed to get ELF header from %s\n", client_path);

  /* Load the program and point the auxv elements at its phdrs and entry.  */
  const char *interp = NULL;
  av_entry->a_un.a_val =
      elfld_load_elf(elf_fd, &ehdr, pagesize, &av_phdr->a_un.a_val,
                     &av_phnum->a_un.a_val, &interp);

  // The elf is mapped into memory, so we can safely close this.
  close(elf_fd);

  ElfW(Addr) entry;
  if (interp) {
    // There was a PT_INTERP, so we have a dynamic linker to load.

    int interp_fd = open(interp, O_RDONLY, 0);
    if (interp_fd < 0)
      _nx_fatal_printf("Cannot open ELF file %s\n", interp);

    if (elfld_getehdr(interp_fd, &ehdr) != 0)
      _nx_fatal_printf("Failed to get ELF header from file\n");

    entry = elfld_load_elf(interp_fd, &ehdr, pagesize, NULL, NULL, NULL);
    close(interp_fd);

    const char *libs[] = {"ld", NULL};
    memorymaps_rewrite_all(libs, client_path, true);
  } else {
    if (sbr_bootstrap_enabled())
      errx(EXIT_FAILURE, "loader bootstrap does not support static images");
#ifdef __x86_64__
    if (first_region(abs_plugin_path) == 0)
    {
      if (launched) {
        /* A static client restarts SaBRe under the dynamic linker in the
         * legacy form (`plugin settings -- client args`), which carries SaBRe
         * and the settings on its command line as before.
         */
        int count = launch.setting_count;
        char **legacy = calloc((size_t)argc + (size_t)count + 4,
                               sizeof(*legacy));
        if (legacy == NULL)
          err(EXIT_FAILURE, "Failed to allocate static client arguments");
        legacy[0] = abs_sabre_path;
        legacy[1] = abs_plugin_path;
        memcpy(legacy + 2, launch.settings, sizeof(char *) * (size_t)count);
        legacy[count + 2] = "--";
        legacy[count + 3] = (char *)client_path;
        for (int i = 1; i < argc; ++i)
          legacy[count + i + 3] = argv[i];
        reexec_static_client_with_plugin(argc + count + 3, legacy);
      }
      reexec_static_client_with_plugin(process_argc, process_argv);
    }
#else
    errx(EXIT_FAILURE, "Static clients are unsupported on this architecture");
#endif
    init_sbr_static_plugin();
    entry = av_entry->a_un.a_val;

    // No dynamic libraries, rewrite the libraries know to have syscalls
    // The binary itself probably has syscalls too, re-write it
    const char *libs[] = {"ld",         "libc",      "librt",
                          "libpthread", "libresolv", NULL};
    memorymaps_rewrite_all(libs, client_path, false);
  }

  // Set up SIGILL handler for dealing with RDTSC instructions and system calls
  // that have been rewritten to use UD
  struct sigaction sa_ill = {.sa_sigaction = sigill_handler,
                             .sa_flags = SA_SIGINFO | SA_NODEFER};
  sigaction(SIGILL, &sa_ill, NULL);

  // Modify the original process stack to represent arguments modified
  // by the plugin.

  _nx_debug_printf("start rewriting stack\n");
  stack_val_t *src = (stack_val_t *)&argv[0];
  stack_val_t *dst = argv_null - argc;

  // Check alignment on 16-byte boundary
  if (((uintptr_t)(dst - 1) & 0xF) != 0) {
    // Move everything down 8 bytes
    dst--;

    // We need to move the whole initial stack frame to restore proper alignment
    ElfW(auxv_t) *auxv_null = av;
    while (auxv_null->a_type != AT_NULL)
      ++auxv_null;
    size_t size =
        (uintptr_t)auxv_null - (uintptr_t)argv_null + sizeof *auxv_null;
    memmove(argv_null, argv_null + 1, size);
  }

  size_t size = sizeof(stack_val_t) * argc;
  memmove(dst, src, size);
  dst[argc] =
      0; // restore argv_null that might have been overwritten by alignment
  *new_stack_top = dst - 1;
  *((stack_val_t *)*new_stack_top) = argc;
  _nx_debug_printf("done rewriting stack\n");

  *new_entry = (void *)entry;
  /* The manually loaded guest's final stack and auxv now exist. The initial
   * kernel exec stop belonged to SaBRe, not this image. Do not enter the guest
   * dynamic linker until the supervisor has initialized the real AT_RANDOM.
   */
  sbr_bootstrap_image(*new_stack_top, *new_entry);
}
