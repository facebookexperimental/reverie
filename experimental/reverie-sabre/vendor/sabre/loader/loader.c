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
#include "compiler.h"
#include "elf_loading.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "loader/backend_stats.h"
#include "macros.h"
#include "maps.h"
#include "plugins/sbr_api_defs.h"
#include "premain.h"
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
  assert(strlen(r_struct->lib_name) < MAX_ICEPT_STRLEN);
  assert(strlen(r_struct->fn_name) < MAX_ICEPT_STRLEN);

  strcpy(intercept_records[registered_icept_cnt].lib_name, r_struct->lib_name);
  strcpy(intercept_records[registered_icept_cnt].fn_name, r_struct->fn_name);
  intercept_records[registered_icept_cnt].callback = r_struct->icept_callback;
  intercept_records[registered_icept_cnt].copy_first_stack_arg =
      copy_first_stack_arg;

  ++registered_icept_cnt;
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
    regs[REG_RAX] = runtime_syscall_router(
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
    uint64_t tsc = (uint64_t)plugin_rdtsc_handler();
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
    regs[REG_A0] = runtime_syscall_router(
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

// Returns the address of entry point and also populates a pointer
// for the top of the new stack
void load(int argc, char *argv[], void **new_entry, void **new_stack_top) {
  int process_argc = argc;
  char **process_argv = argv;
  if (argc < 4) {
    print_usage();
    exit(EXIT_FAILURE);
  }

  // There 2 mallocs in memory because SaBRe loads 2 libcs (one for SaBRe) and
  // one for the client (which is intercepted). These two mallocs will overlap
  // their arenas as malloc uses brk(NULL) to initialize its arena, and this
  // brk(NULL) will always return the same pointer. To avoid this we force
  // SaBRe's malloc to completely skip the arena initialization and keep objects
  // into separate mmap() pages. This of course comes with a small performance
  // decrease, and the potential to OOM if we allocate too many items.
  int ret = mallopt(M_MMAP_THRESHOLD, 0);
  assert(ret == 1);
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

  char *rv = realpath(argv[0], abs_sabre_path);
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
  const char *client_path = argv[client_path_idx];

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
#ifdef __x86_64__
    if (first_region(abs_plugin_path) == 0)
      reexec_static_client_with_plugin(process_argc, process_argv);
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
}
