/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
  This plugin simply intercepts all system calls and vDSO calls and
  reissues them at a user supplied probability for various syscall families.
*/

#include "real_syscall.h"
#include "sbr_api_defs.h"
#include "sysent.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <execinfo.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#undef _GNU_SOURCE

#define RESET "\033[0m"
#define RED "\033[31m"

struct syscall_chances {
  int unassigned;
  int device;
  int file;
  int network;
  int process;
  int memory;
};

enum log_level { LOG_NONE = 0, LOG_FAIL = 1, LOG_ALL = 2 };

static struct syscall_chances failure_probabilities = {.unassigned = 5,
                                                       .device = 5,
                                                       .file = 5,
                                                       .network = 5,
                                                       .process = 5,
                                                       .memory = 5};
static int verbose_flag = 0;
static unsigned int random_seed = 0;
static enum log_level log_lvl = LOG_NONE;
static FILE *out_stream = NULL;
static _Bool output_colors = false;

static long default_handler(long sc_no, long a1, long a2, long a3, long a4,
                            long a5, long a6, void **aux, _Bool *fail);

static const struct sysent sys_entries[] = {
#define X(sc_no, nargs, name, default_errno, families)                         \
  [sc_no] = {nargs, name, default_handler, default_errno, families, NULL},
    SYSENT_SYSCALL_LIST
#undef X
};

// Counters holding the call number for each system call. This strategy is
// obviously broken in multi-threaded scenarios.
static size_t sys_call_nums[SYSENT_NUM_SYSCALLS] = {0};

struct print_system_call_args {
  const struct sysent *entry;
  long sc_no;
  long arg1;
  long arg2;
  long arg3;
  long arg4;
  long arg5;
  long arg6;
  long sys_ret;
};

static void print_system_call(const struct print_system_call_args *args,
                              _Bool caused_failure) {
  if (caused_failure) {
    if (output_colors)
      fputs(RED, out_stream);
    fputs("[FAILURE] ", out_stream);
    if (output_colors)
      fputs(RESET, out_stream);
  }

  switch (args->entry->nargs) {
  case 0:
    fprintf(out_stream, "%s() = %ld #%zu\n", args->entry->sys_name,
            args->sys_ret, sys_call_nums[args->sc_no]);
    break;
  case 1:
    fprintf(out_stream, "%s(%ld) = %ld #%zu\n", args->entry->sys_name,
            args->arg1, args->sys_ret, sys_call_nums[args->sc_no]);
    break;
  case 2:
    fprintf(out_stream, "%s(%ld, %ld) = %ld #%zu\n", args->entry->sys_name,
            args->arg1, args->arg2, args->sys_ret, sys_call_nums[args->sc_no]);
    break;
  case 3:
    fprintf(out_stream, "%s(%ld, %ld, %ld) = %ld #%zu\n", args->entry->sys_name,
            args->arg1, args->arg2, args->arg3, args->sys_ret,
            sys_call_nums[args->sc_no]);
    break;
  case 4:
    fprintf(out_stream, "%s(%ld, %ld, %ld, %ld) = %ld #%zu\n",
            args->entry->sys_name, args->arg1, args->arg2, args->arg3,
            args->arg4, args->sys_ret, sys_call_nums[args->sc_no]);
    break;
  case 5:
    fprintf(out_stream, "%s(%ld, %ld, %ld, %ld, %ld) = %ld #%zu\n",
            args->entry->sys_name, args->arg1, args->arg2, args->arg3,
            args->arg4, args->arg5, args->sys_ret, sys_call_nums[args->sc_no]);
    break;
  case 6:
    fprintf(out_stream, "%s(%ld, %ld, %ld, %ld, %ld, %ld) = %ld #%zu\n",
            args->entry->sys_name, args->arg1, args->arg2, args->arg3,
            args->arg4, args->arg5, args->arg6, args->sys_ret,
            sys_call_nums[args->sc_no]);
    break;
  default:
    __builtin_unreachable();
  }

  fflush(out_stream);
}

static void display_help(void) {
  fputs(
      "Plugin to SaBRe that probabilistically fails system calls for usage in fuzzing applications.\n\
USAGE: sabre libsc-fuzzer.so [OPTIONS] -- <CLIENT APP> [CLIENT ARGUMENTS] ...\n\
  Options:\n\
    -v, --verbose                       Enable some additional unspecified information.\n\
    -h, --help                          Prints this help message and exits.\n\
    -s, --seed [1-UINT_MAX]             Sets the seed to use for srand(). The default is the current epoch.\n\
    -l, --log (all|fail)                Sets the logging level. The value all will behave similarly to strace, whereas fail will only record the system calls the system caused to fail.\n\
    -o, --output FILE_NAME              Uses FILE_NAME to output the logging output to. To use standard IO, use stdout and stderr instead of a file.\n\
    -u, --unassigned [0-100]            Sets the default probability for system calls not assigned a family.\n\
    -d, --device-operations [0-100]     Sets the default probability operating on devices.\n\
    -f, --file-operations [0-100]       Sets the failure probability for file I/O system calls.\n\
    -n, --network-operations [0-100]    Sets the failure probability for network I/O system calls.\n\
    -p, --process-management [0-100]    Sets the failure probability for process management system calls.\n\
    -m, --memory-allocation [0-100]     Sets the failure probability for memory allocation system calls.\n\
",
      stderr);
}

static const char *opt_string = "u:d:f:n:p:m:s:l:o:vh?";

static struct option long_opts[] = {
    {"unassigned", required_argument, NULL, 'u'},
    {"device-operations", required_argument, NULL, 'd'},
    {"file-operations", required_argument, NULL, 'f'},
    {"network-operations", required_argument, NULL, 'n'},
    {"process-management", required_argument, NULL, 'p'},
    {"memory-allocation", required_argument, NULL, 'm'},
    {"seed", required_argument, NULL, 's'},
    {"log", required_argument, NULL, 'l'},
    {"output", required_argument, NULL, 'o'},
    {"verbose", no_argument, &verbose_flag, 1},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

static int extract_probability(const char *probability_str) {
  errno = 0;
  intmax_t probability = strtoimax(probability_str, NULL, 0);
  if (errno) {
    perror("Received an invalid probability on the command line");
    display_help();
    exit(EXIT_FAILURE);
  }
  if (probability < 0 || probability > 100) {
    fprintf(stderr,
            "Received an out of range probability on the command line. The "
            "value was %jd.\n",
            probability);
    display_help();
    exit(EXIT_FAILURE);
  }
  return (int)probability;
}

static void handle_arguments(int *argc, char **argv[]) {
  // Defaults output to stderr
  out_stream = stderr;

  int opt_index = 0;
  int ch = 0;
  while ((ch = getopt_long(*argc, *argv, opt_string, long_opts, &opt_index)) !=
         -1) {
    switch (ch) {
    case 'd':
      failure_probabilities.device = extract_probability(optarg);
      break;

    case 'u':
      failure_probabilities.unassigned = extract_probability(optarg);
      break;

    case 'f':
      failure_probabilities.file = extract_probability(optarg);
      break;

    case 'n':
      failure_probabilities.network = extract_probability(optarg);
      break;

    case 'p':
      failure_probabilities.process = extract_probability(optarg);
      break;

    case 'm':
      failure_probabilities.memory = extract_probability(optarg);
      break;

    case 's':
      errno = 0;
      uintmax_t seed = strtoumax(optarg, NULL, 0);
      if (errno || !seed || seed > (uintmax_t)UINT_MAX) {
        fputs("Received an invalid seed on the command line.\n", stderr);
        display_help();
        exit(EXIT_FAILURE);
      }
      random_seed = (unsigned int)seed;
      break;

    case 'l':
      if (strcmp(optarg, "all") == 0) {
        log_lvl = LOG_ALL;
        break;
      }

      if (strcmp(optarg, "fail") == 0) {
        log_lvl = LOG_FAIL;
        break;
      }

      fputs("Received invalid log level on the command line.\n\n", stderr);
      display_help();
      exit(EXIT_FAILURE);

    case 'o':
      if (strcmp(optarg, "stdout") == 0)
        out_stream = stdout;

      else if (strcmp(optarg, "stderr") == 0)
        out_stream = stderr;

      else {
        errno = 0;
        out_stream = fopen(optarg, "w");
        if (!out_stream) {
          perror("Could not open specified output file for writing");
          display_help();
          exit(EXIT_FAILURE);
        }
      }
      break;

    case 'v':
      verbose_flag = 1;
      break;
    case 'h': // fallthrough
    case '?':
      // Display usage and exit with failure.
      display_help();
      exit(EXIT_SUCCESS);
      break;

    case 0:
      // getopt_long will already have handled this
      if (long_opts[opt_index].flag != NULL)
        break;
      // fallthrough

    default:
      fputs("Unknown or bad arguments!\n\n", stderr);
      display_help();
      exit(EXIT_FAILURE);
    }
  }

  // This is not 100% foolproof as some ttys do not support VTxxx escape
  // sequences (consult your terminfo database for more info). However, the
  // overwhelming majority of terminals do, so this is fine.
  output_colors = isatty(fileno(out_stream));

  // Update the arguments to point to client program and its arguments
  *argc -= optind;
  *argv += optind;
}

/*
 * Does a "random trial" against the advertised failure probabilities. If the
 * trial succeeds  returns the default errno value for this syscall. Otherwise
 * it will let the system call go through. The probabilities for families are
 * checked for a first match, with the ordering:
 *  - SYS_FAMILY_FILE
 *  - SYS_FAMILY_DEVICE
 *  - SYS_FAMILY_NETWORK
 *  - SYS_FAMILY_PROCESS
 *  - SYS_FAMILY_MEMORY
 *  - SYS_FAMILY_UNASSIGNED
 */
static long default_handler(long sc_no, long a1, long a2, long a3, long a4,
                            long a5, long a6, void **aux, _Bool *fail) {
  (void)aux; // unused
  int random = rand() % 100 + 1;
  const struct sysent *entry = &sys_entries[sc_no];

  if (entry->families == SYS_FAMILY_NEVER_FAIL)
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);

  if (entry->families & SYS_FAMILY_FILE) {
    if (random <= failure_probabilities.file)
      goto caused_failure;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_DEVICE) {
    if (random <= failure_probabilities.device)
      goto caused_failure;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_NETWORK) {
    if (random <= failure_probabilities.network)
      goto caused_failure;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_PROCESS) {
    if (random <= failure_probabilities.process)
      goto caused_failure;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_MEMORY) {
    if (random <= failure_probabilities.memory)
      goto caused_failure;
    return real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  }

  if (entry->families & SYS_FAMILY_UNASSIGNED) {
    if (random <= failure_probabilities.unassigned)
      goto caused_failure;
  }

  long sys_ret = real_syscall(sc_no, a1, a2, a3, a4, a5, a6);
  return sys_ret;

caused_failure:
  *fail = true;
  return -entry->default_errno;
}

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {
  (void)wrapper_sp; // unused

  const struct sysent *entry = &sys_entries[sc_no];

  sys_call_nums[sc_no]++;
  _Bool caused_failure = false;
  long sys_ret =
      entry->handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
                     (void **)&entry->handler_state, &caused_failure);

  if ((log_lvl > LOG_NONE && caused_failure) || log_lvl == LOG_ALL) {
    struct print_system_call_args log_args = {.entry = entry,
                                              .sc_no = sc_no,
                                              .arg1 = arg1,
                                              .arg2 = arg2,
                                              .arg3 = arg3,
                                              .arg4 = arg4,
                                              .arg5 = arg5,
                                              .arg6 = arg6,
                                              .sys_ret = sys_ret};
    print_system_call(&log_args, caused_failure);
  }
  return sys_ret;
}

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)(sc_no); // unused
  return actual_fn;
}
#ifdef __NX_INTERCEPT_RDTSC
long handle_rdtsc() {
  long high, low;

  asm volatile("rdtsc;" : "=a"(low), "=d"(high) : :);

  long ret = high;
  ret <<= 32;
  ret |= low;

  return ret;
}
#endif // __NX_INTERCEPT_RDTSC

static void segv_handler(int sig) {
  ssize_t bytes = write(STDERR_FILENO, "Caught SIGSEGV at:\n", 19);
  if (bytes != 19)
    goto error;

  // This does not have the expected behaviour, but leaving it here for now, in
  // case there is a solution
  void *array = alloca(256 * sizeof(void *));
  int cnt = backtrace(array, 256);
  backtrace_symbols_fd(array, cnt, STDERR_FILENO);

  // This is obviously not kosher as not async-signal safe, but this is best
  // effort at this point.
  fflush(out_stream);

  // Pass on the signal (so that a core file is produced).
  struct sigaction sa;
  sa.sa_handler = SIG_DFL;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(sig, &sa, NULL);
error:
  raise(sig);
}

void sbr_init(int *argc, char **argv[], sbr_icept_reg_fn fn_icept_reg,
              sbr_icept_vdso_callback_fn *vdso_callback,
              sbr_sc_handler_fn *syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
              sbr_rdtsc_handler_fn *rdtsc_handler,
#endif
              sbr_post_load_fn *post_load) {
  (void)fn_icept_reg; // unused
  (void)post_load;    // unused

  struct sigaction sig_act;
  sig_act.sa_handler = &segv_handler;
  sigemptyset(&sig_act.sa_mask);
  sig_act.sa_flags = SA_RESTART;

  void *stack = malloc(2 * SIGSTKSZ);
  stack_t ss;
  ss.ss_sp = stack;
  ss.ss_flags = 0;
  ss.ss_size = 2 * SIGSTKSZ;

  if (sigaltstack(&ss, NULL) == 0)
    sig_act.sa_flags |= SA_ONSTACK;

  sigaction(SIGSEGV, &sig_act, NULL);

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;
#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = handle_rdtsc;
#endif
  handle_arguments(argc, argv);

  random_seed = random_seed ? random_seed : time(NULL);

  if (verbose_flag)
    fprintf(out_stream, "The chosen seed is %u\n", random_seed);

  srand(random_seed);
}
