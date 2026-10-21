/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <assert.h>
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <fcntl.h>
#include <sys/mman.h>
#undef __USE_GNU

#include "real_syscall.h"
#include "sbr_api_defs.h"
#include "sysent.h"

static char *sabre_path;
static char *plugin_path;
static char *client_path;

enum vdso_flags { VDSO_STRACE, VDSO_SYSCALL, VDSO_SPECIAL };

// Global state - not the nicest, but this is a tiny application
static enum vdso_flags vdso_arg_flag = VDSO_SYSCALL;

int log_fd;

static void append_buffer(const char *data, ssize_t len) {
  // These should be buffered by the OS anyway and the previous implementation
  // was broken.
  real_syscall(SYS_write, log_fd, (long)data, len, 0, 0, 0);
}

static char *print_cstr(char *dst, const char *str) {
  while (*str != '\0')
    *dst++ = *str++;

  return dst;
}

static const char xdigit[16] = "0123456789ABCDEF";

static char *print_hex_impl(char *dst, unsigned long n) {
  *dst++ = '0';
  *dst++ = 'X';

  // Handle 0 specialy because __builtin_clzl(0) is undefined.
  if (n == 0) {
    *dst++ = '0';
    return dst;
  }

  static const char num_xdigits[] = {
      16, 16, 16, 16, 15, 15, 15, 15, 14, 14, 14, 14, 13, 13, 13, 13, 12,
      12, 12, 12, 11, 11, 11, 11, 10, 10, 10, 10, 9,  9,  9,  9,  8,  8,
      8,  8,  7,  7,  7,  7,  6,  6,  6,  6,  5,  5,  5,  5,  4,  4,  4,
      4,  3,  3,  3,  3,  2,  2,  2,  2,  1,  1,  1,  1,  1};

  char *end = dst + num_xdigits[__builtin_clzl(n)];
  char *curr = end;
  do {
    *curr-- = xdigit[n & 0xf];
    n >>= 4;
  } while (curr >= dst);

  return end + 1;
}

static char *print_hex(char *dst, long n) {
  if (n < 0) {
    *dst++ = '-';
    return print_hex_impl(dst, -n);
  }
  return print_hex_impl(dst, n);
}

static char *print_octal_impl(char *dst, long n) {
  *dst++ = '0';

  // Handle 0 specialy because __builtin_clzl(0) is undefined.
  if (n == 0) {
    *dst++ = '0';
    return dst;
  }

  static const char num_odigits[] = {
      22, 21, 21, 21, 20, 20, 20, 19, 19, 19, 18, 18, 18, 17, 17, 17, 16,
      16, 16, 15, 15, 15, 14, 14, 14, 13, 13, 13, 12, 12, 12, 11, 11, 11,
      10, 10, 10, 9,  9,  9,  8,  8,  8,  7,  7,  7,  6,  6,  6,  5,  5,
      5,  4,  4,  4,  3,  3,  3,  2,  2,  2,  1,  1,  1,  1};

  dst++;
  char *end = dst + num_odigits[__builtin_clzl(n)];
  char *curr = end;
  do {
    *curr-- = xdigit[n & 07];
    n >>= 3;
  } while (curr >= dst);

  return end + 1;
}

static char *print_octal(char *dst, long n) {
  if (n < 0) {
    *dst++ = '-';
    return print_octal_impl(dst, -n);
  }
  return print_octal_impl(dst, n);
}

static char *print_dec_impl(char *dst, unsigned long n) {
  char digits[0x40];

  digits[sizeof(digits) - 1] = '\0';
  char *c = digits + sizeof(digits) - 1;

  do {
    *--c = xdigit[n % 10];
    n /= 10;
  } while (n > 0);

  while (*c != '\0')
    *dst++ = *c++;

  return dst;
}

static char *print_signed_dec(char *dst, long n) {
  if (n < 0) {
    *dst++ = '-';
    return print_dec_impl(dst, -n);
  }

  return print_dec_impl(dst, n);
}

static char *print_fd(char *dst, long n) {
  if ((int)n == AT_FDCWD) {
    return print_cstr(dst, "AT_FDCWD");
  } else {
    return print_signed_dec(dst, (int)n);
  }
}

// We don't want to use ctype since it accesses TLS,
// which messes with %fs and causes segfault
static bool my_isprint(char ch) { return ((ch >= ' ') && (ch <= '~')); }

#define CSTR_MAX_LEN 0x100

static char *print_cstr_escaped(char *dst, const char *str, long max_len) {
  size_t len = 0;
  if (max_len == 0 || max_len >= CSTR_MAX_LEN)
    max_len = CSTR_MAX_LEN;
  *dst++ = '"';
  while (*str != '\0' && len < max_len) {
    if (*str == '\n') {
      *dst++ = '\\';
      *dst++ = 'n';
    } else if (*str == '\\') {
      *dst++ = '\\';
      *dst++ = '\\';
    } else if (*str == '\t') {
      *dst++ = '\\';
      *dst++ = 't';
    } else if (*str == '\"') {
      *dst++ = '\\';
      *dst++ = '"';
    } else if (my_isprint((unsigned char)*str)) {
      *dst++ = *str;
    } else {
      *dst++ = '\\';
      *dst++ = 'x';
      *dst++ = xdigit[((unsigned char)*str) / 0x10];
      *dst++ = xdigit[((unsigned char)*str) % 0x10];
    }

    ++len;
    ++str;
  }

  if (*str != '\0')
    dst = print_cstr(dst, "...");

  *dst++ = '"';

  return dst;
}

static const struct_sysent sysent[] = {
#include "syscallent.h"
};

// clang-format off
#define OUT_ARG output
#define VDSO_ARG handle-vdso
#define ARG_PATTERN2(s) "--" #s "="
#define ARG_PATTERN(s) ARG_PATTERN2(s)
#define ARG_PATTERN_NO_PARAM2(s) "--" #s
#define ARG_PATTERN_NO_PARAM(s) ARG_PATTERN_NO_PARAM2(s)
// clang-format on

static void print_help(void) {
  // This macro works for string literals because char [N] does not decay to
  // char * when passed to sizeof.
#define WRITE_STRING_LITERAL(FD, LIT)                                          \
  real_syscall(SYS_write, (long)(FD), (long)(LIT), sizeof((LIT)), 0, 0, 0)

  WRITE_STRING_LITERAL(log_fd,
                       "Arguments passed to the sbr_strace "
                       "shared object should follow the following syntax:\n");
  WRITE_STRING_LITERAL(log_fd, "[SBR_STRACE_ARGS] -- EXE_PATH [EXE_ARGS]\n");
  WRITE_STRING_LITERAL(log_fd, "SBR_STRACE_ARGS:\n");
  WRITE_STRING_LITERAL(
      log_fd,
      ARG_PATTERN(OUT_ARG) "stream|filename - redirect output to either "
                           "stream or file; default value is stderr\n");
  WRITE_STRING_LITERAL(
      log_fd,
      ARG_PATTERN(VDSO_ARG) "strace|syscall|special - how to handle vDSO "
                            "calls; default value is syscall\n");
#undef WRITE_STRING_LITERAL
}

static char *print_prot(char *dst, long flags) {
  char *dst_next = dst;
  if (!flags) {
    dst_next = print_cstr(dst_next, "PROT_NONE|");
  } else {
    if (flags & PROT_EXEC)
      dst_next = print_cstr(dst_next, "PROT_EXEC|");

    if (flags & PROT_READ)
      dst_next = print_cstr(dst_next, "PROT_READ|");

    if (flags & PROT_WRITE) {
      dst_next = print_cstr(dst_next, "PROT_WRITE|");
    }
  }

  flags &= ~(PROT_EXEC | PROT_READ | PROT_WRITE);
  if (flags)
    dst_next = print_hex(dst_next, flags);
  else if (dst_next != dst)
    dst_next--; // All flags were parsed and we wrote some text, let's get
                // rid of the extra "|" at then end
  return dst_next;
}

static char *print_mmap_flags(char *dst, long flags) {
  if (flags & MAP_SHARED)
    dst = print_cstr(dst, "MAP_SHARED");
  else
    dst = print_cstr(dst, "MAP_PRIVATE");

#ifdef __x86_64__
  if (flags & MAP_32BIT)
    dst = print_cstr(dst, "|MAP_32_BIT");
#endif // __x86_64__

  if (flags & MAP_ANONYMOUS)
    dst = print_cstr(dst, "|MAP_ANONYMOUS");

  if (flags & MAP_DENYWRITE)
    dst = print_cstr(dst, "|MAP_DENYWRITE");

  if (flags & MAP_EXECUTABLE)
    dst = print_cstr(dst, "|MAP_EXECUTABLE");

  if (flags & MAP_FILE)
    dst = print_cstr(dst, "|MAP_FILE");

  if (flags & MAP_FIXED)
    dst = print_cstr(dst, "|MAP_FIXED");

  if (flags & MAP_GROWSDOWN)
    dst = print_cstr(dst, "|MAP_GROWSDOWN");

  if (flags & MAP_HUGETLB)
    dst = print_cstr(dst, "|MAP_HUGETLB");

  if (flags & MAP_LOCKED)
    dst = print_cstr(dst, "|MAP_LOCKED");

  if (flags & MAP_NONBLOCK)
    dst = print_cstr(dst, "|MAP_NONBLOCK");

  if (flags & MAP_NORESERVE)
    dst = print_cstr(dst, "|MAP_NORESERVE");

  if (flags & MAP_POPULATE)
    dst = print_cstr(dst, "|MAP_POPULATE");

  if (flags & MAP_STACK)
    dst = print_cstr(dst, "|MAP_STACK");

  flags &= ~(MAP_SHARED | MAP_PRIVATE |
#ifdef __x86_64__
             MAP_32BIT |
#endif // __x86_64__
             MAP_ANONYMOUS | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_FILE |
             MAP_FIXED | MAP_GROWSDOWN | MAP_HUGETLB | MAP_LOCKED |
             MAP_NONBLOCK | MAP_NORESERVE | MAP_POPULATE | MAP_STACK);

  if (flags) {
    *dst++ = '|';
    dst = print_hex(dst, flags);
  }

  return dst;
}

static char *print_open_flags(char *dst, long flags, bool *creates) {
  *creates = false;

  if (flags & O_RDWR)
    dst = print_cstr(dst, "O_RDWR");

  else if (flags & O_WRONLY)
    dst = print_cstr(dst, "O_WRONLY");

  else
    dst = print_cstr(dst, "O_RDONLY");

  // Creation and file status flags
  if (flags & O_APPEND)
    dst = print_cstr(dst, "|O_APPEND");

  if (flags & O_ASYNC)
    dst = print_cstr(dst, "|O_ASYNC");

  if (flags & O_CLOEXEC)
    dst = print_cstr(dst, "|O_CLOEXEC");

  if (flags & O_CREAT) {
    dst = print_cstr(dst, "|O_CREAT");
    *creates = true;
  }

  if (flags & O_DIRECT)
    dst = print_cstr(dst, "|O_DIRECT");

  if (flags & O_DIRECTORY)
    dst = print_cstr(dst, "|O_DIRECTORY");

  if (flags & O_DSYNC)
    dst = print_cstr(dst, "|O_DSYNC");

  if (flags & O_EXCL)
    dst = print_cstr(dst, "|O_EXCL");

  if (flags & O_NOATIME)
    dst = print_cstr(dst, "|O_NOATIME");

  if (flags & O_NOCTTY)
    dst = print_cstr(dst, "|O_NOCTTY");

  if (flags & O_NOFOLLOW)
    dst = print_cstr(dst, "|O_NOFOLLOW");

  if (flags & O_NONBLOCK)
    dst = print_cstr(dst, "|O_NONBLOCK");

  if (flags & O_PATH)
    dst = print_cstr(dst, "|O_PATH");

  if (flags & O_SYNC)
    dst = print_cstr(dst, "|O_SYNC");

  if (flags & O_TMPFILE) {
    dst = print_cstr(dst, "|O_TMPFILE");
    *creates = true;
  }

  if (flags & O_TRUNC)
    dst = print_cstr(dst, "|O_TRUNC");

  flags &= ~(O_RDWR | O_WRONLY | O_RDONLY | O_APPEND | O_ASYNC | O_CLOEXEC |
             O_CREAT | O_DIRECT | O_DIRECTORY | O_DSYNC | O_EXCL | O_NOATIME |
             O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_PATH | O_SYNC | O_TMPFILE |
             O_TRUNC);

  if (flags) {
    *dst++ = '|';
    dst = print_hex(dst, flags);
  }

  return dst;
}

static char *pre_decode_args(char *dst, long sc, const long args[]) {
  bool creates = false;

  switch (sc) {
  case SYS_mprotect:
    dst = print_hex(dst, args[0]);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[1]);
    dst = print_cstr(dst, ", ");
    dst = print_prot(dst, args[2]);
    break;

#ifdef __x86_64__
  case SYS_access:
    dst = print_cstr_escaped(dst, (char *)args[0], 0);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[1]);
    break;
#endif // __x86_64__

  case SYS_mmap:
    for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
      if (!argno) {
        dst = print_hex(dst, args[argno]);
      } else {
        dst = print_cstr(dst, ", ");
        if (argno == 2)
          dst = print_prot(dst, args[2]);
        else if (argno == 3)
          dst = print_mmap_flags(dst, args[3]);
        else if (argno == 4)
          dst = print_fd(dst, args[4]);
        else
          dst = print_hex(dst, args[argno]);
      }
    }
    break;

#ifdef __x86_64__
  case SYS_open:
    dst = print_cstr_escaped(dst, (char *)args[0], 0);
    dst = print_cstr(dst, ", ");
    creates = false;
    dst = print_open_flags(dst, args[1], &creates);
    if (creates)
      dst = print_octal(dst, args[2]);
    break;
#endif // __x86_64__

  case SYS_openat:
    dst = print_cstr_escaped(dst, (char *)args[1], 0);
    dst = print_cstr(dst, ", ");
    creates = false;
    dst = print_open_flags(dst, args[2], &creates);
    if (creates)
      dst = print_octal(dst, args[3]);
    break;

  case SYS_write:
    for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
      if (!argno) {
        dst = print_fd(dst, args[argno]);
      } else {
        dst = print_cstr(dst, ", ");
        if (argno == 1)
          dst = print_cstr_escaped(dst, (char *)args[argno], args[argno + 1]);
        else
          dst = print_hex(dst, args[argno]);
      }
    }
    break;

  case SYS_read:
    dst = print_fd(dst, args[0]);
    break;

  case SYS_readlink:
    dst = print_cstr_escaped(dst, (const char *)args[0], 0);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[1]);
    break;

  case SYS_readlinkat:
    dst = print_fd(dst, args[0]);
    dst = print_cstr(dst, ", ");
    dst = print_cstr_escaped(dst, (const char *)args[1], 0);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[2]);
    break;

  default:
    for (int argno = 0; argno < sysent[sc].nargs; ++argno) {
      if (!argno) {
        dst = print_hex(dst, args[argno]);
      } else {
        dst = print_cstr(dst, ", ");
        dst = print_hex(dst, args[argno]);
      }
    }
    break;
  }
  return dst;
}

static char *post_decode_args(char *dst, long sc, const long args[], long rtn) {
  (void)rtn; // unused
  switch (sc) {
  case SYS_read:
    for (int argno = 1; argno < sysent[sc].nargs; ++argno) {
      dst = print_cstr(dst, ", ");
      if (argno == 1)
        dst = print_cstr_escaped(dst, (char *)args[argno], args[argno + 1]);
      else
        dst = print_hex(dst, args[argno]);
    }
    break;

  case SYS_readlink:
    dst = print_cstr(dst, " -> ");
    dst = print_cstr_escaped(dst, (const char *)args[1], rtn);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[2]);
    break;

  case SYS_readlinkat:
    dst = print_cstr(dst, " -> ");
    dst = print_cstr_escaped(dst, (const char *)args[2], rtn);
    dst = print_cstr(dst, ", ");
    dst = print_hex(dst, args[3]);
    break;

  default:
    break;
  }
  return dst;
}

long handle_syscall_real(long sc_no, long arg1, long arg2, long arg3, long arg4,
                         long arg5, long arg6, void *wrapper_sp, bool vdso) {
  long local_args[] = {arg1, arg2, arg3, arg4, arg5, arg6};

  long syscall_rtn;
  char local_buffer[0x300];
  char *dst = local_buffer;
  static bool outfd_close = false;

  if (vdso)
    dst = print_cstr(dst, "(vDSO): ");
  dst = print_cstr(dst, sysent[sc_no].sys_name);
  *dst++ = '(';

  // Special-case the exit syscalls
  if ((sc_no == SYS_exit) || (sc_no == SYS_exit_group)) {
    dst = print_signed_dec(dst, arg1);
    dst = print_cstr(dst, ") = ?\n");

    if (outfd_close)
      (void)real_syscall(SYS_close, (long)(log_fd), arg2, arg3, arg4, arg5,
                         arg6);

    // More sophisticated checks should be implemented at some point -
    // what if target app doesn't use output streams at all, and we
    // use stderr? But not closing a stream is not catastrophic.
    /* else if ((out_stream != stdout) && (out_stream != stderr)) */
    /*   fclose(out_stream); */

    append_buffer(local_buffer, dst - local_buffer);
    return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  } else {
    dst = pre_decode_args(dst, sc_no, local_args);

    // If the sandboxed app is closing our output FD
    if ((sc_no == SYS_close) && ((int)arg1 == log_fd)) {
      // A bit hacky - what if there was an error? We can't see in the future
      // though, so...
      syscall_rtn = 0;
      outfd_close = true;
    } else {
      if (sc_no == SYS_clone && arg2 != 0) { // clone
        void *ret_addr = get_syscall_return_address(wrapper_sp);
        syscall_rtn = clone_syscall(arg1, (void *)arg2, (void *)arg3,
                                    (void *)arg4, arg5, ret_addr, NULL);
      } else if (sc_no == SYS_clone3 &&
                 ((struct clone_args *)arg1)->stack != 0) { // clone3
        void *ret_addr = get_syscall_return_address(wrapper_sp);
        syscall_rtn = clone3_syscall(arg1, arg2, arg3, 0, arg5, ret_addr, NULL);
      } else if (sc_no == SYS_vfork ||
                 (sc_no == SYS_clone &&
                  (arg1 & (CLONE_VM | CLONE_VFORK | SIGCHLD)) ==
                      (CLONE_VM | CLONE_VFORK | SIGCHLD))) {
        syscall_rtn = vfork_syscall();
        if (syscall_rtn == 0) { // Child
          return vfork_return_from_child(wrapper_sp);
        }
      } else if (sc_no == SYS_execve) {
        if (access((char *)arg1, F_OK) != 0) {
          // TODO: Double check this is the correct way to return errors.
          syscall_rtn = -ENOENT;
        }

        char **old_argv = (char **)arg2; // Just make our life easier.

        size_t old_argv_size = 0;
        for (int i = 0; old_argv[i] != NULL; i++) {
          old_argv_size++;
        }
        // argv is NULL terminated, and we should copy the NULL too.
        old_argv_size += 1;

        // We will be adding the minimum 3 args.
        // TODO: Support addition of plugin and sabre flags.
        char **n_argv = malloc((old_argv_size + 3) * sizeof(char *));
        assert(n_argv != NULL);
        // argv should always start with the path to the binary.
        // old_argv now has the old binary path by default so
        // we just append it.
        memcpy(n_argv + 3, old_argv, old_argv_size * sizeof(char *));

        n_argv[0] = sabre_path;
        n_argv[1] = plugin_path;
        n_argv[2] = "--";
        // Overwrite first argument of old_argv as sometimes this is not a valid
        // path.
        n_argv[3] = (char *)arg1;

        syscall_rtn = real_syscall(SYS_execve, (long)sabre_path, (long)n_argv,
                                   arg3, arg4, arg5, arg6);
      } else {
        syscall_rtn = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
      }
    }

    dst = post_decode_args(dst, sc_no, local_args, syscall_rtn);

    dst = print_cstr(dst, ") = ");
    if (syscall_rtn > -1) {
      dst = print_hex(dst, syscall_rtn);
    } else {
      dst = print_signed_dec(dst, syscall_rtn);
      dst = print_cstr(dst, "(error)");
    }
    *dst++ = '\n';
    append_buffer(local_buffer, dst - local_buffer);

    return syscall_rtn;
  }
}

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {
  return handle_syscall_real(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
                             wrapper_sp, false);
}

long handle_syscall_clock_gettime(long arg1, long arg2) {
  return handle_syscall_real(SYS_clock_gettime, arg1, arg2, 0, 0, 0, 0, NULL,
                             true);
}

long handle_syscall_getcpu(long arg1, long arg2, long arg3) {
  return handle_syscall_real(SYS_getcpu, arg1, arg2, arg3, 0, 0, 0, NULL, true);
}

long handle_syscall_gettimeofday(long arg1, long arg2) {
  return handle_syscall_real(SYS_gettimeofday, arg1, arg2, 0, 0, 0, 0, NULL,
                             true);
}

#ifdef __x86_64__
long handle_syscall_time(long arg1) {
  return handle_syscall_real(SYS_time, arg1, 0, 0, 0, 0, 0, NULL, true);
}
#endif // __x86_64__

void handle_args(int *argc, char **argv[]) {
  while (**argv) {
    // Handle the output
    if (!strncmp(ARG_PATTERN(OUT_ARG), **argv, strlen(ARG_PATTERN(OUT_ARG)))) {
      char *out_file = (**argv + strlen(ARG_PATTERN(OUT_ARG)));

      if (!strcmp(out_file, "stdout"))
        log_fd = STDOUT_FILENO;

      else if (!strcmp(out_file, "stderr"))
        log_fd = STDERR_FILENO;

      else {
        if (*out_file) {
          log_fd =
              real_syscall(SYS_open, (long)out_file, (long)(O_CREAT | O_RDWR),
                           (long)((mode_t)0700), 0, 0, 0);
          if (log_fd < 0) {
            fputs("Could not open file ", stderr);
            fputs(out_file, stderr);
            fputs(" for sbr_strace output.\n", stderr);
            print_help();
            exit(1);
          }
        } else {
          fputs("Output file is null.\n", stderr);
          print_help();
          exit(1);
        }
      }
    }

    // Handle the vdso arg
    if (!strncmp(ARG_PATTERN(VDSO_ARG), **argv,
                 strlen(ARG_PATTERN(VDSO_ARG)))) {
      char *string_selection = (**argv + strlen(ARG_PATTERN(VDSO_ARG)));

      if (!strcmp(string_selection, "strace"))
        vdso_arg_flag = VDSO_STRACE;

      else if (!strcmp(string_selection, "syscall"))
        vdso_arg_flag = VDSO_SYSCALL;

      else if (!strcmp(string_selection, "special"))
        vdso_arg_flag = VDSO_SPECIAL;

      else {
        fputs("Unsupported vDSO handling option: ", stderr);
        fputs(string_selection, stderr);
        fputc('\n', stderr);
        print_help();
        exit(1);
      }
    }

    --(*argc);
    ++(*argv);
  }
}

void_void_fn vdso_callback_imp(long sc_no, void_void_fn actual_fn) {
  (void)actual_fn; // unused
  switch (sc_no) {
  case SYS_clock_gettime:
    return (void_void_fn)handle_syscall_clock_gettime;
  case SYS_getcpu:
    return (void_void_fn)handle_syscall_getcpu;
  case SYS_gettimeofday:
    return (void_void_fn)handle_syscall_gettimeofday;
#ifdef __x86_64__
  case SYS_time:
    return (void_void_fn)handle_syscall_time;
#endif // __x86_64__
  default:
    return (void_void_fn)NULL;
  }
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
#endif

void_void_fn vdso_callback_none_imp(long sc_no, void_void_fn actual_fn) {
  (void)sc_no; // unused
  return actual_fn;
}

void sbr_init(int *argc, char **argv[], sbr_icept_reg_fn fn_icept_reg,
              sbr_icept_vdso_callback_fn *vdso_callback,
              sbr_sc_handler_fn *syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
              sbr_rdtsc_handler_fn *rdtsc_handler,
#endif
              sbr_post_load_fn *post_load, char *sp, char *cp) {
  (void)fn_icept_reg; // unused
  (void)post_load;    // unused

  sabre_path = sp;
  plugin_path = (*argv)[0];
  client_path = cp;

  // For error messages before handling the args
  log_fd = STDERR_FILENO;

  handle_args(argc, argv);

  *syscall_handler = handle_syscall;

#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = handle_rdtsc;
#endif

  // Deal with vDSO calls
  switch (vdso_arg_flag) {
  case VDSO_SYSCALL:
    *vdso_callback = NULL;
    break;
  case VDSO_SPECIAL:
    *vdso_callback = vdso_callback_imp;
    break;
  case VDSO_STRACE:
    *vdso_callback = vdso_callback_none_imp;
    break;
  }
}
