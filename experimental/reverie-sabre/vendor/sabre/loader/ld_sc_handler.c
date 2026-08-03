/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arch/rewriter_tools.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#endif
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "compiler.h"
#include "global_vars.h"
#include "ld_sc_handler.h"
#include "macros.h"
#include "plugins/real_syscall.h"

// TODO: This code needs refactoring. Split open and mmap syscalls. Find a more
// elegant way for interesting_libs and the other static variables
// THIS IS RACING IN CASE WE HAVE MULTIPLE THREADS OPEN-MMAP LIBS
// WRITE A UNIT TEST
#define NO_FD -1
static int interesting_fd = NO_FD;
static int interesting_lib = NO_FD;

// Libraries known to have syscalls
// ld is not here because it is processed elsewhere (loader.c)
const char *known_syscall_libs[] __hidden = {"libc", "librt", "libpthread",
                                             "libresolv", NULL};

#define SBR_SEGMENTS 4
static uintptr_t start_sbr[SBR_SEGMENTS], end_sbr[SBR_SEGMENTS];

static void hide_sbr_maps(int from_fd, int to_fd) {
  // TODO This code is extracted from maps.c, function maps_read
  //      Refactor that function to be generic instead of copying the code here

  // Go over each line of /proc/self/maps and consider each mapped region one
  // at a time, looking for a gap between regions to allocate.
  char buf[1024] = {'\0'};
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + sizeof(buf) - 1;

  int sbr_segment = 0;

  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(from, '\n',
                          to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread = 0;
      while (to < bufend) {
        nread = read(from_fd, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n';                   /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0;                 /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    uintptr_t gap_end, map_end;
    int name;

    // Parse each line of /proc/<pid>/maps file.
    if (sscanf(from, "%" SCNxPTR "-%" SCNxPTR " %*4s %*d %*x:%*x %*d %n",
               &gap_end, &map_end, &name) > 1) {
      char *pathname = from + name;
      int len = strlen(pathname);
      if (strcmp(pathname + len - 2, "vx")) {
        if (to_fd) {
          if (write(to_fd, from, strlen(from)) == -1) {
            _nx_fatal_printf("write maps failed\n");
          }
          if (write(to_fd, "\n", 1) == -1) {
            _nx_fatal_printf("write maps failed\n");
          }
        }
      } else { // SaBRe segment found
        assert(sbr_segment < SBR_SEGMENTS);
        start_sbr[sbr_segment] = gap_end;
        end_sbr[sbr_segment] = map_end;
        sbr_segment++;
      }
    }
  } while (to > buf);
}

static long process_fd(long fd, const char *pathname, int flags, mode_t mode) {
  if (fd < 0)
    return (long)fd;

  // Q: Why not just copy pathname and pass it to memorymaps_rewrite_lib()?
  // A: Linux uses links for some libraries and the user might give
  // a pathname = /lib/x86_64-linux-gnu/libc.so.6 and the ld will load
  // a /lib/x86_64-linux-gnu/libc-2.26.so. Thus we need to stem the
  // library names anyway.

  int l = which_lib_name_interesting(known_syscall_libs, pathname);
  // dprintf(2, "which_lib_name_interesting: %d %s\n", l, pathname);
  if (l >= 0) {
    if (interesting_fd == NO_FD && interesting_lib == NO_FD) {
      interesting_fd = fd;
      interesting_lib = l;
    } else
      _nx_fatal_printf("ld opened two binaries without mmaping\n");
  }

  _nx_debug_printf("open: exit loader syscall (%lu)\n", (long)fd);

  // TODO: TSan scans /proc/self/maps and quits if it finds anything not listed
  //       on the ELF headers.  This hack works by hiding SaBRe from
  //       /proc/self/maps, but we could trick TSan by adding SaBRe to the ELF
  //       headers as a dynamic library
  if (!strcmp("/proc/self/maps", pathname)) {
    // Hide SaBRe from TSan

    // Create dummy file
    char buf[] = "/tmp/sbrXXXXXX";
    int to = mkstemp(buf);

    // Copy '/proc/self/maps' to dummy except for SaBRe entries
    hide_sbr_maps(fd, to);

    // Close all files
    close(fd);
    close(to);

    // Reopen dummy file and delete it
    to = open(buf, flags, mode);
    unlink(buf);

    // When this fd goes away, file gets deleted
    return to;
  }

  return (long)fd;
}

struct mem_chunk {
  uintptr_t start;
  uintptr_t end;
};

static int intercept_sbr(struct mem_chunk mmaps[]) {
  int c = 0;
  uintptr_t start_mmap = mmaps[c].start;
  uintptr_t end_mmap = mmaps[c].end;

  for (int seg = 0; seg < SBR_SEGMENTS; seg++) {
    bool before_sbr = end_mmap <= start_sbr[seg];
    bool after_sbr = start_mmap >= end_sbr[seg];

    if (!(before_sbr || after_sbr)) {
      if (mmaps[c].start > start_sbr[seg])
        mmaps[c].start = end_sbr[seg];
      else if (mmaps[c].end < end_sbr[seg])
        mmaps[c].end = start_sbr[seg];
      else {
        mmaps[c++].end = start_sbr[seg];
        assert(c < SBR_SEGMENTS + 1);
        mmaps[c].start = end_sbr[seg];
        mmaps[c].end = end_mmap;
      }
    }
  }

  return c;
}

#ifdef __x86_64__
// TODO(andronat): The following is NOT thread safe.
static unsigned long loader_tls_addr;
static unsigned long client_tls_addr;

void load_sabre_tls() {
  assert(client_tls_addr != 0 && loader_tls_addr != 0);
  if (syscall(SYS_arch_prctl, ARCH_SET_FS, loader_tls_addr) == -1)
    _nx_fatal_printf("Failed to switch to loader TLS\n");
}

void load_client_tls() {
  assert(client_tls_addr != 0 && loader_tls_addr != 0);
  if (syscall(SYS_arch_prctl, ARCH_SET_FS, client_tls_addr) == -1)
    _nx_fatal_printf("Failed to switch to client TLS\n");
}

// %fs holds the TLS start address, so ARCH_SET_FS must be handled specially
long arch_set_fs_handler(unsigned long addr) {
  if (loader_tls_addr == 0) {
    assert(client_tls_addr == 0);

    // Save SaBRe TLS
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, &loader_tls_addr) == -1)
      _nx_fatal_printf("Failed to get loader TLS address\n");
    client_tls_addr = addr;

    // Copy SaBRe stack guard value to the client TLS
    const size_t stack_guard_tls_offset =
        0x28; // see glibc-2.27/sysdeps/x86_64/nptl/tls.h
    uintptr_t loader_stack_guard_value =
        *(uintptr_t *)(loader_tls_addr + stack_guard_tls_offset);
    *(uintptr_t *)(client_tls_addr + stack_guard_tls_offset) =
        loader_stack_guard_value;
  } else if (client_tls_addr != addr) {
    _nx_fatal_printf(
        "ARCH_SET_FS attempted to replace initialized client TLS\n");
  }

  // We can't forward ARCH_SET_FS to the plugin. If the plugin uses locks
  // through pthreads or malloc the plugin will segfault, this is because these
  // libraries secretly use the TLS and the FS register. So when we switch the
  // FS register above the plugin will be using the application's pthreads which
  // might be uninitialized and thus segfault.
  // Remember! The plugin (for now) always needs to enter with the SaBRe FS.
  // Optional: To allow the plugin to be aware of this syscall as special hook
  // needs to be introduced that notifies the plugin about the switch only after
  // the switch is done.
  return syscall(SYS_arch_prctl, ARCH_SET_FS, addr);
}
#endif // __x86_64__

long ld_sc_handler(long sc_no, long arg1, long arg2, long arg3, long arg4,
                   long arg5, long arg6, void *wrapper_sp) {
  unreferenced_var(wrapper_sp);

  if (calling_from_plugin != NULL) {
    return runtime_syscall_router(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
                                  wrapper_sp);
  }

#ifdef __x86_64__
  if (loader_tls_addr != 0) {
    load_sabre_tls();
  }
#endif // __x86_64__

  long ret;
  switch (sc_no) {
#ifdef SYS_open
  case SYS_open: {
    const char *pathname = (const char *)arg1;
    int flags = arg2;
    mode_t mode = arg3;

    _nx_debug_printf("open: enter loader syscall\n");

    // long fd = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
    // wrapper_sp);
    long fd = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);

    // TODO: Why do we add a pre-page in our plugin?
    ret = process_fd(fd, pathname, flags, mode);
    break;
  }
#endif // SYS_open

  // Since glibc 2.26, the glibc wrapper function for open()  employs  the
  // openat() system call, rather than the kernel's open() system call.
  case SYS_openat: {
    // int dirfd = arg1;
    const char *pathname = (const char *)arg2;
    int flags = arg3;
    mode_t mode = arg4;

    _nx_debug_printf("openat: enter loader syscall\n");

    // long fd = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
    // wrapper_sp);
    long fd = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);

    ret = process_fd(fd, pathname, flags, mode);
    break;
  }

  case SYS_mmap: {
    void *addr = (void *)arg1;
    size_t length = arg2;
    int prot = arg3;
    int flags = arg4;
    int fd = arg5;
    off_t offset = arg6;

    _nx_debug_printf("mmap: enter loader syscall (%d)\n", fd);

    // Populate start_sbr and end_sbr
    if (start_sbr[0] == 0 || end_sbr[0] == 0) {
      int fd = open("/proc/self/maps", O_RDONLY, 0);
      hide_sbr_maps(fd, 0);
      close(fd);
    }

    void *mmap_addr = NULL;

    if (flags & MAP_FIXED) {
      uintptr_t start_mmap = (uintptr_t)addr;
      uintptr_t end_mmap = start_mmap + length;

      struct mem_chunk mmaps[SBR_SEGMENTS + 1] = {
          [0] = {.start = start_mmap, .end = end_mmap}};
      int nb_chunks = intercept_sbr(mmaps);

      int c = 0;
      // mmap_addr = (void *)plugin_sc_handler(sc_no, mmaps[c].start,
      // (mmaps[c].end - mmaps[c].start), prot, flags, fd, offset, wrapper_sp);
      mmap_addr = (void *)real_syscall(sc_no, mmaps[c].start,
                                       (mmaps[c].end - mmaps[c].start), prot,
                                       flags, fd, offset);

      for (c = 1; c < nb_chunks; c++) {
        // plugin_sc_handler(sc_no, mmaps[c].start, (mmaps[c].end -
        // mmaps[c].start), prot, flags, fd, offset, wrapper_sp);
        real_syscall(sc_no, mmaps[c].start, (mmaps[c].end - mmaps[c].start),
                     prot, flags, fd, offset);
      }
    } else {
      // mmap_addr = (void *)plugin_sc_handler(sc_no, (long)addr, length, prot,
      // flags, fd, offset, wrapper_sp);
      mmap_addr = (void *)real_syscall(sc_no, (long)addr, length, prot, flags,
                                       fd, offset);
    }

    if (fd > 0 && fd == interesting_fd && (prot & PROT_EXEC)) {
      // TODO(andronat): It would be much more efficient to directly work on
      // memory addresses but it is also much harder.
      memorymaps_rewrite_lib(known_syscall_libs[interesting_lib]);
      interesting_fd = NO_FD;
      interesting_lib = NO_FD;
    }

    _nx_debug_printf("mmap: exit loader syscall (%p)\n", mmap_addr);

    ret = (long)mmap_addr;
    break;
  }
#ifdef __x86_64__
  case SYS_arch_prctl: {
    int code = arg1;
    unsigned long addr = arg2;
    if (code == ARCH_SET_FS)
      return arch_set_fs_handler(addr);
    else
      // return plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
      // wrapper_sp);
      return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  }
#endif // __x86_64__

  case SYS_readlink: {
    // Intercept readlink so that we can fool the linker into thinking
    // `/proc/self/exe` points to the target executable instead of sabre itself.
    //
    // This fixes a problem where $ORIGIN in the RPATH gets replaced with the
    // path to sabre, not the real executable.
    //
    // FIXME: Also handle readlinkat? The dynamic linker doesn't use this (yet).
    // FIXME: Every plugin should probably also implement this.
    const char *pathname = (const char *)arg1;
    char *buf = (char *)arg2;
    size_t bufsize = (size_t)arg3;

    if (strcmp(pathname, "/proc/self/exe") == 0) {
      if (buf == NULL) {
        return -EFAULT;
      }

      // strncpy doesn't tell us how many bytes it copied, so we have to
      // calculate that ourselves. Plus, readlink should not append a NUL byte
      // to the end. Best to use memcpy here to mimic the kernel.
      size_t len = strlen(abs_client_path);
      if (len > bufsize) {
        len = bufsize;
      }

      memcpy(buf, abs_client_path, len);

      _nx_debug_printf("readlink: enter loader syscall (\"%s\", %p -> "
                       "\"%.*s\", %zu) -> %zu\n",
                       pathname, buf, (int)len, buf, bufsize, len);

      return len;
    } else {
      size_t len = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
      return len;
    }
  }

  default:
    _nx_debug_printf("calling syscall %ld\n", sc_no);
    // ret = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
    // wrapper_sp);
    ret = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
    _nx_debug_printf("returned from syscall %ld\n", sc_no);
  }

#ifdef __x86_64__
  if (client_tls_addr != 0) {
    load_client_tls();
  }
#endif // __x86_64__

  return ret;
}

// TODO(andronat): Do router for rdtsc

static void_void_fn plugin_clock_gettime = NULL;
static void_void_fn plugin_getcpu = NULL;
static void_void_fn plugin_gettimeofday = NULL;
#ifdef __x86_64__
static void_void_fn plugin_time = NULL;
#endif // __x86_64__

static void_void_fn actual_clock_gettime = NULL;
static void_void_fn actual_getcpu = NULL;
static void_void_fn actual_gettimeofday = NULL;
#ifdef __x86_64__
static void_void_fn actual_time = NULL;
#endif // __x86_64__

typedef int clock_gettime_fn(clockid_t, struct timespec *);
static int vdso_clock_gettime_router(clockid_t arg1, struct timespec *arg2) {
  if (plugin_clock_gettime == NULL || calling_from_plugin == NULL ||
      calling_from_plugin())
    return ((clock_gettime_fn *)actual_clock_gettime)(arg1, arg2);

  enter_plugin();
  int rc = ((clock_gettime_fn *)plugin_clock_gettime)(arg1, arg2);
  exit_plugin();
  return rc;
}

// arg3 has type: struct getcpu_cache *
typedef int getcpu_fn(unsigned *, unsigned *, void *);
static int vdso_getcpu_router(unsigned *arg1, unsigned *arg2, void *arg3) {
  if (plugin_getcpu == NULL || calling_from_plugin == NULL ||
      calling_from_plugin())
    return ((getcpu_fn *)actual_getcpu)(arg1, arg2, arg3);

  enter_plugin();
  int rc = ((getcpu_fn *)plugin_getcpu)(arg1, arg2, arg3);
  exit_plugin();
  return rc;
}

typedef int gettimeofday_fn(struct timeval *, struct timezone *);
static int vdso_gettimeofday_router(struct timeval *arg1,
                                    struct timezone *arg2) {
  if (plugin_gettimeofday == NULL || calling_from_plugin == NULL ||
      calling_from_plugin())
    return ((gettimeofday_fn *)actual_gettimeofday)(arg1, arg2);

  enter_plugin();
  int rc = ((gettimeofday_fn *)plugin_gettimeofday)(arg1, arg2);
  exit_plugin();
  return rc;
}

#ifdef __x86_64__
typedef int time_fn(time_t *);
static int vdso_time_router(time_t *arg1) {
  if (plugin_time == NULL || calling_from_plugin == NULL ||
      calling_from_plugin())
    return ((time_fn *)actual_time)(arg1);

  enter_plugin();
  int rc = ((time_fn *)plugin_time)(arg1);
  exit_plugin();
  return rc;
}
#endif // __x86_64__

void_void_fn ld_vdso_callback(long sc_no, void_void_fn actual_fn) {
  switch (sc_no) {
  case SYS_clock_gettime:
    actual_clock_gettime = actual_fn;
    return (void_void_fn)vdso_clock_gettime_router;
  case SYS_getcpu:
    actual_getcpu = actual_fn;
    return (void_void_fn)vdso_getcpu_router;
  case SYS_gettimeofday:
    actual_gettimeofday = actual_fn;
    return (void_void_fn)vdso_gettimeofday_router;
#ifdef __x86_64__
  case SYS_time:
    actual_time = actual_fn;
    return (void_void_fn)vdso_time_router;
#endif // __x86_64__
  default:
    return (void_void_fn)NULL;
  }
}

void setup_plugin_vdso(sbr_icept_vdso_callback_fn plugin_vdso_callback) {
  plugin_clock_gettime =
      plugin_vdso_callback(SYS_clock_gettime, actual_clock_gettime);
  plugin_getcpu = plugin_vdso_callback(SYS_getcpu, actual_getcpu);
  plugin_gettimeofday =
      plugin_vdso_callback(SYS_gettimeofday, actual_gettimeofday);
#ifdef __x86_64__
  plugin_time = plugin_vdso_callback(SYS_time, actual_time);
#endif // __x86_64__
}

long runtime_syscall_router(long sc_no, long arg1, long arg2, long arg3,
                            long arg4, long arg5, long arg6, void *wrapper_sp) {
  // TODO(andronat): the following if code can be optimized by completely avoid
  // calling real_syscall if we carefully refactor handle_syscall.S
  // TODO(andronat): calling_from_plugin can be optimized if we somehow copy the
  // access to the TLS var directly into assembly.

  // .preinit_array might actually run second as pthreads need to initialize
  // locks etc. While pthreads is initializing, calling_from_plugin is NULL.
  // Look: https://code.woboq.org/userspace/glibc/elf/dl-init.c.html#84
  if (calling_from_plugin == NULL || calling_from_plugin()) {
    if (sc_no == SYS_clone && arg2 != 0) { // clone
      void *ret_addr = get_syscall_return_address(wrapper_sp);
      return clone_syscall(arg1, (void *)arg2, (void *)arg3, (void *)arg4, arg5,
                           ret_addr, NULL);
    } else if (sc_no == SYS_clone3 &&
               ((struct clone_args *)arg1)->stack != 0) { // clone3
      void *ret_addr = get_syscall_return_address(wrapper_sp);
      return clone3_syscall(arg1, arg2, arg3, 0, arg5, ret_addr, NULL);
    }
    assert(sc_no != SYS_execve);
    assert(sc_no != SYS_vfork);
    return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  }

  long rc = 0;
  enter_plugin();
  // ARCH_SET_FS needs special handling because it switches TLS.
  // TODO(andronat): I think we don't need this in runtime as the plugin runs
  // inside the client's space.
  if (sc_no == SYS_arch_prctl && arg1 == ARCH_SET_FS) {
    rc = arch_set_fs_handler(arg2);
  } else {
    rc = plugin_sc_handler(sc_no, arg1, arg2, arg3, arg4, arg5, arg6,
                           wrapper_sp);
  }
  exit_plugin();
  return rc;
}

void post_clone_hook(void *ctx) {
  (void)ctx;
  return;
}
