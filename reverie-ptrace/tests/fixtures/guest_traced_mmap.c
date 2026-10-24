/*
 * Installs its own seccomp filter that returns SECCOMP_RET_TRACE for mmap and
 * SECCOMP_RET_ALLOW for everything else, then maps one page at a fixed hint.
 * Output goes through write(2) from a stack buffer so the program makes no
 * other mapping call after the filter is in place.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HINT 0x100000000000UL

int main(void) {
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };
  char out[64];
  int len;

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return 2;
  }
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
    return 3;
  }
  long page = syscall(
      SYS_mmap,
      HINT,
      4096,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0);
  if (page == -1) {
    len = snprintf(out, sizeof(out), "mmap errno=%d\n", errno);
  } else {
    volatile unsigned char* byte = (volatile unsigned char*)page;
    *byte = 42;
    len = snprintf(out, sizeof(out), "mmap ok byte=%d\n", *byte);
  }
  if (write(1, out, (size_t)len) != len) {
    return 4;
  }
  _exit(0);
}
