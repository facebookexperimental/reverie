/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef REAL_SYSCALL_H
#define REAL_SYSCALL_H

#include <sys/syscall.h>

#ifndef SYS_clone3
#include <linux/types.h>
#include <stddef.h>

#define SYS_clone3 435

// Older compilers don't have this definition yet.
struct clone_args {
  __aligned_u64 flags;
  __aligned_u64 pidfd;
  __aligned_u64 child_tid;
  __aligned_u64 parent_tid;
  __aligned_u64 exit_signal;
  __aligned_u64 stack;
  __aligned_u64 stack_size;
  __aligned_u64 tls;
  __aligned_u64 set_tid;
  __aligned_u64 set_tid_size;
  __aligned_u64 cgroup;
};
#endif

long real_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                  long arg5, long arg6);

long clone_syscall(unsigned long flags, void *child_stack, int *ptid, int *ctid,
                   unsigned long newtls, void *ret_addr, void *ctx);

long clone3_syscall(long arg1, long arg2, long arg3, int not_used, long arg5,
                    void *ret_addr, void *ctx);

long vfork_syscall();
long vfork_return_from_child(void *wrapper_sp);

#endif /* !REAL_SYSCALL_H */
