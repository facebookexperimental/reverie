/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef SC_FUZZER_SYSENT_H
#define SC_FUZZER_SYSENT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#undef _GNU_SOURCE

typedef long (*syscall_handler_fn)(long sc_no, long a1, long a2, long a3,
                                   long a4, long a5, long a6, void **aux,
                                   _Bool *fail);

enum syscall_family {
  SYS_FAMILY_NEVER_FAIL = 0,
  SYS_FAMILY_DEVICE = (1 << 0),
  SYS_FAMILY_FILE = (1 << 1),
  SYS_FAMILY_NETWORK = (1 << 2),
  SYS_FAMILY_PROCESS = (1 << 3),
  SYS_FAMILY_MEMORY = (1 << 4),
  SYS_FAMILY_UNASSIGNED = (1 << 5)
};

struct sysent {
  int nargs;
  const char *sys_name;
  syscall_handler_fn handler;
  int default_errno;
  enum syscall_family families;
  void *handler_state;
};

// TODO: Come up with more sensible default ERRNO
#define SYSENT_SYSCALL_LIST                                                    \
  X(0, 3, "read", EBADF,                                                       \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(1, 3, "write", EBADF,                                                      \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(2, 3, "open", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                  \
  X(3, 1, "close", EBADF,                                                      \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(4, 2, "stat", EIO,                                                         \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(5, 2, "fstat", EBADF,                                                      \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(6, 2, "lstat", EBADF,                                                      \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(7, 3, "poll", EINTR,                                                       \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(8, 3, "lseek", EBADF, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                 \
  X(9, 6, "mmap", ENOMEM, SYS_FAMILY_MEMORY)                                   \
  X(10, 3, "mprotect", ENOMEM, SYS_FAMILY_MEMORY)                              \
  X(11, 2, "munmap", EINVAL, SYS_FAMILY_MEMORY)                                \
  X(12, 1, "brk", ENOMEM, SYS_FAMILY_MEMORY)                                   \
  X(13, 4, "rt_sigaction", EFAULT, SYS_FAMILY_PROCESS)                         \
  X(14, 4, "rt_sigprocmask", EFAULT, SYS_FAMILY_PROCESS)                       \
  X(15, 0, "rt_sigreturn", ENOSYS, SYS_FAMILY_NEVER_FAIL)                      \
  X(16, 3, "ioctl", EIO, SYS_FAMILY_DEVICE)                                    \
  X(17, 4, "pread64", EBADF, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)              \
  X(18, 4, "pwrite64", EBADF, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(19, 3, "readv", EBADF,                                                     \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(20, 3, "writev", EBADF,                                                    \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(21, 2, "access", EIO, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                 \
  X(22, 1, "pipe", ENFILE, SYS_FAMILY_FILE)                                    \
  X(23, 5, "select", EBADF,                                                    \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(24, 0, "sched_yield", ENOSYS, SYS_FAMILY_NEVER_FAIL)                       \
  X(25, 5, "mremap", ENOMEM, SYS_FAMILY_MEMORY)                                \
  X(26, 3, "msync", EBUSY, SYS_FAMILY_MEMORY)                                  \
  X(27, 3, "mincore", ENOMEM, SYS_FAMILY_MEMORY)                               \
  X(28, 3, "madvise", ENOMEM, SYS_FAMILY_MEMORY)                               \
  X(29, 3, "shmget", ENOSPC, SYS_FAMILY_MEMORY)                                \
  X(30, 3, "shmat", EINVAL, SYS_FAMILY_MEMORY)                                 \
  X(31, 3, "shmctl", EINVAL, SYS_FAMILY_MEMORY)                                \
  X(32, 1, "dup", ENFILE, SYS_FAMILY_FILE)                                     \
  X(33, 2, "dup2", ENFILE, SYS_FAMILY_FILE)                                    \
  X(34, 0, "pause", EINTR, SYS_FAMILY_NEVER_FAIL)                              \
  X(35, 2, "nanosleep", EFAULT, SYS_FAMILY_PROCESS)                            \
  X(36, 2, "getitimer", EINVAL, SYS_FAMILY_PROCESS)                            \
  X(37, 1, "alarm", ENOSYS, SYS_FAMILY_NEVER_FAIL)                             \
  X(38, 3, "setitimer", EINVAL, SYS_FAMILY_PROCESS)                            \
  X(39, 0, "getpid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                            \
  X(40, 4, "sendfile", EIO,                                                    \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(41, 3, "socket", EINVAL, SYS_FAMILY_NETWORK)                               \
  X(42, 3, "connect", EAGAIN, SYS_FAMILY_NETWORK)                              \
  X(43, 3, "accept", ENOMEM, SYS_FAMILY_NETWORK)                               \
  X(44, 6, "sendto", EINTR, SYS_FAMILY_NETWORK)                                \
  X(45, 6, "recvfrom", EINTR, SYS_FAMILY_NETWORK)                              \
  X(46, 3, "sendmsg", EINTR, SYS_FAMILY_NETWORK)                               \
  X(47, 3, "recvmsg", EINTR, SYS_FAMILY_NETWORK)                               \
  X(48, 2, "shutdown", EINVAL, SYS_FAMILY_NETWORK)                             \
  X(49, 3, "bind", ENOMEM, SYS_FAMILY_NETWORK)                                 \
  X(50, 2, "listen", EADDRINUSE, SYS_FAMILY_NETWORK)                           \
  X(51, 3, "getsockname", ENOBUFS, SYS_FAMILY_NETWORK)                         \
  X(52, 3, "getpeername", ENOBUFS, SYS_FAMILY_NETWORK)                         \
  X(53, 4, "socketpair", ENFILE, SYS_FAMILY_NETWORK)                           \
  X(54, 5, "setsockopt", ENOPROTOOPT, SYS_FAMILY_NETWORK)                      \
  X(55, 5, "getsockopt", EINVAL, SYS_FAMILY_NETWORK)                           \
  X(56, 5, "clone", ENOMEM, SYS_FAMILY_PROCESS)                                \
  X(57, 0, "fork", ENOMEM, SYS_FAMILY_PROCESS)                                 \
  X(58, 0, "vfork", ENOMEM, SYS_FAMILY_PROCESS)                                \
  X(59, 3, "execve", EIO, SYS_FAMILY_PROCESS)                                  \
  X(60, 1, "exit", ENOSYS, SYS_FAMILY_NEVER_FAIL)                              \
  X(61, 4, "wait4", ECHILD, SYS_FAMILY_PROCESS)                                \
  X(62, 2, "kill", ESRCH, SYS_FAMILY_PROCESS)                                  \
  X(63, 1, "uname", EFAULT, SYS_FAMILY_PROCESS)                                \
  X(64, 3, "semget", EINVAL, SYS_FAMILY_PROCESS)                               \
  X(65, 3, "semop", EINVAL, SYS_FAMILY_PROCESS)                                \
  X(66, 4, "semctl", EINVAL, SYS_FAMILY_PROCESS)                               \
  X(67, 1, "shmdt", EINVAL, SYS_FAMILY_PROCESS)                                \
  X(68, 2, "msgget", EACCES, SYS_FAMILY_NETWORK)                               \
  X(69, 4, "msgsnd", ENOMEM, SYS_FAMILY_NETWORK)                               \
  X(70, 5, "msgrcv", E2BIG, SYS_FAMILY_NETWORK)                                \
  X(71, 3, "msgctl", EIDRM, SYS_FAMILY_NETWORK)                                \
  X(72, 3, "fcntl", EAGAIN, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)               \
  X(73, 2, "flock", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                \
  X(74, 1, "fsync", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)               \
  X(75, 1, "fdatasync", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)           \
  X(76, 2, "truncate", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(77, 2, "ftruncate", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(78, 3, "getdents", EINVAL, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(79, 2, "getcwd", ENOENT, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)              \
  X(80, 1, "chdir", ELOOP, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                \
  X(81, 1, "fchdir", ELOOP, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)               \
  X(82, 2, "rename", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)              \
  X(83, 2, "mkdir", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)               \
  X(84, 1, "rmdir", EBUSY, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                \
  X(85, 2, "creat", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                \
  X(86, 2, "link", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)                \
  X(87, 1, "unlink", EBUSY, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)               \
  X(88, 2, "symlink", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(89, 3, "readlink", EIO, SYS_FAMILY_FILE)                                   \
  X(90, 2, "chmod", ENOMEM, SYS_FAMILY_FILE)                                   \
  X(91, 2, "fchmod", ENOMEM, SYS_FAMILY_FILE)                                  \
  X(92, 3, "chown", ENOMEM, SYS_FAMILY_FILE)                                   \
  X(93, 3, "fchown", ENOMEM, SYS_FAMILY_FILE)                                  \
  X(94, 3, "lchown", ENOMEM, SYS_FAMILY_FILE)                                  \
  X(95, 1, "umask", ENOSYS, SYS_FAMILY_NEVER_FAIL)                             \
  X(96, 2, "gettimeofday", EPERM, SYS_FAMILY_PROCESS)                          \
  X(97, 2, "getrlimit", EPERM, SYS_FAMILY_PROCESS)                             \
  X(98, 2, "getrusage", EINVAL, SYS_FAMILY_PROCESS)                            \
  X(99, 1, "sysinfo", EFAULT, SYS_FAMILY_PROCESS)                              \
  X(100, 1, "times", EFAULT, SYS_FAMILY_PROCESS)                               \
  X(101, 4, "ptrace", ESRCH, SYS_FAMILY_PROCESS)                               \
  X(102, 0, "getuid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                           \
  X(103, 3, "syslog", ENOSYS, SYS_FAMILY_PROCESS)                              \
  X(104, 0, "getgid", ENOSYS, SYS_FAMILY_PROCESS)                              \
  X(105, 1, "setuid", EAGAIN, SYS_FAMILY_PROCESS)                              \
  X(106, 1, "setgid", EPERM, SYS_FAMILY_PROCESS)                               \
  X(107, 0, "geteuid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                          \
  X(108, 0, "getegid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                          \
  X(109, 2, "setpgid", ESRCH, SYS_FAMILY_PROCESS)                              \
  X(110, 0, "getppid", ENOSYS, SYS_FAMILY_PROCESS)                             \
  X(111, 0, "getpgrp", ENOSYS, SYS_FAMILY_PROCESS)                             \
  X(112, 0, "setsid", EPERM, SYS_FAMILY_PROCESS)                               \
  X(113, 2, "setreuid", EAGAIN, SYS_FAMILY_PROCESS)                            \
  X(114, 2, "setregid", EAGAIN, SYS_FAMILY_PROCESS)                            \
  X(115, 2, "getgroups", EINVAL, SYS_FAMILY_PROCESS)                           \
  X(116, 2, "setgroups", ENOMEM, SYS_FAMILY_PROCESS)                           \
  X(117, 3, "setresuid", EAGAIN, SYS_FAMILY_PROCESS)                           \
  X(118, 3, "getresuid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                        \
  X(119, 3, "setresgid", EAGAIN, SYS_FAMILY_PROCESS)                           \
  X(120, 3, "getresgid", ENOSYS, SYS_FAMILY_PROCESS)                           \
  X(121, 1, "getpgid", ENOSYS, SYS_FAMILY_PROCESS)                             \
  X(122, 1, "setfsuid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                         \
  X(123, 1, "setfsgid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                         \
  X(124, 1, "getsid", ESRCH, SYS_FAMILY_PROCESS)                               \
  X(125, 2, "capget", EINVAL, SYS_FAMILY_PROCESS)                              \
  X(126, 2, "capset", EINVAL, SYS_FAMILY_PROCESS)                              \
  X(127, 2, "rt_sigpending", EFAULT, SYS_FAMILY_PROCESS)                       \
  X(128, 4, "rt_sigtimedwait", EINTR, SYS_FAMILY_PROCESS)                      \
  X(129, 3, "rt_sigqueueinfo", EAGAIN, SYS_FAMILY_PROCESS)                     \
  X(130, 2, "rt_sigsuspend", EINTR, SYS_FAMILY_PROCESS)                        \
  X(131, 2, "sigaltstack", EFAULT, SYS_FAMILY_PROCESS)                         \
  X(132, 2, "utime", EACCES, SYS_FAMILY_FILE)                                  \
  X(133, 3, "mknod", ENOSPC, SYS_FAMILY_FILE)                                  \
  X(134, 1, "uselib", ENFILE, SYS_FAMILY_PROCESS)                              \
  X(135, 1, "personality", EINVAL, SYS_FAMILY_PROCESS)                         \
  X(136, 2, "ustat", ENOSYS, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)              \
  X(137, 2, "statfs", ENOSYS, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(138, 2, "fstatfs", ENOSYS, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(139, 3, "sysfs", EINVAL, SYS_FAMILY_DEVICE)                                \
  X(140, 2, "getpriority", ESRCH, SYS_FAMILY_PROCESS)                          \
  X(141, 3, "setpriority", EACCES, SYS_FAMILY_PROCESS)                         \
  X(142, 2, "sched_setparam", ESRCH, SYS_FAMILY_PROCESS)                       \
  X(143, 2, "sched_getparam", ESRCH, SYS_FAMILY_PROCESS)                       \
  X(144, 3, "sched_setscheduler", ESRCH, SYS_FAMILY_PROCESS)                   \
  X(145, 1, "sched_getscheduler", ESRCH, SYS_FAMILY_PROCESS)                   \
  X(146, 1, "sched_get_priority_max", EINVAL, SYS_FAMILY_PROCESS)              \
  X(147, 1, "sched_get_priority_min", EINVAL, SYS_FAMILY_PROCESS)              \
  X(148, 2, "sched_rr_get_interval", ESRCH, SYS_FAMILY_PROCESS)                \
  X(149, 2, "mlock", ENOMEM, SYS_FAMILY_MEMORY)                                \
  X(150, 2, "munlock", EINVAL, SYS_FAMILY_MEMORY)                              \
  X(151, 1, "mlockall", EINVAL, SYS_FAMILY_MEMORY)                             \
  X(152, 0, "munlockall", EPERM, SYS_FAMILY_MEMORY)                            \
  X(153, 0, "vhangup", EPERM, SYS_FAMILY_DEVICE)                               \
  X(154, 3, "modify_ldt", EINVAL, SYS_FAMILY_PROCESS)                          \
  X(155, 2, "pivot_root", EINVAL, SYS_FAMILY_FILE)                             \
  X(156, 1, "_sysctl", EFAULT, SYS_FAMILY_PROCESS)                             \
  X(157, 5, "prctl", EINVAL, SYS_FAMILY_PROCESS)                               \
  X(158, 2, "arch_prctl", EPERM, SYS_FAMILY_PROCESS)                           \
  X(159, 1, "adjtimex", EINVAL, SYS_FAMILY_PROCESS)                            \
  X(160, 2, "setrlimit", EPERM, SYS_FAMILY_PROCESS)                            \
  X(161, 1, "chroot", ELOOP, SYS_FAMILY_PROCESS)                               \
  X(162, 0, "sync", EBADF, SYS_FAMILY_FILE)                                    \
  X(163, 1, "acct", ENOMEM, SYS_FAMILY_PROCESS)                                \
  X(164, 2, "settimeofday", EINVAL, SYS_FAMILY_PROCESS)                        \
  X(165, 5, "mount", EBUSY, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)               \
  X(166, 2, "umount2", EBUSY, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(167, 2, "swapon", EBUSY, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)              \
  X(168, 1, "swapoff", ENOENT, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(169, 4, "reboot", EINVAL, SYS_FAMILY_DEVICE)                               \
  X(170, 2, "sethostname", EPERM, SYS_FAMILY_NETWORK)                          \
  X(171, 2, "setdomainname", EPERM, SYS_FAMILY_NETWORK)                        \
  X(172, 1, "iopl", ENOSYS, SYS_FAMILY_PROCESS)                                \
  X(173, 3, "ioperm", ENOMEM, SYS_FAMILY_PROCESS)                              \
  X(174, 2, "create_module", ENOSYS, SYS_FAMILY_UNASSIGNED)                    \
  X(175, 3, "init_module", ENOMEM, SYS_FAMILY_UNASSIGNED)                      \
  X(176, 2, "delete_module", ENOENT, SYS_FAMILY_UNASSIGNED)                    \
  X(177, 1, "get_kernel_syms", ENOSYS, SYS_FAMILY_UNASSIGNED)                  \
  X(178, 5, "query_module", ENOSYS, SYS_FAMILY_UNASSIGNED)                     \
  X(179, 4, "quotactl", ESRCH, SYS_FAMILY_FILE)                                \
  X(180, 3, "nfsservctl", ENOSYS, SYS_FAMILY_NETWORK)                          \
  X(181, 5, "getpmsg", ENOSYS, SYS_FAMILY_UNASSIGNED)                          \
  X(182, 5, "putpmsg", ENOSYS, SYS_FAMILY_UNASSIGNED)                          \
  X(183, 5, "afs_syscall", ENOSYS, SYS_FAMILY_UNASSIGNED)                      \
  X(184, 3, "tuxcall", ENOSYS, SYS_FAMILY_UNASSIGNED)                          \
  X(185, 3, "security", ENOSYS, SYS_FAMILY_UNASSIGNED)                         \
  X(186, 0, "gettid", ENOSYS, SYS_FAMILY_NEVER_FAIL)                           \
  X(187, 3, "readahead", EINVAL, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(188, 5, "setxattr", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)           \
  X(189, 5, "lsetxattr", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(190, 5, "fsetxattr", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(191, 4, "getxattr", E2BIG, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(192, 4, "lgetxattr", E2BIG, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)           \
  X(193, 4, "fgetxattr", E2BIG, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)           \
  X(194, 3, "listxattr", E2BIG, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)           \
  X(195, 3, "llistxattr", E2BIG, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(196, 3, "flistxattr", E2BIG, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(197, 2, "removexattr", ENODATA, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)       \
  X(198, 2, "lremovexattr", ENODATA, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)      \
  X(199, 2, "fremovexattr", ENODATA, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)      \
  X(200, 2, "tkill", EAGAIN, SYS_FAMILY_PROCESS)                               \
  X(201, 1, "time", ENOSYS, SYS_FAMILY_NEVER_FAIL)                             \
  X(202, 6, "futex", EAGAIN, SYS_FAMILY_UNASSIGNED)                            \
  X(203, 3, "sched_setaffinity", EPERM, SYS_FAMILY_PROCESS)                    \
  X(204, 3, "sched_getaffinity", EPERM, SYS_FAMILY_PROCESS)                    \
  X(205, 1, "set_thread_area", ENOSYS, SYS_FAMILY_UNASSIGNED)                  \
  X(206, 2, "io_setup", ENOMEM, SYS_FAMILY_NETWORK)                            \
  X(207, 1, "io_destroy", ENOSYS, SYS_FAMILY_NEVER_FAIL)                       \
  X(208, 5, "io_getevents", EINTR, SYS_FAMILY_NETWORK)                         \
  X(209, 3, "io_submit", EAGAIN, SYS_FAMILY_NETWORK)                           \
  X(210, 3, "io_cancel", EAGAIN, SYS_FAMILY_NETWORK)                           \
  X(211, 1, "get_thread_area", ENOSYS, SYS_FAMILY_UNASSIGNED)                  \
  X(212, 3, "lookup_dcookie", EINVAL, SYS_FAMILY_FILE)                         \
  X(213, 1, "epoll_create", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)      \
  X(214, 4, "epoll_ctl_old", ENOMEM, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)     \
  X(215, 4, "epoll_wait_old", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)     \
  X(216, 5, "remap_file_pages", EINVAL, SYS_FAMILY_MEMORY)                     \
  X(217, 3, "getdents64", EINVAL, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)         \
  X(218, 1, "set_tid_address", ENOSYS, SYS_FAMILY_NEVER_FAIL)                  \
  X(219, 0, "restart_syscall", EBADF, SYS_FAMILY_UNASSIGNED)                   \
  X(220, 4, "semtimedop", EAGAIN, SYS_FAMILY_PROCESS)                          \
  X(221, 4, "fadvise64", EINVAL, SYS_FAMILY_FILE)                              \
  X(222, 3, "timer_create", EAGAIN, SYS_FAMILY_PROCESS)                        \
  X(223, 4, "timer_settime", EINVAL, SYS_FAMILY_PROCESS)                       \
  X(224, 2, "timer_gettime", EINVAL, SYS_FAMILY_PROCESS)                       \
  X(225, 1, "timer_getoverrun", EINVAL, SYS_FAMILY_PROCESS)                    \
  X(226, 1, "timer_delete", EINVAL, SYS_FAMILY_PROCESS)                        \
  X(227, 2, "clock_settime", EINVAL, SYS_FAMILY_PROCESS)                       \
  X(228, 2, "clock_gettime", EINVAL, SYS_FAMILY_PROCESS)                       \
  X(229, 2, "clock_getres", EINVAL, SYS_FAMILY_PROCESS)                        \
  X(230, 4, "clock_nanosleep", EINTR, SYS_FAMILY_PROCESS)                      \
  X(231, 1, "exit_group", ENOSYS, SYS_FAMILY_NEVER_FAIL)                       \
  X(232, 4, "epoll_wait", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)         \
  X(233, 4, "epoll_ctl", ENOMEM, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)         \
  X(234, 3, "tgkill", EAGAIN, SYS_FAMILY_PROCESS)                              \
  X(235, 2, "utimes", ENOENT, SYS_FAMILY_FILE)                                 \
  X(236, 5, "vserver", ENOSYS, SYS_FAMILY_NEVER_FAIL)                          \
  X(237, 6, "mbind", ENOMEM, SYS_FAMILY_MEMORY)                                \
  X(238, 3, "set_mempolicy", ENOMEM, SYS_FAMILY_MEMORY)                        \
  X(239, 5, "get_mempolicy", EINVAL, SYS_FAMILY_MEMORY)                        \
  X(240, 4, "mq_open", ENOSPC, SYS_FAMILY_PROCESS)                             \
  X(241, 1, "mq_unlink", ENOENT, SYS_FAMILY_PROCESS)                           \
  X(242, 5, "mq_timedsend", EINTR, SYS_FAMILY_PROCESS)                         \
  X(243, 5, "mq_timedreceive", EINTR, SYS_FAMILY_PROCESS)                      \
  X(244, 2, "mq_notify", ENOMEM, SYS_FAMILY_PROCESS)                           \
  X(245, 3, "mq_getsetattr", EINVAL, SYS_FAMILY_PROCESS)                       \
  X(246, 4, "kexec_load", EBUSY, SYS_FAMILY_PROCESS)                           \
  X(247, 5, "waitid", ECHILD, SYS_FAMILY_PROCESS)                              \
  X(248, 5, "add_key", EDQUOT, SYS_FAMILY_UNASSIGNED)                          \
  X(249, 4, "request_key", EKEYEXPIRED, SYS_FAMILY_UNASSIGNED)                 \
  X(250, 5, "keyctl", EAGAIN, SYS_FAMILY_UNASSIGNED)                           \
  X(251, 3, "ioprio_set", EPERM, SYS_FAMILY_PROCESS)                           \
  X(252, 2, "ioprio_get", EPERM, SYS_FAMILY_PROCESS)                           \
  X(253, 0, "inotify_init", ENFILE, SYS_FAMILY_FILE)                           \
  X(254, 3, "inotify_add_watch", ENOSPC, SYS_FAMILY_FILE)                      \
  X(255, 2, "inotify_rm_watch", EINVAL, SYS_FAMILY_FILE)                       \
  X(256, 4, "migrate_pages", EINVAL, SYS_FAMILY_MEMORY)                        \
  X(257, 4, "openat", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)              \
  X(258, 3, "mkdirat", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(259, 4, "mknodat", ENOSPC, SYS_FAMILY_FILE)                                \
  X(260, 5, "fchownat", ENOMEM, SYS_FAMILY_FILE)                               \
  X(261, 3, "futimesat", ENOENT, SYS_FAMILY_FILE)                              \
  X(262, 4, "newfstatat", EBADF,                                               \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(263, 3, "unlinkat", EBUSY, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)            \
  X(264, 4, "renameat", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)           \
  X(265, 5, "linkat", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(266, 3, "symlinkat", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(267, 4, "readlinkat", EIO, SYS_FAMILY_FILE)                                \
  X(268, 3, "fchmodat", ENOMEM, SYS_FAMILY_FILE)                               \
  X(269, 3, "faccessat", EIO, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)             \
  X(270, 6, "pselect6", EINTR, SYS_FAMILY_FILE)                                \
  X(271, 5, "ppoll", EINTR,                                                    \
    SYS_FAMILY_FILE | SYS_FAMILY_DEVICE | SYS_FAMILY_NETWORK)                  \
  X(272, 1, "unshare", ENOSPC, SYS_FAMILY_PROCESS)                             \
  X(273, 2, "set_robust_list", EINVAL, SYS_FAMILY_PROCESS)                     \
  X(274, 3, "get_robust_list", ESRCH, SYS_FAMILY_PROCESS)                      \
  X(275, 6, "splice", EINVAL, SYS_FAMILY_FILE)                                 \
  X(276, 4, "tee", ENOMEM, SYS_FAMILY_FILE)                                    \
  X(277, 4, "sync_file_range", EIO, SYS_FAMILY_FILE)                           \
  X(278, 4, "vmsplice", ENOMEM, SYS_FAMILY_FILE | SYS_FAMILY_MEMORY)           \
  X(279, 6, "move_pages", E2BIG, SYS_FAMILY_MEMORY)                            \
  X(280, 4, "utimensat", ENONET, SYS_FAMILY_FILE)                              \
  X(281, 6, "epoll_pwait", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)         \
  X(282, 3, "signalfd", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)          \
  X(283, 2, "timerfd_create", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)    \
  X(284, 1, "eventfd", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)           \
  X(285, 4, "fallocate", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(286, 4, "timerfd_settime", EBADF, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)    \
  X(287, 2, "timerfd_gettime", EBADF, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)    \
  X(288, 4, "accept4", ENOMEM, SYS_FAMILY_NETWORK)                             \
  X(289, 4, "signalfd4", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)         \
  X(290, 2, "eventfd2", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)          \
  X(291, 1, "epoll_create1", ENFILE, SYS_FAMILY_FILE | SYS_FAMILY_PROCESS)     \
  X(292, 3, "dup3", ENFILE, SYS_FAMILY_FILE)                                   \
  X(293, 2, "pipe2", ENFILE, SYS_FAMILY_FILE)                                  \
  X(294, 1, "inotify_init1", ENFILE, SYS_FAMILY_FILE)                          \
  X(295, 4, "preadv", EOVERFLOW, SYS_FAMILY_FILE)                              \
  X(296, 4, "pwritev", EOVERFLOW, SYS_FAMILY_FILE)                             \
  X(297, 4, "rt_tgsigqueueinfo", EAGAIN, SYS_FAMILY_PROCESS)                   \
  X(298, 5, "perf_event_open", EBUSY, SYS_FAMILY_UNASSIGNED)                   \
  X(299, 5, "recvmmsg", EINTR, SYS_FAMILY_NETWORK)                             \
  X(300, 2, "fanotify_init", ENOMEM, SYS_FAMILY_FILE)                          \
  X(301, 5, "fanotify_mark", ENOMEM, SYS_FAMILY_UNASSIGNED)                    \
  X(302, 4, "prlimit64", EPERM, SYS_FAMILY_PROCESS)                            \
  X(303, 5, "name_to_handle_at", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)   \
  X(304, 3, "open_by_handle_at", EINTR, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)   \
  X(305, 2, "clock_adjtime", EINVAL, SYS_FAMILY_UNASSIGNED)                    \
  X(306, 1, "syncfs", EBADF, SYS_FAMILY_FILE)                                  \
  X(307, 4, "sendmmsg", EINTR, SYS_FAMILY_NETWORK)                             \
  X(308, 2, "setns", EINVAL, SYS_FAMILY_PROCESS)                               \
  X(309, 3, "getcpu", ENOSYS, SYS_FAMILY_NEVER_FAIL)                           \
  X(310, 6, "process_vm_readv", ENOMEM,                                        \
    SYS_FAMILY_PROCESS | SYS_FAMILY_MEMORY)                                    \
  X(311, 6, "process_vm_writev", ENOMEM,                                       \
    SYS_FAMILY_PROCESS | SYS_FAMILY_MEMORY)                                    \
  X(312, 5, "kcmp", EPERM, SYS_FAMILY_PROCESS)                                 \
  X(313, 3, "finit_module", ENOMEM, SYS_FAMILY_UNASSIGNED)                     \
  X(314, 3, "sched_setattr", EPERM, SYS_FAMILY_PROCESS)                        \
  X(315, 4, "sched_getattr", ESRCH, SYS_FAMILY_PROCESS)                        \
  X(316, 5, "renameat2", ENOSPC, SYS_FAMILY_FILE | SYS_FAMILY_DEVICE)          \
  X(317, 3, "seccomp", ENOMEM, SYS_FAMILY_PROCESS)                             \
  X(318, 3, "getrandom", EINTR, SYS_FAMILY_UNASSIGNED)                         \
  X(319, 2, "memfd_create", ENOMEM, SYS_FAMILY_MEMORY)                         \
  X(320, 5, "kexec_file_load", EBUSY, SYS_FAMILY_PROCESS)                      \
  X(321, 3, "bpf", EACCES, SYS_FAMILY_UNASSIGNED)                              \
  X(322, 5, "execveat", EIO, SYS_FAMILY_PROCESS)                               \
  X(323, 1, "userfaultfd", ENFILE, SYS_FAMILY_MEMORY)                          \
  X(324, 2, "membarrier", EBADF, SYS_FAMILY_UNASSIGNED)                        \
  X(325, 3, "mlock2", ENOMEM, SYS_FAMILY_MEMORY)                               \
  X(326, 6, "copy_file_range", ENOSPC, SYS_FAMILY_FILE)                        \
  X(327, 6, "preadv2", EOVERFLOW, SYS_FAMILY_FILE)                             \
  X(328, 6, "pwritev2", EOVERFLOW, SYS_FAMILY_FILE)                            \
  X(329, 4, "pkey_mprotect", ENOMEM, SYS_FAMILY_MEMORY)                        \
  X(330, 2, "pkey_alloc", ENOSPC, SYS_FAMILY_MEMORY)                           \
  X(331, 1, "pkey_free", ENOSYS, SYS_FAMILY_NEVER_FAIL)                        \
  X(332, 5, "statx", ENOMEM, SYS_FAMILY_FILE)

#define SYSENT_NUM_SYSCALLS 333

#endif /* !SC_FUZZER_SYSENT_H */
