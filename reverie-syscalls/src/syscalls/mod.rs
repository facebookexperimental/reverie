/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

pub mod family;

use crate::args::{
    ioctl, ArchPrctlCmd, CArrayPtr, CStrPtr, ClockId, FcntlCmd, PathPtr, PollFd, StatPtr,
    StatxMask, StatxPtr, Timespec, Timeval, Timezone, Whence,
};
use crate::display::Displayable;
use crate::memory::{Addr, AddrMut};
use crate::raw::FromToRaw;
use ::syscalls::{SyscallArgs, Sysno};

// Re-export flags that used by syscalls from the `nix` crate so downstream
// projects don't need to add another dependency on it.
pub use nix::{
    fcntl::{AtFlags, OFlag},
    sched::CloneFlags,
    sys::{
        epoll::EpollCreateFlags,
        eventfd::EfdFlags,
        inotify::InitFlags,
        mman::{MapFlags, ProtFlags},
        signalfd::SfdFlags,
        socket::SockFlag,
        stat::Mode,
        timerfd::TimerFlags,
        wait::WaitPidFlag,
    },
};

/// A trait that all syscalls implement.
pub trait SyscallInfo: Displayable + Copy + Send {
    /// The return type of the syscall.
    type Return: Displayable + FromToRaw;

    /// Returns the syscall name.
    fn name(&self) -> &'static str;

    /// Returns the syscall number.
    fn number(&self) -> Sysno;

    /// Converts the syscall into its constituent parts.
    fn into_parts(self) -> (Sysno, SyscallArgs);
}

// After adding a new type-safe syscall, uncomment the corresponding line below.
// The syscalls lower ranks and higher probabilities should be implemented
// first.
syscall_list! {
    /// Full list of type-safe syscalls.
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[allow(missing_docs)]
    #[non_exhaustive]
    pub enum Syscall {
        SYS_read => Read,
        SYS_write => Write,
        SYS_open => Open,
        SYS_close => Close,
        SYS_stat => Stat,
        SYS_fstat => Fstat,
        SYS_lstat => Lstat,
        SYS_poll => Poll,
        SYS_lseek => Lseek,
        SYS_mmap => Mmap,
        SYS_mprotect => Mprotect,
        SYS_munmap => Munmap,
        SYS_brk => Brk,
        SYS_rt_sigaction => RtSigaction,
        SYS_rt_sigprocmask => RtSigprocmask,
        SYS_rt_sigreturn => RtSigreturn,
        SYS_ioctl => Ioctl,
        SYS_pread64 => Pread64,
        SYS_pwrite64 => Pwrite64,
        SYS_readv => Readv,
        SYS_writev => Writev,
        SYS_access => Access,
        SYS_pipe => Pipe,
        SYS_select => Select,
        SYS_sched_yield => SchedYield,
        SYS_mremap => Mremap,
        SYS_msync => Msync,
        SYS_mincore => Mincore,
        SYS_madvise => Madvise,
        SYS_shmget => Shmget,
        SYS_shmat => Shmat,
        SYS_shmctl => Shmctl,
        SYS_dup => Dup,
        SYS_dup2 => Dup2,
        SYS_pause => Pause,
        SYS_nanosleep => Nanosleep,
        SYS_getitimer => Getitimer,
        SYS_alarm => Alarm,
        SYS_setitimer => Setitimer,
        SYS_getpid => Getpid,
        SYS_sendfile => Sendfile,
        SYS_socket => Socket,
        SYS_connect => Connect,
        SYS_accept => Accept,
        SYS_sendto => Sendto,
        SYS_recvfrom => Recvfrom,
        SYS_sendmsg => Sendmsg,
        SYS_recvmsg => Recvmsg,
        SYS_shutdown => Shutdown,
        SYS_bind => Bind,
        SYS_listen => Listen,
        SYS_getsockname => Getsockname,
        SYS_getpeername => Getpeername,
        SYS_socketpair => Socketpair,
        SYS_setsockopt => Setsockopt,
        SYS_getsockopt => Getsockopt,
        SYS_clone => Clone,
        SYS_fork => Fork,
        SYS_vfork => Vfork,
        SYS_execve => Execve,
        SYS_exit => Exit,
        SYS_wait4 => Wait4,
        SYS_kill => Kill,
        SYS_uname => Uname,
        SYS_semget => Semget,
        SYS_semop => Semop,
        SYS_semctl => Semctl,
        SYS_shmdt => Shmdt,
        SYS_msgget => Msgget,
        SYS_msgsnd => Msgsnd,
        SYS_msgrcv => Msgrcv,
        SYS_msgctl => Msgctl,
        SYS_fcntl => Fcntl,
        SYS_flock => Flock,
        SYS_fsync => Fsync,
        SYS_fdatasync => Fdatasync,
        SYS_truncate => Truncate,
        SYS_ftruncate => Ftruncate,
        SYS_getdents => Getdents,
        SYS_getcwd => Getcwd,
        SYS_chdir => Chdir,
        SYS_fchdir => Fchdir,
        SYS_rename => Rename,
        SYS_mkdir => Mkdir,
        SYS_rmdir => Rmdir,
        SYS_creat => Creat,
        SYS_link => Link,
        SYS_unlink => Unlink,
        SYS_symlink => Symlink,
        SYS_readlink => Readlink,
        SYS_chmod => Chmod,
        SYS_fchmod => Fchmod,
        SYS_chown => Chown,
        SYS_fchown => Fchown,
        SYS_lchown => Lchown,
        SYS_umask => Umask,
        SYS_gettimeofday => Gettimeofday,
        SYS_getrlimit => Getrlimit,
        SYS_getrusage => Getrusage,
        SYS_sysinfo => Sysinfo,
        SYS_times => Times,
        SYS_ptrace => Ptrace,
        SYS_getuid => Getuid,
        SYS_syslog => Syslog,
        SYS_getgid => Getgid,
        SYS_setuid => Setuid,
        SYS_setgid => Setgid,
        SYS_geteuid => Geteuid,
        SYS_getegid => Getegid,
        SYS_setpgid => Setpgid,
        SYS_getppid => Getppid,
        SYS_getpgrp => Getpgrp,
        SYS_setsid => Setsid,
        SYS_setreuid => Setreuid,
        SYS_setregid => Setregid,
        SYS_getgroups => Getgroups,
        SYS_setgroups => Setgroups,
        SYS_setresuid => Setresuid,
        SYS_getresuid => Getresuid,
        SYS_setresgid => Setresgid,
        SYS_getresgid => Getresgid,
        SYS_getpgid => Getpgid,
        SYS_setfsuid => Setfsuid,
        SYS_setfsgid => Setfsgid,
        SYS_getsid => Getsid,
        SYS_capget => Capget,
        SYS_capset => Capset,
        SYS_rt_sigpending => RtSigpending,
        SYS_rt_sigtimedwait => RtSigtimedwait,
        SYS_rt_sigqueueinfo => RtSigqueueinfo,
        SYS_rt_sigsuspend => RtSigsuspend,
        SYS_sigaltstack => Sigaltstack,
        SYS_utime => Utime,
        SYS_mknod => Mknod,
        SYS_uselib => Uselib,
        SYS_personality => Personality,
        SYS_ustat => Ustat,
        SYS_statfs => Statfs,
        SYS_fstatfs => Fstatfs,
        SYS_sysfs => Sysfs,
        SYS_getpriority => Getpriority,
        SYS_setpriority => Setpriority,
        SYS_sched_setparam => SchedSetparam,
        SYS_sched_getparam => SchedGetparam,
        SYS_sched_setscheduler => SchedSetscheduler,
        SYS_sched_getscheduler => SchedGetscheduler,
        SYS_sched_get_priority_max => SchedGetPriorityMax,
        SYS_sched_get_priority_min => SchedGetPriorityMin,
        SYS_sched_rr_get_interval => SchedRrGetInterval,
        SYS_mlock => Mlock,
        SYS_munlock => Munlock,
        SYS_mlockall => Mlockall,
        SYS_munlockall => Munlockall,
        SYS_vhangup => Vhangup,
        SYS_modify_ldt => ModifyLdt,
        SYS_pivot_root => PivotRoot,
        #[allow(non_camel_case_types)]
        SYS__sysctl => _sysctl,
        SYS_prctl => Prctl,
        SYS_arch_prctl => ArchPrctl,
        SYS_adjtimex => Adjtimex,
        SYS_setrlimit => Setrlimit,
        SYS_chroot => Chroot,
        SYS_sync => Sync,
        SYS_acct => Acct,
        SYS_settimeofday => Settimeofday,
        SYS_mount => Mount,
        SYS_umount2 => Umount2,
        SYS_swapon => Swapon,
        SYS_swapoff => Swapoff,
        SYS_reboot => Reboot,
        SYS_sethostname => Sethostname,
        SYS_setdomainname => Setdomainname,
        SYS_iopl => Iopl,
        SYS_ioperm => Ioperm,
        SYS_create_module => CreateModule,
        SYS_init_module => InitModule,
        SYS_delete_module => DeleteModule,
        SYS_get_kernel_syms => GetKernelSyms,
        SYS_query_module => QueryModule,
        SYS_quotactl => Quotactl,
        SYS_nfsservctl => Nfsservctl,
        SYS_getpmsg => Getpmsg,
        SYS_putpmsg => Putpmsg,
        SYS_afs_syscall => AfsSyscall,
        SYS_tuxcall => Tuxcall,
        SYS_security => Security,
        SYS_gettid => Gettid,
        SYS_readahead => Readahead,
        SYS_setxattr => Setxattr,
        SYS_lsetxattr => Lsetxattr,
        SYS_fsetxattr => Fsetxattr,
        SYS_getxattr => Getxattr,
        SYS_lgetxattr => Lgetxattr,
        SYS_fgetxattr => Fgetxattr,
        SYS_listxattr => Listxattr,
        SYS_llistxattr => Llistxattr,
        SYS_flistxattr => Flistxattr,
        SYS_removexattr => Removexattr,
        SYS_lremovexattr => Lremovexattr,
        SYS_fremovexattr => Fremovexattr,
        SYS_tkill => Tkill,
        SYS_time => Time,
        SYS_futex => Futex,
        SYS_sched_setaffinity => SchedSetaffinity,
        SYS_sched_getaffinity => SchedGetaffinity,
        SYS_set_thread_area => SetThreadArea,
        SYS_io_setup => IoSetup,
        SYS_io_destroy => IoDestroy,
        SYS_io_getevents => IoGetevents,
        SYS_io_submit => IoSubmit,
        SYS_io_cancel => IoCancel,
        SYS_get_thread_area => GetThreadArea,
        SYS_lookup_dcookie => LookupDcookie,
        SYS_epoll_create => EpollCreate,
        SYS_epoll_ctl_old => EpollCtlOld,
        SYS_epoll_wait_old => EpollWaitOld,
        SYS_remap_file_pages => RemapFilePages,
        SYS_getdents64 => Getdents64,
        SYS_set_tid_address => SetTidAddress,
        SYS_restart_syscall => RestartSyscall,
        SYS_semtimedop => Semtimedop,
        SYS_fadvise64 => Fadvise64,
        SYS_timer_create => TimerCreate,
        SYS_timer_settime => TimerSettime,
        SYS_timer_gettime => TimerGettime,
        SYS_timer_getoverrun => TimerGetoverrun,
        SYS_timer_delete => TimerDelete,
        SYS_clock_settime => ClockSettime,
        SYS_clock_gettime => ClockGettime,
        SYS_clock_getres => ClockGetres,
        SYS_clock_nanosleep => ClockNanosleep,
        SYS_exit_group => ExitGroup,
        SYS_epoll_wait => EpollWait,
        SYS_epoll_ctl => EpollCtl,
        SYS_tgkill => Tgkill,
        SYS_utimes => Utimes,
        SYS_vserver => Vserver,
        SYS_mbind => Mbind,
        SYS_set_mempolicy => SetMempolicy,
        SYS_get_mempolicy => GetMempolicy,
        SYS_mq_open => MqOpen,
        SYS_mq_unlink => MqUnlink,
        SYS_mq_timedsend => MqTimedsend,
        SYS_mq_timedreceive => MqTimedreceive,
        SYS_mq_notify => MqNotify,
        SYS_mq_getsetattr => MqGetsetattr,
        SYS_kexec_load => KexecLoad,
        SYS_waitid => Waitid,
        SYS_add_key => AddKey,
        SYS_request_key => RequestKey,
        SYS_keyctl => Keyctl,
        SYS_ioprio_set => IoprioSet,
        SYS_ioprio_get => IoprioGet,
        SYS_inotify_init => InotifyInit,
        SYS_inotify_add_watch => InotifyAddWatch,
        SYS_inotify_rm_watch => InotifyRmWatch,
        SYS_migrate_pages => MigratePages,
        SYS_openat => Openat,
        SYS_mkdirat => Mkdirat,
        SYS_mknodat => Mknodat,
        SYS_fchownat => Fchownat,
        SYS_futimesat => Futimesat,
        SYS_newfstatat => Newfstatat,
        SYS_unlinkat => Unlinkat,
        SYS_renameat => Renameat,
        SYS_linkat => Linkat,
        SYS_symlinkat => Symlinkat,
        SYS_readlinkat => Readlinkat,
        SYS_fchmodat => Fchmodat,
        SYS_faccessat => Faccessat,
        SYS_pselect6 => Pselect6,
        SYS_ppoll => Ppoll,
        SYS_unshare => Unshare,
        SYS_set_robust_list => SetRobustList,
        SYS_get_robust_list => GetRobustList,
        SYS_splice => Splice,
        SYS_tee => Tee,
        SYS_sync_file_range => SyncFileRange,
        SYS_vmsplice => Vmsplice,
        SYS_move_pages => MovePages,
        SYS_utimensat => Utimensat,
        SYS_epoll_pwait => EpollPwait,
        SYS_signalfd => Signalfd,
        SYS_timerfd_create => TimerfdCreate,
        SYS_eventfd => Eventfd,
        SYS_fallocate => Fallocate,
        SYS_timerfd_settime => TimerfdSettime,
        SYS_timerfd_gettime => TimerfdGettime,
        SYS_accept4 => Accept4,
        SYS_signalfd4 => Signalfd4,
        SYS_eventfd2 => Eventfd2,
        SYS_epoll_create1 => EpollCreate1,
        SYS_dup3 => Dup3,
        SYS_pipe2 => Pipe2,
        SYS_inotify_init1 => InotifyInit1,
        SYS_preadv => Preadv,
        SYS_pwritev => Pwritev,
        SYS_rt_tgsigqueueinfo => RtTgsigqueueinfo,
        SYS_perf_event_open => PerfEventOpen,
        SYS_recvmmsg => Recvmmsg,
        SYS_fanotify_init => FanotifyInit,
        SYS_fanotify_mark => FanotifyMark,
        SYS_prlimit64 => Prlimit64,
        SYS_name_to_handle_at => NameToHandleAt,
        SYS_open_by_handle_at => OpenByHandleAt,
        SYS_clock_adjtime => ClockAdjtime,
        SYS_syncfs => Syncfs,
        SYS_sendmmsg => Sendmmsg,
        SYS_setns => Setns,
        SYS_getcpu => Getcpu,
        SYS_process_vm_readv => ProcessVmReadv,
        SYS_process_vm_writev => ProcessVmWritev,
        SYS_kcmp => Kcmp,
        SYS_finit_module => FinitModule,
        SYS_sched_setattr => SchedSetattr,
        SYS_sched_getattr => SchedGetattr,
        SYS_renameat2 => Renameat2,
        SYS_seccomp => Seccomp,
        SYS_getrandom => Getrandom,
        SYS_memfd_create => MemfdCreate,
        SYS_kexec_file_load => KexecFileLoad,
        SYS_bpf => Bpf,
        SYS_execveat => Execveat,
        SYS_userfaultfd => Userfaultfd,
        SYS_membarrier => Membarrier,
        SYS_mlock2 => Mlock2,
        SYS_copy_file_range => CopyFileRange,
        SYS_preadv2 => Preadv2,
        SYS_pwritev2 => Pwritev2,
        SYS_pkey_mprotect => PkeyMprotect,
        SYS_pkey_alloc => PkeyAlloc,
        SYS_pkey_free => PkeyFree,
        SYS_statx => Statx,
    }
}

typed_syscall! {
    pub struct Read {
        fd: i32,
        // TODO: Change this to a slice and print out part of the contents of
        // the read.
        buf: Option<AddrMut<u8>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Write {
        fd: i32,
        // TODO: Change this to a slice and print out part of the contents of
        // the write (after the syscall has been executed).
        buf: Option<Addr<u8>>,
        len: usize,
    }
}

fn get_mode(flags: OFlag, mode: u64) -> Option<Mode> {
    if flags.intersects(OFlag::O_CREAT | OFlag::O_TMPFILE) {
        Some(FromToRaw::from_raw(mode))
    } else {
        None
    }
}

typed_syscall! {
    pub struct Open -> i32 {
        path: Option<PathPtr>,
        flags: OFlag,

        /// The mode is only present when `O_CREAT` or `O_TMPFILE` is specified
        /// in the flags. It is ignored otherwise.
        mode?: {
            fn get(&self) -> Option<Mode> {
                get_mode(self.flags(), self.raw.arg2)
            }

            fn set(mut self, v: Option<Mode>) -> Self {
                self.raw.arg2 = v.into_raw();
                self
            }
        },
    }
}

impl From<Creat> for Open {
    /// A call to creat() is equivalent to calling open() with flags equal to
    /// O_CREAT|O_WRONLY|O_TRUNC
    fn from(creat: Creat) -> Self {
        let Creat { mut raw } = creat;
        raw.arg2 = raw.arg1;
        raw.arg1 = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
        Open { raw }
    }
}

typed_syscall! {
    pub struct Close {
        fd: i32,
    }
}

typed_syscall! {
    pub struct Stat {
        path: Option<PathPtr>,
        stat: Option<StatPtr>,
    }
}

typed_syscall! {
    pub struct Fstat {
        fd: i32,
        stat: Option<StatPtr>,
    }
}

typed_syscall! {
    pub struct Lstat {
        path: Option<PathPtr>,
        stat: Option<StatPtr>,
    }
}

typed_syscall! {
    pub struct Poll {
        fds: Option<AddrMut<PollFd>>,
        nfds: libc::nfds_t,
        timeout: libc::c_int,
    }
}

typed_syscall! {
    pub struct Mmap {
        addr: Option<Addr<libc::c_void>>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: libc::off_t,
    }
}

typed_syscall! {
    pub struct Lseek {
        fd: i32,
        offset: libc::off_t,
        whence: Whence,
    }
}

typed_syscall! {
    pub struct Mprotect {
        addr: Option<AddrMut<libc::c_void>>,
        len: usize,
        protection: ProtFlags,
    }
}

typed_syscall! {
    pub struct Munmap {
        addr: Option<Addr<libc::c_void>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Brk {
        addr: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct RtSigaction {
        signum: i32,
        action: Option<Addr<libc::sigaction>>,
        old_action: Option<AddrMut<libc::sigaction>>,
        /// Should always be 8 (`size_of::<u64>()`).
        sigsetsize: usize,
    }
}

typed_syscall! {
    pub struct RtSigprocmask {
        how: i32,
        set: Option<Addr<libc::sigset_t>>,
        oldset: Option<AddrMut<libc::sigset_t>>,
        /// Should always be 8 (`size_of::<u64>()`).
        sigsetsize: usize,
    }
}

typed_syscall! {
    pub struct RtSigreturn {
    }
}

typed_syscall! {
    pub struct Ioctl {
        fd: i32,
        request: {
            fn get(&self) -> ioctl::Request {
                ioctl::Request::from_raw(self.raw.arg1, self.raw.arg2)
            }

            fn set(mut self, v: ioctl::Request) -> Self {
                let (request, arg) = v.into_raw();
                self.raw.arg1 = request;
                self.raw.arg2 = arg;
                self
            }
        },
    }
}

typed_syscall! {
    pub struct Pread64 {
        fd: i32,
        // TODO: Change this to a slice and print out part of the contents of
        // the read.
        buf: Option<AddrMut<u8>>,
        len: usize,
        offset: libc::off_t,
    }
}

typed_syscall! {
    pub struct Pwrite64 {
        fd: i32,
        // TODO: Change this to a slice and print out part of the contents of
        // the write.
        buf: Option<Addr<u8>>,
        len: usize,
        offset: libc::off_t,
    }
}

typed_syscall! {
    pub struct Readv {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Writev {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Access {
        path: Option<PathPtr>,
        mode: Mode,
    }
}

typed_syscall! {
    pub struct Pipe {
        pipefd: Option<AddrMut<[i32; 2]>>,
    }
}

typed_syscall! {
    pub struct Select {
        nfds: i32,
        readfds: Option<AddrMut<libc::fd_set>>,
        writefds: Option<AddrMut<libc::fd_set>>,
        exceptfds: Option<AddrMut<libc::fd_set>>,
        timeout: Option<AddrMut<libc::timeval>>,
    }
}

typed_syscall! {
    pub struct SchedYield {}
}

typed_syscall! {
    pub struct Mremap {
        addr: Option<AddrMut<libc::c_void>>,
        old_len: usize,
        new_len: usize,
        flags: usize,
        new_addr: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Msync {
        addr: Option<AddrMut<libc::c_void>>,
        len: usize,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Mincore {
        addr: Option<AddrMut<libc::c_void>>,
        len: usize,
        vec: Option<AddrMut<u8>>,
    }
}

typed_syscall! {
    pub struct Madvise {
        addr: Option<AddrMut<libc::c_void>>,
        len: usize,
        advice: i32,
    }
}

typed_syscall! {
    pub struct Shmget {
        key: libc::key_t,
        size: usize,
        shmflg: i32,
    }
}

typed_syscall! {
    pub struct Shmat {
        shmid: i32,
        shmaddr: Option<Addr<libc::c_void>>,
        shmflg: i32,
    }
}

typed_syscall! {
    pub struct Shmctl {
        shmid: i32,
        cmd: i32,
        buf: Option<AddrMut<libc::shmid_ds>>,
    }
}

typed_syscall! {
    pub struct Dup {
        oldfd: i32,
    }
}

typed_syscall! {
    pub struct Dup2 {
        oldfd: i32,
        newfd: i32,
    }
}

typed_syscall! { pub struct Pause {} }

typed_syscall! {
    pub struct Nanosleep {
        req: Option<Addr<Timespec>>,
        rem: Option<AddrMut<Timespec>>,
    }
}

typed_syscall! {
    pub struct Getitimer {
        which: i32,
        value: Option<AddrMut<libc::itimerval>>,
    }
}

typed_syscall! {
    pub struct Alarm {
        seconds: u32,
    }
}

typed_syscall! {
    pub struct Setitimer {
        which: i32,
        value: Option<AddrMut<libc::itimerval>>,
        ovalue: Option<AddrMut<libc::itimerval>>,
    }
}

typed_syscall! {
    pub struct Getpid {}
}

typed_syscall! {
    pub struct Sendfile {
        out_fd: i32,
        in_fd: i32,
        offset: Option<AddrMut<libc::loff_t>>,
        count: usize,
    }
}

typed_syscall! {
    // TODO: Give more meaningful types to these arguments.
    pub struct Socket {
        family: i32,
        r#type: i32,
        protocol: i32,
    }
}

typed_syscall! {
    pub struct Connect {
        fd: i32,
        uservaddr: Option<AddrMut<libc::sockaddr>>,
        addrlen: i32,
    }
}

typed_syscall! {
    pub struct Accept {
        sockfd: i32,
        sockaddr: Option<AddrMut<libc::sockaddr>>,
        addrlen: Option<AddrMut<usize>>,
    }
}

typed_syscall! {
    pub struct Sendto {
        fd: i32,
        buf: Option<AddrMut<libc::c_void>>,
        size: usize,
        flags: u32,
        addr: Option<AddrMut<libc::sockaddr>>,
        addr_len: i32,
    }
}

typed_syscall! {
    pub struct Recvfrom {
        fd: i32,
        buf: Option<AddrMut<u8>>,
        len: usize,
        flags: i32,
        addr: Option<AddrMut<libc::sockaddr>>,
        addr_len: Option<AddrMut<libc::socklen_t>>,
    }
}

typed_syscall! {
    pub struct Sendmsg {
        fd: i32,
        msg: Option<Addr<libc::msghdr>>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Recvmsg {
        sockfd: i32,
        msg: Option<AddrMut<libc::msghdr>>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Shutdown {
        fd: i32,
        how: i32,
    }
}

typed_syscall! {
    pub struct Bind {
        fd: i32,
        umyaddr: Option<AddrMut<libc::sockaddr>>,
        addrlen: i32,
    }
}

typed_syscall! {
    pub struct Listen {
        fd: i32,
        backlog: i32,
    }
}

typed_syscall! {
    pub struct Getsockname {
        fd: i32,
        usockaddr: Option<AddrMut<libc::sockaddr>>,
        usockaddr_len: Option<AddrMut<libc::socklen_t>>,
    }
}

typed_syscall! {
    pub struct Getpeername {
        fd: i32,
        usockaddr: Option<AddrMut<libc::sockaddr>>,
        usockaddr_len: Option<AddrMut<libc::socklen_t>>,
    }
}

typed_syscall! {
    // TODO: Give more meaningful types to these arguments.
    pub struct Socketpair {
        family: i32,
        r#type: i32,
        protocol: i32,
        usockvec: Option<AddrMut<[i32; 2]>>,
    }
}

typed_syscall! {
    pub struct Setsockopt {
        fd: i32,
        level: i32,
        optname: i32,
        optval: Option<Addr<libc::c_void>>,
        optlen: libc::socklen_t,
    }
}

typed_syscall! {
    pub struct Getsockopt {
        fd: i32,
        level: i32,
        optname: i32,
        optval: Option<AddrMut<libc::c_void>>,
        optlen: Option<AddrMut<libc::socklen_t>>,
    }
}

#[cfg(any(target_arch = "x86_64"))]
typed_syscall! {
    pub struct Clone {
        flags: CloneFlags,
        child_stack: Option<AddrMut<libc::c_void>>,
        ptid: Option<AddrMut<libc::pid_t>>,
        ctid: Option<AddrMut<libc::pid_t>>,
        newtls: u64,
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64", target_arch = "x86"))]
typed_syscall! {
    pub struct Clone {
        flags: CloneFlags,
        child_stack: Option<AddrMut<libc::c_void>>,
        ptid: Option<AddrMut<libc::pid_t>>,
        newtls: u64,
        ctid: Option<AddrMut<libc::pid_t>>,
    }
}

impl From<Vfork> for Clone {
    /// Since `clone` offers a superset of functionality over `vfork`, a `vfork`
    /// syscall can be transformed into a `clone` syscall by passing in the
    /// right flags. In fact, this is how the Linux kernel implements `vfork`.
    /// See kernel/fork.c for more details.
    fn from(_: Vfork) -> Self {
        let raw = SyscallArgs {
            arg0: (libc::CLONE_VFORK | libc::CLONE_VM | libc::SIGCHLD) as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        Self { raw }
    }
}

impl From<Fork> for Clone {
    /// Since `clone` offers a superset of functionality over `fork`, a `fork`
    /// syscall can be transformed into a `clone` syscall by passing in the
    /// right flags. In fact, this is how the Linux kernel implements `fork`.
    /// See kernel/fork.c for more details.
    fn from(_: Fork) -> Self {
        let raw = SyscallArgs {
            arg0: libc::SIGCHLD as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        Self { raw }
    }
}

typed_syscall! {
    pub struct Fork {}
}

typed_syscall! {
    pub struct Vfork {}
}

typed_syscall! {
    pub struct Execve {
        path: Option<PathPtr>,
        argv: Option<CArrayPtr<CStrPtr>>,
        envp: Option<CArrayPtr<CStrPtr>>,
    }
}

typed_syscall! {
    pub struct Exit {
        status: libc::c_int,
    }
}

typed_syscall! {
    pub struct Wait4 {
        pid: libc::pid_t,
        wstatus: Option<AddrMut<libc::c_int>>,
        options: WaitPidFlag,
        rusage: Option<AddrMut<libc::rusage>>,
    }
}

typed_syscall! {
    pub struct Kill {
        pid: libc::pid_t,
        // TODO: Change the signal to a type that prints out the signal passed
        // to it.
        sig: libc::c_int,
    }
}

typed_syscall! {
    pub struct Uname {
        buf: Option<AddrMut<libc::utsname>>,
    }
}

typed_syscall! {
    pub struct Semget {
        key: libc::key_t,
        nsems: i32,
        semflg: i32,
    }
}

typed_syscall! {
    pub struct Semop {
        semid: i32,
        tsops: Option<AddrMut<libc::sembuf>>,
        nsops: usize,
    }
}

typed_syscall! {
    pub struct Semctl {
        semid: i32,
        semnum: i32,
        cmd: i32,
        arg: u64,
    }
}

typed_syscall! {
    pub struct Shmdt {
        shmaddr: Option<Addr<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Msgget {
        key: libc::key_t,
        msgflg: i32,
    }
}

typed_syscall! {
    pub struct Msgsnd {
        msqid: i32,
        msgp: Option<Addr<libc::c_void>>,
        msgsz: usize,
        msgflg: i32,
    }
}

typed_syscall! {
    pub struct Msgrcv {
        msqid: i32,
        msgp: Option<AddrMut<libc::c_void>>,
        msgsz: usize,
        msgtyp: libc::c_long,
        msgflg: i32,
    }
}

typed_syscall! {
    pub struct Msgctl {
        msqid: i32,
        cmd: i32,
        buf: Option<AddrMut<libc::msqid_ds>>,
    }
}

typed_syscall! {
    pub struct Fcntl {
        /// The file descriptor to perform the operation on.
        fd: i32,

        cmd: {
            fn get(&self) -> FcntlCmd {
                FcntlCmd::from_raw(self.raw.arg1 as libc::c_int, self.raw.arg2)
            }

            fn set(mut self, v: FcntlCmd) -> Self {
                let (cmd, arg) = v.into_raw();
                self.raw.arg1 = cmd as u64;
                self.raw.arg2 = arg;
                self
            }
        },
    }
}

typed_syscall! {
    pub struct Flock {
        fd: i32,
        // TODO: Give this a more restricted type.
        operation: i32,
    }
}

typed_syscall! {
    pub struct Fsync {
        fd: i32,
    }
}

typed_syscall! {
    pub struct Fdatasync {
        fd: i32,
    }
}

typed_syscall! {
    pub struct Truncate {
        path: Option<PathPtr>,
        length: libc::off_t,
    }
}

typed_syscall! {
    pub struct Ftruncate {
        fd: i32,
        length: libc::off_t,
    }
}

typed_syscall! {
    pub struct Getdents {
        fd: u32,
        dirent: Option<AddrMut<libc::dirent>>,
        count: u32,
    }
}

typed_syscall! {
    pub struct Getcwd {
        // TODO: Replace this with a PathPtrMut.
        buf: Option<AddrMut<libc::c_char>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Chdir {
        path: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Fchdir {
        fd: i32,
    }
}

typed_syscall! {
    pub struct Rename {
        oldpath: Option<PathPtr>,
        newpath: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Mkdir {
        path: Option<PathPtr>,
        mode: Mode,
    }
}

typed_syscall! {
    pub struct Rmdir {
        path: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Creat {
        path: Option<PathPtr>,
        mode: Mode,
    }
}

typed_syscall! {
    pub struct Link {
        oldpath: Option<PathPtr>,
        newpath: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Unlink {
        path: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Symlink {
        target: Option<PathPtr>,
        linkpath: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Readlink {
        path: Option<PathPtr>,
        // TODO: Replace this with a PathPtrMut
        buf: Option<AddrMut<libc::c_char>>,
        bufsize: usize,
    }
}

typed_syscall! {
    pub struct Chmod {
        path: Option<PathPtr>,
        mode: Mode,
    }
}

typed_syscall! {
    pub struct Fchmod {
        fd: i32,
        mode: Mode,
    }
}

typed_syscall! {
    pub struct Chown {
        path: Option<PathPtr>,
        owner: libc::uid_t,
        group: libc::gid_t,
    }
}

typed_syscall! {
    pub struct Fchown {
        fd: i32,
        owner: libc::uid_t,
        group: libc::gid_t,
    }
}

typed_syscall! {
    pub struct Lchown {
        path: Option<PathPtr>,
        owner: libc::uid_t,
        group: libc::gid_t,
    }
}

typed_syscall! {
    pub struct Umask {
        mask: Mode,
    }
}

typed_syscall! {
    pub struct Gettimeofday {
        tv: Option<AddrMut<Timeval>>,
        tz: Option<AddrMut<Timezone>>,
    }
}

typed_syscall! {
    pub struct Getrlimit {
        resource: i32,
        rlim: Option<AddrMut<libc::rlimit>>,
    }
}

typed_syscall! {
    pub struct Getrusage {
        who: i32,
        usage: Option<AddrMut<libc::rusage>>,
    }
}

typed_syscall! {
    pub struct Sysinfo {
        info: Option<AddrMut<libc::sysinfo>>,
    }
}

typed_syscall! {
    pub struct Times -> libc::clock_t {
        buf: Option<AddrMut<libc::tms>>,
    }
}

typed_syscall! {
    pub struct Ptrace {
        request: u32,
        pid: libc::pid_t,
        addr: Option<AddrMut<libc::c_void>>,
        data: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! { pub struct Getuid {} }

typed_syscall! {
    pub struct Syslog {
        priority: i32,
        buf: Option<Addr<libc::c_char>>,
        len: usize,
    }
}

typed_syscall! { pub struct Getgid {} }
typed_syscall! { pub struct Setuid { uid: libc::uid_t, } }
typed_syscall! { pub struct Setgid { uid: libc::gid_t, } }
typed_syscall! { pub struct Geteuid {} }
typed_syscall! { pub struct Getegid {} }
typed_syscall! { pub struct Setpgid { pid: libc::pid_t, pgid: libc::pid_t, } }
typed_syscall! { pub struct Getppid {} }
typed_syscall! { pub struct Getpgrp {} }

typed_syscall! { pub struct Setsid {} }
typed_syscall! { pub struct Setreuid { ruid: libc::uid_t, euid: libc::uid_t, } }
typed_syscall! { pub struct Setregid { rgid: libc::gid_t, egid: libc::gid_t, } }

typed_syscall! {
    pub struct Getgroups {
        // TODO: Make this a slice.
        size: i32,
        list: Option<AddrMut<libc::gid_t>>,
    }
}

typed_syscall! {
    pub struct Setgroups {
        // TODO: Make this a slice.
        size: usize,
        list: Option<Addr<libc::gid_t>>,
    }
}

typed_syscall! {
    pub struct Setresuid {
        ruid: libc::uid_t,
        euid: libc::uid_t,
        suid: libc::uid_t,
    }
}
typed_syscall! {
    pub struct Getresuid {
        ruid: Option<AddrMut<libc::gid_t>>,
        euid: Option<AddrMut<libc::gid_t>>,
        suid: Option<AddrMut<libc::gid_t>>,
    }
}
typed_syscall! {
    pub struct Setresgid {
        rgid: libc::gid_t,
        egid: libc::gid_t,
        sgid: libc::gid_t,
    }
}
typed_syscall! {
    pub struct Getresgid {
        rgid: Option<AddrMut<libc::gid_t>>,
        egid: Option<AddrMut<libc::gid_t>>,
        sgid: Option<AddrMut<libc::gid_t>>,
    }
}
typed_syscall! { pub struct Getpgid {} }
typed_syscall! { pub struct Setfsuid {} }
typed_syscall! { pub struct Setfsgid {} }
typed_syscall! { pub struct Getsid {} }

typed_syscall! {
    pub struct Capget {
        header: Option<AddrMut<libc::c_void>>,
        data: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Capset {
        header: Option<AddrMut<libc::c_void>>,
        data: Option<Addr<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct RtSigpending {
        set: Option<AddrMut<libc::sigset_t>>,
        /// Should always be 8 (`size_of::<u64>()`).
        sigsetsize: usize,
    }
}

typed_syscall! {
    pub struct RtSigtimedwait {
        set: Option<AddrMut<libc::sigset_t>>,
        info: Option<AddrMut<libc::siginfo_t>>,
        timeout: Option<Addr<Timespec>>,
        /// Should always be 8 (`size_of::<u64>()`).
        sigsetsize: usize,
    }
}

typed_syscall! {
    pub struct RtSigqueueinfo {
        tgid: libc::pid_t,
        sig: i32,
        siginfo: Option<AddrMut<libc::siginfo_t>>,
    }
}

typed_syscall! {
    pub struct RtSigsuspend {
        mask: Option<Addr<libc::sigset_t>>,
        /// Should always be 8 (`size_of::<u64>()`).
        sigsetsize: usize,
    }
}

typed_syscall! {
    pub struct Sigaltstack {
        ss: Option<Addr<libc::stack_t>>,
        old_ss: Option<AddrMut<libc::stack_t>>,
    }
}

typed_syscall! {
    pub struct Utime {
        path: Option<PathPtr>,
        times: Option<AddrMut<libc::utimbuf>>,
    }
}

typed_syscall! {
    pub struct Mknod {
        path: Option<PathPtr>,
        mode: Mode,
        dev: libc::dev_t,
    }
}

typed_syscall! {
    pub struct Uselib {
        library: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Personality {
        persona: u64,
    }
}

typed_syscall! {
    pub struct Ustat {
        dev: libc::dev_t,
        // TODO: Change this to libc::ustat if/when it exists.
        ubuf: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Statfs {
        path: Option<PathPtr>,
        buf: Option<AddrMut<libc::statfs>>,
    }
}

typed_syscall! {
    pub struct Fstatfs {
        fd: i32,
        buf: Option<AddrMut<libc::statfs>>,
    }
}

typed_syscall! {
    pub struct Sysfs {
        option: i32,
        arg1: u64,
        arg2: u64,
    }
}

typed_syscall! {
    pub struct Getpriority {
        which: i32,
        who: libc::id_t,
    }
}

typed_syscall! {
    pub struct Setpriority {
        which: i32,
        who: libc::id_t,
        prio: i32,
    }
}

typed_syscall! {
    pub struct SchedSetparam {
        pid: libc::pid_t,
        param: Option<Addr<libc::sched_param>>,
    }
}

typed_syscall! {
    pub struct SchedGetparam {
        pid: libc::pid_t,
        param: Option<AddrMut<libc::sched_param>>,
    }
}

typed_syscall! {
    pub struct SchedSetscheduler {
        pid: libc::pid_t,
        policy: i32,
        param: Option<Addr<libc::sched_param>>,
    }
}

typed_syscall! {
    pub struct SchedGetscheduler {
        pid: libc::pid_t,
    }
}

typed_syscall! {
    pub struct SchedGetPriorityMax {
        policy: i32,
    }
}

typed_syscall! {
    pub struct SchedGetPriorityMin {
        policy: i32,
    }
}

typed_syscall! {
    pub struct SchedRrGetInterval {
        pid: libc::pid_t,
        tp: Option<AddrMut<Timespec>>,
    }
}

typed_syscall! {
    pub struct Mlock {
        addr: Option<Addr<libc::c_void>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Munlock {
        addr: Option<Addr<libc::c_void>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Mlockall {
        flags: i32,
    }
}

typed_syscall! { pub struct Munlockall {} }

typed_syscall! { pub struct Vhangup {} }

typed_syscall! {
    pub struct ModifyLdt {
        func: i32,
        ptr: Option<AddrMut<libc::c_void>>,
        bytecount: u64,
    }
}

typed_syscall! {
    pub struct PivotRoot {
        new_root: Option<PathPtr>,
        put_old: Option<PathPtr>,
    }
}

typed_syscall! {
    #[allow(non_camel_case_types)]
    pub struct _sysctl {
        // TODO: Use _sysctl_args struct.
        args: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Prctl {
        option: i32,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    }
}

typed_syscall! {
    pub struct ArchPrctl {
        cmd: {
            fn get(&self) -> ArchPrctlCmd {
                ArchPrctlCmd::from_raw(self.raw.arg0 as i32, self.raw.arg1)
            }

            fn set(mut self, v: ArchPrctlCmd) -> Self {
                let (cmd, arg) = v.into_raw();
                self.raw.arg0 = cmd as u64;
                self.raw.arg1 = arg;
                self
            }
        },
    }
}

typed_syscall! {
    pub struct Adjtimex {
        buf: Option<AddrMut<libc::timex>>,
    }
}

typed_syscall! {
    pub struct Setrlimit {
        resource: i32,
        rlim: Option<Addr<libc::rlimit>>,
    }
}

typed_syscall! {
    pub struct Chroot {
        path: Option<PathPtr>,
    }
}

typed_syscall! { pub struct Sync {} }

typed_syscall! {
    pub struct Acct {
        filename: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Settimeofday {
        tv: Option<Addr<libc::timeval>>,
        tz: Option<Addr<libc::timezone>>,
    }
}

typed_syscall! {
    pub struct Mount {
        source: Option<PathPtr>,
        target: Option<PathPtr>,
        filesystemtype: Option<CStrPtr>,
        flags: u64,
        data: Option<Addr<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Umount2 {
        target: Option<PathPtr>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Swapon {
        path: Option<PathPtr>,
        swapflags: i32,
    }
}

typed_syscall! {
    pub struct Swapoff {
        path: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Reboot {
        magic1: i32,
        magic2: i32,
        cmd: u32,
        arg: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Sethostname {
        name: Option<Addr<libc::c_char>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Setdomainname {
        name: Option<Addr<libc::c_char>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct Iopl {
        level: u32,
    }
}

typed_syscall! {
    pub struct Ioperm {
        from: u64,
        num: u64,
        turn_on: i32,
    }
}

typed_syscall! {
    /// Note: This system call is present only in kernels before Linux 2.6.
    pub struct CreateModule {
        name: Option<Addr<libc::c_char>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct InitModule {
        module_image: Option<AddrMut<libc::c_void>>,
        len: usize,
        param_values: Option<CStrPtr>,
    }
}

typed_syscall! {
    pub struct DeleteModule {
        name: Option<CStrPtr>,
        flags: i32,
    }
}

typed_syscall! {
    /// Note: This system call is present only in kernels before Linux 2.6.
    pub struct GetKernelSyms {
        table: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct QueryModule {
        name: Option<CStrPtr>,
        which: i32,
        buf: Option<AddrMut<libc::c_void>>,
        bufsize: usize,
        ret: Option<AddrMut<usize>>,
    }
}

typed_syscall! {
    pub struct Quotactl {
        cmd: i32,
        special: Option<CStrPtr>,
        id: i32,
        addr: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    /// Note: Since Linux 3.1, this system call no longer exists. It has been
    /// replaced by a set of files in the nfsd filesystem; see `nfsd(7)`.
    pub struct Nfsservctl {
        cmd: i32,
        argp: Option<AddrMut<libc::c_void>>,
        resp: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Getpmsg {}
}

typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Putpmsg {}
}

typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct AfsSyscall {}
}

typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Tuxcall {}
}

typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Security {}
}

typed_syscall! { pub struct Gettid {} }

typed_syscall! {
    pub struct Readahead {
        fd: i32,
        offset: libc::loff_t,
        count: usize,
    }
}

typed_syscall! {
    pub struct Setxattr {
        path: Option<PathPtr>,
        name: Option<CStrPtr>,
        value: Option<Addr<libc::c_void>>,
        size: usize,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Lsetxattr {
        path: Option<PathPtr>,
        name: Option<CStrPtr>,
        value: Option<Addr<libc::c_void>>,
        size: usize,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Fsetxattr {
        fd: i32,
        name: Option<CStrPtr>,
        value: Option<Addr<libc::c_void>>,
        size: usize,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Getxattr {
        path: Option<PathPtr>,
        name: Option<CStrPtr>,
        value: Option<AddrMut<libc::c_void>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Lgetxattr {
        path: Option<PathPtr>,
        name: Option<CStrPtr>,
        value: Option<AddrMut<libc::c_void>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Fgetxattr {
        fd: i32,
        name: Option<CStrPtr>,
        value: Option<AddrMut<libc::c_void>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Listxattr {
        path: Option<PathPtr>,
        list: Option<AddrMut<libc::c_char>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Llistxattr {
        path: Option<PathPtr>,
        list: Option<AddrMut<libc::c_char>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Flistxattr {
        fd: i32,
        list: Option<AddrMut<libc::c_char>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct Removexattr {
        path: Option<PathPtr>,
        name: Option<CStrPtr>,
    }
}

typed_syscall! {
    pub struct Lremovexattr {
        path: Option<PathPtr>,
        name: Option<CStrPtr>,
    }
}

typed_syscall! {
    pub struct Fremovexattr {
        fd: i32,
        name: Option<CStrPtr>,
    }
}

typed_syscall! {
    pub struct Tkill {
        tid: libc::pid_t,
        sig: libc::c_int,
    }
}

typed_syscall! {
    pub struct Time {
        tloc: Option<AddrMut<libc::time_t>>,
    }
}

typed_syscall! {
    // TODO: Wrap each futex operation in a type, similar to fcntl and ioctl.
    pub struct Futex {
        uaddr: Option<AddrMut<libc::c_int>>,
        futex_op: libc::c_int,
        val: libc::c_int,
        timeout: Option<Addr<Timespec>>,
        uaddr2: Option<AddrMut<libc::c_int>>,
        val3: libc::c_int,
    }
}

typed_syscall! {
    pub struct SchedSetaffinity {
        pid: libc::pid_t,
        len: u32,
        mask: Option<Addr<libc::c_ulong>>,
    }
}

typed_syscall! {
    pub struct SchedGetaffinity {
        pid: libc::pid_t,
        len: u32,
        mask: Option<AddrMut<libc::c_ulong>>,
    }
}

typed_syscall! {
    pub struct SetThreadArea {
        addr: Option<Addr<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct IoSetup {
        nr_events: u32,
        context: Option<AddrMut<libc::c_ulong>>,
    }
}

typed_syscall! {
    pub struct IoDestroy {
        context: libc::c_ulong,
    }
}

typed_syscall! {
    pub struct IoGetevents {
        context: libc::c_ulong,
        min_nr: libc::c_long,
        nr: libc::c_long,
        // FIXME: This should be a pointer to an `io_event`.
        events: Option<AddrMut<libc::c_void>>,
        timeout: Option<Addr<Timespec>>,
    }
}

typed_syscall! {
    pub struct IoSubmit {
        context: libc::c_ulong,
        nr: libc::c_long,
        // FIXME: This should be a pointer to a pointer of `iocb`.
        iocb: Option<AddrMut<AddrMut<libc::c_void>>>,
    }
}

typed_syscall! {
    pub struct IoCancel {
        context: libc::c_ulong,
        iocb: Option<AddrMut<libc::c_void>>,
        // FIXME: This should be a pointer to an `io_event`.
        result: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct GetThreadArea {
        addr: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct LookupDcookie {
        cookie: u64,
        buf: Option<AddrMut<libc::c_char>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct EpollCreate {
        /// The kernel doesn't actually use this parameter, but it must be
        /// greater than 0. (It was used as a size hint at one point in time.)
        size: i32,
    }
}

typed_syscall! {
    /// Undocumented.
    pub struct EpollCtlOld {}
}

typed_syscall! {
    /// Undocumented.
    pub struct EpollWaitOld {}
}

typed_syscall! {
    pub struct RemapFilePages {
        addr: Option<AddrMut<libc::c_void>>,
        size: u64,
        prot: i32,
        pgoff: usize,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Getdents64 {
        fd: u32,
        dirent: Option<AddrMut<libc::dirent64>>,
        count: u32,
    }
}

typed_syscall! {
    pub struct SetTidAddress {
        tidptr: Option<AddrMut<libc::c_int>>,
    }
}

typed_syscall! { pub struct RestartSyscall { } }

typed_syscall! {
    pub struct Semtimedop {
        semid: i32,
        tsops: Option<AddrMut<libc::sembuf>>,
        nsops: u32,
        timeout: Option<Addr<Timespec>>,
    }
}

typed_syscall! {
    pub struct Fadvise64 {
        fd: i32,
        offset: libc::loff_t,
        len: usize,
        advice: i32,
    }
}

typed_syscall! {
    pub struct TimerCreate {
        clockid: ClockId,
        sevp: Option<AddrMut<libc::sigevent>>,
        timerid: Option<AddrMut<libc::c_int>>,
    }
}

typed_syscall! {
    pub struct TimerSettime {
        timerid: libc::c_int,
        flags: i32,
        new_value: Option<Addr<libc::itimerspec>>,
        old_value: Option<AddrMut<libc::itimerspec>>,
    }
}

typed_syscall! {
    pub struct TimerGettime {
        timerid: libc::c_int,
        value: Option<AddrMut<libc::itimerspec>>,
    }
}

typed_syscall! {
    pub struct TimerGetoverrun {
        timerid: libc::c_int,
    }
}

typed_syscall! {
    pub struct TimerDelete {
        timerid: libc::c_int,
    }
}

typed_syscall! {
    pub struct ClockSettime {
        clockid: ClockId,
        tp: Option<Addr<Timespec>>,
    }
}

typed_syscall! {
    pub struct ClockGettime {
        clockid: ClockId,
        tp: Option<AddrMut<Timespec>>,
    }
}

typed_syscall! {
    pub struct ClockGetres {
        clockid: ClockId,
        res: Option<AddrMut<Timespec>>,
    }
}

typed_syscall! {
    pub struct ClockNanosleep {
        clockid: ClockId,
        flags: i32,
        req: Option<Addr<Timespec>>,
        rem: Option<AddrMut<Timespec>>,
    }
}

typed_syscall! {
    pub struct ExitGroup {
        status: libc::c_int,
    }
}

typed_syscall! {
    pub struct EpollWait {
        epfd: i32,
        events: Option<AddrMut<libc::epoll_event>>,
        maxevents: i32,
        timeout: i32, // Milliseconds.
    }
}

typed_syscall! {
    pub struct EpollCtl {
        epfd: i32,
        op: i32,
        fd: i32,
        event: Option<AddrMut<libc::epoll_event>>,
    }
}

typed_syscall! {
    pub struct Tgkill {
        tgid: libc::pid_t,
        tid: libc::pid_t,
        sig: libc::c_int,
    }
}

typed_syscall! {
    pub struct Utimes {
        filename: Option<PathPtr>,
        times: Option<Addr<[libc::timeval; 2]>>,
    }
}

typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Vserver { }
}

typed_syscall! {
    pub struct Mbind {
        addr: Option<AddrMut<libc::c_void>>,
        len: u64,
        mode: i32,
        nodemask: Option<Addr<libc::c_ulong>>,
        maxnode: u64,
        flags: u32,
    }
}

typed_syscall! {
    pub struct SetMempolicy {
        mode: i32,
        nodemask: Option<Addr<libc::c_ulong>>,
        maxnode: u64,
    }
}

typed_syscall! {
    pub struct GetMempolicy {
        policy: Option<AddrMut<libc::c_int>>,
        nodemask: Option<Addr<libc::c_ulong>>,
        maxnode: u64,
        addr: Option<Addr<libc::c_void>>,
        flags: u32,
    }
}

typed_syscall! {
    pub struct MqOpen {
        name: Option<PathPtr>,
        oflag: i32,
        mode: libc::mode_t,
        attr: Option<AddrMut<libc::mq_attr>>,
    }
}

typed_syscall! {
    pub struct MqUnlink {
        name: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct MqTimedsend {
        mqdes: libc::mqd_t,
        msg: Option<Addr<libc::c_char>>,
        msg_len: usize,
        priority: u32,
        timeout: Option<Addr<Timespec>>,
    }
}

typed_syscall! {
    pub struct MqTimedreceive {
        mqdes: libc::mqd_t,
        msg: Option<AddrMut<libc::c_char>>,
        msg_len: usize,
        priority: u32,
        timeout: Option<Addr<Timespec>>,
    }
}

typed_syscall! {
    pub struct MqNotify {
        mqdes: libc::mqd_t,
        sevp: Option<Addr<libc::sigevent>>,
    }
}

typed_syscall! {
    pub struct MqGetsetattr {
        mqdes: libc::mqd_t,
        newattr: Option<Addr<libc::mq_attr>>,
        oldattr: Option<AddrMut<libc::mq_attr>>,
    }
}

typed_syscall! {
    pub struct KexecLoad {
        entry: u64,
        nr_segments: u64,
        // FIXME: This should be a pointer to `kexec_segment`.
        segments: Option<Addr<libc::c_void>>,
        flags: u64,
    }
}

typed_syscall! {
    pub struct Waitid {
        which: i32,
        pid: libc::pid_t,
        info: Option<AddrMut<libc::siginfo_t>>,
        options: i32,
        rusage: Option<AddrMut<libc::rusage>>,
    }
}

typed_syscall! {
    pub struct AddKey {
        key_type: Option<CStrPtr>,
        description: Option<CStrPtr>,
        payload: Option<Addr<libc::c_void>>,
        payload_len: usize,
        keyring: libc::c_int,
    }
}

typed_syscall! {
    pub struct RequestKey {
        key_type: Option<CStrPtr>,
        description: Option<CStrPtr>,
        callout_info: Option<CStrPtr>,
        dest_keyring: libc::c_int,
    }
}

typed_syscall! {
    pub struct Keyctl {
        option: i32,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg6: u64,
    }
}

typed_syscall! {
    pub struct IoprioSet {
        which: i32,
        who: i32,
        priority: i32,
    }
}

typed_syscall! {
    pub struct IoprioGet {
        which: i32,
        who: i32,
    }
}

typed_syscall! { pub struct InotifyInit {} }

typed_syscall! {
    pub struct InotifyAddWatch {
        fd: i32,
        path: Option<PathPtr>,
        mask: u32,
    }
}

typed_syscall! {
    pub struct InotifyRmWatch {
        fd: i32,
        wd: i32,
    }
}

typed_syscall! {
    pub struct MigratePages {
        pid: libc::pid_t,
        maxnode: u64,
        old_nodes: Option<Addr<libc::c_ulong>>,
        new_nodes: Option<Addr<libc::c_ulong>>,
    }
}

typed_syscall! {
    pub struct Openat {
        dirfd: i32,
        path: Option<PathPtr>,
        flags: OFlag,

        /// The mode is only present when `O_CREAT` or `O_TMPFILE` is specified
        /// in the flags. It is ignored otherwise.
        mode?: {
            fn get(&self) -> Option<Mode> {
                get_mode(self.flags(), self.raw.arg3)
            }

            fn set(mut self, v: Mode) -> Self {
                self.raw.arg3 = v.into_raw();
                self
            }
        },
    }
}

impl From<Open> for Openat {
    /// An `open` syscall can be trivially transformed into an `openat`
    /// syscall by shifting all the arguments to the right and setting the first
    /// argument to `AT_FDCWD` (the current working directory).
    fn from(open: Open) -> Self {
        let Open { mut raw } = open;
        raw.arg3 = raw.arg2;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Openat { raw }
    }
}

impl From<Creat> for Openat {
    /// A call to creat() is equivalent to calling open() with flags equal to
    /// O_CREAT|O_WRONLY|O_TRUNC
    fn from(creat: Creat) -> Self {
        let Creat { mut raw } = creat;
        raw.arg3 = raw.arg1;
        raw.arg2 = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Openat { raw }
    }
}

typed_syscall! {
    pub struct Mkdirat {
        dirfd: i32,
        path: Option<PathPtr>,
        mode: Mode,
    }
}

impl From<Mkdir> for Mkdirat {
    /// An `mkdir` syscall can be trivially transformed into a `mkdirat` syscall
    /// by shifting all the arguments to the right and setting the first argument
    /// to `AT_FDCWD` (the current working directory).
    fn from(syscall: Mkdir) -> Self {
        let Mkdir { mut raw } = syscall;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Mkdirat { raw }
    }
}

typed_syscall! {
    pub struct Mknodat {
        dirfd: i32,
        path: Option<PathPtr>,
        mode: Mode,
        dev: libc::dev_t,
    }
}

impl From<Mknod> for Mknodat {
    /// An `mknod` syscall can be trivially transformed into an `mknodat` syscall
    /// by shifting all the arguments to the right and setting the first argument
    /// to `AT_FDCWD` (the current working directory).
    fn from(syscall: Mknod) -> Self {
        let Mknod { mut raw } = syscall;
        raw.arg3 = raw.arg2;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Mknodat { raw }
    }
}

typed_syscall! {
    pub struct Fchownat {
        dirfd: i32,
        path: Option<PathPtr>,
        owner: libc::uid_t,
        group: libc::gid_t,
        flags: AtFlags,
    }
}

typed_syscall! {
    pub struct Futimesat {
        dirfd: i32,
        path: Option<PathPtr>,
        utimes: Option<Addr<[libc::timeval; 2]>>,
    }
}

typed_syscall! {
    pub struct Newfstatat {
        dirfd: i32,
        path: Option<PathPtr>,
        stat: Option<StatPtr>,
        flags: AtFlags,
    }
}

impl From<Stat> for Newfstatat {
    fn from(stat: Stat) -> Self {
        let Stat { mut raw } = stat;
        raw.arg3 = 0;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Newfstatat { raw }
    }
}

impl From<Lstat> for Newfstatat {
    fn from(lstat: Lstat) -> Self {
        let Lstat { mut raw } = lstat;
        raw.arg3 = AtFlags::AT_SYMLINK_NOFOLLOW.bits() as u64;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Newfstatat { raw }
    }
}

typed_syscall! {
    pub struct Unlinkat {
        dirfd: i32,
        path: Option<PathPtr>,
        flags: AtFlags,
    }
}

impl From<Unlink> for Unlinkat {
    fn from(unlink: Unlink) -> Self {
        let Unlink { mut raw } = unlink;
        raw.arg2 = 0;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Unlinkat { raw }
    }
}

impl From<Rmdir> for Unlinkat {
    fn from(rmdir: Rmdir) -> Self {
        let Rmdir { mut raw } = rmdir;
        raw.arg2 = libc::AT_REMOVEDIR as u64;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Unlinkat { raw }
    }
}

typed_syscall! {
    pub struct Renameat {
        olddirfd: i32,
        oldpath: Option<PathPtr>,
        newdirfd: i32,
        newpath: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Linkat {
        olddirfd: i32,
        oldpath: Option<PathPtr>,
        newdirfd: i32,
        newpath: Option<PathPtr>,
        flags: AtFlags,
    }
}

impl From<Link> for Linkat {
    /// A `link` syscall can be trivially transformed into a `linkat` syscall
    /// by rearranging the `oldpath` and `newpath` arguments,
    /// setting both old and new directory file descriptors to the special value
    /// `AT_FDCWD` (indicating the current working directory),
    /// and clearing the flags.
    fn from(link: Link) -> Self {
        let Link { mut raw } = link;
        raw.arg3 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        raw.arg2 = libc::AT_FDCWD as u64;
        raw.arg4 = 0;
        Linkat { raw }
    }
}

typed_syscall! {
    pub struct Symlinkat {
        target: Option<PathPtr>,
        newdirfd: i32,
        linkpath: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Readlinkat {
        dirfd: i32,
        path: Option<PathPtr>,
        buf: Option<AddrMut<libc::c_char>>,
        buf_len: usize,
    }
}

typed_syscall! {
    pub struct Fchmodat {
        dirfd: i32,
        path: Option<PathPtr>,
        mode: Mode,
        flags: AtFlags,
    }
}

typed_syscall! {
    pub struct Faccessat {
        dirfd: i32,
        path: Option<PathPtr>,
        mode: Mode,
        flags: AtFlags,
    }
}

typed_syscall! {
    pub struct Pselect6 {
        nfds: i32,
        readfds: Option<AddrMut<libc::fd_set>>,
        writefds: Option<AddrMut<libc::fd_set>>,
        exceptfds: Option<AddrMut<libc::fd_set>>,
        timeout: Option<Addr<libc::timeval>>,
        sigmask: Option<Addr<libc::sigset_t>>,
    }
}

typed_syscall! {
    pub struct Ppoll {
        fds: Option<AddrMut<libc::pollfd>>,
        nfds: libc::nfds_t,
        timeout: Option<Addr<libc::timeval>>,
        sigmask: Option<Addr<libc::sigset_t>>,
        sigsetsize: usize,
    }
}

typed_syscall! {
    pub struct Unshare {
        flags: CloneFlags,
    }
}

typed_syscall! {
    pub struct SetRobustList {
        // FIXME: This should be pointer to `robust_list_head`.
        head: Option<AddrMut<libc::c_void>>,
        len: usize,
    }
}

typed_syscall! {
    pub struct GetRobustList {
        pid: libc::pid_t,
        // FIXME: This should be pointer to `robust_list_head`.
        head_ptr: Option<AddrMut<AddrMut<libc::c_void>>>,
        len_ptr: Option<AddrMut<usize>>,
    }
}

typed_syscall! {
    pub struct Splice {
        fd_in: i32,
        off_in: Option<AddrMut<libc::loff_t>>,
        fd_out: i32,
        off_out: Option<AddrMut<libc::loff_t>>,
        len: usize,
        flags: u32,
    }
}

typed_syscall! {
    pub struct Tee {
        fd_in: i32,
        fd_out: i32,
        len: usize,
        flags: u32,
    }
}

typed_syscall! {
    pub struct SyncFileRange {
        fd: i32,
        offset: libc::loff_t,
        nbytes: libc::loff_t,
        flags: u32,
    }
}

typed_syscall! {
    pub struct Vmsplice {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        nr_segs: u64,
        flags: u32,
    }
}

typed_syscall! {
    pub struct MovePages {
        pid: libc::pid_t,
        nr_pages: u64,
        pages: Option<Addr<Addr<libc::c_void>>>,
        nodes: Option<Addr<Addr<i32>>>,
        status: Option<AddrMut<i32>>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Utimensat {
        dirfd: i32,
        path: Option<PathPtr>,
        times: Option<Addr<[Timespec; 2]>>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct EpollPwait {
        epfd: i32,
        events: Option<AddrMut<libc::epoll_event>>,
        maxevents: i32,
        timeout: i32,
        sigmask: Option<Addr<libc::sigset_t>>,
        sigsetsize: usize,
    }
}

typed_syscall! {
    /// Naked signalfd(2) is not the same as glibc wrapper.
    /// see kernel fs/signalfd.c for more details.
    /// NB: kernel_sigset_t is 8 bytes (sizeof usize), we still use
    /// libc::sigset_t here because kernel access only the 1st 8 bytes.
    /// NB2: glibc wrapper will call signalfd4(2) instead, this this
    /// syscall is only possible when user calls libc::syscall directly.
    pub struct Signalfd {
        fd: i32,
        mask: Option<AddrMut<libc::sigset_t>>,
        size: usize,
    }
}

typed_syscall! {
    pub struct TimerfdCreate {
        clockid: ClockId,
        flags: TimerFlags,
    }
}

typed_syscall! {
    pub struct Eventfd {
        count: u32,
    }
}

typed_syscall! {
    pub struct Fallocate {
        fd: i32,
        mode: i32,
        offset: libc::loff_t,
        len: libc::loff_t,
    }
}

typed_syscall! {
    pub struct TimerfdSettime {
        fd: i32,
        flags: i32,
        new_value: Option<Addr<libc::itimerspec>>,
        old_value: Option<AddrMut<libc::itimerspec>>,
    }
}

typed_syscall! {
    pub struct TimerfdGettime {
        fd: i32,
        value: Option<AddrMut<libc::itimerspec>>,
    }
}

typed_syscall! {
    pub struct Accept4 {
        sockfd: i32,
        sockaddr: Option<AddrMut<libc::sockaddr>>,
        addrlen: Option<AddrMut<usize>>,
        flags: SockFlag,
    }
}

impl From<Accept> for Accept4 {
    /// If flags is 0, then accept4() is the same as accept().
    fn from(accept: Accept) -> Self {
        let Accept { mut raw } = accept;
        raw.arg3 = 0;
        Accept4 { raw }
    }
}

typed_syscall! {
    /// Naked signalfd4(2) is not the same as glibc wrapper.
    /// see kernel fs/signalfd.c for more details.
    /// NB: kernel_sigset_t is 8 bytes (sizeof usize), we still use
    /// libc::sigset_t here because kernel access only the 1st 8 bytes.
    pub struct Signalfd4 {
        fd: i32,
        mask: Option<AddrMut<libc::sigset_t>>,
        size: usize,
        flags: SfdFlags,
    }
}

impl From<Signalfd> for Signalfd4 {
    fn from(signalfd: Signalfd) -> Self {
        let Signalfd { mut raw } = signalfd;
        raw.arg3 = 0;
        Signalfd4 { raw }
    }
}

typed_syscall! {
    pub struct Eventfd2 {
        count: u32,
        flags: EfdFlags,
    }
}

impl From<Eventfd> for Eventfd2 {
    /// eventfd2 provide an extra `flags' argument, it's safe
    /// to convert eventfd(2) to eventfd2(2), as a result.
    /// glibc should have wrapped all eventfd syscall into eventfd2.
    fn from(eventfd: Eventfd) -> Self {
        let Eventfd { mut raw } = eventfd;
        raw.arg1 = 0;
        Eventfd2 { raw }
    }
}

typed_syscall! {
    pub struct EpollCreate1 {
        flags: EpollCreateFlags,
    }
}

impl From<EpollCreate> for EpollCreate1 {
    /// `size' in epoll_create(2) is ignored but must be >= 0 since 2.6.9
    /// We still allows convert `epoll_create` to `epoll_create1` by forcing
    /// `flags` to 0. This could have changed behavior when calling
    /// `epoll_create(-1)` but shouldn't be a real concern in practice.
    fn from(epoll_create: EpollCreate) -> Self {
        let EpollCreate { mut raw } = epoll_create;
        raw.arg0 = 0;
        EpollCreate1 { raw }
    }
}

typed_syscall! {
    pub struct Dup3 {
        oldfd: i32,
        newfd: i32,
        flags: OFlag,
    }
}

typed_syscall! {
    pub struct Pipe2 {
        pipefd: Option<AddrMut<[i32; 2]>>,
        flags: OFlag,
    }
}

impl From<Pipe> for Pipe2 {
    /// If flags is 0, then pipe2() is the same as pipe().
    fn from(pipe: Pipe) -> Self {
        let Pipe { mut raw } = pipe;
        raw.arg1 = 0;
        Pipe2 { raw }
    }
}

typed_syscall! {
    pub struct InotifyInit1 {
        flags: InitFlags,
    }
}

impl From<InotifyInit> for InotifyInit1 {
    /// If flags is 0, then inotify_init1 is the same as inotify_init.
    /// Note that inotify_init was introduced in 2.6.13 and inotify_init1
    /// was added in 2.6.27.
    fn from(inotify_init: InotifyInit) -> Self {
        let InotifyInit { mut raw } = inotify_init;
        raw.arg0 = 0;
        InotifyInit1 { raw }
    }
}

typed_syscall! {
    pub struct Preadv {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        iov_len: usize,
        pos_l: u64,
        pos_h: u64,
    }
}

typed_syscall! {
    pub struct Pwritev {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        iov_len: usize,
        pos_l: u64,
        pos_h: u64,
    }
}

typed_syscall! {
    pub struct RtTgsigqueueinfo {
        tgid: libc::pid_t,
        tid: libc::pid_t,
        sig: i32,
        siginfo: Option<AddrMut<libc::siginfo_t>>,
    }
}

typed_syscall! {
    pub struct PerfEventOpen {
        // FIXME: This should be a pointer to `perf_event_attr`.
        attr: Option<AddrMut<libc::c_void>>,
        pid: libc::pid_t,
        cpu: i32,
        group_fd: i32,
        flags: u64,
    }
}

typed_syscall! {
    pub struct Recvmmsg {
        fd: i32,
        mmsg: Option<AddrMut<libc::mmsghdr>>,
        vlen: u32,
        flags: u32,
        timeout: Option<Addr<Timespec>>,
    }
}

typed_syscall! {
    pub struct FanotifyInit {
        flags: u32,
        event_f_flags: u32,
    }
}

typed_syscall! {
    pub struct FanotifyMark {
        fanotify_fd: i32,
        flags: u32,
        mask: u64,
        dirfd: i32,
        pathname: Option<PathPtr>,
    }
}

typed_syscall! {
    pub struct Prlimit64 {
        pid: libc::pid_t,
        resource: u32,
        new_rlim: Option<Addr<libc::rlimit64>>,
        old_rlim: Option<AddrMut<libc::rlimit64>>,
    }
}

typed_syscall! {
    pub struct NameToHandleAt {
        dirfd: i32,
        pathname: Option<PathPtr>,
        // FIXME: This should be a pointer to `file_handle`.
        handle: Option<AddrMut<libc::c_void>>,
        mount_id: Option<AddrMut<i32>>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct OpenByHandleAt {
        mount_fd: i32,
        // FIXME: This should be a pointer to `file_handle`.
        handle: Option<AddrMut<libc::c_void>>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct ClockAdjtime {
        clockid: ClockId,
        buf: Option<AddrMut<libc::timex>>,
    }
}

typed_syscall! {
    pub struct Syncfs {
        fd: i32,
    }
}

typed_syscall! {
    pub struct Sendmmsg {
        sockfd: i32,
        msgvec: Option<Addr<libc::msghdr>>,
        vlen: u32,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Setns {
        fd: i32,
        nstype: CloneFlags,
    }
}

// NB: getcpu_cache (third argument) is unused in kernel >= 2.6.23 should be
// always NULL.
typed_syscall! {
    pub struct Getcpu {
        cpu: Option<AddrMut<u32>>,
        node: Option<AddrMut<u32>>,
    }
}

typed_syscall! {
    pub struct ProcessVmReadv {
        pid: libc::pid_t,
        local_iov: Option<Addr<libc::iovec>>,
        local_iov_count: u64,
        remote_iov: Option<Addr<libc::iovec>>,
        remote_iov_count: u64,
        flags: u64,
    }
}

typed_syscall! {
    pub struct ProcessVmWritev {
        pid: libc::pid_t,
        local_iov: Option<Addr<libc::iovec>>,
        local_iov_count: u64,
        remote_iov: Option<Addr<libc::iovec>>,
        remote_iov_count: u64,
        flags: u64,
    }
}

typed_syscall! {
    pub struct Kcmp {
        pid1: libc::pid_t,
        pid2: libc::pid_t,
        typ: i32,
        idx1: u64,
        idx2: u64,
    }
}

typed_syscall! {
    pub struct FinitModule {
        fd: i32,
        param_values: Option<CStrPtr>,
        flags: i32,
    }
}

typed_syscall! {
    pub struct SchedSetattr {
        pid: libc::pid_t,
        attr: Option<AddrMut<libc::c_void /* sched_attr */>>,
        flags: u32,
    }
}

typed_syscall! {
    pub struct SchedGetattr {
        pid: libc::pid_t,
        // FIXME: This should be a pointer to a `sched_attr`.
        attr: Option<AddrMut<libc::c_void>>,
        size: u32,
        flags: u32,
    }
}

typed_syscall! {
    pub struct Renameat2 {
        olddirfd: i32,
        oldpath: Option<PathPtr>,
        newdirfd: i32,
        newpath: Option<PathPtr>,
        // TODO: Make some `RENAME_*` bitflags to cover this.
        flags: libc::c_uint,
    }
}

impl From<Rename> for Renameat2 {
    fn from(rename: Rename) -> Self {
        let Rename { mut raw } = rename;
        raw.arg4 = 0;
        raw.arg3 = raw.arg1;
        raw.arg2 = libc::AT_FDCWD as u64;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Renameat2 { raw }
    }
}

impl From<Renameat> for Renameat2 {
    fn from(renameat: Renameat) -> Self {
        let Renameat { mut raw } = renameat;
        raw.arg4 = 0;
        Renameat2 { raw }
    }
}

typed_syscall! {
    pub struct Seccomp {
        op: u32,
        flags: u32,
        args: Option<AddrMut<libc::c_void>>,
    }
}

typed_syscall! {
    pub struct Getrandom {
        /// The buffer should never be NULL (None), or this represents an invalid call when passed
        /// to the kernel.  Nevertheless, we retain the ability here to represent that invalid call.
        buf: Option<AddrMut<u8>>,
        buflen: usize,
        flags: usize,
    }
}

typed_syscall! {
    pub struct MemfdCreate {
        name: Option<PathPtr>,
        flags: u32,
    }
}

typed_syscall! {
    pub struct KexecFileLoad {
        kernel_fd: i32,
        initrd_fd: i32,
        cmdline_len: u64,
        cmdline: Option<Addr<libc::c_char>>,
        flags: u64,
    }
}

typed_syscall! {
    pub struct Bpf {
        cmd: i32,
        attr: Option<AddrMut<libc::c_void /* bpf_attr */>>,
        size: u32,
    }
}

typed_syscall! {
    pub struct Execveat {
        dirfd: i32,
        path: Option<PathPtr>,
        argv: Option<CArrayPtr<CStrPtr>>,
        envp: Option<CArrayPtr<CStrPtr>>,
        flags: i32,
    }
}

impl From<Execve> for Execveat {
    /// An `execve` syscall can be trivially transformed into an `execveat`
    /// syscall by shifting all the arguments to the right and setting the first
    /// argument to `AT_FDCWD` (the current working directory).
    fn from(execve: Execve) -> Self {
        let Execve { mut raw } = execve;
        raw.arg4 = 0; // flags
        raw.arg3 = raw.arg2;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as u64;
        Execveat { raw }
    }
}

typed_syscall! {
    pub struct Userfaultfd {
        flags: i32,
    }
}

typed_syscall! {
    pub struct Membarrier {
        cmd: i32,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Mlock2 {
        addr: Option<Addr<libc::c_void>>,
        len: usize,
        flags: i32,
    }
}

typed_syscall! {
    pub struct CopyFileRange {
        fd_in: i32,
        off_in: Option<AddrMut<libc::loff_t>>,
        fd_out: i32,
        off_out: Option<AddrMut<libc::loff_t>>,
        len: usize,
        flags: u32,
    }
}

typed_syscall! {
    pub struct Preadv2 {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        iov_len: u64,
        pos_l: u64,
        pos_h: u64,
        flags: i32,
    }
}

typed_syscall! {
    pub struct Pwritev2 {
        fd: i32,
        iov: Option<Addr<libc::iovec>>,
        iov_len: u64,
        pos_l: u64,
        pos_h: u64,
        flags: i32,
    }
}

typed_syscall! {
    pub struct PkeyMprotect {
        addr: Option<AddrMut<libc::c_void>>,
        len: usize,
        prot: i32,
        pkey: i32,
    }
}

typed_syscall! {
    pub struct PkeyAlloc {
        flags: u64,
        access_rights: u64,
    }
}

typed_syscall! {
    pub struct PkeyFree {
        pkey: i32,
    }
}

typed_syscall! {
    pub struct Statx {
        dirfd: i32,
        path: Option<PathPtr>,
        flags: AtFlags,
        mask: StatxMask,
        statx: Option<StatxPtr>,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Displayable, LocalMemory, ReadAddr};

    use std::{ffi::CString, path::Path};

    use syscalls::{SyscallArgs, Sysno};

    #[test]
    fn test_syscall_open() {
        assert_eq!(Open::NAME, "open");
        assert_eq!(Open::NUMBER, Sysno::open);

        let name = CString::new("/some/file/path").unwrap();

        let syscall = Open::new()
            .with_path(PathPtr::from_ptr(name.as_ptr()))
            .with_flags(OFlag::O_RDONLY | OFlag::O_APPEND)
            .with_mode(Some(Mode::from_bits_truncate(0o644)));

        assert_eq!(Open::from(SyscallArgs::from(syscall)), syscall);

        let memory = LocalMemory::new();

        assert_eq!(
            syscall.path().unwrap().read(&memory).unwrap(),
            Path::new("/some/file/path")
        );

        assert_eq!(
            format!("{}", syscall.display(&memory)),
            format!("open({:p} -> \"/some/file/path\", O_APPEND)", name.as_ptr())
        );
    }

    #[test]
    fn test_syscall_openat() {
        assert_eq!(Openat::NAME, "openat");
        assert_eq!(Openat::NUMBER, Sysno::openat);

        let memory = LocalMemory::new();

        assert_eq!(
            format!(
                "{}",
                Openat::new()
                    .with_dirfd(-100)
                    .with_path(None)
                    .with_flags(OFlag::O_APPEND)
                    .display(&memory)
            ),
            "openat(-100, NULL, O_APPEND)"
        );

        assert_eq!(
            format!(
                "{}",
                Openat::new()
                    .with_dirfd(-100)
                    .with_path(None)
                    .with_flags(OFlag::O_CREAT)
                    .with_mode(Mode::from_bits_truncate(0o644))
                    .display(&memory)
            ),
            "openat(-100, NULL, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)"
        );

        assert_eq!(
            format!(
                "{}",
                Openat::new()
                    .with_dirfd(-100)
                    .with_path(None)
                    .with_flags(OFlag::O_TMPFILE)
                    .with_mode(Mode::from_bits_truncate(0o600))
                    .display(&memory)
            ),
            "openat(-100, NULL, O_DIRECTORY | O_TMPFILE, S_IRUSR | S_IWUSR)"
        );

        assert_eq!(
            Openat::new()
                .with_dirfd(libc::AT_FDCWD)
                .with_path(None)
                .with_flags(OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_TRUNC)
                .with_mode(Mode::from_bits_truncate(0o600)),
            Creat::new()
                .with_path(None)
                .with_mode(Mode::from_bits_truncate(0o600))
                .into()
        );
    }

    #[test]
    fn test_syscall_stat() {
        let name = CString::new("/dev/null").unwrap();

        let stat = nix::sys::stat::stat("/dev/null").unwrap();

        let syscall = Stat::new()
            .with_path(PathPtr::from_ptr(name.as_ptr()))
            .with_stat(StatPtr::from_ptr(&stat as *const libc::stat));

        let memory = LocalMemory::new();

        assert_eq!(
            format!("{}", syscall.display_with_outputs(&memory)),
            format!(
                "stat({:p} -> \"/dev/null\", {:p} -> {{st_mode=S_IFCHR | 0666, st_size=0, ...}})",
                name.as_ptr(),
                &stat as *const _
            )
        );
    }

    #[test]
    fn test_syscall_fcntl() {
        let memory = LocalMemory::new();

        assert_eq!(
            format!(
                "{}",
                Fcntl::new()
                    .with_fd(1)
                    .with_cmd(FcntlCmd::F_DUPFD(2))
                    .display(&memory)
            ),
            "fcntl(1, F_DUPFD, 2)"
        );
    }

    #[test]
    fn test_syscall_pipe2() {
        let memory: Option<AddrMut<[i32; 2]>> = AddrMut::from_raw(0x1245);

        assert_eq!(
            Pipe2::new().with_pipefd(memory),
            Pipe::new().with_pipefd(memory).into()
        );

        assert_ne!(
            Pipe2::new()
                .with_pipefd(memory)
                .with_flags(OFlag::O_CLOEXEC),
            Pipe::new().with_pipefd(memory).into()
        );
    }

    #[test]
    fn test_syscall_linkat() {
        let foo = CString::new("foo").unwrap();
        let bar = CString::new("bar").unwrap();

        assert_eq!(
            Linkat::new()
                .with_olddirfd(libc::AT_FDCWD)
                .with_oldpath(PathPtr::from_ptr(foo.as_ptr()))
                .with_newdirfd(libc::AT_FDCWD)
                .with_newpath(PathPtr::from_ptr(bar.as_ptr()))
                .with_flags(AtFlags::empty()),
            Link::new()
                .with_oldpath(PathPtr::from_ptr(foo.as_ptr()))
                .with_newpath(PathPtr::from_ptr(bar.as_ptr()))
                .into(),
        );
    }
}
