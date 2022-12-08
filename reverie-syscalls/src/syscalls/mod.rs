/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

pub mod family;

use ::syscalls::SyscallArgs;
use ::syscalls::Sysno;
// Re-export flags that used by syscalls from the `nix` crate so downstream
// projects don't need to add another dependency on it.
pub use nix::fcntl::AtFlags;
pub use nix::fcntl::OFlag;
// FIXME: Switch everything over to `crate::args::CloneFlags`.
use nix::sched::CloneFlags;
pub use nix::sys::epoll::EpollCreateFlags;
pub use nix::sys::eventfd::EfdFlags;
pub use nix::sys::inotify::InitFlags;
pub use nix::sys::mman::MapFlags;
pub use nix::sys::mman::ProtFlags;
pub use nix::sys::signalfd::SfdFlags;
pub use nix::sys::socket::SockFlag;
pub use nix::sys::stat::Mode;
pub use nix::sys::timerfd::TimerFlags;
pub use nix::sys::wait::WaitPidFlag;

use crate::args;
use crate::args::ioctl;
use crate::args::CArrayPtr;
use crate::args::CStrPtr;
use crate::args::ClockId;
use crate::args::CloneArgs;
use crate::args::FcntlCmd;
use crate::args::PathPtr;
use crate::args::StatPtr;
use crate::args::StatxMask;
use crate::args::StatxPtr;
use crate::args::Timespec;
use crate::args::TimespecMutPtr;
use crate::args::TimevalMutPtr;
use crate::args::Timezone;
use crate::display::Displayable;
use crate::raw::FromToRaw;
use crate::Addr;
use crate::AddrMut;

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
        read => Read,
        write => Write,
        #[cfg(not(target_arch = "aarch64"))]
        open => Open,
        close => Close,
        #[cfg(not(target_arch = "aarch64"))]
        stat => Stat,
        fstat => Fstat,
        #[cfg(not(target_arch = "aarch64"))]
        lstat => Lstat,
        #[cfg(not(target_arch = "aarch64"))]
        poll => Poll,
        #[cfg(not(target_arch = "aarch64"))]
        lseek => Lseek,
        mmap => Mmap,
        mprotect => Mprotect,
        munmap => Munmap,
        brk => Brk,
        rt_sigaction => RtSigaction,
        rt_sigprocmask => RtSigprocmask,
        rt_sigreturn => RtSigreturn,
        ioctl => Ioctl,
        pread64 => Pread64,
        pwrite64 => Pwrite64,
        readv => Readv,
        writev => Writev,
        #[cfg(not(target_arch = "aarch64"))]
        access => Access,
        #[cfg(not(target_arch = "aarch64"))]
        pipe => Pipe,
        #[cfg(not(target_arch = "aarch64"))]
        select => Select,
        sched_yield => SchedYield,
        mremap => Mremap,
        msync => Msync,
        mincore => Mincore,
        madvise => Madvise,
        shmget => Shmget,
        shmat => Shmat,
        shmctl => Shmctl,
        dup => Dup,
        #[cfg(not(target_arch = "aarch64"))]
        dup2 => Dup2,
        #[cfg(not(target_arch = "aarch64"))]
        pause => Pause,
        nanosleep => Nanosleep,
        getitimer => Getitimer,
        #[cfg(not(target_arch = "aarch64"))]
        alarm => Alarm,
        setitimer => Setitimer,
        getpid => Getpid,
        sendfile => Sendfile,
        socket => Socket,
        connect => Connect,
        accept => Accept,
        sendto => Sendto,
        recvfrom => Recvfrom,
        sendmsg => Sendmsg,
        recvmsg => Recvmsg,
        shutdown => Shutdown,
        bind => Bind,
        listen => Listen,
        getsockname => Getsockname,
        getpeername => Getpeername,
        socketpair => Socketpair,
        setsockopt => Setsockopt,
        getsockopt => Getsockopt,
        clone => Clone,
        #[cfg(not(target_arch = "aarch64"))]
        fork => Fork,
        #[cfg(not(target_arch = "aarch64"))]
        vfork => Vfork,
        execve => Execve,
        exit => Exit,
        wait4 => Wait4,
        kill => Kill,
        uname => Uname,
        semget => Semget,
        semop => Semop,
        semctl => Semctl,
        shmdt => Shmdt,
        msgget => Msgget,
        msgsnd => Msgsnd,
        msgrcv => Msgrcv,
        msgctl => Msgctl,
        fcntl => Fcntl,
        flock => Flock,
        fsync => Fsync,
        fdatasync => Fdatasync,
        truncate => Truncate,
        ftruncate => Ftruncate,
        #[cfg(not(target_arch = "aarch64"))]
        getdents => Getdents,
        getcwd => Getcwd,
        chdir => Chdir,
        fchdir => Fchdir,
        #[cfg(not(target_arch = "aarch64"))]
        rename => Rename,
        #[cfg(not(target_arch = "aarch64"))]
        mkdir => Mkdir,
        #[cfg(not(target_arch = "aarch64"))]
        rmdir => Rmdir,
        #[cfg(not(target_arch = "aarch64"))]
        creat => Creat,
        #[cfg(not(target_arch = "aarch64"))]
        link => Link,
        #[cfg(not(target_arch = "aarch64"))]
        unlink => Unlink,
        #[cfg(not(target_arch = "aarch64"))]
        symlink => Symlink,
        #[cfg(not(target_arch = "aarch64"))]
        readlink => Readlink,
        #[cfg(not(target_arch = "aarch64"))]
        chmod => Chmod,
        fchmod => Fchmod,
        #[cfg(not(target_arch = "aarch64"))]
        chown => Chown,
        fchown => Fchown,
        #[cfg(not(target_arch = "aarch64"))]
        lchown => Lchown,
        umask => Umask,
        gettimeofday => Gettimeofday,
        getrlimit => Getrlimit,
        getrusage => Getrusage,
        sysinfo => Sysinfo,
        times => Times,
        ptrace => Ptrace,
        getuid => Getuid,
        syslog => Syslog,
        getgid => Getgid,
        setuid => Setuid,
        setgid => Setgid,
        geteuid => Geteuid,
        getegid => Getegid,
        setpgid => Setpgid,
        getppid => Getppid,
        #[cfg(not(target_arch = "aarch64"))]
        getpgrp => Getpgrp,
        setsid => Setsid,
        setreuid => Setreuid,
        setregid => Setregid,
        getgroups => Getgroups,
        setgroups => Setgroups,
        setresuid => Setresuid,
        getresuid => Getresuid,
        setresgid => Setresgid,
        getresgid => Getresgid,
        getpgid => Getpgid,
        setfsuid => Setfsuid,
        setfsgid => Setfsgid,
        getsid => Getsid,
        capget => Capget,
        capset => Capset,
        rt_sigpending => RtSigpending,
        rt_sigtimedwait => RtSigtimedwait,
        rt_sigqueueinfo => RtSigqueueinfo,
        rt_sigsuspend => RtSigsuspend,
        sigaltstack => Sigaltstack,
        #[cfg(not(target_arch = "aarch64"))]
        utime => Utime,
        #[cfg(not(target_arch = "aarch64"))]
        mknod => Mknod,
        #[cfg(not(target_arch = "aarch64"))]
        uselib => Uselib,
        personality => Personality,
        #[cfg(not(target_arch = "aarch64"))]
        ustat => Ustat,
        statfs => Statfs,
        fstatfs => Fstatfs,
        #[cfg(not(target_arch = "aarch64"))]
        sysfs => Sysfs,
        getpriority => Getpriority,
        setpriority => Setpriority,
        sched_setparam => SchedSetparam,
        sched_getparam => SchedGetparam,
        sched_setscheduler => SchedSetscheduler,
        sched_getscheduler => SchedGetscheduler,
        sched_get_priority_max => SchedGetPriorityMax,
        sched_get_priority_min => SchedGetPriorityMin,
        sched_rr_get_interval => SchedRrGetInterval,
        mlock => Mlock,
        munlock => Munlock,
        mlockall => Mlockall,
        munlockall => Munlockall,
        vhangup => Vhangup,
        #[cfg(not(target_arch = "aarch64"))]
        modify_ldt => ModifyLdt,
        pivot_root => PivotRoot,
        #[allow(non_camel_case_types)]
        #[cfg(not(target_arch = "aarch64"))]
        _sysctl => _sysctl,
        prctl => Prctl,
        #[cfg(not(target_arch = "aarch64"))]
        arch_prctl => ArchPrctl,
        adjtimex => Adjtimex,
        setrlimit => Setrlimit,
        chroot => Chroot,
        sync => Sync,
        acct => Acct,
        settimeofday => Settimeofday,
        mount => Mount,
        umount2 => Umount2,
        swapon => Swapon,
        swapoff => Swapoff,
        reboot => Reboot,
        sethostname => Sethostname,
        setdomainname => Setdomainname,
        #[cfg(not(target_arch = "aarch64"))]
        iopl => Iopl,
        #[cfg(not(target_arch = "aarch64"))]
        ioperm => Ioperm,
        #[cfg(not(target_arch = "aarch64"))]
        create_module => CreateModule,
        init_module => InitModule,
        delete_module => DeleteModule,
        #[cfg(not(target_arch = "aarch64"))]
        get_kernel_syms => GetKernelSyms,
        #[cfg(not(target_arch = "aarch64"))]
        query_module => QueryModule,
        quotactl => Quotactl,
        nfsservctl => Nfsservctl,
        #[cfg(not(target_arch = "aarch64"))]
        getpmsg => Getpmsg,
        #[cfg(not(target_arch = "aarch64"))]
        putpmsg => Putpmsg,
        #[cfg(not(target_arch = "aarch64"))]
        afs_syscall => AfsSyscall,
        #[cfg(not(target_arch = "aarch64"))]
        tuxcall => Tuxcall,
        #[cfg(not(target_arch = "aarch64"))]
        security => Security,
        gettid => Gettid,
        readahead => Readahead,
        setxattr => Setxattr,
        lsetxattr => Lsetxattr,
        fsetxattr => Fsetxattr,
        getxattr => Getxattr,
        lgetxattr => Lgetxattr,
        fgetxattr => Fgetxattr,
        listxattr => Listxattr,
        llistxattr => Llistxattr,
        flistxattr => Flistxattr,
        removexattr => Removexattr,
        lremovexattr => Lremovexattr,
        fremovexattr => Fremovexattr,
        tkill => Tkill,
        #[cfg(not(target_arch = "aarch64"))]
        time => Time,
        futex => Futex,
        sched_setaffinity => SchedSetaffinity,
        sched_getaffinity => SchedGetaffinity,
        #[cfg(not(target_arch = "aarch64"))]
        set_thread_area => SetThreadArea,
        io_setup => IoSetup,
        io_destroy => IoDestroy,
        io_getevents => IoGetevents,
        io_submit => IoSubmit,
        io_cancel => IoCancel,
        #[cfg(not(target_arch = "aarch64"))]
        get_thread_area => GetThreadArea,
        lookup_dcookie => LookupDcookie,
        #[cfg(not(target_arch = "aarch64"))]
        epoll_create => EpollCreate,
        #[cfg(not(target_arch = "aarch64"))]
        epoll_ctl_old => EpollCtlOld,
        #[cfg(not(target_arch = "aarch64"))]
        epoll_wait_old => EpollWaitOld,
        remap_file_pages => RemapFilePages,
        getdents64 => Getdents64,
        set_tid_address => SetTidAddress,
        restart_syscall => RestartSyscall,
        semtimedop => Semtimedop,
        fadvise64 => Fadvise64,
        timer_create => TimerCreate,
        timer_settime => TimerSettime,
        timer_gettime => TimerGettime,
        timer_getoverrun => TimerGetoverrun,
        timer_delete => TimerDelete,
        clock_settime => ClockSettime,
        clock_gettime => ClockGettime,
        clock_getres => ClockGetres,
        clock_nanosleep => ClockNanosleep,
        exit_group => ExitGroup,
        #[cfg(not(target_arch = "aarch64"))]
        epoll_wait => EpollWait,
        epoll_ctl => EpollCtl,
        tgkill => Tgkill,
        #[cfg(not(target_arch = "aarch64"))]
        utimes => Utimes,
        #[cfg(not(target_arch = "aarch64"))]
        vserver => Vserver,
        mbind => Mbind,
        set_mempolicy => SetMempolicy,
        get_mempolicy => GetMempolicy,
        mq_open => MqOpen,
        mq_unlink => MqUnlink,
        mq_timedsend => MqTimedsend,
        mq_timedreceive => MqTimedreceive,
        mq_notify => MqNotify,
        mq_getsetattr => MqGetsetattr,
        kexec_load => KexecLoad,
        waitid => Waitid,
        add_key => AddKey,
        request_key => RequestKey,
        keyctl => Keyctl,
        ioprio_set => IoprioSet,
        ioprio_get => IoprioGet,
        #[cfg(not(target_arch = "aarch64"))]
        inotify_init => InotifyInit,
        inotify_add_watch => InotifyAddWatch,
        inotify_rm_watch => InotifyRmWatch,
        migrate_pages => MigratePages,
        openat => Openat,
        mkdirat => Mkdirat,
        mknodat => Mknodat,
        fchownat => Fchownat,
        #[cfg(not(target_arch = "aarch64"))]
        futimesat => Futimesat,
        #[cfg(target_arch = "x86_64")]
        newfstatat => Newfstatat,
        #[cfg(target_arch = "aarch64")]
        fstatat => Fstatat,
        unlinkat => Unlinkat,
        renameat => Renameat,
        linkat => Linkat,
        symlinkat => Symlinkat,
        readlinkat => Readlinkat,
        fchmodat => Fchmodat,
        faccessat => Faccessat,
        pselect6 => Pselect6,
        ppoll => Ppoll,
        unshare => Unshare,
        set_robust_list => SetRobustList,
        get_robust_list => GetRobustList,
        splice => Splice,
        tee => Tee,
        #[cfg(not(target_arch = "aarch64"))]
        sync_file_range => SyncFileRange,
        vmsplice => Vmsplice,
        move_pages => MovePages,
        utimensat => Utimensat,
        epoll_pwait => EpollPwait,
        #[cfg(not(target_arch = "aarch64"))]
        signalfd => Signalfd,
        timerfd_create => TimerfdCreate,
        #[cfg(not(target_arch = "aarch64"))]
        eventfd => Eventfd,
        fallocate => Fallocate,
        timerfd_settime => TimerfdSettime,
        timerfd_gettime => TimerfdGettime,
        accept4 => Accept4,
        signalfd4 => Signalfd4,
        eventfd2 => Eventfd2,
        epoll_create1 => EpollCreate1,
        dup3 => Dup3,
        pipe2 => Pipe2,
        inotify_init1 => InotifyInit1,
        preadv => Preadv,
        pwritev => Pwritev,
        rt_tgsigqueueinfo => RtTgsigqueueinfo,
        perf_event_open => PerfEventOpen,
        recvmmsg => Recvmmsg,
        fanotify_init => FanotifyInit,
        fanotify_mark => FanotifyMark,
        prlimit64 => Prlimit64,
        name_to_handle_at => NameToHandleAt,
        open_by_handle_at => OpenByHandleAt,
        clock_adjtime => ClockAdjtime,
        syncfs => Syncfs,
        sendmmsg => Sendmmsg,
        setns => Setns,
        getcpu => Getcpu,
        process_vm_readv => ProcessVmReadv,
        process_vm_writev => ProcessVmWritev,
        kcmp => Kcmp,
        finit_module => FinitModule,
        sched_setattr => SchedSetattr,
        sched_getattr => SchedGetattr,
        renameat2 => Renameat2,
        seccomp => Seccomp,
        getrandom => Getrandom,
        memfd_create => MemfdCreate,
        kexec_file_load => KexecFileLoad,
        bpf => Bpf,
        execveat => Execveat,
        userfaultfd => Userfaultfd,
        membarrier => Membarrier,
        mlock2 => Mlock2,
        copy_file_range => CopyFileRange,
        preadv2 => Preadv2,
        pwritev2 => Pwritev2,
        pkey_mprotect => PkeyMprotect,
        pkey_alloc => PkeyAlloc,
        pkey_free => PkeyFree,
        statx => Statx,
        // Missing: io_pgetevents => IoPgetevents,
        // Missing: rseq => Rseq,
        // Missing: pidfd_send_signal => PidfdSendSignal,
        io_uring_setup => IoUringSetup,
        io_uring_enter => IoUringEnter,
        io_uring_register => IoUringRegister,
        // Missing: open_tree => OpenTree,
        // Missing: move_mount => MoveMount,
        // Missing: fsopen => Fsopen,
        // Missing: fsconfig => Fsconfig,
        // Missing: fsmount => Fsmount,
        // Missing: fspick => Fspick,
        // Missing: pidfd_open => PidfdOpen,
        clone3 => Clone3,
        // Missing: close_range => CloseRange,
        // Missing: openat2 => Openat2,
        // Missing: pidfd_getfd => PidfdGetfd,
        // Missing: faccessat2 => Faccessat2,
        // Missing: process_madvise => ProcessMadvise,
        // Missing: epoll_pwait2 => EpollPwait2,
        // Missing: mount_setattr => MountSetattr,
        // Missing: quotactl_path => QuotactlPath,
        // Missing: landlock_create_ruleset => LandlockCreateRuleset,
        // Missing: landlock_add_rule => LandlockAddRule,
        // Missing: landlock_restrict_self => LandlockRestrictSelf,
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

fn get_mode(flags: OFlag, mode: usize) -> Option<Mode> {
    if flags.intersects(OFlag::O_CREAT | OFlag::O_TMPFILE) {
        Some(FromToRaw::from_raw(mode))
    } else {
        None
    }
}

// Open not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Open not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Creat> for Open {
    /// A call to creat() is equivalent to calling open() with flags equal to
    /// O_CREAT|O_WRONLY|O_TRUNC
    fn from(creat: Creat) -> Self {
        let Creat { mut raw } = creat;
        raw.arg2 = raw.arg1;
        raw.arg1 = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as usize;
        Open { raw }
    }
}

typed_syscall! {
    pub struct Close {
        fd: i32,
    }
}

// Stat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Lstat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Lstat {
        path: Option<PathPtr>,
        stat: Option<StatPtr>,
    }
}

// Poll not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Poll {
        fds: Option<AddrMut<args::PollFd>>,
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

// Lseek not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Lseek {
        fd: i32,
        offset: libc::off_t,
        whence: args::Whence,
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

// Access not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Access {
        path: Option<PathPtr>,
        mode: Mode,
    }
}

// Pipe not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Pipe {
        pipefd: Option<AddrMut<[i32; 2]>>,
    }
}

// Select not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Dup2 not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Dup2 {
        oldfd: i32,
        newfd: i32,
    }
}

// Pause not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Alarm not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Vfork not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Vfork> for Clone {
    /// Since `clone` offers a superset of functionality over `vfork`, a `vfork`
    /// syscall can be transformed into a `clone` syscall by passing in the
    /// right flags. In fact, this is how the Linux kernel implements `vfork`.
    /// See kernel/fork.c for more details.
    fn from(_: Vfork) -> Self {
        let raw = SyscallArgs {
            arg0: (libc::CLONE_VFORK | libc::CLONE_VM | libc::SIGCHLD) as usize,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        Self { raw }
    }
}

// Fork not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Fork> for Clone {
    /// Since `clone` offers a superset of functionality over `fork`, a `fork`
    /// syscall can be transformed into a `clone` syscall by passing in the
    /// right flags. In fact, this is how the Linux kernel implements `fork`.
    /// See kernel/fork.c for more details.
    fn from(_: Fork) -> Self {
        let raw = SyscallArgs {
            arg0: libc::SIGCHLD as usize,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        Self { raw }
    }
}
// Fork not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Fork {}
}
// Vfork not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
                self.raw.arg1 = cmd as usize;
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
// Getdents not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
// Rename not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Rename {
        oldpath: Option<PathPtr>,
        newpath: Option<PathPtr>,
    }
}
// Mkdir not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Mkdir {
        path: Option<PathPtr>,
        mode: Mode,
    }
}
// Rmdir not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Rmdir {
        path: Option<PathPtr>,
    }
}
// Creat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Creat {
        path: Option<PathPtr>,
        mode: Mode,
    }
}
// Link not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Link {
        oldpath: Option<PathPtr>,
        newpath: Option<PathPtr>,
    }
}
// Unlink not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Unlink {
        path: Option<PathPtr>,
    }
}
// Symlink not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Symlink {
        target: Option<PathPtr>,
        linkpath: Option<PathPtr>,
    }
}

// Readlink not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Readlink {
        path: Option<PathPtr>,
        // TODO: Replace this with a PathPtrMut
        buf: Option<AddrMut<libc::c_char>>,
        bufsize: usize,
    }
}

// Chmod not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
// Chown not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
// Lchown not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
        tv: Option<TimevalMutPtr>,
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

// Getpgrp not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// utime not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Utime {
        path: Option<PathPtr>,
        times: Option<AddrMut<libc::utimbuf>>,
    }
}

// Mknod not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Mknod {
        path: Option<PathPtr>,
        mode: Mode,
        dev: libc::dev_t,
    }
}

// Uselib not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Ustat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Sysfs not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Sysfs {
        option: i32,
        arg1: usize,
        arg2: usize,
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

// ModifyLdt not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct ModifyLdt {
        func: i32,
        ptr: Option<AddrMut<libc::c_void>>,
        bytecount: usize,
    }
}

typed_syscall! {
    pub struct PivotRoot {
        new_root: Option<PathPtr>,
        put_old: Option<PathPtr>,
    }
}

// _sysctl not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// ArchPrctl not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct ArchPrctl {
        cmd: {
            fn get(&self) -> args::ArchPrctlCmd {
                args::ArchPrctlCmd::from_raw(self.raw.arg0 as i32, self.raw.arg1)
            }

            fn set(mut self, v: args::ArchPrctlCmd) -> Self {
                let (cmd, arg) = v.into_raw();
                self.raw.arg0 = cmd as usize;
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

// Iopl not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Iopl {
        level: u32,
    }
}

// Ioperm not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Ioperm {
        from: u64,
        num: u64,
        turn_on: i32,
    }
}

// CreateModule not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// GetKernelSyms not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    /// Note: This system call is present only in kernels before Linux 2.6.
    pub struct GetKernelSyms {
        table: Option<AddrMut<libc::c_void>>,
    }
}

// QueryModule not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Getpmsg not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Getpmsg {}
}

// Putmsp not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Putpmsg {}
}

// AfsSyscall not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct AfsSyscall {}
}

// Tuxcall not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    /// Unimplemented in the kernel.
    pub struct Tuxcall {}
}

// Security not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Time not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// SetThreadArea not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// GetThreadArea not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// EpollCreate not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct EpollCreate {
        /// The kernel doesn't actually use this parameter, but it must be
        /// greater than 0. (It was used as a size hint at one point in time.)
        size: i32,
    }
}

// EpollCtlOld not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    /// Undocumented.
    pub struct EpollCtlOld {}
}

// EpollWaitOld not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
        tp: Option<TimespecMutPtr>,
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

// EpollWait not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Utimes not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Utimes {
        filename: Option<PathPtr>,
        times: Option<Addr<[libc::timeval; 2]>>,
    }
}

// Vserver not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// InotifyInit not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

            fn set(mut self, v: Option<Mode>) -> Self {
                self.raw.arg3 = v.into_raw();
                self
            }
        },
    }
}

// Open not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Open> for Openat {
    /// An `open` syscall can be trivially transformed into an `openat`
    /// syscall by shifting all the arguments to the right and setting the first
    /// argument to `AT_FDCWD` (the current working directory).
    fn from(open: Open) -> Self {
        let Open { mut raw } = open;
        raw.arg3 = raw.arg2;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
        Openat { raw }
    }
}

// Creat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Creat> for Openat {
    /// A call to creat() is equivalent to calling open() with flags equal to
    /// O_CREAT|O_WRONLY|O_TRUNC
    fn from(creat: Creat) -> Self {
        let Creat { mut raw } = creat;
        raw.arg3 = raw.arg1;
        raw.arg2 = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as usize;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
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

// Mkdir not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Mkdir> for Mkdirat {
    /// An `mkdir` syscall can be trivially transformed into a `mkdirat` syscall
    /// by shifting all the arguments to the right and setting the first argument
    /// to `AT_FDCWD` (the current working directory).
    fn from(syscall: Mkdir) -> Self {
        let Mkdir { mut raw } = syscall;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
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

// Mknod not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Mknod> for Mknodat {
    /// An `mknod` syscall can be trivially transformed into an `mknodat` syscall
    /// by shifting all the arguments to the right and setting the first argument
    /// to `AT_FDCWD` (the current working directory).
    fn from(syscall: Mknod) -> Self {
        let Mknod { mut raw } = syscall;
        raw.arg3 = raw.arg2;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
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

// Futimesat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
typed_syscall! {
    pub struct Futimesat {
        dirfd: i32,
        path: Option<PathPtr>,
        utimes: Option<Addr<[libc::timeval; 2]>>,
    }
}

// Newfstatat not available in aarch64
#[cfg(target_arch = "x86_64")]
typed_syscall! {
    pub struct Newfstatat {
        dirfd: i32,
        path: Option<PathPtr>,
        stat: Option<StatPtr>,
        flags: AtFlags,
    }
}

/// Alias for Newfstatat. Architectures other than x86-64 usually name this
/// syscall `fstatat`.
#[cfg(target_arch = "x86_64")]
pub type Fstatat = Newfstatat;

#[cfg(target_arch = "aarch64")]
typed_syscall! {
    pub struct Fstatat {
        dirfd: i32,
        path: Option<PathPtr>,
        stat: Option<StatPtr>,
        flags: AtFlags,
    }
}

// `Stat` is not available in aarch64
#[cfg(target_arch = "x86_64")]
impl From<Stat> for Fstatat {
    fn from(stat: Stat) -> Self {
        let Stat { mut raw } = stat;
        raw.arg3 = 0;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
        Self { raw }
    }
}

// Lstat is not available in aarch64
#[cfg(target_arch = "x86_64")]
impl From<Lstat> for Fstatat {
    fn from(lstat: Lstat) -> Self {
        let Lstat { mut raw } = lstat;
        raw.arg3 = AtFlags::AT_SYMLINK_NOFOLLOW.bits() as usize;
        raw.arg2 = raw.arg1;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
        Self { raw }
    }
}

typed_syscall! {
    pub struct Unlinkat {
        dirfd: i32,
        path: Option<PathPtr>,
        flags: AtFlags,
    }
}

// Unlink not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Unlink> for Unlinkat {
    fn from(unlink: Unlink) -> Self {
        let Unlink { mut raw } = unlink;
        raw.arg2 = 0;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
        Unlinkat { raw }
    }
}

// Rmdir not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Rmdir> for Unlinkat {
    fn from(rmdir: Rmdir) -> Self {
        let Rmdir { mut raw } = rmdir;
        raw.arg2 = libc::AT_REMOVEDIR as usize;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
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

// Link not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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
        raw.arg0 = libc::AT_FDCWD as usize;
        raw.arg2 = libc::AT_FDCWD as usize;
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

// SyncFileRange not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Signalfd not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Eventfd not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Signalfd not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Eventfd not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// EpollCreate not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Pipe not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// InotifyInit1 not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
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

// Rename not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<Rename> for Renameat2 {
    fn from(rename: Rename) -> Self {
        let Rename { mut raw } = rename;
        raw.arg4 = 0;
        raw.arg3 = raw.arg1;
        raw.arg2 = libc::AT_FDCWD as usize;
        raw.arg1 = raw.arg0;
        raw.arg0 = libc::AT_FDCWD as usize;
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
        raw.arg0 = libc::AT_FDCWD as usize;
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

typed_syscall! {
    pub struct IoUringSetup {
        entries: u32,
        params: Option<AddrMut<args::IoUringParams>>,
    }
}

typed_syscall! {
    pub struct IoUringEnter {
        fd: u32,
        to_submit: u32,
        min_complete: u32,
        flags: u32,
        sig: Option<Addr<libc::sigset_t>>,
        sigsz: usize,
    }
}

typed_syscall! {
    pub struct IoUringRegister {
        fd: u32,
        opcode: u32,
        arg: Option<AddrMut<libc::c_void>>,
        nr_args: u32,
    }
}

typed_syscall! {
    pub struct Clone3 {
        args: Option<AddrMut<CloneArgs>>,
        size: usize,
    }
}

#[cfg(test)]
mod test {
    use std::ffi::CString;
    use std::path::Path;

    use syscalls::SyscallArgs;
    use syscalls::Sysno;

    use super::*;
    use crate::Displayable;
    use crate::LocalMemory;
    use crate::ReadAddr;

    #[test]
    fn test_syscall_openat_path() {
        assert_eq!(Openat::NAME, "openat");
        assert_eq!(Openat::NUMBER, Sysno::openat);

        let name = CString::new("/some/file/path").unwrap();

        let syscall = Openat::new()
            .with_dirfd(-100)
            .with_path(PathPtr::from_ptr(name.as_ptr()))
            .with_flags(OFlag::O_RDONLY | OFlag::O_APPEND)
            .with_mode(Some(Mode::from_bits_truncate(0o644)));

        assert_eq!(Openat::from(SyscallArgs::from(syscall)), syscall);

        let memory = LocalMemory::new();

        assert_eq!(
            syscall.path().unwrap().read(&memory).unwrap(),
            Path::new("/some/file/path")
        );

        assert_eq!(
            format!("{}", syscall.display(&memory)),
            format!(
                "openat(-100, {:p} -> \"/some/file/path\", O_APPEND)",
                name.as_ptr()
            )
        );
    }

    #[test]
    fn test_syscall_openat_display() {
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
                    .with_mode(Some(Mode::from_bits_truncate(0o644)))
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
                    .with_mode(Some(Mode::from_bits_truncate(0o600)))
                    .display(&memory)
            ),
            "openat(-100, NULL, O_DIRECTORY | O_TMPFILE, S_IRUSR | S_IWUSR)"
        );

        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            Openat::new()
                .with_dirfd(libc::AT_FDCWD)
                .with_path(None)
                .with_flags(OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_TRUNC)
                .with_mode(Some(Mode::from_bits_truncate(0o600))),
            Creat::new()
                .with_path(None)
                .with_mode(Mode::from_bits_truncate(0o600))
                .into()
        );
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_syscall_pipe2() {
        let memory: Option<AddrMut<[i32; 2]>> = AddrMut::from_raw(0x1245);

        // NOTE: `pipe` is not available on aarch64.
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_syscall_linkat() {
        let foo = CString::new("foo").unwrap();
        let bar = CString::new("bar").unwrap();

        // NOTE: `link` is not available on aarch64.
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
