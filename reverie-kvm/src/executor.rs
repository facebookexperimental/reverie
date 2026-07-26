/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use crate::GuestMemory;
use crate::SyscallRequest;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::SegmentBase;
use crate::elf::LoadedStaticElf;
use crate::elf::STACK_LIMIT;
use crate::runtime::SyscallExecutor;

const MAX_HOST_IO: usize = 16 * 1024 * 1024;
const MAX_CAPTURED_OUTPUT: usize = 64 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
const GUEST_NOFILE_LIMIT: libc::c_int = 1 << 20;
const KERNEL_SIGACTION_SIZE: usize = 32;
const KERNEL_SIGSET_SIZE: usize = 8;
const MEMBARRIER_SUPPORTED: libc::c_int = 0x1;
// prctl(2) PR_CAPBSET_READ option; the deterministic container runs the guest as
// root with the full capability bounding set up to a fixed CAP_LAST_CAP so the
// answer is host-independent.
const PR_CAPBSET_READ: u64 = 23;
const GUEST_CAP_LAST_CAP: u64 = 40;
const PROCESS_CLONE_TID_FLAGS: u64 = libc::CLONE_PARENT_SETTID as u64
    | libc::CLONE_CHILD_SETTID as u64
    | libc::CLONE_CHILD_CLEARTID as u64;
// TODO-HUMAN-REVIEW(PR-92): Review clone3 signal-disposition reset semantics.
// CLONE_CLEAR_SIGHAND (bit 32): reset the child's caught signal handlers to
// SIG_DFL. glibc >= 2.36 `posix_spawn` sets this in its clone3 alongside
// CLONE_VM|CLONE_VFORK, so modern `make`/`gcc` job spawning depends on it being
// accepted rather than rejected as unsupported. Defined locally as a `u64`
// because `libc::CLONE_CLEAR_SIGHAND` is (incorrectly) typed `c_int` on gnu and
// truncates to 0.
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const GUEST_SUPPLEMENTARY_GROUPS: &[libc::gid_t] = &[65_534];
const LEGACY_OPEN_FLAGS: u64 = (libc::O_ACCMODE
    | libc::O_APPEND
    | libc::O_ASYNC
    | libc::O_CLOEXEC
    | libc::O_CREAT
    | libc::O_DIRECT
    | libc::O_DIRECTORY
    | libc::O_DSYNC
    | libc::O_EXCL
    | libc::O_LARGEFILE
    | libc::O_NOATIME
    | libc::O_NOCTTY
    | libc::O_NOFOLLOW
    | libc::O_NONBLOCK
    | libc::O_PATH
    | libc::O_SYNC
    | libc::O_TMPFILE
    | libc::O_TRUNC) as u64;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GuestStack {
    sp: u64,
    flags: libc::c_int,
    _padding: libc::c_uint,
    size: u64,
}

pub(crate) enum SyscallAction {
    Continue {
        result: i64,
        segment: Option<(SegmentBase, u64)>,
    },
    Exit(i32),
}

#[derive(Default)]
pub(crate) struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CapturedOutput {
    pub(crate) fn take(&mut self) -> (Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut self.stdout),
            std::mem::take(&mut self.stderr),
        )
    }
}

pub(crate) enum ProcessAction {
    Fork {
        child_pid: i32,
        child_stack: Option<u64>,
        // AUTONOMOUS-BOT-IMPLEMENTED: Model legacy process-clone TID bookkeeping.
        // TODO-HUMAN-REVIEW(#89): Review clone TID timing and clear-pointer lifecycle.
        parent_tid: Option<u64>,
        child_tid: Option<u64>,
        clear_child_tid: Option<u64>,
        // TODO-HUMAN-REVIEW(PR-92): Review CLONE_CLEAR_SIGHAND child state.
        clear_sighand: bool,
    },
    Exec {
        image: Vec<u8>,
        argv: Vec<String>,
        envp: Vec<String>,
    },
}

pub(crate) fn is_process_syscall(number: u64) -> bool {
    number == libc::SYS_fork as u64
        || number == libc::SYS_vfork as u64
        || number == libc::SYS_clone as u64
        || number == libc::SYS_clone3 as u64
        || number == libc::SYS_execve as u64
        || number == libc::SYS_execveat as u64
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-92): Review wait4 process-action classification.
        || number == libc::SYS_wait4 as u64
}

#[cfg(test)]
pub(crate) fn execute_basic_syscall(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
) -> SyscallAction {
    execute_basic_syscall_with_output(memory, state, request, None)
}

fn execute_basic_syscall_with_output(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
    output: Option<&mut CapturedOutput>,
) -> SyscallAction {
    let args = request.args();
    let number = request.number();

    if number == libc::SYS_exit as u64 || number == libc::SYS_exit_group as u64 {
        return SyscallAction::Exit(args[0] as i32);
    }

    let result = if number == libc::SYS_write as u64 {
        write(memory, state, args, output)
    } else if number == libc::SYS_read as u64 {
        read(memory, state, args)
    } else if number == libc::SYS_writev as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(#120)
        writev(memory, state, args, output)
    } else if number == libc::SYS_readv as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(#120)
        readv(memory, state, args)
    } else if number == libc::SYS_pread64 as u64 {
        pread64(memory, state, args)
    } else if number == libc::SYS_pwrite64 as u64 {
        pwrite64(memory, state, args)
    } else if number == libc::SYS_lseek as u64 {
        lseek(state, args)
    } else if number == libc::SYS_ftruncate as u64 {
        ftruncate(state, args)
    } else if number == libc::SYS_fsync as u64 {
        sync_file(state, args[0], false)
    } else if number == libc::SYS_fdatasync as u64 {
        sync_file(state, args[0], true)
    } else if number == libc::SYS_pipe as u64 {
        pipe2(memory, state, args[0], 0)
    } else if number == libc::SYS_pipe2 as u64 {
        pipe2(memory, state, args[0], args[1])
    } else if number == libc::SYS_poll as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        poll(memory, state, args)
    } else if number == libc::SYS_epoll_create1 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_create1(state, args[0])
    } else if number == libc::SYS_epoll_ctl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_ctl(memory, state, args)
    } else if number == libc::SYS_epoll_wait as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_wait(memory, state, args, false)
    } else if number == libc::SYS_epoll_pwait as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_wait(memory, state, args, true)
    } else if number == libc::SYS_eventfd as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        eventfd2(state, args[0], 0)
    } else if number == libc::SYS_eventfd2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        eventfd2(state, args[0], args[1])
    } else if number == libc::SYS_socket as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        socket(state, args)
    } else if number == libc::SYS_connect as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        connect(memory, state, args)
    } else if number == libc::SYS_ioctl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        ioctl(state, args)
    } else if number == libc::SYS_dup as u64 {
        duplicate_fd(state, args[0], None, 0, false)
    } else if number == libc::SYS_dup2 as u64 {
        duplicate_fd(state, args[0], Some(args[1]), 0, false)
    } else if number == libc::SYS_dup3 as u64 {
        duplicate_fd(state, args[0], Some(args[1]), args[2], true)
    } else if number == libc::SYS_fcntl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fcntl(state, args)
    } else if number == libc::SYS_open as u64 {
        open(memory, state, args)
    } else if number == libc::SYS_openat as u64 {
        openat(memory, state, args)
    } else if number == libc::SYS_creat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        creat(memory, state, args)
    } else if number == libc::SYS_fstat as u64 {
        fstat(memory, state, args)
    } else if number == libc::SYS_stat as u64 {
        path_stat(memory, state, args, 0)
    } else if number == libc::SYS_lstat as u64 {
        path_stat(memory, state, args, libc::AT_SYMLINK_NOFOLLOW)
    } else if number == libc::SYS_newfstatat as u64 {
        newfstatat(memory, state, args)
    } else if number == libc::SYS_statx as u64 {
        statx(memory, state, args)
    } else if number == libc::SYS_statfs as u64 {
        statfs(memory, state, args)
    } else if number == libc::SYS_fstatfs as u64 {
        fstatfs(memory, state, args)
    } else if number == libc::SYS_access as u64 {
        access(memory, state, args)
    } else if number == libc::SYS_faccessat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        faccessat(memory, state, args)
    } else if number == libc::SYS_faccessat2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        faccessat2(memory, state, args)
    } else if number == libc::SYS_mkdir as u64 {
        mkdir_at(memory, state, libc::AT_FDCWD, args[0], args[1])
    } else if number == libc::SYS_mkdirat as u64 {
        mkdir_at(memory, state, args[0] as libc::c_int, args[1], args[2])
    } else if number == libc::SYS_unlink as u64 {
        unlink_at(memory, state, libc::AT_FDCWD, args[0], 0)
    } else if number == libc::SYS_rmdir as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-111): Review rmdir->unlinkat(AT_REMOVEDIR) mapping.
        // rmdir(path) is unlinkat(AT_FDCWD, path, AT_REMOVEDIR). Without this
        // arm the guest's bare rmdir(2) fell through to ENOSYS, so coreutils
        // `rmdir` (and `mktemp -d` cleanup) failed under the KVM backend even
        // though `rm -rf`, which uses unlinkat(AT_REMOVEDIR), worked.
        unlink_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_REMOVEDIR as u64,
        )
    } else if number == libc::SYS_unlinkat as u64 {
        unlink_at(memory, state, args[0] as libc::c_int, args[1], args[2])
    } else if number == libc::SYS_rename as u64 {
        rename_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            0,
        )
    } else if number == libc::SYS_renameat as u64 {
        rename_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            0,
        )
    } else if number == libc::SYS_renameat2 as u64 {
        rename_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            args[4],
        )
    } else if number == libc::SYS_link as u64 {
        link_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            0,
        )
    } else if number == libc::SYS_linkat as u64 {
        link_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            args[4],
        )
    } else if number == libc::SYS_symlink as u64 {
        symlink_at(memory, state, args[0], libc::AT_FDCWD, args[1])
    } else if number == libc::SYS_symlinkat as u64 {
        symlink_at(memory, state, args[0], args[1] as libc::c_int, args[2])
    } else if number == libc::SYS_getcwd as u64 {
        getcwd(memory, state, args)
    } else if number == libc::SYS_chdir as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        chdir(memory, state, args)
    } else if number == libc::SYS_fchdir as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchdir(state, args)
    } else if number == libc::SYS_getdents64 as u64 {
        getdents64(memory, state, args)
    } else if number == libc::SYS_getpid as u64 || number == libc::SYS_gettid as u64 {
        i64::from(state.pid)
    } else if number == libc::SYS_getppid as u64 {
        i64::from(state.ppid)
    } else if number == libc::SYS_getpgrp as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-92): Review fixed guest process-group identity.
        i64::from(state.pid)
    } else if number == libc::SYS_wait4 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        wait4(memory, state, args)
    } else if number == libc::SYS_getuid as u64
        || number == libc::SYS_geteuid as u64
        || number == libc::SYS_getgid as u64
        || number == libc::SYS_getegid as u64
    {
        0
    } else if number == libc::SYS_setresuid as u64 || number == libc::SYS_setresgid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        set_fixed_root_ids(&args[..3])
    } else if number == libc::SYS_getgroups as u64 {
        getgroups(memory, args)
    } else if number == libc::SYS_flock as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        flock(state, args)
    } else if number == libc::SYS_fchown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchown(state, args[0])
    } else if number == libc::SYS_chown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchownat(memory, state, libc::AT_FDCWD, args[0], 0)
    } else if number == libc::SYS_lchown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchownat(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } else if number == libc::SYS_fchownat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchownat(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[4] as libc::c_int,
        )
    } else if number == libc::SYS_listxattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        path_xattr_list(state, memory, args[0], false)
    } else if number == libc::SYS_llistxattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        path_xattr_list(state, memory, args[0], true)
    } else if number == libc::SYS_flistxattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fd_xattr_list(state, args[0])
    } else if number == libc::SYS_umask as u64 {
        let previous = state.umask;
        state.umask = args[0] as libc::mode_t & 0o777;
        i64::from(previous)
    } else if number == libc::SYS_fchmod as u64 {
        fchmod(state, args)
    } else if number == libc::SYS_chmod as u64 {
        fchmodat(memory, state, libc::AT_FDCWD, args[0], args[1], 0)
    } else if number == libc::SYS_fchmodat as u64 {
        // SYS_fchmodat has three arguments; r10 is unspecified guest state.
        fchmodat(memory, state, args[0] as libc::c_int, args[1], args[2], 0)
    } else if number == libc::SYS_mknod as u64 {
        mknod_at(memory, state, libc::AT_FDCWD, args[0], args[1], args[2])
    } else if number == libc::SYS_mknodat as u64 {
        mknod_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2],
            args[3],
        )
    } else if number == libc::SYS_utimensat as u64 {
        utimensat(memory, state, args)
    } else if number == libc::SYS_arch_prctl as u64 {
        return arch_prctl(memory, state, args);
    } else if number == libc::SYS_prctl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        prctl(args)
    } else if number == libc::SYS_getxattr as u64
        || number == libc::SYS_lgetxattr as u64
        || number == libc::SYS_fgetxattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        getxattr(memory, state, number, args)
    } else if number == libc::SYS_brk as u64 {
        brk(memory, state, args[0])
    } else if number == libc::SYS_mmap as u64 {
        mmap(memory, state, args)
    } else if number == libc::SYS_munmap as u64 {
        munmap(memory, args[0], args[1])
    } else if number == libc::SYS_mremap as u64 {
        mremap(memory, state, args)
    } else if number == libc::SYS_mprotect as u64 || number == libc::SYS_madvise as u64 {
        validate_range(memory, args[0], args[1])
    } else if number == libc::SYS_mincore as u64 {
        mincore(memory, args)
    } else if number == libc::SYS_getcpu as u64 {
        getcpu(memory, args)
    } else if number == libc::SYS_sched_getaffinity as u64 {
        sched_getaffinity(memory, state, args)
    } else if number == libc::SYS_sched_getscheduler as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_getscheduler(state, args)
    } else if number == libc::SYS_sched_setscheduler as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_setscheduler(memory, state, args)
    } else if number == libc::SYS_sched_getparam as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_getparam(memory, state, args)
    } else if number == libc::SYS_sched_setparam as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_setparam(memory, state, args)
    } else if number == libc::SYS_sched_getattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_getattr(memory, state, args)
    } else if number == libc::SYS_sched_get_priority_min as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_priority_bound(args[0], false)
    } else if number == libc::SYS_sched_get_priority_max as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_priority_bound(args[0], true)
    } else if number == libc::SYS_getpriority as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        getpriority(state, args)
    } else if number == libc::SYS_setpriority as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        setpriority(state, args)
    } else if number == libc::SYS_ioprio_get as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        ioprio_get(state, args)
    } else if number == libc::SYS_ioprio_set as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        ioprio_set(state, args)
    } else if number == libc::SYS_membarrier as u64 {
        match (args[0] as libc::c_int, args[1] as libc::c_uint) {
            (0, 0) => i64::from(MEMBARRIER_SUPPORTED),
            (1, 0) => 0,
            _ => negative_errno(libc::EINVAL),
        }
    } else if number == libc::SYS_getrandom as u64 {
        getrandom(memory, args[0], args[1])
    } else if number == libc::SYS_clock_gettime as u64 {
        write_bytes(memory, args[1], &[0; 16])
    } else if number == libc::SYS_gettimeofday as u64 {
        gettimeofday(memory, args)
    } else if number == libc::SYS_readlink as u64 {
        readlink(memory, state, args)
    } else if number == libc::SYS_uname as u64 {
        uname(memory, args[0])
    } else if number == libc::SYS_prlimit64 as u64 {
        prlimit64(memory, args)
    } else if number == libc::SYS_rt_sigaction as u64 {
        rt_sigaction(memory, state, args)
    } else if number == libc::SYS_rt_sigprocmask as u64 {
        rt_sigprocmask(memory, state, args)
    } else if number == libc::SYS_sigaltstack as u64 {
        sigaltstack(memory, state, args)
    } else if number == libc::SYS_kill as u64
        || number == libc::SYS_tkill as u64
        || number == libc::SYS_tgkill as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        return kill_signal(state, number, args);
    } else if number == libc::SYS_close as u64 {
        close(state, args[0])
    } else if number == libc::SYS_set_robust_list as u64
        || number == libc::SYS_rseq as u64
        || number == libc::SYS_futex as u64
    {
        0
    } else {
        negative_errno(libc::ENOSYS)
    };

    continue_with(result)
}

/// A [`SyscallExecutor`] that supplies the static-ELF guest-kernel semantics
/// ([`execute_basic_syscall`]) to the tool-driven run loop
/// ([`crate::KvmBackend::run_static_elf_with_tool`]).
///
/// `execute` returns the raw syscall result and records, as side effects for
/// the run loop to apply after the tool handler completes, any pending FS/GS
/// base update (from `arch_prctl`) and the exit code (from `exit`/`exit_group`).
/// This lets a Reverie tool's `tail_inject` drive the same guest-kernel that
/// [`crate::KvmBackend::run_static_elf`] uses directly.
pub(crate) struct ElfExecutor {
    state: LoadedStaticElf,
    output: Option<CapturedOutput>,
    next_pid: Arc<AtomicI32>,
    process_action: Option<ProcessAction>,
    pending_segment: Option<(SegmentBase, u64)>,
    exit_code: Option<i32>,
    clear_child_tid: Option<u64>,
}

impl ElfExecutor {
    pub(crate) fn new(state: LoadedStaticElf, capture_output: bool) -> Self {
        Self {
            state,
            output: capture_output.then(CapturedOutput::default),
            next_pid: Arc::new(AtomicI32::new(2)),
            process_action: None,
            pending_segment: None,
            exit_code: None,
            clear_child_tid: None,
        }
    }

    fn execute_process_action(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Option<i64> {
        let number = request.number();
        let args = request.args();
        if number == libc::SYS_set_tid_address as u64 {
            self.clear_child_tid = (args[0] != 0).then_some(args[0]);
            return Some(i64::from(self.state.pid));
        }
        if number == libc::SYS_fork as u64 || number == libc::SYS_vfork as u64 {
            return Some(self.prepare_fork(None, None, None, None, false));
        }
        if number == libc::SYS_clone as u64 {
            return Some(self.prepare_clone(
                args[0],
                (args[1] != 0).then_some(args[1]),
                args[2],
                args[3],
            ));
        }
        if number == libc::SYS_clone3 as u64 {
            return Some(match read_clone3(memory, args[0], args[1]) {
                Ok(request) => match validate_process_clone_flags(request.flags) {
                    Err(error) => error,
                    Ok(())
                        if request.flags & PROCESS_CLONE_TID_FLAGS != 0
                            || request.tid_fields_present =>
                    {
                        negative_errno(libc::ENOTSUP)
                    }
                    Ok(()) => self.prepare_fork(
                        request.child_stack,
                        None,
                        None,
                        None,
                        request.flags & CLONE_CLEAR_SIGHAND != 0,
                    ),
                },
                Err(error) => error,
            });
        }
        if number == libc::SYS_execve as u64 {
            return Some(self.prepare_exec(memory, args[0], args[1], args[2], libc::AT_FDCWD, 0));
        }
        if number == libc::SYS_execveat as u64 {
            return Some(self.prepare_exec(
                memory,
                args[1],
                args[2],
                args[3],
                args[0] as i32,
                args[4],
            ));
        }
        None
    }

    fn prepare_clone(
        &mut self,
        flags: u64,
        child_stack: Option<u64>,
        parent_tid_address: u64,
        child_tid_address: u64,
    ) -> i64 {
        if let Err(error) = validate_process_clone_flags(flags) {
            return error;
        }
        let parent_tid =
            (flags & libc::CLONE_PARENT_SETTID as u64 != 0).then_some(parent_tid_address);
        let child_tid = (flags & libc::CLONE_CHILD_SETTID as u64 != 0).then_some(child_tid_address);
        let clear_child_tid = (flags & libc::CLONE_CHILD_CLEARTID as u64 != 0
            && child_tid_address != 0)
            .then_some(child_tid_address);
        self.prepare_fork(
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            flags & CLONE_CLEAR_SIGHAND != 0,
        )
    }

    fn prepare_fork(
        &mut self,
        child_stack: Option<u64>,
        parent_tid: Option<u64>,
        child_tid: Option<u64>,
        clear_child_tid: Option<u64>,
        clear_sighand: bool,
    ) -> i64 {
        if self.process_action.is_some() {
            return negative_errno(libc::EBUSY);
        }
        let child_pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        if child_pid <= 0 {
            return negative_errno(libc::EAGAIN);
        }
        self.process_action = Some(ProcessAction::Fork {
            child_pid,
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            clear_sighand,
        });
        i64::from(child_pid)
    }

    fn prepare_exec(
        &mut self,
        memory: &GuestMemory,
        path_address: u64,
        argv_address: u64,
        envp_address: u64,
        dirfd: i32,
        flags: u64,
    ) -> i64 {
        if self.process_action.is_some() {
            return negative_errno(libc::EBUSY);
        }
        if flags != 0 || dirfd != libc::AT_FDCWD {
            return negative_errno(libc::ENOTSUP);
        }
        let path = match read_c_string(memory, path_address, 4096) {
            Ok(path) if !path.is_empty() => path,
            Ok(_) => return negative_errno(libc::ENOENT),
            Err(error) => return read_c_string_errno(error),
        };
        let argv = match read_string_array(memory, argv_address) {
            Ok(argv) => argv,
            Err(error) => return error,
        };
        let envp = match read_string_array(memory, envp_address) {
            Ok(envp) => envp,
            Err(error) => return error,
        };
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(path));
        let path = if path.is_absolute() {
            path
        } else {
            self.state.cwd.join(path)
        };
        let image = match std::fs::read(&path) {
            Ok(image) => image,
            Err(error) => return io_error(error),
        };
        let argv = if argv.is_empty() {
            vec![path.to_string_lossy().into_owned()]
        } else {
            argv
        };
        // TODO-HUMAN-REVIEW(reverie-kvm): in-guest execve `#!` interpreter
        // resolution. The KVM ELF loader only maps ELF images, so a guest that
        // execs a `#!`-script must have its interpreter resolved here, as the
        // kernel's binfmt_script loader does.
        let (image, argv) = match resolve_exec_shebang(path, image, argv) {
            Ok((_interpreter, image, argv)) => (image, argv),
            Err(errno) => return errno,
        };
        self.process_action = Some(ProcessAction::Exec { image, argv, envp });
        0
    }

    pub(crate) fn fork_child(&self, child_pid: i32, clear_sighand: bool) -> crate::Result<Self> {
        let mut state = self.state.try_clone_for_fork(child_pid)?;
        if clear_sighand {
            state.signal_actions.retain(|_, action| {
                let handler = usize::from_ne_bytes(
                    action[..std::mem::size_of::<usize>()]
                        .try_into()
                        .expect("signal handler field size"),
                );
                handler == libc::SIG_IGN
            });
        }
        Ok(Self {
            state,
            output: self.output.is_some().then(CapturedOutput::default),
            next_pid: self.next_pid.clone(),
            process_action: None,
            pending_segment: None,
            exit_code: None,
            clear_child_tid: None,
        })
    }

    pub(crate) fn set_clear_child_tid(&mut self, address: Option<u64>) {
        self.clear_child_tid = address;
    }

    pub(crate) fn take_clear_child_tid(&mut self) -> Option<u64> {
        self.clear_child_tid.take()
    }

    pub(crate) fn take_process_action(&mut self) -> Option<ProcessAction> {
        self.process_action.take()
    }

    pub(crate) fn replace_after_exec(&mut self, state: LoadedStaticElf) {
        let previous = std::mem::replace(&mut self.state, state);
        self.state.inherit_process_state(previous);
        self.pending_segment = None;
        self.exit_code = None;
        self.clear_child_tid = None;
    }

    pub(crate) fn record_child_exit(&mut self, pid: i32, code: i32) {
        self.state.children.insert(pid, code);
    }

    pub(crate) fn append_output(&mut self, stdout: Vec<u8>, stderr: Vec<u8>) {
        if let Some(output) = self.output.as_mut() {
            output.stdout.extend(stdout);
            output.stderr.extend(stderr);
        }
    }

    pub(crate) fn cwd(&self) -> &std::path::Path {
        &self.state.cwd
    }

    pub(crate) fn auxv(&self) -> &[(libc::c_ulong, libc::c_ulong)] {
        &self.state.auxv
    }

    pub(crate) fn segment_bases(&self) -> (u64, u64) {
        (self.state.fs_base, self.state.gs_base)
    }

    /// Returns and clears a pending FS/GS base update requested via `arch_prctl`.
    pub(crate) fn take_segment(&mut self) -> Option<(SegmentBase, u64)> {
        self.pending_segment.take()
    }

    /// Returns and clears the exit code once the guest calls `exit`/`exit_group`.
    pub(crate) fn take_exit(&mut self) -> Option<i32> {
        self.exit_code.take()
    }

    pub(crate) fn take_output(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.output
            .as_mut()
            .map(CapturedOutput::take)
            .unwrap_or_default()
    }
}

impl SyscallExecutor for ElfExecutor {
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        if let Some(result) = self.execute_process_action(request, memory) {
            return result;
        }
        // Clones share the underlying MAP_SHARED mapping, so writes through this
        // handle reach the guest; `execute_basic_syscall` needs `&mut` access.
        let mut memory = memory.clone();
        match execute_basic_syscall_with_output(
            &mut memory,
            &mut self.state,
            request,
            self.output.as_mut(),
        ) {
            SyscallAction::Continue { result, segment } => {
                if segment.is_some() {
                    self.pending_segment = segment;
                }
                result
            }
            SyscallAction::Exit(code) => {
                self.exit_code = Some(code);
                0
            }
        }
    }
}

fn fd_status_flags(fd: RawFd) -> Result<libc::c_int, i64> {
    // SAFETY: fd names a live descriptor and F_GETFL takes no third argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        Ok(flags)
    }
}

fn file_status_flags(file: &std::fs::File) -> Result<libc::c_int, i64> {
    fd_status_flags(file.as_raw_fd())
}

fn file_mode(file: &std::fs::File) -> Result<libc::mode_t, i64> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and file owns a live descriptor.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    Ok(unsafe { stat.assume_init() }.st_mode)
}

fn ensure_read_access(file: &std::fs::File) -> Result<(), i64> {
    let flags = file_status_flags(file)?;
    if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE == libc::O_WRONLY {
        return Err(negative_errno(libc::EBADF));
    }
    Ok(())
}

fn ensure_readable(file: &std::fs::File) -> Result<(), i64> {
    ensure_read_access(file)?;
    if file_mode(file)? & libc::S_IFMT == libc::S_IFDIR {
        return Err(negative_errno(libc::EISDIR));
    }
    Ok(())
}

fn ensure_writable(file: &std::fs::File) -> Result<(), i64> {
    ensure_writable_fd(file.as_raw_fd())
}

fn ensure_writable_fd(fd: RawFd) -> Result<(), i64> {
    let flags = fd_status_flags(fd)?;
    if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE == libc::O_RDONLY {
        Err(negative_errno(libc::EBADF))
    } else {
        Ok(())
    }
}

fn ensure_directory(file: &std::fs::File) -> Result<(), i64> {
    if file_status_flags(file)? & libc::O_PATH != 0 {
        return Err(negative_errno(libc::EBADF));
    }
    if file_mode(file)? & libc::S_IFMT != libc::S_IFDIR {
        return Err(negative_errno(libc::ENOTDIR));
    }
    Ok(())
}

/// Maximum `#!` interpreter indirection levels, matching the Linux kernel's
/// `BINPRM_MAX_RECURSION` limit for chained script interpreters.
const MAX_SHEBANG_DEPTH: usize = 4;

/// Resolve `#!` interpreter scripts for in-guest `execve(2)`, mirroring the
/// kernel's `binfmt_script` loader (`fs/binfmt_script.c`).
///
/// The reverie-kvm ELF loader can only map ELF images, so a guest that execs a
/// `#!`-script (for example a `sh` wrapper that execs another wrapper) must have
/// its interpreter resolved here. On success the returned image is the
/// interpreter's file contents and `argv` is rewritten in kernel order:
/// `[interp, shebang_args.., script_path, <original argv[1..]>]`. Errors are
/// returned as negative errnos.
fn resolve_exec_shebang(
    mut path: std::path::PathBuf,
    mut image: Vec<u8>,
    mut argv: Vec<String>,
) -> Result<(std::path::PathBuf, Vec<u8>, Vec<String>), i64> {
    let mut depth = 0;
    while image.starts_with(b"#!") {
        depth += 1;
        if depth > MAX_SHEBANG_DEPTH {
            return Err(negative_errno(libc::ELOOP));
        }
        let line_end = image
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(image.len());
        // Skip "#!" and any leading blanks, then take the interpreter token.
        let mut start = 2;
        while start < line_end && matches!(image[start], b' ' | b'\t') {
            start += 1;
        }
        let mut end = start;
        while end < line_end && !matches!(image[end], b' ' | b'\t' | b'\r') {
            end += 1;
        }
        if start == end {
            return Err(negative_errno(libc::ENOEXEC));
        }
        let interpreter = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&image[start..end]));
        // Remaining tokens on the directive line become interpreter arguments.
        let mut shebang_args: Vec<String> = String::from_utf8_lossy(&image[end..line_end])
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();

        let mut rewritten = Vec::with_capacity(argv.len() + shebang_args.len() + 2);
        rewritten.push(interpreter.to_string_lossy().into_owned());
        rewritten.append(&mut shebang_args);
        rewritten.push(path.to_string_lossy().into_owned());
        if argv.len() > 1 {
            rewritten.extend_from_slice(&argv[1..]);
        }
        argv = rewritten;

        path = interpreter;
        image = std::fs::read(&path).map_err(io_error)?;
    }
    Ok((path, image, argv))
}

fn ensure_read_capable(file: &std::fs::File) -> Result<(), i64> {
    ensure_read_access(file)?;
    // A zero-iovec readv tests FMODE_CAN_READ without consuming input or
    // invoking the descriptor's file-specific read implementation.
    let result = unsafe { libc::readv(file.as_raw_fd(), std::ptr::null::<libc::iovec>(), 0) };
    if result < 0 {
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn write(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    output: Option<&mut CapturedOutput>,
) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let standard = is_open_standard(state, fd);
    let output_destination = output_alias(state, fd);
    if !standard && !state.files.contains_key(&fd) {
        return negative_errno(libc::EBADF);
    }
    let descriptor = if standard && fd == libc::STDIN_FILENO {
        state.stdin.as_ref()
    } else if standard {
        None
    } else {
        state.files.get(&fd)
    };
    if let Some(descriptor) = descriptor
        && let Err(error) = ensure_writable(descriptor)
    {
        return error;
    }
    if length == 0 {
        return 0;
    }

    let mut bytes = vec![0; length];
    if memory.read(args[1], &mut bytes).is_err() {
        return negative_errno(libc::EFAULT);
    }

    if let Some(output_destination) = output_destination {
        if let Some(output) = output {
            let destination = match output_destination {
                OutputAlias::Stdout => &mut output.stdout,
                OutputAlias::Stderr => &mut output.stderr,
            };
            if destination
                .len()
                .checked_add(bytes.len())
                .is_none_or(|length| length > MAX_CAPTURED_OUTPUT)
            {
                return negative_errno(libc::EFBIG);
            }
            destination.extend_from_slice(&bytes);
            return bytes.len() as i64;
        }
        if standard {
            return host_write(fd, &bytes);
        }
    }
    if standard {
        return state
            .stdin
            .as_mut()
            .expect("open standard input disappeared")
            .write(&bytes)
            .map_or_else(io_error, |count| count as i64);
    }

    write_without_sigpipe(
        state
            .files
            .get(&fd)
            .expect("owned descriptor disappeared")
            .as_raw_fd(),
        &bytes,
    )
}

fn signal_is_pending(signal: libc::c_int) -> Result<bool, libc::c_int> {
    let mut pending = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: pending is writable and sigpending initializes it on success.
    if unsafe { libc::sigpending(pending.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    // SAFETY: sigpending initialized the set on success.
    let member = unsafe { libc::sigismember(pending.as_ptr(), signal) };
    if member < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(member == 1)
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#120): guest writev gathers each iovec and reuses
// the scalar write path, so descriptor routing, captured-output aliasing, and
// SIGPIPE suppression stay identical to write(2). Programs such as javac/java
// emit their startup diagnostics with writev and abort (exit 127) when it is
// ENOSYS.
fn writev(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    mut output: Option<&mut CapturedOutput>,
) -> i64 {
    let Ok(count) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if count > libc::UIO_MAXIOV as usize {
        return negative_errno(libc::EINVAL);
    }
    let mut total: i64 = 0;
    for index in 0..count {
        let entry = args[1] + (index as u64) * 16;
        let mut base = [0u8; 8];
        let mut len = [0u8; 8];
        if memory.read(entry, &mut base).is_err() || memory.read(entry + 8, &mut len).is_err() {
            return if total > 0 {
                total
            } else {
                negative_errno(libc::EFAULT)
            };
        }
        let iov_base = u64::from_le_bytes(base);
        let iov_len = u64::from_le_bytes(len);
        if iov_len == 0 {
            continue;
        }
        let write_args = [args[0], iov_base, iov_len, 0, 0, 0];
        let result = write(memory, state, &write_args, output.as_deref_mut());
        if result < 0 {
            return if total > 0 { total } else { result };
        }
        total = total.saturating_add(result);
        if (result as u64) < iov_len {
            break; // a short write ends the gather, matching writev(2)
        }
    }
    total
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#120): guest readv scatters into each iovec via the
// scalar read path; a short read or EOF stops the scatter, matching readv(2).
fn readv(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(count) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if count > libc::UIO_MAXIOV as usize {
        return negative_errno(libc::EINVAL);
    }
    let mut total: i64 = 0;
    for index in 0..count {
        let entry = args[1] + (index as u64) * 16;
        let mut base = [0u8; 8];
        let mut len = [0u8; 8];
        if memory.read(entry, &mut base).is_err() || memory.read(entry + 8, &mut len).is_err() {
            return if total > 0 {
                total
            } else {
                negative_errno(libc::EFAULT)
            };
        }
        let iov_base = u64::from_le_bytes(base);
        let iov_len = u64::from_le_bytes(len);
        if iov_len == 0 {
            continue;
        }
        let read_args = [args[0], iov_base, iov_len, 0, 0, 0];
        let result = read(memory, state, &read_args);
        if result < 0 {
            return if total > 0 { total } else { result };
        }
        total = total.saturating_add(result);
        if (result as u64) < iov_len {
            break; // a short read or EOF ends the scatter
        }
    }
    total
}

fn write_without_sigpipe(fd: RawFd, bytes: &[u8]) -> i64 {
    // A guest backing pipe must not deliver SIGPIPE into the supervisor. Block it in this thread,
    // then synchronously consume the signal generated by this write while preserving a signal that
    // was already pending before the write.
    let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: blocked is writable and sigemptyset initializes it on success.
    if unsafe { libc::sigemptyset(blocked.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: sigemptyset initialized blocked, and SIGPIPE is a valid signal.
    if unsafe { libc::sigaddset(blocked.as_mut_ptr(), libc::SIGPIPE) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: both calls above initialized blocked.
    let blocked = unsafe { blocked.assume_init() };
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: blocked is initialized, previous is writable, and pthread_sigmask copies the old mask.
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous.as_mut_ptr()) };
    if mask_result != 0 {
        return negative_errno(mask_result);
    }
    // SAFETY: pthread_sigmask initialized previous on success.
    let previous = unsafe { previous.assume_init() };

    let had_pending_sigpipe = match signal_is_pending(libc::SIGPIPE) {
        Ok(pending) => pending,
        Err(error) => {
            // SAFETY: previous contains the signal mask saved above.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
            return negative_errno(error);
        }
    };

    // SAFETY: bytes is a live host buffer and fd is a live backing descriptor.
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
    let error = (written < 0).then(std::io::Error::last_os_error);

    let mut drain_error = None;
    if error.as_ref().and_then(std::io::Error::raw_os_error) == Some(libc::EPIPE)
        && !had_pending_sigpipe
    {
        match signal_is_pending(libc::SIGPIPE) {
            Ok(true) => {
                let mut signal = 0;
                loop {
                    // SAFETY: blocked contains only SIGPIPE and signal is writable.
                    let wait_result = unsafe { libc::sigwait(&blocked, &mut signal) };
                    if wait_result == 0 {
                        debug_assert_eq!(signal, libc::SIGPIPE);
                        break;
                    }
                    if wait_result != libc::EINTR {
                        drain_error = Some(wait_result);
                        break;
                    }
                }
            }
            Ok(false) => {}
            Err(error) => drain_error = Some(error),
        }
    }

    // SAFETY: previous contains the signal mask saved by pthread_sigmask.
    let restore_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    if restore_result != 0 {
        return negative_errno(restore_result);
    }
    if let Some(error) = drain_error {
        return negative_errno(error);
    }
    error.map_or(written as i64, io_error)
}

fn host_write(fd: RawFd, bytes: &[u8]) -> i64 {
    // SAFETY: bytes is a live host buffer and fd is a standard output descriptor.
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
    if written < 0 {
        negative_errno(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        )
    } else {
        written as i64
    }
}

fn host_read(memory: &mut GuestMemory, fd: RawFd, address: u64, length: usize) -> i64 {
    if !range_is_valid(memory, address, length as u64) {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; length];
    // SAFETY: bytes is writable for length bytes and fd is a live host descriptor.
    let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len()) };
    if count < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let count = count as usize;
    if count == 0 {
        return 0;
    }
    match memory.write(address, &bytes[..count]) {
        Ok(()) => count as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn read(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    if is_open_standard(state, fd) {
        if fd != libc::STDIN_FILENO {
            return negative_errno(libc::EBADF);
        }
        let Some(stdin) = state.stdin.as_ref() else {
            return negative_errno(libc::EBADF);
        };
        if let Err(error) = ensure_read_capable(stdin) {
            return error;
        }
        if !range_is_valid(memory, args[1], args[2]) {
            return negative_errno(libc::EFAULT);
        }
        return host_read(memory, stdin.as_raw_fd(), args[1], length);
    }
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_read_capable(file) {
        return error;
    }
    if !range_is_valid(memory, args[1], args[2]) {
        return negative_errno(libc::EFAULT);
    }
    if let Err(error) = ensure_readable(file) {
        return error;
    }
    if requested_length == 0 {
        return 0;
    }
    let mut bytes = vec![0; length];
    match state
        .files
        .get_mut(&fd)
        .expect("owned descriptor disappeared")
        .read(&mut bytes)
    {
        Ok(count) => match memory.write(args[1], &bytes[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        },
        Err(error) => io_error(error),
    }
}

fn pread64(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_readable(file) {
        return error;
    }
    if length == 0 {
        return 0;
    }
    if !range_is_valid(memory, args[1], length as u64) {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; length];
    match file.read_at(&mut bytes, args[3]) {
        Ok(count) => match memory.write(args[1], &bytes[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        },
        Err(error) => io_error(error),
    }
}

fn pwrite64(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_writable(file) {
        return error;
    }
    if length == 0 {
        return 0;
    }
    let mut bytes = vec![0; length];
    if memory.read(args[1], &mut bytes).is_err() {
        return negative_errno(libc::EFAULT);
    }
    file.write_at(&bytes, args[3])
        .map_or_else(io_error, |count| count as i64)
}

fn lseek(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(whence) = i32::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    // SAFETY: host_fd names a live descriptor. Linux validates offset and whence.
    let result = unsafe { libc::lseek(host_fd, args[1] as libc::off_t, whence) };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result as i64
    }
}

fn ftruncate(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_writable_fd(host_fd) {
        return error;
    }
    let length = args[1] as libc::off_t;
    if length < 0 {
        return negative_errno(libc::EINVAL);
    }
    // SAFETY: host_fd names a live writable descriptor and length is nonnegative.
    if unsafe { libc::ftruncate(host_fd, length) } == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

fn sync_file(state: &LoadedStaticElf, raw_fd: u64, data_only: bool) -> i64 {
    let Ok(fd) = i32::try_from(raw_fd) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    // SAFETY: host_fd names a live descriptor. The host syscall validates its type.
    let result = unsafe {
        if data_only {
            libc::fdatasync(host_fd)
        } else {
            libc::fsync(host_fd)
        }
    };
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

fn open(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    open_file(memory, state, libc::AT_FDCWD, args[0], args[1], args[2])
}

fn openat(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    open_file(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2],
        args[3],
    )
}

// TODO-HUMAN-REVIEW(PR-112): Review creat delegation to the open path.
//
// `creat(path, mode)` is defined by Linux as
// `open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)`. GNU tar (and other
// programs) still emit the raw `creat` syscall for their output file, which
// previously fell through to `ENOSYS`. Delegating to `open_file` reuses the
// existing create/procfs/umask handling so the behavior matches the equivalent
// `open`/`openat` call exactly.
fn creat(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let flags = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
    open_file(memory, state, libc::AT_FDCWD, args[0], flags, args[1])
}

fn open_file(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_flags: u64,
    raw_mode: u64,
) -> i64 {
    let path = match read_c_string(memory, path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() {
        return negative_errno(libc::ENOENT);
    }
    // Serve the synthetic /proc surface before touching the host filesystem, so
    // deterministic content replaces the deliberately-refused real procfs.
    if let Some(content) = synthetic_proc_content(state, &path) {
        let flags = u64::from(raw_flags as libc::c_int as u32) & LEGACY_OPEN_FLAGS;
        if flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 {
            return negative_errno(libc::EACCES);
        }
        let normalized =
            normalize_proc_path(state, &path).expect("a synthesized /proc path always normalizes");
        let close_on_exec = flags & libc::O_CLOEXEC as u64 != 0;
        return open_synthetic_proc(state, &normalized, &content, close_on_exec);
    }
    let flags = u64::from(raw_flags as libc::c_int as u32) & LEGACY_OPEN_FLAGS;
    let guest_cloexec = flags & libc::O_CLOEXEC as u64 != 0;
    if let Some(guest_fd) = guest_fd_path(&path) {
        return open_guest_fd_path(state, guest_fd, flags, guest_cloexec);
    }
    if path == b"/dev/random" || path == b"/dev/urandom" {
        let bytes = (0..64 * 1024)
            .map(|index| (index as u8).wrapping_mul(73).wrapping_add(41))
            .collect::<Vec<_>>();
        return open_virtual_file(state, &bytes, flags, guest_cloexec);
    }
    if path == b"/proc/uptime" {
        return open_virtual_file(state, b"0.00 0.00\n", flags, guest_cloexec);
    }
    if path == b"/proc/self/loginuid" {
        return open_virtual_file(state, b"0", flags, guest_cloexec);
    }
    let Ok((host_dirfd, path)) = host_dirfd_and_path(state, guest_dirfd, &path) else {
        return negative_errno(libc::EBADF);
    };
    let uses_mode = flags & libc::O_CREAT as u64 != 0
        || flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64;
    let mode = if uses_mode {
        u64::from(raw_mode as libc::mode_t & 0o7777 & !state.umask)
    } else {
        0
    };
    let named_create = flags & libc::O_CREAT as u64 != 0
        && flags & libc::O_TMPFILE as u64 != libc::O_TMPFILE as u64;
    // Hermit requires a stable external filesystem. This follow-target probe
    // distinguishes an existing target from a dangling symlink before the
    // atomic O_EXCL create attempt below.
    let target_existed = named_create && open_host_metadata_path(host_dirfd, &path, false).is_ok();
    let open_with_flags = |open_flags| {
        let how = OpenHow {
            flags: open_flags,
            mode,
            resolve: RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: path and how are live; Linux validates the descriptor and flags.
        unsafe {
            libc::syscall(
                libc::SYS_openat2,
                host_dirfd,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        }
    };
    let (host_fd, created) = if named_create {
        let exclusive_fd = open_with_flags(flags | libc::O_EXCL as u64);
        if exclusive_fd >= 0 {
            (exclusive_fd, true)
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) || flags & libc::O_EXCL as u64 != 0 {
                return io_error(error);
            }
            let host_fd = open_with_flags(flags);
            if host_fd < 0 {
                return io_error(std::io::Error::last_os_error());
            }
            (host_fd, !target_existed)
        }
    } else {
        let host_fd = open_with_flags(flags);
        if host_fd < 0 {
            return io_error(std::io::Error::last_os_error());
        }
        (
            host_fd,
            flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64,
        )
    };
    // SAFETY: openat2 returned a new owned descriptor on success.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd as RawFd) };
    if let Err(error) = ensure_not_procfs(&file) {
        return error;
    }
    if uses_mode && created {
        // Override the supervisor umask only for a file created by this call.
        // SAFETY: file is a live owned descriptor and mode is bounded above.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return io_error(std::io::Error::last_os_error());
        }
    }
    insert_file_with_flags(state, file, guest_cloexec, None)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review deterministic random-device and procfs virtual files.
fn open_virtual_file(
    state: &mut LoadedStaticElf,
    contents: &[u8],
    flags: u64,
    close_on_exec: bool,
) -> i64 {
    let unsupported = (libc::O_CREAT
        | libc::O_DIRECTORY
        | libc::O_EXCL
        | libc::O_PATH
        | libc::O_TMPFILE
        | libc::O_TRUNC) as u64;
    if flags & unsupported != 0 {
        return negative_errno(libc::EINVAL);
    }
    if flags as libc::c_int & libc::O_ACCMODE != libc::O_RDONLY {
        return negative_errno(libc::EACCES);
    }
    let name = c"reverie-kvm-virtual";
    let host_fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    if let Err(error) = file.write_all(contents) {
        return io_error(error);
    }
    let read_only = match std::fs::OpenOptions::new()
        .read(true)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
    {
        Ok(read_only) => read_only,
        Err(error) => return io_error(error),
    };
    drop(file);
    insert_file_with_flags(state, read_only, close_on_exec, None)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn guest_fd_path(path: &[u8]) -> Option<libc::c_int> {
    let suffix = path
        .strip_prefix(b"/dev/fd/")
        .or_else(|| path.strip_prefix(b"/proc/self/fd/"))?;
    if suffix.is_empty() || !suffix.iter().all(u8::is_ascii_digit) {
        return None;
    }
    suffix.iter().try_fold(0_i32, |value, digit| {
        value.checked_mul(10)?.checked_add(i32::from(*digit - b'0'))
    })
}

// TODO-HUMAN-REVIEW(PR-92): Review guest-fd metadata translation.
#[derive(Clone, Copy)]
struct GuestFdMetadata {
    guest_fd: libc::c_int,
    host_fd: RawFd,
    no_follow: bool,
}

fn guest_fd_metadata(
    state: &LoadedStaticElf,
    path: &[u8],
    no_follow: bool,
) -> Result<Option<GuestFdMetadata>, i64> {
    let Some(guest_fd) = guest_fd_path(path) else {
        return Ok(None);
    };
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return Err(negative_errno(libc::ENOENT));
    };
    Ok(Some(GuestFdMetadata {
        guest_fd,
        host_fd,
        no_follow,
    }))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review guest /dev/fd duplication without supervisor procfs exposure.
fn open_guest_fd_path(
    state: &mut LoadedStaticElf,
    guest_fd: libc::c_int,
    flags: u64,
    close_on_exec: bool,
) -> i64 {
    let Some(source_host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::ENOENT);
    };
    let unsupported = (libc::O_CREAT
        | libc::O_DIRECTORY
        | libc::O_EXCL
        | libc::O_NOFOLLOW
        | libc::O_TMPFILE
        | libc::O_TRUNC) as u64;
    if flags & unsupported != 0 {
        return negative_errno(libc::EINVAL);
    }
    let source_flags = match fd_status_flags(source_host_fd) {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    if source_flags & libc::O_ACCMODE != flags as libc::c_int & libc::O_ACCMODE {
        return negative_errno(libc::EACCES);
    }
    let source_alias = output_alias(state, guest_fd);
    let source_proc_inode = state.proc_files.get(&guest_fd).copied();
    // SAFETY: source_host_fd names a live descriptor and F_DUPFD_CLOEXEC
    // returns a new owned descriptor.
    let duplicated = unsafe { libc::fcntl(source_host_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(duplicated) };
    let new_fd = insert_file_with_flags(state, file, close_on_exec, source_alias);
    if new_fd >= 0
        && let Some(inode) = source_proc_inode
    {
        state.proc_files.insert(new_fd as libc::c_int, inode);
    }
    new_fd
}

fn ensure_not_procfs(file: &std::fs::File) -> Result<(), i64> {
    ensure_fd_not_procfs(file.as_raw_fd())
}

fn ensure_fd_not_procfs(fd: RawFd) -> Result<(), i64> {
    let mut statfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs is writable and fd is live.
    if unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstatfs initialized statfs on success.
    if unsafe { statfs.assume_init() }.f_type as libc::c_long == PROC_SUPER_MAGIC {
        return Err(negative_errno(libc::EACCES));
    }
    Ok(())
}

fn open_metadata_path(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
    nofollow: bool,
) -> Result<std::fs::File, i64> {
    let (host_dirfd, path) = host_dirfd_and_path(state, guest_dirfd, path)?;
    let mut flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    if nofollow {
        flags |= libc::O_NOFOLLOW as u64;
    }
    let how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: path and how are live for the call and Linux validates host_dirfd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            host_dirfd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned descriptor on success.
    let file = unsafe { std::fs::File::from_raw_fd(fd as RawFd) };
    ensure_not_procfs(&file)?;
    Ok(file)
}

// AUTONOMOUS-BOT-IMPLEMENTED: Resolve mutation targets without host magic links.
// TODO-HUMAN-REVIEW(#86): Review procfs isolation and Linux mutation semantics.
fn open_host_metadata_path(
    host_dirfd: RawFd,
    path: &CStr,
    nofollow: bool,
) -> Result<std::fs::File, i64> {
    let mut flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    if nofollow {
        flags |= libc::O_NOFOLLOW as u64;
    }
    let how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: path and how are live for the call and Linux validates host_dirfd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            host_dirfd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned descriptor on success.
    let file = unsafe { std::fs::File::from_raw_fd(fd as RawFd) };
    ensure_not_procfs(&file)?;
    Ok(file)
}

fn ensure_mutation_parent_not_procfs(host_dirfd: RawFd, path: &CStr) -> Result<(), i64> {
    let bytes = path.to_bytes();
    if bytes.is_empty() {
        return Ok(());
    }
    let parent = match bytes.iter().rposition(|byte| *byte == b'/') {
        Some(0) => b"/".as_slice(),
        Some(index) => &bytes[..index],
        None => b".".as_slice(),
    };
    let parent = CString::new(parent).map_err(|_| negative_errno(libc::EINVAL))?;
    let parent = open_host_metadata_path(host_dirfd, &parent, false)?;
    if !parent.metadata().map_err(io_error)?.is_dir() {
        return Err(negative_errno(libc::ENOTDIR));
    }
    Ok(())
}

// AUTONOMOUS-BOT-IMPLEMENTED: Preserve captured stdio identity across descriptor duplication.
// TODO-HUMAN-REVIEW(#91): Review output alias lifecycle across dup, close, fork, and exec.
#[derive(Clone, Copy)]
enum OutputAlias {
    Stdout,
    Stderr,
}

fn output_alias(state: &LoadedStaticElf, fd: libc::c_int) -> Option<OutputAlias> {
    if state.stdout_alias_fds.contains(&fd)
        || (fd == libc::STDOUT_FILENO && is_open_standard(state, fd))
    {
        Some(OutputAlias::Stdout)
    } else if state.stderr_alias_fds.contains(&fd)
        || (fd == libc::STDERR_FILENO && is_open_standard(state, fd))
    {
        Some(OutputAlias::Stderr)
    } else {
        None
    }
}

fn set_output_alias(state: &mut LoadedStaticElf, fd: libc::c_int, alias: Option<OutputAlias>) {
    state.stdout_alias_fds.remove(&fd);
    state.stderr_alias_fds.remove(&fd);
    match alias {
        Some(OutputAlias::Stdout) => {
            state.stdout_alias_fds.insert(fd);
        }
        Some(OutputAlias::Stderr) => {
            state.stderr_alias_fds.insert(fd);
        }
        None => {}
    }
}

fn insert_file_with_flags(
    state: &mut LoadedStaticElf,
    file: std::fs::File,
    close_on_exec: bool,
    output_alias: Option<OutputAlias>,
) -> i64 {
    let Some(fd) = (0..GUEST_NOFILE_LIMIT)
        .find(|fd| !is_open_standard(state, *fd) && !state.files.contains_key(fd))
    else {
        return negative_errno(libc::EMFILE);
    };
    state.files.insert(fd, file);
    if close_on_exec {
        state.cloexec_fds.insert(fd);
    } else {
        state.cloexec_fds.remove(&fd);
    }
    set_output_alias(state, fd, output_alias);
    i64::from(fd)
}

// AUTONOMOUS-BOT-IMPLEMENTED: Model fcntl descriptor duplication in the guest table.
// TODO-HUMAN-REVIEW(#91): Review minimum/error precedence and standard-fd ownership.
fn duplicate_fd_at_or_above(
    state: &mut LoadedStaticElf,
    old_host_fd: RawFd,
    raw_minimum: u64,
    close_on_exec: bool,
    output_alias: Option<OutputAlias>,
    source_proc_inode: Option<u64>,
) -> i64 {
    let minimum = raw_minimum as libc::c_int;
    if !(0..GUEST_NOFILE_LIMIT).contains(&minimum) {
        return negative_errno(libc::EINVAL);
    }
    let Some(fd) = (minimum..GUEST_NOFILE_LIMIT)
        .find(|fd| !is_open_standard(state, *fd) && !state.files.contains_key(fd))
    else {
        return negative_errno(libc::EMFILE);
    };

    // SAFETY: old_host_fd is live. F_DUPFD_CLOEXEC returns an owned
    // descriptor; guest CLOEXEC is modeled independently in cloexec_fds.
    let duplicated = unsafe { libc::fcntl(old_host_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(duplicated) };
    state.files.insert(fd, file);
    if close_on_exec {
        state.cloexec_fds.insert(fd);
    } else {
        state.cloexec_fds.remove(&fd);
    }
    if (0..=2).contains(&fd) {
        state.closed_standard_fds.insert(fd);
    } else {
        state.closed_standard_fds.remove(&fd);
    }
    set_output_alias(state, fd, output_alias);
    if let Some(inode) = source_proc_inode {
        state.proc_files.insert(fd, inode);
    }
    i64::from(fd)
}

fn duplicate_fd(
    state: &mut LoadedStaticElf,
    raw_old_fd: u64,
    raw_new_fd: Option<u64>,
    raw_flags: u64,
    is_dup3: bool,
) -> i64 {
    let flags = raw_flags as libc::c_int;
    if !is_dup3 && flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    if is_dup3 && flags & !libc::O_CLOEXEC != 0 {
        return negative_errno(libc::EINVAL);
    }
    let old_fd = raw_old_fd as libc::c_int;
    let source_alias = output_alias(state, old_fd);
    let source_proc_inode = state.proc_files.get(&old_fd).copied();
    let Some(old_host_fd) = host_fd(state, old_fd) else {
        return negative_errno(libc::EBADF);
    };
    let close_on_exec = is_dup3 && flags & libc::O_CLOEXEC != 0;

    let new_fd = match raw_new_fd {
        Some(raw_new_fd) => {
            let new_fd = raw_new_fd as libc::c_int;
            if !(0..GUEST_NOFILE_LIMIT).contains(&new_fd) {
                return negative_errno(libc::EBADF);
            }
            if new_fd == old_fd {
                return if is_dup3 {
                    negative_errno(libc::EINVAL)
                } else {
                    i64::from(new_fd)
                };
            }
            Some(new_fd)
        }
        None => None,
    };

    // SAFETY: old_host_fd names a live descriptor. F_DUPFD_CLOEXEC returns a
    // new owned descriptor and prevents it leaking through a supervisor exec.
    let duplicated = unsafe { libc::fcntl(old_host_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(duplicated) };
    if let Some(new_fd) = new_fd {
        state.files.insert(new_fd, file);
        if close_on_exec {
            state.cloexec_fds.insert(new_fd);
        } else {
            state.cloexec_fds.remove(&new_fd);
        }
        if (0..=2).contains(&new_fd) {
            state.closed_standard_fds.insert(new_fd);
        } else {
            state.closed_standard_fds.remove(&new_fd);
        }
        set_output_alias(state, new_fd, source_alias);
        if let Some(inode) = source_proc_inode {
            state.proc_files.insert(new_fd, inode);
        } else {
            state.proc_files.remove(&new_fd);
        }
        i64::from(new_fd)
    } else {
        let new_fd = insert_file_with_flags(state, file, close_on_exec, source_alias);
        if new_fd >= 0
            && let Some(inode) = source_proc_inode
        {
            state.proc_files.insert(new_fd as libc::c_int, inode);
        }
        new_fd
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#54): Confirm guest-fd ownership and pipe2 flag boundaries.
fn pipe2(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    address: u64,
    raw_flags: u64,
) -> i64 {
    let flags = raw_flags as libc::c_int;
    let allowed_flags = libc::O_CLOEXEC | libc::O_DIRECT | libc::O_NONBLOCK | libc::O_EXCL;
    if flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    let mut host_fds = [-1; 2];
    // Host descriptors are internal implementation details and must never leak through a
    // supervisor exec. Guest close-on-exec state will need separate modeling when KVM gains exec.
    let host_flags = flags | libc::O_CLOEXEC;
    // SAFETY: host_fds has room for both descriptors and flags were validated above.
    if unsafe { libc::pipe2(host_fds.as_mut_ptr(), host_flags) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new owned descriptors on success.
    let read_end = unsafe { std::fs::File::from_raw_fd(host_fds[0]) };
    // SAFETY: pipe2 returned two new owned descriptors on success.
    let write_end = unsafe { std::fs::File::from_raw_fd(host_fds[1]) };
    let close_on_exec = flags & libc::O_CLOEXEC != 0;

    let read_fd = insert_file_with_flags(state, read_end, close_on_exec, None);
    if read_fd < 0 {
        return read_fd;
    }
    let write_fd = insert_file_with_flags(state, write_end, close_on_exec, None);
    if write_fd < 0 {
        state.files.remove(&(read_fd as libc::c_int));
        state.cloexec_fds.remove(&(read_fd as libc::c_int));
        return write_fd;
    }

    let read_fd = read_fd as libc::c_int;
    let write_fd = write_fd as libc::c_int;
    let mut bytes = [0; std::mem::size_of::<[libc::c_int; 2]>()];
    bytes[..std::mem::size_of::<libc::c_int>()].copy_from_slice(&read_fd.to_ne_bytes());
    bytes[std::mem::size_of::<libc::c_int>()..].copy_from_slice(&write_fd.to_ne_bytes());
    if memory.write(address, &bytes).is_err() {
        state.files.remove(&read_fd);
        state.files.remove(&write_fd);
        state.cloexec_fds.remove(&read_fd);
        state.cloexec_fds.remove(&write_fd);
        return negative_errno(libc::EFAULT);
    }
    0
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review guest descriptor translation and deterministic nonblocking poll semantics.
fn poll(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(count) = usize::try_from(args[1]) else {
        return negative_errno(libc::EINVAL);
    };
    if count > GUEST_NOFILE_LIMIT as usize {
        return negative_errno(libc::EINVAL);
    }
    let Some(byte_length) = count.checked_mul(std::mem::size_of::<libc::pollfd>()) else {
        return negative_errno(libc::EINVAL);
    };
    if byte_length > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    let mut poll_fds = vec![
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        };
        count
    ];
    {
        // SAFETY: poll_fds is initialized plain ABI data and the byte view is
        // exactly bounded to the vector allocation.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(poll_fds.as_mut_ptr().cast::<u8>(), byte_length)
        };
        if memory.read(args[0], bytes).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }

    let guest_fds = poll_fds
        .iter()
        .map(|poll_fd| poll_fd.fd)
        .collect::<Vec<_>>();
    let mut invalid = vec![false; count];
    for (index, poll_fd) in poll_fds.iter_mut().enumerate() {
        poll_fd.revents = 0;
        if poll_fd.fd < 0 {
            continue;
        }
        match host_fd(state, poll_fd.fd) {
            Some(host_fd) => poll_fd.fd = host_fd,
            None => {
                poll_fd.fd = -1;
                invalid[index] = true;
            }
        }
    }

    // Host wall time is outside the deterministic guest clock. Preserve
    // already-ready events while making every backend poll nonblocking.
    let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), count as libc::nfds_t, 0) };
    if ready < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let mut invalid_count = 0;
    for (index, poll_fd) in poll_fds.iter_mut().enumerate() {
        poll_fd.fd = guest_fds[index];
        if invalid[index] {
            poll_fd.revents = libc::POLLNVAL;
            invalid_count += 1;
        }
    }
    {
        // SAFETY: poll_fds remains initialized ABI data and the byte view is
        // exactly bounded to the vector allocation.
        let bytes =
            unsafe { std::slice::from_raw_parts(poll_fds.as_ptr().cast::<u8>(), byte_length) };
        if memory.write(args[0], bytes).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    i64::from(ready + invalid_count)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review deterministic event-loop and AF_UNIX syscall boundaries.
fn epoll_create1(state: &mut LoadedStaticElf, raw_flags: u64) -> i64 {
    let flags = raw_flags as libc::c_int;
    if flags & !libc::EPOLL_CLOEXEC != 0 {
        return negative_errno(libc::EINVAL);
    }
    // Keep the supervisor descriptor private even when the guest did not ask
    // for close-on-exec; guest descriptor flags are modeled separately.
    let host_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: epoll_create1 returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, flags & libc::EPOLL_CLOEXEC != 0, None)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn epoll_ctl(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(epoll_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Some(target_fd) = host_fd(state, args[2] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let operation = args[1] as libc::c_int;
    let mut event = if operation == libc::EPOLL_CTL_DEL {
        libc::epoll_event { events: 0, u64: 0 }
    } else {
        match read_guest_struct::<libc::epoll_event>(memory, args[3]) {
            Ok(event) => event,
            Err(error) => return error,
        }
    };
    // SAFETY: both descriptors were translated from live guest descriptors;
    // event is initialized and Linux validates the requested operation.
    zero_or_errno(unsafe { libc::epoll_ctl(epoll_fd, operation, target_fd, &mut event) })
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn epoll_wait(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    pwait: bool,
) -> i64 {
    if pwait && args[4] != 0 {
        if args[5] != KERNEL_SIGSET_SIZE as u64 {
            return negative_errno(libc::EINVAL);
        }
        let mut signal_mask = [0; KERNEL_SIGSET_SIZE];
        if memory.read(args[4], &mut signal_mask).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    let Some(epoll_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(max_events) = libc::c_int::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if max_events <= 0 {
        return negative_errno(libc::EINVAL);
    }
    let Ok(count) = usize::try_from(max_events) else {
        return negative_errno(libc::EINVAL);
    };
    let Some(byte_length) = count.checked_mul(std::mem::size_of::<libc::epoll_event>()) else {
        return negative_errno(libc::EINVAL);
    };
    if byte_length > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; count];
    // A real-time host timeout is not a deterministic guest clock. Readiness
    // for already-available descriptor events is preserved with a zero timeout.
    // Guest signal masks are modeled in guest state and must not alter the
    // supervisor thread. With a zero timeout there is no guest blocking window.
    // SAFETY: the event array is writable for max_events entries.
    let ready = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), max_events, 0) };
    if ready < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let ready = ready as usize;
    if ready == 0 {
        return 0;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            events.as_ptr().cast::<u8>(),
            ready * std::mem::size_of::<libc::epoll_event>(),
        )
    };
    match memory.write(args[1], bytes) {
        Ok(()) => ready as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn eventfd2(state: &mut LoadedStaticElf, initial: u64, raw_flags: u64) -> i64 {
    let flags = raw_flags as libc::c_int;
    let allowed = libc::EFD_CLOEXEC | libc::EFD_NONBLOCK | libc::EFD_SEMAPHORE;
    if flags & !allowed != 0 || initial > u64::from(u32::MAX) {
        return negative_errno(libc::EINVAL);
    }
    let host_fd = unsafe { libc::eventfd(initial as libc::c_uint, flags | libc::EFD_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: eventfd returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, flags & libc::EFD_CLOEXEC != 0, None)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn socket(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[0] as libc::c_int != libc::AF_UNIX || args[2] != 0 {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    let socket_type = args[1] as libc::c_int;
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    if base_type != libc::SOCK_DGRAM && base_type != libc::SOCK_STREAM {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let host_fd = unsafe { libc::socket(libc::AF_UNIX, socket_type | libc::SOCK_CLOEXEC, 0) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, socket_type & libc::SOCK_CLOEXEC != 0, None)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn connect(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if host_fd(state, args[0] as libc::c_int).is_none() {
        return negative_errno(libc::EBADF);
    }
    let Ok(length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if length < std::mem::size_of::<libc::sa_family_t>()
        || length > std::mem::size_of::<libc::sockaddr_un>()
    {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; length];
    if memory.read(args[1], &mut address).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let family = libc::sa_family_t::from_ne_bytes(
        address[..std::mem::size_of::<libc::sa_family_t>()]
            .try_into()
            .expect("family slice has exact size"),
    );
    if family != libc::AF_UNIX as libc::sa_family_t {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    let path = &address[std::mem::size_of::<libc::sa_family_t>()..];
    let path = path.split(|byte| *byte == 0).next().unwrap_or(path);
    if path == b"/dev/log" {
        return 0;
    }
    negative_errno(libc::ECONNREFUSED)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn ioctl(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if host_fd(state, args[0] as libc::c_int).is_none() {
        return negative_errno(libc::EBADF);
    }
    match args[1] as libc::c_ulong {
        libc::TCGETS | libc::TIOCGWINSZ | libc::TIOCGPGRP => negative_errno(libc::ENOTTY),
        _ => negative_errno(libc::ENOTTY),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#54): Confirm the fixed root-plus-overflow-group KVM persona.
fn getgroups(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    let size = args[0] as libc::c_int;
    if size < 0 {
        return negative_errno(libc::EINVAL);
    }

    let count = GUEST_SUPPLEMENTARY_GROUPS.len() as libc::c_int;
    if size == 0 {
        return i64::from(count);
    }
    if size < count {
        return negative_errno(libc::EINVAL);
    }

    let mut bytes = Vec::with_capacity(count as usize * std::mem::size_of::<libc::gid_t>());
    for group in GUEST_SUPPLEMENTARY_GROUPS {
        bytes.extend_from_slice(&group.to_ne_bytes());
    }
    match memory.write(args[1], &bytes) {
        Ok(()) => i64::from(count),
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn set_fixed_root_ids(ids: &[u64]) -> i64 {
    if ids.iter().all(|id| matches!(*id as u32, 0 | u32::MAX)) {
        0
    } else {
        negative_errno(libc::EPERM)
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn flock(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let operation = args[1] as libc::c_int;
    let base = operation & !libc::LOCK_NB;
    if !matches!(base, libc::LOCK_SH | libc::LOCK_EX | libc::LOCK_UN)
        || operation & !(libc::LOCK_SH | libc::LOCK_EX | libc::LOCK_UN | libc::LOCK_NB) != 0
    {
        return negative_errno(libc::EINVAL);
    }
    // Detcore owns guest scheduling; host advisory locks would expose external
    // lock ownership and can block on host wall time. A validated guest fd
    // receives the deterministic single-process lock result.
    let _ = host_fd;
    0
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn fchown(state: &LoadedStaticElf, raw_fd: u64) -> i64 {
    if host_fd(state, raw_fd as libc::c_int).is_some() {
        0
    } else {
        negative_errno(libc::EBADF)
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn fchownat(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    flags: libc::c_int,
) -> i64 {
    let allowed = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
    if flags & !allowed != 0 {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(memory, path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() {
        if flags & libc::AT_EMPTY_PATH == 0 {
            return negative_errno(libc::ENOENT);
        }
        return fchown(state, guest_dirfd as u64);
    }
    match open_metadata_path(
        state,
        guest_dirfd,
        &path,
        flags & libc::AT_SYMLINK_NOFOLLOW != 0,
    ) {
        Ok(_) => 0,
        Err(error) => error,
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review the deterministic no-xattr KVM filesystem view.
// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn path_xattr_list(
    state: &LoadedStaticElf,
    memory: &GuestMemory,
    path_address: u64,
    no_follow: bool,
) -> i64 {
    let path = match read_c_string(memory, path_address, 4096) {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => return negative_errno(libc::ENOENT),
        Err(error) => return read_c_string_errno(error),
    };
    match open_metadata_path(state, libc::AT_FDCWD, &path, no_follow) {
        Ok(_) => 0,
        Err(error) => error,
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn fd_xattr_list(state: &LoadedStaticElf, raw_fd: u64) -> i64 {
    if host_fd(state, raw_fd as libc::c_int).is_some() {
        0
    } else {
        negative_errno(libc::EBADF)
    }
}

fn fstat(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and host_fd is a standard or owned descriptor.
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fstat initialized stat on success.
    let mut stat = unsafe { stat.assume_init() };
    if let Some(&inode) = state.proc_files.get(&fd) {
        sanitize_proc_stat(&mut stat, inode);
    }
    sanitize_stat_timestamps(&mut stat);
    write_struct(memory, args[1], &stat)
}

fn path_stat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    flags: libc::c_int,
) -> i64 {
    fstatat_impl(memory, state, libc::AT_FDCWD, args[0], args[1], flags)
}

fn newfstatat(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    fstatat_impl(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2],
        args[3] as libc::c_int,
    )
}

fn fstatat_impl(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    output_address: u64,
    flags: libc::c_int,
) -> i64 {
    let path = match read_c_string(memory, path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    let allowed_flags = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT;
    if flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    if path.is_empty() && flags & libc::AT_EMPTY_PATH == 0 {
        return negative_errno(libc::ENOENT);
    }
    // Path-addressed synthetic /proc file: synthesize deterministic metadata.
    // synthetic_proc_content returns None for an empty path, so no explicit
    // AT_EMPTY_PATH guard is needed here.
    if let Some(content) = synthetic_proc_content(state, &path) {
        let normalized =
            normalize_proc_path(state, &path).expect("a synthesized /proc path always normalizes");
        let stat = synthetic_proc_stat(synthetic_proc_inode(&normalized), content.len());
        return write_struct(memory, output_address, &stat);
    }

    let guest_path = match guest_fd_metadata(state, &path, flags & libc::AT_SYMLINK_NOFOLLOW != 0) {
        Ok(metadata) => metadata,
        Err(error) => return error,
    };
    if let Some(metadata) = guest_path
        && metadata.no_follow
    {
        let stat = synthetic_guest_fd_symlink_stat(metadata.guest_fd);
        return write_struct(memory, output_address, &stat);
    }
    let opened_file;
    let host_fd = if let Some(metadata) = guest_path {
        metadata.host_fd
    } else if path.is_empty() {
        let Ok((host_fd, _)) = host_dirfd_and_path(state, guest_dirfd, &path) else {
            return negative_errno(libc::EBADF);
        };
        if let Err(error) = ensure_fd_not_procfs(host_fd) {
            return error;
        }
        host_fd
    } else {
        opened_file = match open_metadata_path(
            state,
            guest_dirfd,
            &path,
            flags & libc::AT_SYMLINK_NOFOLLOW != 0,
        ) {
            Ok(file) => file,
            Err(error) => return error,
        };
        opened_file.as_raw_fd()
    };

    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and host_fd is live for the call.
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fstat initialized stat on success.
    let mut stat = unsafe { stat.assume_init() };
    if let Some(metadata) = guest_path {
        sanitize_guest_fd_stat(state, metadata.guest_fd, &mut stat);
    } else {
        // AT_EMPTY_PATH stat of a synthetic /proc descriptor.
        let empty_path_proc_inode = path
            .is_empty()
            .then(|| state.proc_files.get(&guest_dirfd).copied())
            .flatten();
        if let Some(inode) = empty_path_proc_inode {
            sanitize_proc_stat(&mut stat, inode);
        }
        sanitize_stat_timestamps(&mut stat);
    }
    write_struct(memory, output_address, &stat)
}

fn statx(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(memory, args[1], 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    let flags = args[2] as libc::c_int;
    let allowed_flags = libc::AT_EMPTY_PATH
        | libc::AT_SYMLINK_NOFOLLOW
        | libc::AT_NO_AUTOMOUNT
        | libc::AT_STATX_SYNC_TYPE;
    if flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    if path.is_empty() && flags & libc::AT_EMPTY_PATH == 0 {
        return negative_errno(libc::ENOENT);
    }
    // Path-addressed synthetic /proc file: synthesize deterministic metadata.
    if !path.is_empty() {
        if let Some(content) = synthetic_proc_content(state, &path) {
            let normalized = normalize_proc_path(state, &path)
                .expect("a synthesized /proc path always normalizes");
            let stx = synthetic_proc_statx(synthetic_proc_inode(&normalized), content.len() as u64);
            return write_struct(memory, args[4], &stx);
        }
    } else if let Some(&inode) = state.proc_files.get(&(args[0] as libc::c_int)) {
        // AT_EMPTY_PATH statx of a synthetic /proc descriptor: report the memfd's
        // (deterministic) size with synthesized identity.
        let size = match host_fd(state, args[0] as libc::c_int) {
            Some(host_fd) => {
                let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
                // SAFETY: stat is writable and host_fd is a live memfd descriptor.
                if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } != 0 {
                    return io_error(std::io::Error::last_os_error());
                }
                // SAFETY: fstat initialized stat on success.
                unsafe { stat.assume_init() }.st_size as u64
            }
            None => return negative_errno(libc::EBADF),
        };
        let stx = synthetic_proc_statx(inode, size);
        return write_struct(memory, args[4], &stx);
    }

    let guest_path = match guest_fd_metadata(state, &path, flags & libc::AT_SYMLINK_NOFOLLOW != 0) {
        Ok(metadata) => metadata,
        Err(error) => return error,
    };
    if let Some(metadata) = guest_path
        && metadata.no_follow
    {
        let stat = synthetic_guest_fd_symlink_statx(metadata.guest_fd);
        return write_struct(memory, args[4], &stat);
    }
    let opened_file;
    let host_fd = if let Some(metadata) = guest_path {
        metadata.host_fd
    } else if path.is_empty() {
        let Ok((host_fd, _)) = host_dirfd_and_path(state, args[0] as libc::c_int, &path) else {
            return negative_errno(libc::EBADF);
        };
        if let Err(error) = ensure_fd_not_procfs(host_fd) {
            return error;
        }
        host_fd
    } else {
        opened_file = match open_metadata_path(
            state,
            args[0] as libc::c_int,
            &path,
            flags & libc::AT_SYMLINK_NOFOLLOW != 0,
        ) {
            Ok(file) => file,
            Err(error) => return error,
        };
        opened_file.as_raw_fd()
    };

    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let empty_path = b"\0";
    let statx_flags = libc::AT_EMPTY_PATH | (flags & libc::AT_STATX_SYNC_TYPE);
    // SAFETY: empty_path is NUL-terminated, stat is writable, host_fd is live,
    // and the remaining scalar arguments are passed through unchanged.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            host_fd,
            empty_path.as_ptr(),
            statx_flags,
            args[3] as libc::c_uint,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: statx initialized stat on success.
    let mut stat = unsafe { stat.assume_init() };
    if let Some(metadata) = guest_path {
        sanitize_guest_fd_statx(state, metadata.guest_fd, &mut stat);
    } else {
        for timestamp in [
            &mut stat.stx_atime,
            &mut stat.stx_btime,
            &mut stat.stx_ctime,
            &mut stat.stx_mtime,
        ] {
            timestamp.tv_sec = 0;
            timestamp.tv_nsec = 0;
        }
    }
    write_struct(memory, args[4], &stat)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn sanitize_stat_timestamps(stat: &mut libc::stat) {
    stat.st_atime = 0;
    stat.st_atime_nsec = 0;
    stat.st_mtime = 0;
    stat.st_mtime_nsec = 0;
    stat.st_ctime = 0;
    stat.st_ctime_nsec = 0;
}

fn statfs(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(memory, args[0], 4096) {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => return negative_errno(libc::ENOENT),
        Err(error) => return read_c_string_errno(error),
    };
    let file = match open_metadata_path(state, libc::AT_FDCWD, &path, false) {
        Ok(file) => file,
        Err(error) => return error,
    };
    fstatfs_host(memory, file.as_raw_fd(), args[1])
}

fn fstatfs(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(guest_fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_fd_not_procfs(host_fd) {
        return error;
    }
    fstatfs_host(memory, host_fd, args[1])
}

fn fstatfs_host(memory: &mut GuestMemory, host_fd: RawFd, output: u64) -> i64 {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: stat is writable and host_fd names a live descriptor.
    if unsafe { libc::fstatfs(host_fd, stat.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized stat on success.
    write_struct(memory, output, &unsafe { stat.assume_init() })
}

fn access(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // access(2) is faccessat2(AT_FDCWD, path, mode, 0): a real-UID check that
    // follows symlinks and rejects an empty path with ENOENT.
    faccessat_impl(
        memory,
        state,
        libc::AT_FDCWD,
        args[0],
        args[1] as libc::c_int,
        0,
    )
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(reverie#124): faccessat access check so bash
// `test -r/-w/-x` and program startup probes resolve correctly under the KVM
// backend instead of falling through to ENOSYS.
fn faccessat(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // faccessat(2) has no flags argument, so it behaves like access(2) relative
    // to the supplied directory descriptor: real-UID check, follow symlinks.
    faccessat_impl(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2] as libc::c_int,
        0,
    )
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(reverie#124): faccessat2 access check. glibc routes the
// C `access`/`euidaccess` helpers and the shell `test -r/-w/-x` operators
// through faccessat2; without this arm every access probe returned ENOSYS.
fn faccessat2(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    faccessat_impl(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2] as libc::c_int,
        args[3] as libc::c_int,
    )
}

// Shared access-check implementation for access(2)/faccessat(2)/faccessat2(2).
// The guest dirfd, cwd, and AT_SYMLINK_NOFOLLOW are resolved locally into an
// O_PATH descriptor; the permission decision itself is delegated to the host
// kernel via AT_EMPTY_PATH so the answer matches what the ptrace backend sees.
fn faccessat_impl(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    mode: libc::c_int,
    flags: libc::c_int,
) -> i64 {
    // mode is F_OK or a bitmask of R_OK/W_OK/X_OK; anything else is invalid.
    if mode & !(libc::R_OK | libc::W_OK | libc::X_OK) != 0 {
        return negative_errno(libc::EINVAL);
    }
    let allowed_flags = libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    if flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(memory, path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() && flags & libc::AT_EMPTY_PATH == 0 {
        return negative_errno(libc::ENOENT);
    }
    // Synthetic /proc files exist and are world-readable but never writable or
    // executable, matching the read-only surface open_file serves.
    if synthetic_proc_content(state, &path).is_some() {
        if mode & (libc::W_OK | libc::X_OK) != 0 {
            return negative_errno(libc::EACCES);
        }
        return 0;
    }
    let file = match open_metadata_path(
        state,
        guest_dirfd,
        &path,
        flags & libc::AT_SYMLINK_NOFOLLOW != 0,
    ) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let empty_path = b"\0";
    // Forward AT_EACCESS so an effective-ID probe keeps its meaning; the O_PATH
    // fd is addressed with AT_EMPTY_PATH.
    let host_flags = libc::AT_EMPTY_PATH | (flags & libc::AT_EACCESS);
    // SAFETY: empty_path is NUL-terminated and file owns a live O_PATH fd.
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            file.as_raw_fd(),
            empty_path.as_ptr(),
            mode,
            host_flags,
        )
    };
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

fn read_path_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    address: u64,
    allow_empty: bool,
) -> Result<(RawFd, CString), i64> {
    let path = read_c_string(memory, address, 4096).map_err(read_c_string_errno)?;
    if path.is_empty() && !allow_empty {
        return Err(negative_errno(libc::ENOENT));
    }
    let (host_dirfd, path) = host_dirfd_and_path(state, guest_dirfd, &path)?;
    ensure_mutation_parent_not_procfs(host_dirfd, &path)?;
    Ok((host_dirfd, path))
}

fn mkdir_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_mode: u64,
) -> i64 {
    let (host_dirfd, path) = match read_path_at(memory, state, guest_dirfd, path_address, false) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let mode = raw_mode as libc::mode_t & 0o7777 & !state.umask;
    // SAFETY: path is NUL-terminated and host_dirfd was translated from guest state.
    if unsafe { libc::mkdirat(host_dirfd, path.as_ptr(), mode) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // Override the supervisor host umask with the deterministic guest umask.
    // SAFETY: mkdirat created this path as a directory above.
    zero_or_errno(unsafe { libc::fchmodat(host_dirfd, path.as_ptr(), mode, 0) })
}

fn unlink_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_flags: u64,
) -> i64 {
    if raw_flags & !(libc::AT_REMOVEDIR as u64) != 0 {
        return negative_errno(libc::EINVAL);
    }
    let (host_dirfd, path) = match read_path_at(memory, state, guest_dirfd, path_address, false) {
        Ok(path) => path,
        Err(error) => return error,
    };
    // SAFETY: path is NUL-terminated and flags were validated.
    zero_or_errno(unsafe { libc::unlinkat(host_dirfd, path.as_ptr(), raw_flags as libc::c_int) })
}

fn rename_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    old_guest_dirfd: libc::c_int,
    old_path_address: u64,
    new_guest_dirfd: libc::c_int,
    new_path_address: u64,
    raw_flags: u64,
) -> i64 {
    let allowed_flags = (libc::RENAME_NOREPLACE | libc::RENAME_EXCHANGE) as u64;
    if raw_flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    let (old_host_dirfd, old_path) =
        match read_path_at(memory, state, old_guest_dirfd, old_path_address, false) {
            Ok(path) => path,
            Err(error) => return error,
        };
    let (new_host_dirfd, new_path) =
        match read_path_at(memory, state, new_guest_dirfd, new_path_address, false) {
            Ok(path) => path,
            Err(error) => return error,
        };
    // SAFETY: both paths are NUL-terminated, dirfds were translated, and flags
    // are restricted to non-whiteout rename operations.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_host_dirfd,
            old_path.as_ptr(),
            new_host_dirfd,
            new_path.as_ptr(),
            raw_flags as libc::c_uint,
        )
    };
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

fn link_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    old_guest_dirfd: libc::c_int,
    old_path_address: u64,
    new_guest_dirfd: libc::c_int,
    new_path_address: u64,
    raw_flags: u64,
) -> i64 {
    let flags = raw_flags as libc::c_int;
    if flags & !libc::AT_SYMLINK_FOLLOW != 0 {
        return negative_errno(libc::EINVAL);
    }
    let (old_host_dirfd, old_path) =
        match read_path_at(memory, state, old_guest_dirfd, old_path_address, false) {
            Ok(path) => path,
            Err(error) => return error,
        };
    let (new_host_dirfd, new_path) =
        match read_path_at(memory, state, new_guest_dirfd, new_path_address, false) {
            Ok(path) => path,
            Err(error) => return error,
        };
    let follows_source = flags & libc::AT_SYMLINK_FOLLOW != 0;
    let old_file = match open_host_metadata_path(old_host_dirfd, &old_path, !follows_source) {
        Ok(file) => file,
        Err(error) => return error,
    };
    if follows_source {
        // Resolve the trusted held descriptor, not the guest pathname, so a
        // source swap cannot redirect AT_SYMLINK_FOLLOW into supervisor procfs.
        let proc_path = CString::new(format!("/proc/self/fd/{}", old_file.as_raw_fd()))
            .expect("supervisor fd path has no NUL");
        // SAFETY: proc_path names old_file and the destination was translated.
        return zero_or_errno(unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                proc_path.as_ptr(),
                new_host_dirfd,
                new_path.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        });
    }
    // Without AT_SYMLINK_FOLLOW, a swapped procfs symlink is linked as a
    // symlink rather than dereferenced into the supervisor descriptor table.
    // Keep old_file alive to retain the validated source during the operation.
    let result = unsafe {
        libc::linkat(
            old_host_dirfd,
            old_path.as_ptr(),
            new_host_dirfd,
            new_path.as_ptr(),
            0,
        )
    };
    drop(old_file);
    zero_or_errno(result)
}

fn symlink_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    target_address: u64,
    new_guest_dirfd: libc::c_int,
    new_path_address: u64,
) -> i64 {
    let target = match read_c_string(memory, target_address, 4096) {
        Ok(target) => match CString::new(target) {
            Ok(target) => target,
            Err(_) => return negative_errno(libc::EINVAL),
        },
        Err(error) => return read_c_string_errno(error),
    };
    let (new_host_dirfd, new_path) =
        match read_path_at(memory, state, new_guest_dirfd, new_path_address, false) {
            Ok(path) => path,
            Err(error) => return error,
        };
    // SAFETY: target and new_path are NUL-terminated.
    zero_or_errno(unsafe { libc::symlinkat(target.as_ptr(), new_host_dirfd, new_path.as_ptr()) })
}

fn fchmod(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(guest_fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    let mode = args[1] as libc::mode_t & 0o7777;
    // SAFETY: host_fd names a live descriptor and mode is bounded to permission bits.
    zero_or_errno(unsafe { libc::fchmod(host_fd, mode) })
}

fn fchmodat(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_mode: u64,
    raw_flags: u64,
) -> i64 {
    if raw_flags != 0 {
        return negative_errno(libc::ENOTSUP);
    }
    let (host_dirfd, path) = match read_path_at(memory, state, guest_dirfd, path_address, false) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let file = match open_host_metadata_path(host_dirfd, &path, false) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let mode = raw_mode as libc::mode_t & 0o7777;
    let empty_path = b"\0";
    // Mutate the checked inode rather than re-resolving the guest pathname.
    // SAFETY: file owns a live O_PATH descriptor and empty_path is terminated.
    let mut result = unsafe {
        libc::syscall(
            libc::SYS_fchmodat2,
            file.as_raw_fd(),
            empty_path.as_ptr(),
            mode,
            libc::AT_EMPTY_PATH,
        )
    };
    if result < 0
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL)
        )
    {
        // fchmodat2(AT_EMPTY_PATH) was added after openat2. On older kernels,
        // a supervisor-generated procfs path to our held descriptor preserves
        // inode identity without re-resolving guest-controlled path components.
        let proc_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .expect("supervisor fd path has no NUL");
        // SAFETY: proc_path identifies the checked descriptor held by file.
        result = unsafe { libc::fchmodat(libc::AT_FDCWD, proc_path.as_ptr(), mode, 0) } as _;
    }
    zero_or_errno(result as libc::c_int)
}

fn mknod_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_mode: u64,
    raw_device: u64,
) -> i64 {
    let mode = raw_mode as libc::mode_t;
    let kind = mode & libc::S_IFMT;
    if !matches!(kind, 0 | libc::S_IFREG | libc::S_IFIFO) || raw_device != 0 {
        return negative_errno(libc::EPERM);
    }
    let (host_dirfd, path) = match read_path_at(memory, state, guest_dirfd, path_address, false) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let mode = (mode & (libc::S_IFMT | 0o7777)) & !(state.umask as libc::mode_t);
    // SAFETY: path is NUL-terminated; device nodes are rejected above.
    if unsafe { libc::mknodat(host_dirfd, path.as_ptr(), mode, 0) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // Override the supervisor host umask with the deterministic guest umask.
    // SAFETY: mknodat created a regular file or FIFO at this path above.
    zero_or_errno(unsafe { libc::fchmodat(host_dirfd, path.as_ptr(), mode & 0o7777, 0) })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#80): Confirm the fixed timestamp against supported host filesystems.
// Keep synthetic "now" inside the timestamp range supported by common host
// filesystems while remaining independent of host wall time.
const DETERMINISTIC_UTIME_SECONDS: libc::time_t = 1_640_995_199;

fn utimensat(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let raw_flags = args[3] as libc::c_int;
    let allowed_flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    if raw_flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    let requested_times = if args[2] == 0 {
        None
    } else {
        match read_guest_struct::<[libc::timespec; 2]>(memory, args[2]) {
            Ok(times) => Some(times),
            Err(error) => return error,
        }
    };
    if requested_times
        .as_ref()
        .is_some_and(|times| times.iter().all(|time| time.tv_nsec == libc::UTIME_OMIT))
    {
        return 0;
    }
    if args[1] == 0 && raw_flags != 0 {
        return negative_errno(libc::EINVAL);
    }

    let mut opened_path = None;
    let target_fd = if args[1] == 0 {
        let guest_fd = args[0] as libc::c_int;
        let Some(host_fd) = host_fd(state, guest_fd) else {
            return negative_errno(libc::EBADF);
        };
        if let Err(error) = ensure_fd_not_procfs(host_fd) {
            return error;
        }
        if fd_status_flags(host_fd).is_ok_and(|flags| flags & libc::O_PATH != 0) {
            return negative_errno(libc::EBADF);
        }
        host_fd
    } else {
        let allow_empty = raw_flags & libc::AT_EMPTY_PATH != 0;
        let (host_dirfd, path) =
            match read_path_at(memory, state, args[0] as libc::c_int, args[1], allow_empty) {
                Ok(target) => target,
                Err(error) => return error,
            };
        if path.to_bytes().is_empty() {
            if let Err(error) = ensure_fd_not_procfs(host_dirfd) {
                return error;
            }
            host_dirfd
        } else {
            let nofollow = raw_flags & libc::AT_SYMLINK_NOFOLLOW != 0;
            let file = match open_host_metadata_path(host_dirfd, &path, nofollow) {
                Ok(file) => file,
                Err(error) => return error,
            };
            let fd = file.as_raw_fd();
            opened_path = Some(file);
            fd
        }
    };

    let mut times = requested_times.unwrap_or([
        libc::timespec {
            tv_sec: DETERMINISTIC_UTIME_SECONDS,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: DETERMINISTIC_UTIME_SECONDS,
            tv_nsec: 0,
        },
    ]);
    for time in &mut times {
        if time.tv_nsec == libc::UTIME_NOW {
            time.tv_sec = DETERMINISTIC_UTIME_SECONDS;
            time.tv_nsec = 0;
        } else if time.tv_nsec != libc::UTIME_OMIT && !(0..1_000_000_000).contains(&time.tv_nsec) {
            return negative_errno(libc::EINVAL);
        }
    }

    // Mutate the already-validated inode instead of re-resolving the guest
    // pathname. Explicit deterministic timestamps are intentionally stricter
    // than Linux UTIME_NOW for writable files not owned by the caller; a
    // virtual metadata overlay is required to emulate that exception without
    // exposing host wall time.
    let empty_path = b"\0";
    let mut target_flags = libc::AT_EMPTY_PATH;
    if raw_flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        target_flags |= libc::AT_SYMLINK_NOFOLLOW;
    }
    // SAFETY: target_fd is live through opened_path or guest descriptor state,
    // empty_path is NUL-terminated, and times is live for the syscall.
    let mut result = unsafe {
        libc::syscall(
            libc::SYS_utimensat,
            target_fd,
            empty_path.as_ptr(),
            times.as_ptr(),
            target_flags,
        )
    };
    if result < 0
        && raw_flags & libc::AT_SYMLINK_NOFOLLOW == 0
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL)
        )
    {
        let proc_path = CString::new(format!("/proc/self/fd/{target_fd}"))
            .expect("supervisor fd path has no NUL");
        // SAFETY: proc_path identifies the checked descriptor kept live above.
        result =
            unsafe { libc::utimensat(libc::AT_FDCWD, proc_path.as_ptr(), times.as_ptr(), 0) } as _;
    }
    drop(opened_path);
    zero_or_errno(result as libc::c_int)
}

fn getcwd(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let bytes = state.cwd.as_os_str().as_bytes();
    let Ok(capacity) = usize::try_from(args[1]) else {
        return negative_errno(libc::EINVAL);
    };
    let Some(required) = bytes.len().checked_add(1) else {
        return negative_errno(libc::ERANGE);
    };
    if capacity < required {
        return negative_errno(libc::ERANGE);
    }
    let mut terminated = Vec::with_capacity(required);
    terminated.extend_from_slice(bytes);
    terminated.push(0);
    match memory.write(args[0], &terminated) {
        Ok(()) => required as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(reverie-kvm): Review KVM guest chdir/fchdir cwd semantics.
//
// `chdir`/`fchdir` update the emulated working directory that `getcwd` reports
// and that relative-path resolution (`host_dirfd_and_path`) resolves against.
// Both replace `state.cwd_fd` with a fresh `O_PATH|O_DIRECTORY` handle so cwd
// identity survives host renames (the same invariant `cwd_fd` had at load), and
// canonicalize `state.cwd` from that handle so `getcwd` returns a stable, real
// host path -- deterministic given the same external filesystem.
fn chdir(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(memory, args[0], 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() {
        return negative_errno(libc::ENOENT);
    }
    let (host_dirfd, path) = match host_dirfd_and_path(state, libc::AT_FDCWD, &path) {
        Ok(resolved) => resolved,
        Err(error) => return error,
    };
    let directory = match open_cwd_directory(host_dirfd, &path) {
        Ok(directory) => directory,
        Err(error) => return error,
    };
    set_cwd(state, directory)
}

fn fchdir(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    // Rejects non-directories (ENOTDIR) and O_PATH descriptors (EBADF), matching
    // the kernel's fchdir precondition that the fd be a readable directory.
    if let Err(error) = ensure_directory(file) {
        return error;
    }
    // Reopen the directory itself ("." relative to the guest's own descriptor)
    // as an independent O_PATH cwd handle so a later guest `close(fd)` cannot
    // invalidate the working directory.
    let directory = match open_cwd_directory(file.as_raw_fd(), c".") {
        Ok(directory) => directory,
        Err(error) => return error,
    };
    set_cwd(state, directory)
}

/// Open `path` (relative to `host_dirfd`) as an `O_PATH|O_DIRECTORY` handle
/// suitable for use as `state.cwd_fd`. `O_DIRECTORY` yields `ENOTDIR` for a
/// non-directory and procfs is refused, keeping cwd within the same isolation
/// boundary as [`open_file`].
fn open_cwd_directory(host_dirfd: RawFd, path: &CStr) -> Result<std::fs::File, i64> {
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: path and how are live for the call; Linux validates host_dirfd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            host_dirfd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned descriptor on success.
    let file = unsafe { std::fs::File::from_raw_fd(fd as RawFd) };
    ensure_not_procfs(&file)?;
    Ok(file)
}

/// Commit `directory` as the new working directory, deriving the canonical
/// `state.cwd` string from the descriptor so `getcwd` stays consistent with it.
fn set_cwd(state: &mut LoadedStaticElf, directory: std::fs::File) -> i64 {
    match canonical_fd_path(directory.as_raw_fd()) {
        Ok(path) => {
            state.cwd = path;
            state.cwd_fd = directory;
            0
        }
        Err(error) => error,
    }
}

/// Resolve the canonical absolute path a descriptor refers to via the
/// supervisor's own `/proc/self/fd`. This is a host-side operation on a
/// supervisor descriptor (like the existing `link_at`/`utimensat` fallbacks),
/// not a guest-visible procfs access.
fn canonical_fd_path(fd: RawFd) -> Result<std::path::PathBuf, i64> {
    let proc_path =
        CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| negative_errno(libc::EINVAL))?;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: proc_path is NUL-terminated and buffer is writable for its length.
    let count = unsafe {
        libc::readlink(
            proc_path.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
        )
    };
    if count < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    buffer.truncate(count as usize);
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        buffer,
    )))
}

// ===== Synthetic /proc surface =====
//
// TODO-HUMAN-REVIEW(reverie-kvm): Review synthetic /proc content and determinism.
//
// Real procfs is refused (see `ensure_not_procfs`) because its contents are
// host-specific and would break `--verify`. To still support programs that read
// a few well-known /proc files (uptime, diagnostics, self-inspection), a small
// allowlist is synthesized with DETERMINISTIC content and served from a memfd,
// so the ordinary read/lseek/close/dup/fork paths apply unchanged. `fstat`,
// `newfstatat`, and `statx` on such a descriptor report synthesized, run-stable
// metadata, because the backing memfd's own inode varies per run and would
// otherwise perturb determinism. Directory enumeration of /proc itself is not
// provided, so tools that scan every PID (e.g. `ps`) are out of scope here.
const SYNTHETIC_DEV_MAJOR: u32 = 0;
const SYNTHETIC_PROC_DEV_MINOR: u32 = 0xff01;
const SYNTHETIC_GUEST_FD_DEV_MINOR: u32 = 0xff02;

fn synthetic_dev(minor: u32) -> libc::dev_t {
    libc::makedev(SYNTHETIC_DEV_MAJOR, minor)
}

/// Deterministic inode for a normalized synthetic /proc path (FNV-1a). Stable
/// across runs so `--verify` sees identical `stat` results.
fn synthetic_proc_inode(path: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Keep clear of low, conventionally-reserved inode numbers.
    hash | 0x1000
}

/// Rewrite a `/proc/<pid>` path (for this guest's own pid) to the canonical
/// `/proc/self` form so both spellings resolve to the same synthetic content.
fn normalize_proc_path(state: &LoadedStaticElf, path: &[u8]) -> Option<Vec<u8>> {
    if path != b"/proc" && !path.starts_with(b"/proc/") {
        return None;
    }
    let pid = format!("/proc/{}", state.pid).into_bytes();
    if path == pid.as_slice() {
        return Some(b"/proc/self".to_vec());
    }
    let mut pid_dir = pid;
    pid_dir.push(b'/');
    if let Some(rest) = path.strip_prefix(pid_dir.as_slice()) {
        let mut normalized = b"/proc/self/".to_vec();
        normalized.extend_from_slice(rest);
        return Some(normalized);
    }
    Some(path.to_vec())
}

/// Synthesize deterministic content for a recognized /proc path, or `None` when
/// the path is not part of the supported surface.
fn synthetic_proc_content(state: &LoadedStaticElf, path: &[u8]) -> Option<Vec<u8>> {
    let normalized = normalize_proc_path(state, path)?;
    let content = match normalized.as_slice() {
        b"/proc/uptime" => b"0.00 0.00\n".to_vec(),
        b"/proc/loadavg" => b"0.00 0.00 0.00 1/1 1\n".to_vec(),
        b"/proc/version" => b"Linux version 6.0.0 (reverie-kvm) #1 SMP x86_64\n".to_vec(),
        b"/proc/filesystems" => b"nodev\tproc\nnodev\ttmpfs\n\text4\n".to_vec(),
        b"/proc/mounts" | b"/proc/self/mounts" => b"rootfs / rootfs rw 0 0\n".to_vec(),
        b"/proc/stat" => concat!(
            "cpu  0 0 0 0 0 0 0 0 0 0\n",
            "cpu0 0 0 0 0 0 0 0 0 0 0\n",
            "intr 0\n",
            "ctxt 0\n",
            "btime 0\n",
            "processes 1\n",
            "procs_running 1\n",
            "procs_blocked 0\n",
        )
        .as_bytes()
        .to_vec(),
        b"/proc/meminfo" => concat!(
            "MemTotal:        2097152 kB\n",
            "MemFree:         1048576 kB\n",
            "MemAvailable:    1572864 kB\n",
            "Buffers:               0 kB\n",
            "Cached:                0 kB\n",
            "SwapTotal:             0 kB\n",
            "SwapFree:              0 kB\n",
        )
        .as_bytes()
        .to_vec(),
        b"/proc/cpuinfo" => concat!(
            "processor\t: 0\n",
            "vendor_id\t: GenuineIntel\n",
            "cpu family\t: 6\n",
            "model\t\t: 0\n",
            "model name\t: reverie-kvm virtual CPU\n",
            "cpu MHz\t\t: 1000.000\n",
            "cache size\t: 0 KB\n",
            "physical id\t: 0\n",
            "siblings\t: 1\n",
            "core id\t\t: 0\n",
            "cpu cores\t: 1\n",
            "flags\t\t: fpu\n",
            "\n",
        )
        .as_bytes()
        .to_vec(),
        b"/proc/self/stat" => proc_self_stat_content(state),
        b"/proc/self/status" => proc_self_status_content(state),
        b"/proc/self/cmdline" => proc_self_cmdline_content(state),
        _ => return None,
    };
    Some(content)
}

/// The kernel's `comm`: the program basename, capped at 15 bytes.
fn proc_comm(state: &LoadedStaticElf) -> String {
    let base = state
        .argv0
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or(&state.argv0);
    String::from_utf8_lossy(&base.iter().copied().take(15).collect::<Vec<u8>>()).into_owned()
}

fn proc_self_cmdline_content(state: &LoadedStaticElf) -> Vec<u8> {
    // Minimal: argv[0] followed by a NUL. reverie-kvm does not retain the full
    // guest argv here, so consumers needing the complete command line get only
    // argv[0]; the common "who am I" use is satisfied and the file is
    // NUL-terminated like the kernel's.
    let mut content = state.argv0.clone();
    content.push(0);
    content
}

fn proc_self_stat_content(state: &LoadedStaticElf) -> Vec<u8> {
    // pid (comm) state ppid ... The fields after ppid are process-accounting
    // values reported as zero so no nondeterministic host state leaks. The real
    // file has 52 fields; pad with zeros so field-counting parsers are satisfied.
    let mut line = format!(
        "{} ({}) R {} 0 0 0 -1 0",
        state.pid,
        proc_comm(state),
        state.ppid
    );
    for _ in 0..44 {
        line.push_str(" 0");
    }
    line.push('\n');
    line.into_bytes()
}

fn proc_self_status_content(state: &LoadedStaticElf) -> Vec<u8> {
    format!(
        "Name:\t{comm}\n\
         Umask:\t{umask:04o}\n\
         State:\tR (running)\n\
         Tgid:\t{pid}\n\
         Ngid:\t0\n\
         Pid:\t{pid}\n\
         PPid:\t{ppid}\n\
         TracerPid:\t0\n\
         Uid:\t0\t0\t0\t0\n\
         Gid:\t0\t0\t0\t0\n\
         FDSize:\t64\n\
         Threads:\t1\n",
        comm = proc_comm(state),
        umask = state.umask,
        pid = state.pid,
        ppid = state.ppid,
    )
    .into_bytes()
}

/// Back a synthesized /proc file with a memfd holding `content` and record it in
/// `proc_files` so `fstat`/`statx` report deterministic metadata.
fn open_synthetic_proc(
    state: &mut LoadedStaticElf,
    normalized_path: &[u8],
    content: &[u8],
    close_on_exec: bool,
) -> i64 {
    // SAFETY: the name is a valid NUL-terminated C string.
    let raw = unsafe {
        libc::memfd_create(
            c"reverie-kvm-proc".as_ptr(),
            libc::MFD_CLOEXEC as libc::c_uint,
        )
    };
    if raw < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new owned descriptor on success.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw as RawFd) };
    if file.write_all(content).is_err() {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: file owns a live descriptor; rewind so the guest reads from zero.
    if unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let inode = synthetic_proc_inode(normalized_path);
    let guest_fd = insert_file_with_flags(state, file, close_on_exec, None);
    if guest_fd >= 0 {
        state.proc_files.insert(guest_fd as i32, inode);
    }
    guest_fd
}

/// Overwrite the nondeterministic fields of a memfd `stat` with the stable
/// synthetic identity of a /proc file, keeping the (deterministic) size.
fn sanitize_proc_stat(stat: &mut libc::stat, inode: u64) {
    stat.st_dev = synthetic_dev(SYNTHETIC_PROC_DEV_MINOR);
    stat.st_ino = inode;
    stat.st_mode = libc::S_IFREG | 0o444;
    stat.st_nlink = 1;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_rdev = 0;
    stat.st_blksize = PAGE_SIZE as libc::blksize_t;
    // 512-byte blocks, rounded up. A shift avoids the still-unstable
    // int_roundings `div_ceil` on the pinned toolchain (512 == 1 << 9).
    stat.st_blocks = (stat.st_size + 511) >> 9;
    stat.st_atime = 0;
    stat.st_atime_nsec = 0;
    stat.st_mtime = 0;
    stat.st_mtime_nsec = 0;
    stat.st_ctime = 0;
    stat.st_ctime_nsec = 0;
}

/// A fully synthetic `stat` for a path-addressed /proc file of `size` bytes.
fn synthetic_proc_stat(inode: u64, size: usize) -> libc::stat {
    // SAFETY: libc::stat is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_size = size as libc::off_t;
    sanitize_proc_stat(&mut stat, inode);
    stat
}

/// A synthetic `statx` mirroring [`synthetic_proc_stat`].
fn synthetic_proc_statx(inode: u64, size: u64) -> libc::statx {
    // SAFETY: libc::statx is plain-old-data; a zeroed value is valid.
    let mut stx = unsafe { std::mem::zeroed::<libc::statx>() };
    stx.stx_mask = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_GID
        | libc::STATX_INO
        | libc::STATX_SIZE
        | libc::STATX_BLOCKS;
    stx.stx_blksize = PAGE_SIZE as u32;
    stx.stx_nlink = 1;
    stx.stx_uid = 0;
    stx.stx_gid = 0;
    stx.stx_mode = (libc::S_IFREG | 0o444) as u16;
    stx.stx_ino = inode;
    stx.stx_size = size;
    stx.stx_blocks = (size + 511) >> 9;
    stx.stx_dev_major = SYNTHETIC_DEV_MAJOR;
    stx.stx_dev_minor = SYNTHETIC_PROC_DEV_MINOR;
    stx
}

// TODO-HUMAN-REVIEW(PR-92): Review deterministic guest-fd alias metadata.
fn synthetic_guest_fd_inode(guest_fd: libc::c_int, symlink: bool) -> u64 {
    0x2000_0000 + (guest_fd as u64 * 2) + u64::from(symlink)
}

fn sanitize_guest_fd_stat(state: &LoadedStaticElf, guest_fd: libc::c_int, stat: &mut libc::stat) {
    if let Some(&inode) = state.proc_files.get(&guest_fd) {
        sanitize_proc_stat(stat, inode);
        return;
    }
    stat.st_dev = synthetic_dev(SYNTHETIC_GUEST_FD_DEV_MINOR);
    stat.st_ino = synthetic_guest_fd_inode(guest_fd, false);
    sanitize_stat_timestamps(stat);
}

fn sanitize_guest_fd_statx(state: &LoadedStaticElf, guest_fd: libc::c_int, stat: &mut libc::statx) {
    if let Some(&inode) = state.proc_files.get(&guest_fd) {
        *stat = synthetic_proc_statx(inode, stat.stx_size);
        return;
    }
    stat.stx_ino = synthetic_guest_fd_inode(guest_fd, false);
    stat.stx_dev_major = SYNTHETIC_DEV_MAJOR;
    stat.stx_dev_minor = SYNTHETIC_GUEST_FD_DEV_MINOR;
    for timestamp in [
        &mut stat.stx_atime,
        &mut stat.stx_btime,
        &mut stat.stx_ctime,
        &mut stat.stx_mtime,
    ] {
        timestamp.tv_sec = 0;
        timestamp.tv_nsec = 0;
    }
}

fn synthetic_guest_fd_symlink_stat(guest_fd: libc::c_int) -> libc::stat {
    // SAFETY: libc::stat is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_dev = synthetic_dev(SYNTHETIC_GUEST_FD_DEV_MINOR);
    stat.st_ino = synthetic_guest_fd_inode(guest_fd, true);
    stat.st_mode = libc::S_IFLNK | 0o777;
    stat.st_nlink = 1;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_blksize = PAGE_SIZE as libc::blksize_t;
    stat
}

fn synthetic_guest_fd_symlink_statx(guest_fd: libc::c_int) -> libc::statx {
    // SAFETY: libc::statx is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::statx>() };
    stat.stx_mask = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_GID
        | libc::STATX_INO
        | libc::STATX_SIZE;
    stat.stx_blksize = PAGE_SIZE as u32;
    stat.stx_nlink = 1;
    stat.stx_mode = (libc::S_IFLNK | 0o777) as u16;
    stat.stx_ino = synthetic_guest_fd_inode(guest_fd, true);
    stat.stx_dev_minor = SYNTHETIC_GUEST_FD_DEV_MINOR;
    stat
}

fn getdents64(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_directory(file) {
        return error;
    }
    if length >= 24 && !range_is_valid(memory, args[1], length as u64) {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; length];
    // SAFETY: file owns a live descriptor and bytes is writable for length bytes.
    let count = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            file.as_raw_fd(),
            bytes.as_mut_ptr().cast::<libc::c_void>(),
            bytes.len(),
        )
    };
    if count < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let count = count as usize;
    if count == 0 {
        return 0;
    }
    match memory.write(args[1], &bytes[..count]) {
        Ok(()) => count as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn is_open_standard(state: &LoadedStaticElf, guest_fd: libc::c_int) -> bool {
    (0..=2).contains(&guest_fd)
        && (guest_fd != libc::STDIN_FILENO || state.stdin.is_some())
        && !state.closed_standard_fds.contains(&guest_fd)
        && !state.files.contains_key(&guest_fd)
}

fn host_fd(state: &LoadedStaticElf, guest_fd: libc::c_int) -> Option<RawFd> {
    state
        .files
        .get(&guest_fd)
        .map(AsRawFd::as_raw_fd)
        .or_else(|| {
            if !is_open_standard(state, guest_fd) {
                None
            } else if guest_fd == libc::STDIN_FILENO {
                state.stdin.as_ref().map(AsRawFd::as_raw_fd)
            } else {
                Some(guest_fd)
            }
        })
}

// TODO-HUMAN-REVIEW(PR-52): Review KVM guest fcntl compatibility boundaries.
fn fcntl(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    let source_alias = output_alias(state, guest_fd);
    let source_proc_inode = state.proc_files.get(&guest_fd).copied();
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    match args[1] as libc::c_int {
        libc::F_DUPFD => duplicate_fd_at_or_above(
            state,
            host_fd,
            args[2],
            false,
            source_alias,
            source_proc_inode,
        ),
        libc::F_DUPFD_CLOEXEC => duplicate_fd_at_or_above(
            state,
            host_fd,
            args[2],
            true,
            source_alias,
            source_proc_inode,
        ),
        libc::F_GETFL => match fd_status_flags(host_fd) {
            Ok(flags) => flags as i64,
            Err(error) => error,
        },
        libc::F_GETFD => {
            if state.cloexec_fds.contains(&guest_fd) {
                i64::from(libc::FD_CLOEXEC)
            } else {
                0
            }
        }
        libc::F_SETFD => {
            if args[2] & libc::FD_CLOEXEC as u64 != 0 {
                state.cloexec_fds.insert(guest_fd);
            } else {
                state.cloexec_fds.remove(&guest_fd);
            }
            0
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(#120): guest F_SETFL applies the
        // kernel-settable file status flags (O_APPEND/O_ASYNC/O_DIRECT/
        // O_NOATIME/O_NONBLOCK) to the backing host descriptor. Access mode and
        // creation flags are silently ignored, matching fcntl(2). Without this,
        // programs that set O_NONBLOCK on a freshly created pipe (e.g. xz)
        // observe ENOSYS and abort.
        libc::F_SETFL => {
            let settable = libc::O_APPEND
                | libc::O_ASYNC
                | libc::O_DIRECT
                | libc::O_NOATIME
                | libc::O_NONBLOCK;
            let flags = args[2] as libc::c_int & settable;
            // SAFETY: host_fd names a live descriptor; F_SETFL consumes one int flag word.
            zero_or_errno(unsafe { libc::fcntl(host_fd, libc::F_SETFL, flags) })
        }
        _ => negative_errno(libc::ENOSYS),
    }
}

fn host_dirfd_and_path(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
) -> Result<(RawFd, CString), i64> {
    if path.starts_with(b"/") {
        return CString::new(path)
            .map(|path| (libc::AT_FDCWD, path))
            .map_err(|_| negative_errno(libc::EINVAL));
    }
    if guest_dirfd == libc::AT_FDCWD {
        return CString::new(path)
            .map(|path| (state.cwd_fd.as_raw_fd(), path))
            .map_err(|_| negative_errno(libc::EINVAL));
    }
    let Some(host_fd) = host_fd(state, guest_dirfd) else {
        return Err(negative_errno(libc::EBADF));
    };
    CString::new(path)
        .map(|path| (host_fd, path))
        .map_err(|_| negative_errno(libc::EINVAL))
}

fn close(state: &mut LoadedStaticElf, raw_fd: u64) -> i64 {
    let Ok(fd) = i32::try_from(raw_fd) else {
        return negative_errno(libc::EBADF);
    };
    if state.files.remove(&fd).is_some() {
        state.cloexec_fds.remove(&fd);
        state.proc_files.remove(&fd);
        set_output_alias(state, fd, None);
        return 0;
    }
    if is_open_standard(state, fd) {
        if fd == libc::STDIN_FILENO {
            state.stdin.take();
        }
        state.closed_standard_fds.insert(fd);
        state.cloexec_fds.remove(&fd);
        set_output_alias(state, fd, None);
        return 0;
    }
    negative_errno(libc::EBADF)
}

fn arch_prctl(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> SyscallAction {
    match args[0] {
        ARCH_SET_FS | ARCH_SET_GS if args[1] < memory.guest_end() => {
            let (base, segment) = if args[0] == ARCH_SET_FS {
                state.fs_base = args[1];
                (state.fs_base, SegmentBase::Fs)
            } else {
                state.gs_base = args[1];
                (state.gs_base, SegmentBase::Gs)
            };
            SyscallAction::Continue {
                result: 0,
                segment: Some((segment, base)),
            }
        }
        ARCH_SET_FS | ARCH_SET_GS => continue_with(negative_errno(libc::EPERM)),
        ARCH_GET_FS => continue_with(write_u64(memory, args[1], state.fs_base)),
        ARCH_GET_GS => continue_with(write_u64(memory, args[1], state.gs_base)),
        _ => continue_with(negative_errno(libc::EINVAL)),
    }
}

// TODO-HUMAN-REVIEW(PR-108): Review the prctl(2) subset for the KVM guest.
//
// Only PR_CAPBSET_READ is modeled. The deterministic container runs the guest as
// root with the full capability bounding set, so libcap's cap_get_bound() must
// report each valid capability as present (1) and out-of-range capabilities as
// EINVAL, exactly as a root process observes on Linux. Without this, the query
// fell through to ENOSYS and tools such as `ls -l` printed a spurious
// "Function not implemented" that neither a native run nor the ptrace backend
// emits. Answers are fixed constants, so run 1 and run 2 of --verify agree and
// results do not depend on the host kernel's CAP_LAST_CAP.
fn prctl(args: &[u64; 6]) -> i64 {
    match args[0] {
        PR_CAPBSET_READ => {
            if args[1] <= GUEST_CAP_LAST_CAP {
                1
            } else {
                negative_errno(libc::EINVAL)
            }
        }
        // Other prctl operations are not modeled yet.
        _ => negative_errno(libc::ENOSYS),
    }
}

// TODO-HUMAN-REVIEW(PR-116): Review the no-xattr KVM guest model and errors.
//
// The deterministic container models no extended attributes, but Linux still
// validates the target and attribute name before reporting ENODATA. Preserve
// those observable path/fd/memory errors without exposing host xattr contents.
fn getxattr(memory: &GuestMemory, state: &LoadedStaticElf, number: u64, args: &[u64; 6]) -> i64 {
    if number == libc::SYS_fgetxattr as u64 {
        let Ok(guest_fd) = libc::c_int::try_from(args[0]) else {
            return negative_errno(libc::EBADF);
        };
        if host_fd(state, guest_fd).is_none() {
            return negative_errno(libc::EBADF);
        }
    } else {
        let path = match read_c_string(memory, args[0], 4096) {
            Ok(path) => path,
            Err(error) => return read_c_string_errno(error),
        };
        if path.is_empty() {
            return negative_errno(libc::ENOENT);
        }
        if synthetic_proc_content(state, &path).is_none() {
            let nofollow = number == libc::SYS_lgetxattr as u64;
            if let Err(error) = open_metadata_path(state, libc::AT_FDCWD, &path, nofollow) {
                return error;
            }
        }
    }

    match read_c_string(memory, args[1], 256) {
        Ok(name) if name.is_empty() => negative_errno(libc::ERANGE),
        Ok(name) => {
            let empty_namespace =
                [b"user.".as_slice(), b"trusted.", b"security."].contains(&name.as_slice());
            if empty_namespace {
                return negative_errno(libc::EINVAL);
            }
            let supported_namespace = [b"user.".as_slice(), b"trusted.", b"security."]
                .iter()
                .any(|prefix| name.starts_with(prefix));
            let supported_system_name = matches!(
                name.as_slice(),
                b"system.posix_acl_access" | b"system.posix_acl_default"
            );
            if supported_namespace || supported_system_name {
                negative_errno(libc::ENODATA)
            } else {
                negative_errno(libc::EOPNOTSUPP)
            }
        }
        Err(ReadCStringError::Fault) => negative_errno(libc::EFAULT),
        Err(ReadCStringError::NameTooLong) => negative_errno(libc::ERANGE),
    }
}

fn brk(memory: &mut GuestMemory, state: &mut LoadedStaticElf, requested: u64) -> i64 {
    if requested == 0 {
        return state.program_break as i64;
    }
    if requested < BOOT_RESERVED_END || requested >= state.brk_limit {
        return state.program_break as i64;
    }
    if requested > state.program_break {
        let Ok(length) = usize::try_from(requested - state.program_break) else {
            return state.program_break as i64;
        };
        if memory.zero(state.program_break, length).is_err() {
            return state.program_break as i64;
        }
    }
    state.program_break = requested;
    requested as i64
}

fn mmap(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[1] == 0 {
        return negative_errno(libc::EINVAL);
    }
    let flags = args[3];
    let is_anonymous = flags & libc::MAP_ANONYMOUS as u64 != 0;
    let is_private = flags & libc::MAP_PRIVATE as u64 != 0;
    let is_shared = flags & libc::MAP_SHARED as u64 != 0;
    if !is_private && !is_shared {
        return negative_errno(libc::EINVAL);
    }

    let Some(length) = align_up(args[1], PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    let fixed = flags & libc::MAP_FIXED as u64 != 0;
    if fixed && !args[0].is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    if !is_anonymous && !args[5].is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    // Linux treats a nonfixed address as a hint. This bounded personality uses
    // its deterministic allocator rather than risking an occupied mapping.
    let address = if fixed { args[0] } else { state.mmap_next };
    let Some(end) = address.checked_add(length) else {
        return negative_errno(libc::ENOMEM);
    };
    if address < BOOT_RESERVED_END || end > state.mmap_limit {
        return negative_errno(libc::ENOMEM);
    }
    let Ok(length) = usize::try_from(length) else {
        return negative_errno(libc::ENOMEM);
    };
    let file_bytes = if !is_anonymous {
        let Ok(fd) = i32::try_from(args[4]) else {
            return negative_errno(libc::EBADF);
        };
        let Some(file) = state.files.get(&fd) else {
            return negative_errno(libc::EBADF);
        };
        let mut bytes = vec![0; length];
        let mut count = 0;
        while count < length {
            match file.read_at(&mut bytes[count..], args[5].saturating_add(count as u64)) {
                Ok(0) => break,
                Ok(read) => count += read,
                Err(error) => return io_error(error),
            }
        }
        Some(bytes)
    } else if args[4] as i32 != -1 {
        return negative_errno(libc::EINVAL);
    } else {
        None
    };

    if memory.zero(address, length).is_err() {
        return negative_errno(libc::ENOMEM);
    }
    if let Some(bytes) = file_bytes
        && memory.write(address, &bytes).is_err()
    {
        return negative_errno(libc::EFAULT);
    }

    if !fixed {
        state.mmap_next = end;
    }
    address as i64
}

fn munmap(memory: &mut GuestMemory, address: u64, length: u64) -> i64 {
    let Some(length) = align_up(length, PAGE_SIZE) else {
        return negative_errno(libc::EINVAL);
    };
    if address < BOOT_RESERVED_END
        || !address.is_multiple_of(PAGE_SIZE)
        || length == 0
        || !range_is_valid(memory, address, length)
    {
        return negative_errno(libc::EINVAL);
    }
    let Ok(length) = usize::try_from(length) else {
        return negative_errno(libc::EINVAL);
    };
    match memory.zero(address, length) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EINVAL),
    }
}

fn mremap(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let old_address = args[0];
    let Some(old_length) = align_up(args[1], PAGE_SIZE) else {
        return negative_errno(libc::EINVAL);
    };
    let Some(new_length) = align_up(args[2], PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    let flags = args[3];
    let allowed_flags = (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64;
    if old_length == 0
        || new_length == 0
        || !old_address.is_multiple_of(PAGE_SIZE)
        || flags & !allowed_flags != 0
        || flags & libc::MREMAP_FIXED as u64 != 0 && flags & libc::MREMAP_MAYMOVE as u64 == 0
        || !range_is_valid(memory, old_address, old_length)
    {
        return negative_errno(libc::EINVAL);
    }

    if flags & libc::MREMAP_FIXED as u64 == 0 && new_length <= old_length {
        if new_length < old_length {
            let tail = old_address + new_length;
            let Ok(length) = usize::try_from(old_length - new_length) else {
                return negative_errno(libc::ENOMEM);
            };
            if memory.zero(tail, length).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
        return old_address as i64;
    }

    let old_end = old_address + old_length;
    if flags & libc::MREMAP_FIXED as u64 == 0 && old_end == state.mmap_next {
        let Some(new_end) = old_address.checked_add(new_length) else {
            return negative_errno(libc::ENOMEM);
        };
        if new_end <= state.mmap_limit {
            let Ok(extension) = usize::try_from(new_length - old_length) else {
                return negative_errno(libc::ENOMEM);
            };
            if memory.zero(old_end, extension).is_err() {
                return negative_errno(libc::ENOMEM);
            }
            state.mmap_next = new_end;
            return old_address as i64;
        }
    }

    if flags & libc::MREMAP_MAYMOVE as u64 == 0 {
        return negative_errno(libc::ENOMEM);
    }
    let destination = if flags & libc::MREMAP_FIXED as u64 != 0 {
        args[4]
    } else {
        state.mmap_next
    };
    let Some(destination_end) = destination.checked_add(new_length) else {
        return negative_errno(libc::ENOMEM);
    };
    if destination < BOOT_RESERVED_END
        || !destination.is_multiple_of(PAGE_SIZE)
        || destination_end > state.mmap_limit
        || destination < old_end && old_address < destination_end
    {
        return negative_errno(libc::EINVAL);
    }

    let copy_length = old_length.min(new_length);
    let Ok(copy_length) = usize::try_from(copy_length) else {
        return negative_errno(libc::ENOMEM);
    };
    let Ok(old_length_usize) = usize::try_from(old_length) else {
        return negative_errno(libc::ENOMEM);
    };
    let Ok(new_length_usize) = usize::try_from(new_length) else {
        return negative_errno(libc::ENOMEM);
    };
    let mut bytes = vec![0; copy_length];
    if memory.read(old_address, &mut bytes).is_err()
        || memory.zero(destination, new_length_usize).is_err()
        || memory.write(destination, &bytes).is_err()
        || memory.zero(old_address, old_length_usize).is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    if flags & libc::MREMAP_FIXED as u64 == 0 {
        state.mmap_next = destination_end;
    }
    destination as i64
}

fn validate_range(memory: &GuestMemory, address: u64, length: u64) -> i64 {
    if length == 0 || !range_is_valid(memory, address, length) {
        negative_errno(libc::EINVAL)
    } else {
        0
    }
}

fn mincore(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    let address = args[0];
    let length = args[1];
    if length == 0 || !address.is_multiple_of(PAGE_SIZE) || !range_is_valid(memory, address, length)
    {
        return negative_errno(libc::EINVAL);
    }
    let Some(page_count) = length.checked_add(PAGE_SIZE - 1).map(|n| n / PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    let Ok(page_count) = usize::try_from(page_count) else {
        return negative_errno(libc::ENOMEM);
    };
    let residency = vec![1_u8; page_count];
    match memory.write(args[2], &residency) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn getcpu(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    if args[0] != 0 {
        let result = write_struct(memory, args[0], &0_u32);
        if result != 0 {
            return result;
        }
    }
    if args[1] != 0 {
        return write_struct(memory, args[1], &0_u32);
    }
    0
}

fn sched_getaffinity(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let requested_pid = args[0] as i64;
    if requested_pid != 0 && requested_pid != i64::from(state.pid) {
        return negative_errno(libc::ESRCH);
    }
    const MASK_BYTES: usize = std::mem::size_of::<libc::c_ulong>();
    let Ok(capacity) = usize::try_from(args[1]) else {
        return negative_errno(libc::EINVAL);
    };
    if capacity < MASK_BYTES {
        return negative_errno(libc::EINVAL);
    }
    let mut mask = [0_u8; MASK_BYTES];
    mask[0] = 1;
    match memory.write(args[2], &mask) {
        Ok(()) => MASK_BYTES as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// SCHED_RESET_ON_FORK may be ORed into the policy passed to sched_setscheduler.
const SCHED_RESET_ON_FORK: libc::c_int = 0x4000_0000;
const SCHED_DEADLINE: libc::c_int = 6;
const SCHED_EXT: libc::c_int = 7;
const IOPRIO_WHO_PROCESS: libc::c_int = 1;
const IOPRIO_WHO_PGRP: libc::c_int = 2;
const IOPRIO_WHO_USER: libc::c_int = 3;
const IOPRIO_CLASS_SHIFT: libc::c_int = 13;
const IOPRIO_CLASS_RT: libc::c_int = 1;
const IOPRIO_CLASS_BE: libc::c_int = 2;
const IOPRIO_CLASS_IDLE: libc::c_int = 3;
const IOPRIO_LEVEL_MASK: libc::c_int = 0x7;

// TODO-HUMAN-REVIEW(PR-119): Review guest scheduler pid validation and lookup.
fn sched_pid_value(raw_pid: u64) -> Result<libc::c_int, i64> {
    let pid = raw_pid as u32 as libc::c_int;
    if pid < 0 {
        Err(negative_errno(libc::EINVAL))
    } else {
        Ok(pid)
    }
}

fn sched_target_result(state: &LoadedStaticElf, pid: libc::c_int) -> Result<(), i64> {
    if pid == 0 || pid == state.pid {
        Ok(())
    } else {
        Err(negative_errno(libc::ESRCH))
    }
}

// TODO-HUMAN-REVIEW(PR-119): Review guest sched_param memory validation.
fn read_sched_param(memory: &GuestMemory, address: u64) -> Result<libc::c_int, i64> {
    if address == 0 {
        return Err(negative_errno(libc::EINVAL));
    }
    let mut priority = [0; std::mem::size_of::<libc::c_int>()];
    memory
        .read(address, &mut priority)
        .map_err(|_| negative_errno(libc::EFAULT))?;
    Ok(libc::c_int::from_ne_bytes(priority))
}

// TODO-HUMAN-REVIEW(PR-119): Review guest sched_param output validation.
fn write_sched_param(memory: &mut GuestMemory, address: u64, priority: libc::c_int) -> i64 {
    match memory.write(address, &priority.to_ne_bytes()) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-119): Review settable policy and priority validation.
fn sched_policy_settable(policy: libc::c_int) -> bool {
    matches!(
        policy,
        libc::SCHED_OTHER
            | libc::SCHED_FIFO
            | libc::SCHED_RR
            | libc::SCHED_BATCH
            | libc::SCHED_IDLE
    )
}

fn sched_priority_valid(policy: libc::c_int, priority: libc::c_int) -> bool {
    match policy {
        libc::SCHED_FIFO | libc::SCHED_RR => (1..=99).contains(&priority),
        libc::SCHED_OTHER | libc::SCHED_BATCH | libc::SCHED_IDLE => priority == 0,
        _ => false,
    }
}

// TODO-HUMAN-REVIEW(PR-110): Review scheduler policy priority bounds.
// TODO-HUMAN-REVIEW(PR-119): Review modern policy-bound compatibility.
fn sched_priority_bound(policy: u64, want_max: bool) -> i64 {
    let policy = policy as u32 as libc::c_int;
    match policy {
        libc::SCHED_FIFO | libc::SCHED_RR => {
            if want_max {
                99
            } else {
                1
            }
        }
        libc::SCHED_OTHER | libc::SCHED_BATCH | libc::SCHED_IDLE | SCHED_DEADLINE | SCHED_EXT => 0,
        _ => negative_errno(libc::EINVAL),
    }
}

// TODO-HUMAN-REVIEW(PR-110): Review virtual sched_getscheduler behavior.
// TODO-HUMAN-REVIEW(PR-119): Review stateful scheduler query behavior.
fn sched_getscheduler(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let pid = match sched_pid_value(args[0]) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    if let Err(error) = sched_target_result(state, pid) {
        return error;
    }
    let reset = if state.sched_reset_on_fork {
        SCHED_RESET_ON_FORK
    } else {
        0
    };
    i64::from(state.sched_policy | reset)
}

// TODO-HUMAN-REVIEW(PR-110): Review virtual sched_setscheduler behavior.
// TODO-HUMAN-REVIEW(PR-119): Review stateful scheduler mutation and errno ordering.
fn sched_setscheduler(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let pid = match sched_pid_value(args[0]) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    let policy_with_flags = args[1] as u32 as libc::c_int;
    if policy_with_flags < 0 {
        return negative_errno(libc::EINVAL);
    }
    let priority = match read_sched_param(memory, args[2]) {
        Ok(priority) => priority,
        Err(error) => return error,
    };
    if let Err(error) = sched_target_result(state, pid) {
        return error;
    }
    let policy = policy_with_flags & !SCHED_RESET_ON_FORK;
    if !sched_policy_settable(policy) || !sched_priority_valid(policy, priority) {
        return negative_errno(libc::EINVAL);
    }
    state.sched_policy = policy;
    state.sched_priority = priority;
    state.sched_reset_on_fork = policy_with_flags & SCHED_RESET_ON_FORK != 0;
    0
}

// TODO-HUMAN-REVIEW(PR-110): Review virtual sched_getparam behavior.
// TODO-HUMAN-REVIEW(PR-119): Review scheduler parameter query errno ordering.
fn sched_getparam(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let pid = match sched_pid_value(args[0]) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    if args[1] == 0 {
        return negative_errno(libc::EINVAL);
    }
    if let Err(error) = sched_target_result(state, pid) {
        return error;
    }
    write_sched_param(memory, args[1], state.sched_priority)
}

// TODO-HUMAN-REVIEW(PR-110): Review virtual sched_setparam behavior.
// TODO-HUMAN-REVIEW(PR-119): Review scheduler parameter mutation errno ordering.
fn sched_setparam(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let pid = match sched_pid_value(args[0]) {
        Ok(pid) => pid,
        Err(error) => return error,
    };
    let priority = match read_sched_param(memory, args[1]) {
        Ok(priority) => priority,
        Err(error) => return error,
    };
    if let Err(error) = sched_target_result(state, pid) {
        return error;
    }
    if !sched_priority_valid(state.sched_policy, priority) {
        return negative_errno(libc::EINVAL);
    }
    state.sched_priority = priority;
    0
}

// TODO-HUMAN-REVIEW(PR-119): Review single-process ioprio target validation.
// Group and user selectors deterministically address the current KVM executor only;
// this is a one-task approximation and does not claim cross-executor group updates.
fn ioprio_target_result(state: &LoadedStaticElf, which: u64, who: u64) -> Result<(), i64> {
    let which = which as u32 as libc::c_int;
    let who = who as u32;
    let target_matches = match which {
        IOPRIO_WHO_PROCESS | IOPRIO_WHO_PGRP => who == 0 || who == state.pid as u32,
        IOPRIO_WHO_USER => who == 0,
        _ => return Err(negative_errno(libc::EINVAL)),
    };
    if target_matches {
        Ok(())
    } else {
        Err(negative_errno(libc::ESRCH))
    }
}

// TODO-HUMAN-REVIEW(PR-119): Review policy-derived effective ioprio defaults.
fn ioprio_effective_default(state: &LoadedStaticElf) -> libc::c_int {
    let class = match state.sched_policy {
        libc::SCHED_IDLE => IOPRIO_CLASS_IDLE,
        libc::SCHED_FIFO | libc::SCHED_RR | SCHED_DEADLINE => IOPRIO_CLASS_RT,
        _ => IOPRIO_CLASS_BE,
    };
    (class << IOPRIO_CLASS_SHIFT) | 4
}

// TODO-HUMAN-REVIEW(PR-110): Review virtual ioprio_get behavior.
// TODO-HUMAN-REVIEW(PR-119): Review raw versus effective ioprio query results.
fn ioprio_get(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if let Err(error) = ioprio_target_result(state, args[0], args[1]) {
        return error;
    }
    if state.ioprio >> IOPRIO_CLASS_SHIFT == 0
        && args[0] as u32 as libc::c_int != IOPRIO_WHO_PROCESS
    {
        i64::from(ioprio_effective_default(state))
    } else {
        i64::from(state.ioprio)
    }
}

// TODO-HUMAN-REVIEW(PR-110): Review virtual ioprio_set behavior.
// TODO-HUMAN-REVIEW(PR-119): Review modern class, level, and hint payload handling.
fn ioprio_set(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let ioprio = args[2] as u32 as libc::c_int;
    if ioprio < 0 {
        return negative_errno(libc::EINVAL);
    }
    let class = ioprio >> IOPRIO_CLASS_SHIFT;
    let valid = match class {
        0 => ioprio & IOPRIO_LEVEL_MASK == 0,
        IOPRIO_CLASS_RT | IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => true,
        _ => false,
    };
    if !valid {
        return negative_errno(libc::EINVAL);
    }
    if let Err(error) = ioprio_target_result(state, args[0], args[1]) {
        return error;
    }
    state.ioprio = ioprio;
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

// The pid/target argument must name the guest process (0 or its own pid).
fn is_self_target(raw_pid: u64, state: &LoadedStaticElf) -> bool {
    let pid = raw_pid as u32 as libc::pid_t;
    pid == 0 || pid == state.pid
}

// TODO-HUMAN-REVIEW(PR-92): Review stateful virtual nice queries.
fn getpriority(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[0] as u32 != libc::PRIO_PROCESS {
        return negative_errno(libc::EINVAL);
    }
    if !is_self_target(args[1], state) {
        return negative_errno(libc::ESRCH);
    }
    i64::from(20 - state.nice)
}

// TODO-HUMAN-REVIEW(PR-92): Review stateful virtual nice mutation and clamping.
fn setpriority(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[0] as u32 != libc::PRIO_PROCESS {
        return negative_errno(libc::EINVAL);
    }
    if !is_self_target(args[1], state) {
        return negative_errno(libc::ESRCH);
    }
    state.nice = (args[2] as u32 as libc::c_int).clamp(-20, 19);
    0
}

// TODO-HUMAN-REVIEW(PR-92): Review bounded sched_getattr ABI writes.
fn sched_getattr(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let size = args[2] as u32 as usize;
    if !(48..=PAGE_SIZE as usize).contains(&size) || args[3] as u32 != 0 {
        return negative_errno(libc::EINVAL);
    }
    if !is_self_target(args[0], state) {
        return negative_errno(libc::ESRCH);
    }
    let attr = SchedAttr {
        size: std::mem::size_of::<SchedAttr>() as u32,
        sched_policy: state.sched_policy as u32,
        sched_flags: u64::from(state.sched_reset_on_fork),
        sched_nice: state.nice,
        sched_priority: state.sched_priority as u32,
        sched_runtime: 2_800_000,
        sched_deadline: 0,
        sched_period: 0,
        sched_util_min: 0,
        sched_util_max: 0,
    };
    let length = size.min(std::mem::size_of::<SchedAttr>());
    // SAFETY: attr is initialized repr(C) data and length is bounded to it.
    let bytes =
        unsafe { std::slice::from_raw_parts((&attr as *const SchedAttr).cast::<u8>(), length) };
    match memory.write(args[1], bytes) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn getrandom(memory: &mut GuestMemory, address: u64, length: u64) -> i64 {
    let Ok(length) = usize::try_from(length) else {
        return negative_errno(libc::EINVAL);
    };
    if length > MAX_HOST_IO {
        return negative_errno(libc::E2BIG);
    }
    let bytes: Vec<u8> = (0..length)
        .map(|index| (index as u8).wrapping_mul(17).wrapping_add(0x5a))
        .collect();
    match memory.write(address, &bytes) {
        Ok(()) => length as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn gettimeofday(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    if args[0] != 0 {
        let timeval = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let result = write_struct(memory, args[0], &timeval);
        if result != 0 {
            return result;
        }
    }
    if args[1] != 0 {
        return write_bytes(
            memory,
            args[1],
            &[0; std::mem::size_of::<libc::c_int>() * 2],
        );
    }
    0
}

fn readlink(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(memory, args[0], 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    let Ok(requested_capacity) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if requested_capacity == 0 {
        return negative_errno(libc::EINVAL);
    }
    let capacity = requested_capacity.min(MAX_HOST_IO);

    if path == b"/proc/self/exe" {
        let count = capacity.min(state.argv0.len());
        return match memory.write(args[1], &state.argv0[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }
    // /proc/self (and /proc/<pid>) is a symlink to the numeric pid directory.
    if path == b"/proc/self" || path == format!("/proc/{}", state.pid).as_bytes() {
        let target = state.pid.to_string().into_bytes();
        let count = capacity.min(target.len());
        return match memory.write(args[1], &target[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }

    let file = match open_metadata_path(state, libc::AT_FDCWD, &path, true) {
        Ok(file) => file,
        Err(error) => return error,
    };
    match file_mode(&file) {
        Ok(mode) if mode & libc::S_IFMT == libc::S_IFLNK => {}
        Ok(_) => return negative_errno(libc::EINVAL),
        Err(error) => return error,
    }
    let empty_path = b"\0";
    let mut bytes = vec![0; capacity];
    // SAFETY: empty_path is NUL-terminated, file is an O_PATH descriptor for
    // the symlink itself, and bytes is writable for capacity bytes.
    let count = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            empty_path.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let count = count as usize;
    match memory.write(args[1], &bytes[..count]) {
        Ok(()) => count as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn uname(memory: &mut GuestMemory, address: u64) -> i64 {
    let mut utsname = [0; 65 * 6];
    for (index, value) in [
        b"Linux".as_slice(),
        b"reverie-kvm".as_slice(),
        b"6.0.0".as_slice(),
        b"#1".as_slice(),
        b"x86_64".as_slice(),
        b"(none)".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let start = index * 65;
        utsname[start..start + value.len()].copy_from_slice(value);
    }
    write_bytes(memory, address, &utsname)
}

fn prlimit64(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    if args[2] != 0 {
        return negative_errno(libc::EPERM);
    }
    if args[3] == 0 {
        return 0;
    }
    let limit = if args[1] as libc::c_uint == libc::RLIMIT_NOFILE as libc::c_uint {
        GUEST_NOFILE_LIMIT as u64
    } else {
        STACK_LIMIT
    };
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&limit.to_le_bytes());
    bytes[8..].copy_from_slice(&limit.to_le_bytes());
    write_bytes(memory, args[3], &bytes)
}

fn rt_sigaction(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[3] != KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    let Ok(signal) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EINVAL);
    };
    if !(1..=64).contains(&signal) {
        return negative_errno(libc::EINVAL);
    }
    let mut action = if args[1] == 0 {
        None
    } else {
        match read_guest_bytes::<KERNEL_SIGACTION_SIZE>(memory, args[1]) {
            Ok(action) => Some(action),
            Err(error) => return error,
        }
    };
    if let Some(action) = &mut action {
        let mask = &mut action[KERNEL_SIGACTION_SIZE - KERNEL_SIGSET_SIZE..];
        for signal in [libc::SIGKILL, libc::SIGSTOP] {
            let bit = (signal - 1) as usize;
            mask[bit / 8] &= !(1 << (bit % 8));
        }
    }
    if action.is_some() && matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
        return negative_errno(libc::EINVAL);
    }

    let previous = state
        .signal_actions
        .get(&signal)
        .copied()
        .unwrap_or([0; KERNEL_SIGACTION_SIZE]);
    if let Some(action) = action {
        state.signal_actions.insert(signal, action);
    }
    if args[2] != 0 {
        return write_bytes(memory, args[2], &previous);
    }
    0
}

fn rt_sigprocmask(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[3] != KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    let requested = if args[1] == 0 {
        None
    } else {
        match read_guest_bytes::<KERNEL_SIGSET_SIZE>(memory, args[1]) {
            Ok(mask) => Some(mask),
            Err(error) => return error,
        }
    };
    let previous = state.signal_mask;
    if let Some(requested) = requested {
        match args[0] as libc::c_int {
            libc::SIG_BLOCK => {
                for (current, requested) in state.signal_mask.iter_mut().zip(requested) {
                    *current |= requested;
                }
            }
            libc::SIG_UNBLOCK => {
                for (current, requested) in state.signal_mask.iter_mut().zip(requested) {
                    *current &= !requested;
                }
            }
            libc::SIG_SETMASK => state.signal_mask = requested,
            _ => return negative_errno(libc::EINVAL),
        }
        for signal in [libc::SIGKILL, libc::SIGSTOP] {
            let bit = (signal - 1) as usize;
            state.signal_mask[bit / 8] &= !(1 << (bit % 8));
        }
    }
    if args[2] != 0 {
        return write_bytes(memory, args[2], &previous);
    }
    0
}

/// Effective action for a signal after honoring any handler installed through
/// `rt_sigaction`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SignalDisposition {
    /// Default action terminates the process.
    Terminate,
    /// Signal is ignored (default or `SIG_IGN`).
    Ignore,
    /// Default action stops the process.
    Stop,
    /// A user handler is installed that this guest kernel cannot deliver.
    Handled,
}

/// Emulates `kill`/`tkill`/`tgkill` for the single-process guest model.
///
/// This guest kernel does not deliver asynchronous signals or run user handlers.
/// However, a process that signals itself with a fatal, default-disposition
/// signal (most importantly glibc `abort()` raising `SIGABRT` via `tgkill`) must
/// still terminate. Before this handler those syscalls returned `ENOSYS`, so
/// `abort()` fell through to its "unreachable" `hlt` trap and the VM reported a
/// spurious `#GP` (exception vector 13) instead of exiting. A self-directed
/// fatal signal now terminates the process with the conventional `128 + signo`
/// status; ignored, stopped, blocked, or user-handled signals are reported as
/// accepted without altering control flow.
// TODO-HUMAN-REVIEW(#95): Review self-signal termination and the default-disposition table.
fn kill_signal(state: &LoadedStaticElf, number: u64, args: &[u64; 6]) -> SyscallAction {
    // tgkill(tgid, tid, sig) carries the signal in its third argument, whereas
    // kill(pid, sig) and tkill(tid, sig) carry it in the second.
    let (target, raw_signal) = if number == libc::SYS_tgkill as u64 {
        (args[1] as i64, args[2])
    } else {
        (args[0] as i64, args[1])
    };
    let Ok(signal) = libc::c_int::try_from(raw_signal) else {
        return continue_with(negative_errno(libc::EINVAL));
    };
    if !(0..=64).contains(&signal) {
        return continue_with(negative_errno(libc::EINVAL));
    }

    // Only self-directed signals are modeled. `kill` accepts the process id, its
    // own process group (0), or the broadcast set (-1); `tkill`/`tgkill` name
    // the sole guest thread by its tid.
    let targets_self = if number == libc::SYS_kill as u64 {
        target == i64::from(state.pid) || target == 0 || target == -1
    } else {
        target == i64::from(state.pid)
    };
    if !targets_self {
        return continue_with(negative_errno(libc::ESRCH));
    }

    // Signal 0 is a permission/liveness probe that delivers nothing.
    if signal == 0 {
        return continue_with(0);
    }

    // SIGKILL can never be caught, blocked, or ignored.
    if signal == libc::SIGKILL {
        return SyscallAction::Exit(128 + signal);
    }

    // A blocked signal stays pending; this guest kernel does not queue pending
    // signals, so report success without terminating.
    if signal_is_blocked(state, signal) {
        return continue_with(0);
    }

    match signal_disposition(state, signal) {
        SignalDisposition::Terminate => SyscallAction::Exit(128 + signal),
        SignalDisposition::Ignore | SignalDisposition::Stop | SignalDisposition::Handled => {
            continue_with(0)
        }
    }
}

/// Resolves the effective disposition of `signal`, honoring any installed
/// handler before falling back to the kernel default action.
fn signal_disposition(state: &LoadedStaticElf, signal: libc::c_int) -> SignalDisposition {
    if let Some(action) = state.signal_actions.get(&signal) {
        let handler = u64::from_le_bytes(action[0..8].try_into().expect("8-byte handler word"));
        const SIG_DFL: u64 = 0;
        const SIG_IGN: u64 = 1;
        match handler {
            SIG_DFL => {}
            SIG_IGN => return SignalDisposition::Ignore,
            _ => return SignalDisposition::Handled,
        }
    }
    default_signal_disposition(signal)
}

/// The kernel default action for `signal` when no handler is installed.
fn default_signal_disposition(signal: libc::c_int) -> SignalDisposition {
    match signal {
        libc::SIGCHLD | libc::SIGURG | libc::SIGWINCH | libc::SIGCONT => SignalDisposition::Ignore,
        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => SignalDisposition::Stop,
        _ => SignalDisposition::Terminate,
    }
}

/// Reports whether `signal` is currently blocked by the guest's signal mask.
fn signal_is_blocked(state: &LoadedStaticElf, signal: libc::c_int) -> bool {
    let bit = (signal - 1) as usize;
    state
        .signal_mask
        .get(bit / 8)
        .is_some_and(|mask| mask & (1 << (bit % 8)) != 0)
}

fn sigaltstack(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let requested = if args[0] == 0 {
        None
    } else {
        let stack = match read_guest_struct::<GuestStack>(memory, args[0]) {
            Ok(stack) => stack,
            Err(error) => return error,
        };
        const SS_AUTODISARM: libc::c_int = libc::c_int::MIN;
        let allowed_flags = libc::SS_DISABLE | SS_AUTODISARM;
        if stack.flags & !allowed_flags != 0
            || stack.flags & libc::SS_DISABLE != 0 && stack.flags & SS_AUTODISARM != 0
        {
            return negative_errno(libc::EINVAL);
        }
        if stack.flags & libc::SS_DISABLE == 0 && stack.size < libc::MINSIGSTKSZ as u64 {
            return negative_errno(libc::ENOMEM);
        }
        Some(stack)
    };
    let previous = state.signal_alt_stack.clone();
    if let Some(requested) = requested {
        state.signal_alt_stack = if requested.flags & libc::SS_DISABLE != 0 {
            None
        } else {
            Some(struct_bytes(&requested))
        };
    }
    if args[1] != 0 {
        if let Some(previous) = previous.as_ref() {
            return write_bytes(memory, args[1], previous);
        }
        return write_struct(
            memory,
            args[1],
            &GuestStack {
                sp: 0,
                flags: libc::SS_DISABLE,
                _padding: 0,
                size: 0,
            },
        );
    }
    0
}

fn wait4(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // pid_t is a 32-bit signed value; the guest passes wait4(-1) as 0xFFFFFFFF
    // in a 64-bit register. Truncate to i32 before sign-extending so the common
    // wait-for-any-child form (-1), process-group forms (0, <-1), and a specific
    // pid are all interpreted correctly instead of collapsing to ECHILD.
    let requested = args[0] as i32 as i64;
    if args[2] & !(libc::WNOHANG as u64) != 0 {
        return negative_errno(libc::EINVAL);
    }
    let child_pid = if requested > 0 {
        i32::try_from(requested)
            .ok()
            .filter(|pid| state.children.contains_key(pid))
    } else {
        // -1 (any child), 0 and <-1 (any child in a process group): this guest
        // models a single process group, so reap any recorded child.
        state.children.keys().next().copied()
    };
    let Some(child_pid) = child_pid else {
        return negative_errno(libc::ECHILD);
    };
    let status = state.children[&child_pid] & 0xff;
    if args[1] != 0 && memory.write(args[1], &(status << 8).to_le_bytes()).is_err() {
        return negative_errno(libc::EFAULT);
    }
    if args[3] != 0
        && memory
            .zero(args[3], std::mem::size_of::<libc::rusage>())
            .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    state.children.remove(&child_pid);
    i64::from(child_pid)
}

fn write_u64(memory: &mut GuestMemory, address: u64, value: u64) -> i64 {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_bytes(memory: &mut GuestMemory, address: u64, bytes: &[u8]) -> i64 {
    match memory.write(address, bytes) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn write_struct<T>(memory: &mut GuestMemory, address: u64, value: &T) -> i64 {
    // SAFETY: Linux ABI structs are initialized plain data. The byte view is
    // bounded to value and copied into guest memory before value is dropped.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    };
    write_bytes(memory, address, bytes)
}

fn read_guest_bytes<const N: usize>(memory: &GuestMemory, address: u64) -> Result<[u8; N], i64> {
    let mut bytes = [0; N];
    memory
        .read(address, &mut bytes)
        .map_err(|_| negative_errno(libc::EFAULT))?;
    Ok(bytes)
}

fn read_guest_struct<T>(memory: &GuestMemory, address: u64) -> Result<T, i64> {
    let mut value = std::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: value is writable for exactly size_of::<T>() bytes and is not
    // observed until guest memory has initialized the complete byte range.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), std::mem::size_of::<T>())
    };
    memory
        .read(address, bytes)
        .map_err(|_| negative_errno(libc::EFAULT))?;
    // SAFETY: the entire plain-data Linux ABI value was initialized above.
    Ok(unsafe { value.assume_init() })
}

fn struct_bytes<T>(value: &T) -> Vec<u8> {
    // SAFETY: Linux ABI structs are initialized plain data and the returned
    // Vec owns its copy before value can be dropped.
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
        .to_vec()
    }
}

fn zero_or_errno(result: libc::c_int) -> i64 {
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

enum ReadCStringError {
    Fault,
    NameTooLong,
}

fn read_c_string_errno(error: ReadCStringError) -> i64 {
    match error {
        ReadCStringError::Fault => negative_errno(libc::EFAULT),
        ReadCStringError::NameTooLong => negative_errno(libc::ENAMETOOLONG),
    }
}

fn read_c_string(
    memory: &GuestMemory,
    address: u64,
    limit: usize,
) -> Result<Vec<u8>, ReadCStringError> {
    let mut result = Vec::new();
    for offset in 0..limit {
        let address = address
            .checked_add(offset as u64)
            .ok_or(ReadCStringError::Fault)?;
        let mut byte = [0];
        memory
            .read(address, &mut byte)
            .map_err(|_| ReadCStringError::Fault)?;
        if byte[0] == 0 {
            return Ok(result);
        }
        result.push(byte[0]);
    }
    Err(ReadCStringError::NameTooLong)
}

fn validate_process_clone_flags(flags: u64) -> Result<(), i64> {
    let signal = flags & 0xff;
    if signal != 0 && signal != libc::SIGCHLD as u64 {
        return Err(negative_errno(libc::EINVAL));
    }
    let allowed = 0xff
        | libc::CLONE_VM as u64
        | libc::CLONE_VFORK as u64
        | libc::CLONE_PARENT_SETTID as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64
        // The fork action clears caught handlers in the child snapshot.
        | CLONE_CLEAR_SIGHAND;
    if flags & !allowed != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    let shared_address_space = flags & (libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64);
    if shared_address_space != 0
        && shared_address_space != (libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64)
    {
        return Err(negative_errno(libc::ENOTSUP));
    }
    if shared_address_space != 0 && flags & PROCESS_CLONE_TID_FLAGS != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    Ok(())
}

struct ProcessCloneRequest {
    flags: u64,
    child_stack: Option<u64>,
    tid_fields_present: bool,
}

fn read_clone3(memory: &GuestMemory, address: u64, size: u64) -> Result<ProcessCloneRequest, i64> {
    const REQUIRED_SIZE: usize = 64;
    const MAX_SIZE: usize = 88;

    let Ok(size) = usize::try_from(size) else {
        return Err(negative_errno(libc::E2BIG));
    };
    if !(REQUIRED_SIZE..=MAX_SIZE).contains(&size) {
        return Err(negative_errno(libc::EINVAL));
    }
    let mut bytes = [0; MAX_SIZE];
    memory
        .read(address, &mut bytes[..size])
        .map_err(|_| negative_errno(libc::EFAULT))?;
    let field = |offset: usize| {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("u64 clone3 field"),
        )
    };
    if field(8) != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    let tid_fields_present = field(16) != 0 || field(24) != 0;
    let flags = field(0) | field(32);
    let stack = field(40);
    let stack_size = field(48);
    let child_stack = if stack == 0 {
        None
    } else {
        stack.checked_add(stack_size)
    };
    if stack != 0 && child_stack.is_none() {
        return Err(negative_errno(libc::EINVAL));
    }
    Ok(ProcessCloneRequest {
        flags,
        child_stack,
        tid_fields_present,
    })
}

fn read_string_array(memory: &GuestMemory, address: u64) -> Result<Vec<String>, i64> {
    const MAX_ENTRIES: usize = 4096;
    const MAX_STRING_BYTES: usize = 128 * 1024;

    if address == 0 {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut total_bytes = 0;
    for index in 0..MAX_ENTRIES {
        let pointer_address = address
            .checked_add((index * std::mem::size_of::<u64>()) as u64)
            .ok_or_else(|| negative_errno(libc::EFAULT))?;
        let mut pointer = [0; 8];
        memory
            .read(pointer_address, &mut pointer)
            .map_err(|_| negative_errno(libc::EFAULT))?;
        let pointer = u64::from_le_bytes(pointer);
        if pointer == 0 {
            return Ok(result);
        }
        let remaining = MAX_STRING_BYTES
            .checked_sub(total_bytes)
            .ok_or_else(|| negative_errno(libc::E2BIG))?;
        let bytes = read_c_string(memory, pointer, remaining).map_err(read_c_string_errno)?;
        total_bytes = total_bytes
            .checked_add(bytes.len() + 1)
            .ok_or_else(|| negative_errno(libc::E2BIG))?;
        result.push(String::from_utf8(bytes).map_err(|_| negative_errno(libc::EINVAL))?);
    }
    Err(negative_errno(libc::E2BIG))
}

fn range_is_valid(memory: &GuestMemory, address: u64, length: u64) -> bool {
    address >= memory.guest_base()
        && address
            .checked_add(length)
            .is_some_and(|end| end <= memory.guest_end())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn continue_with(result: i64) -> SyscallAction {
    SyscallAction::Continue {
        result,
        segment: None,
    }
}

fn io_error(error: std::io::Error) -> i64 {
    negative_errno(error.raw_os_error().unwrap_or(libc::EIO))
}

const fn negative_errno(errno: libc::c_int) -> i64 {
    -(errno as i64)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("reverie-kvm-fs-{}-{id}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn test_state(cwd: &Path) -> LoadedStaticElf {
        LoadedStaticElf {
            entry_point: 0,
            stack_pointer: 0,
            program_break: BOOT_RESERVED_END,
            brk_limit: BOOT_RESERVED_END + PAGE_SIZE,
            mmap_next: BOOT_RESERVED_END + PAGE_SIZE,
            mmap_limit: BOOT_RESERVED_END + 2 * PAGE_SIZE,
            argv0: b"test".to_vec(),
            cwd: cwd.to_owned(),
            cwd_fd: std::fs::File::open(cwd).unwrap(),
            stdin: Some(std::fs::File::open("/dev/null").unwrap()),
            auxv: Vec::new(),
            fs_base: 0,
            gs_base: 0,
            pid: 1,
            ppid: 0,
            umask: 0o022,
            nice: 0,
            sched_policy: libc::SCHED_OTHER,
            sched_priority: 0,
            sched_reset_on_fork: false,
            ioprio: 0,
            signal_actions: BTreeMap::new(),
            signal_mask: [0; KERNEL_SIGSET_SIZE],
            signal_alt_stack: None,
            files: BTreeMap::new(),
            stdout_alias_fds: BTreeSet::new(),
            stderr_alias_fds: BTreeSet::new(),
            cloexec_fds: BTreeSet::new(),
            closed_standard_fds: BTreeSet::new(),
            children: BTreeMap::new(),
            proc_files: BTreeMap::new(),
        }
    }

    fn syscall_result(
        memory: &mut GuestMemory,
        state: &mut LoadedStaticElf,
        number: libc::c_long,
        args: [u64; 6],
    ) -> i64 {
        match execute_basic_syscall(memory, state, &SyscallRequest::new(number as u64, args)) {
            SyscallAction::Continue {
                result,
                segment: None,
            } => result,
            SyscallAction::Continue {
                segment: Some(_), ..
            } => {
                panic!("filesystem syscall changed a segment base")
            }
            SyscallAction::Exit(code) => panic!("filesystem syscall exited with {code}"),
        }
    }

    fn read_struct<T>(memory: &GuestMemory, address: u64) -> T {
        let mut value = std::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: value is writable for exactly size_of::<T>() bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                value.as_mut_ptr().cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        };
        memory.read(address, bytes).unwrap();
        // SAFETY: zeroed storage was fully initialized by memory.read.
        unsafe { value.assume_init() }
    }

    fn write_c_string(memory: &mut GuestMemory, address: u64, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        memory.write(address, &bytes).unwrap();
    }

    /// Read the emulated working directory back through `getcwd`.
    fn current_directory(memory: &mut GuestMemory, state: &mut LoadedStaticElf) -> PathBuf {
        let buffer_address = 0x800;
        let result = syscall_result(
            memory,
            state,
            libc::SYS_getcwd,
            [buffer_address, 0x400, 0, 0, 0, 0],
        );
        assert!(result > 0, "getcwd failed: {result}");
        let mut bytes = vec![0u8; result as usize];
        memory.read(buffer_address, &mut bytes).unwrap();
        // getcwd includes the trailing NUL in its returned length.
        assert_eq!(bytes.pop(), Some(0));
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    }

    #[test]
    fn chdir_updates_cwd_and_resolves_relative_paths() {
        let root = TestDir::new();
        std::fs::create_dir(root.0.join("sub")).unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x2000).unwrap();

        // Relative chdir into an existing subdirectory.
        write_c_string(&mut memory, 0x100, "sub");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chdir,
                [0x100, 0, 0, 0, 0, 0]
            ),
            0
        );
        let expected = std::fs::canonicalize(root.0.join("sub")).unwrap();
        assert_eq!(current_directory(&mut memory, &mut state), expected);

        // A relative create now resolves against the new working directory.
        write_c_string(&mut memory, 0x100, "created");
        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                0x100,
                (libc::O_CREAT | libc::O_WRONLY) as u64,
                0o644,
                0,
                0,
            ],
        );
        assert!(fd >= 0, "openat failed: {fd}");
        assert!(root.0.join("sub").join("created").exists());

        // Absolute chdir back to the root.
        let root_path = std::fs::canonicalize(&root.0).unwrap();
        write_c_string(&mut memory, 0x100, root_path.to_str().unwrap());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chdir,
                [0x100, 0, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(current_directory(&mut memory, &mut state), root_path);
    }

    #[test]
    fn chdir_rejects_missing_and_nondirectory_targets() {
        let root = TestDir::new();
        std::fs::write(root.0.join("file"), b"x").unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        write_c_string(&mut memory, 0x100, "missing");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chdir,
                [0x100, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOENT)
        );

        write_c_string(&mut memory, 0x100, "file");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chdir,
                [0x100, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOTDIR)
        );

        // chdir("") is ENOENT, matching Linux.
        write_c_string(&mut memory, 0x100, "");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chdir,
                [0x100, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOENT)
        );
    }

    #[test]
    fn fchdir_follows_open_directory_descriptor() {
        let root = TestDir::new();
        std::fs::create_dir(root.0.join("sub")).unwrap();
        std::fs::write(root.0.join("sub").join("inside"), b"y").unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x2000).unwrap();

        // fchdir onto a regular-file descriptor is ENOTDIR; a stale fd is EBADF.
        write_c_string(&mut memory, 0x100, "sub/inside");
        let file_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, 0x100, libc::O_RDONLY as u64, 0, 0, 0],
        );
        assert!(file_fd >= 0, "openat file failed: {file_fd}");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchdir,
                [file_fd as u64, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOTDIR)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchdir,
                [9999, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::EBADF)
        );

        // Open the subdirectory as a guest directory descriptor and fchdir to it.
        write_c_string(&mut memory, 0x100, "sub");
        let dir_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                0x100,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0,
            ],
        );
        assert!(dir_fd >= 0, "openat dir failed: {dir_fd}");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchdir,
                [dir_fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        let expected = std::fs::canonicalize(root.0.join("sub")).unwrap();
        assert_eq!(current_directory(&mut memory, &mut state), expected);

        // The cwd handle is independent of the source fd: closing it leaves the
        // working directory usable for later relative resolution.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [dir_fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        write_c_string(&mut memory, 0x100, "inside");
        let reopened = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, 0x100, libc::O_RDONLY as u64, 0, 0, 0],
        );
        assert!(
            reopened >= 0,
            "relative open after close failed: {reopened}"
        );
    }

    fn open_readonly(memory: &mut GuestMemory, state: &mut LoadedStaticElf, path: &str) -> i64 {
        write_c_string(memory, 0x100, path);
        syscall_result(
            memory,
            state,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, 0x100, libc::O_RDONLY as u64, 0, 0, 0],
        )
    }

    fn read_fd_to_end(memory: &mut GuestMemory, state: &mut LoadedStaticElf, fd: i64) -> Vec<u8> {
        let buffer = 0x1000;
        let mut content = Vec::new();
        loop {
            let n = syscall_result(
                memory,
                state,
                libc::SYS_read,
                [fd as u64, buffer, 0x400, 0, 0, 0],
            );
            assert!(n >= 0, "read failed: {n}");
            if n == 0 {
                break;
            }
            let mut chunk = vec![0u8; n as usize];
            memory.read(buffer, &mut chunk).unwrap();
            content.extend_from_slice(&chunk);
        }
        content
    }

    #[test]
    fn synthetic_proc_files_serve_deterministic_content() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();

        let fd = open_readonly(&mut memory, &mut state, "/proc/uptime");
        assert!(fd >= 0, "open /proc/uptime failed: {fd}");
        assert_eq!(read_fd_to_end(&mut memory, &mut state, fd), b"0.00 0.00\n");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        // The descriptor is no longer tracked once closed.
        assert!(state.proc_files.is_empty());

        let fd = open_readonly(&mut memory, &mut state, "/proc/meminfo");
        assert!(fd >= 0);
        let content = read_fd_to_end(&mut memory, &mut state, fd);
        assert!(
            content.starts_with(b"MemTotal:"),
            "{}",
            String::from_utf8_lossy(&content)
        );
    }

    #[test]
    fn synthetic_proc_self_reflects_guest_identity() {
        let root = TestDir::new();
        let mut state = test_state(&root.0); // pid=1, ppid=0, argv0="test"
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();

        let fd = open_readonly(&mut memory, &mut state, "/proc/self/stat");
        let stat = read_fd_to_end(&mut memory, &mut state, fd);
        assert!(
            String::from_utf8_lossy(&stat).starts_with("1 (test) R 0 "),
            "{}",
            String::from_utf8_lossy(&stat)
        );

        let fd = open_readonly(&mut memory, &mut state, "/proc/self/cmdline");
        assert_eq!(read_fd_to_end(&mut memory, &mut state, fd), b"test\0");

        let fd = open_readonly(&mut memory, &mut state, "/proc/self/status");
        let status = String::from_utf8(read_fd_to_end(&mut memory, &mut state, fd)).unwrap();
        assert!(status.contains("Pid:\t1\n"), "{status}");
        assert!(status.contains("PPid:\t0\n"), "{status}");

        // /proc/<pid> aliases /proc/self for this guest's own pid.
        let fd = open_readonly(&mut memory, &mut state, "/proc/1/cmdline");
        assert_eq!(read_fd_to_end(&mut memory, &mut state, fd), b"test\0");
    }

    #[test]
    fn synthetic_proc_metadata_is_synthetic_and_stable() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();

        // fstat of an open synthetic descriptor reports synthesized identity.
        let fd = open_readonly(&mut memory, &mut state, "/proc/uptime");
        let stat_address = 0x1000;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fstat,
                [fd as u64, stat_address, 0, 0, 0, 0]
            ),
            0
        );
        let stat: libc::stat = read_struct(&memory, stat_address);
        assert_eq!(stat.st_mode, libc::S_IFREG | 0o444);
        assert_eq!(stat.st_ino, synthetic_proc_inode(b"/proc/uptime"));
        assert_eq!(stat.st_dev, synthetic_dev(SYNTHETIC_PROC_DEV_MINOR));
        assert_eq!(stat.st_size, b"0.00 0.00\n".len() as libc::off_t);
        assert_eq!(stat.st_uid, 0);
        assert_eq!(stat.st_mtime, 0);

        // A path-addressed newfstatat yields the identical synthetic identity.
        write_c_string(&mut memory, 0x100, "/proc/uptime");
        let path_stat_address = 0x1200;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_newfstatat,
                [libc::AT_FDCWD as u64, 0x100, path_stat_address, 0, 0, 0]
            ),
            0
        );
        let path_stat: libc::stat = read_struct(&memory, path_stat_address);
        assert_eq!(path_stat.st_ino, stat.st_ino);
        assert_eq!(path_stat.st_size, stat.st_size);
        assert_eq!(path_stat.st_mode, stat.st_mode);
    }

    #[test]
    fn synthetic_proc_rejects_writes_and_ignores_unlisted_paths() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        // A writable open of a synthetic file is refused.
        write_c_string(&mut memory, 0x100, "/proc/uptime");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_openat,
                [libc::AT_FDCWD as u64, 0x100, libc::O_WRONLY as u64, 0, 0, 0]
            ),
            negative_errno(libc::EACCES)
        );

        // access() reports the read-only surface.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [0x100, libc::R_OK as u64, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [0x100, libc::W_OK as u64, 0, 0, 0, 0]
            ),
            negative_errno(libc::EACCES)
        );

        // An unlisted /proc path is not part of the synthesized surface.
        assert!(synthetic_proc_content(&state, b"/proc/self/maps").is_none());
        assert!(synthetic_proc_content(&state, b"/etc/passwd").is_none());
    }

    #[test]
    fn virtual_identity_and_random_files_are_read_only() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        for (path, first_byte) in [("/dev/urandom", 41), ("/proc/self/loginuid", b'0')] {
            write_c_string(&mut memory, 0x100, path);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_openat,
                    [libc::AT_FDCWD as u64, 0x100, libc::O_RDWR as u64, 0, 0, 0]
                ),
                negative_errno(libc::EACCES)
            );

            let fd = open_readonly(&mut memory, &mut state, path);
            assert!(fd >= 0, "open {path} failed: {fd}");
            let flags = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
            );
            assert_eq!(flags as libc::c_int & libc::O_ACCMODE, libc::O_RDONLY);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_read,
                    [fd as u64, 0x200, 1, 0, 0, 0]
                ),
                1
            );
            let mut byte = [0];
            memory.read(0x200, &mut byte).unwrap();
            assert_eq!(byte[0], first_byte);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_write,
                    [fd as u64, 0x200, 1, 0, 0, 0]
                ),
                negative_errno(libc::EBADF)
            );
        }
    }

    #[test]
    fn fcntl_getfl_translates_guest_descriptors() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        let stdin = state.stdin.as_ref().unwrap();
        let host_flags = fd_status_flags(stdin.as_raw_fd()).unwrap();
        // SAFETY: stdin owns a live descriptor and F_SETFL consumes an integer flag word.
        assert_eq!(
            unsafe {
                libc::fcntl(
                    stdin.as_raw_fd(),
                    libc::F_SETFL,
                    host_flags | libc::O_NONBLOCK,
                )
            },
            0
        );

        let flags = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [0, libc::F_GETFL as u64, 0, 0, 0, 0],
        );
        assert!(flags >= 0);
        assert_eq!(flags as libc::c_int & libc::O_ACCMODE, libc::O_RDONLY);
        assert_ne!(flags as libc::c_int & libc::O_NONBLOCK, 0);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [99, libc::F_GETFL as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );

        state.closed_standard_fds.insert(libc::STDIN_FILENO);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [0, libc::F_GETFL as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
    }

    #[test]
    fn fcntl_setfl_applies_status_flags() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        const PIPE_FDS: u64 = 0x100;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, 0, 0, 0, 0, 0]
            ),
            0
        );
        let pipe_fds: [libc::c_int; 2] = read_struct(&memory, PIPE_FDS);
        let write_fd = pipe_fds[1];

        // F_SETFL O_NONBLOCK on the guest write end succeeds (previously ENOSYS).
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [
                    write_fd as u64,
                    libc::F_SETFL as u64,
                    libc::O_NONBLOCK as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        // F_GETFL now reflects the applied status flag.
        let flags = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [write_fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
        );
        assert!(flags >= 0);
        assert_ne!(flags as libc::c_int & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn writev_and_readv_gather_scatter_round_trip() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x8000).unwrap();

        const PIPE_FDS: u64 = 0x100;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, 0, 0, 0, 0, 0]
            ),
            0
        );
        let pipe_fds: [libc::c_int; 2] = read_struct(&memory, PIPE_FDS);
        let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);

        const BUF_A: u64 = 0x200;
        const BUF_B: u64 = 0x210;
        memory.write(BUF_A, b"foo").unwrap();
        memory.write(BUF_B, b"barbaz").unwrap();
        const IOV: u64 = 0x300;
        write_struct(&mut memory, IOV, &[BUF_A, 3u64]);
        write_struct(&mut memory, IOV + 16, &[BUF_B, 6u64]);

        // writev gathers both iovecs into the pipe.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_writev,
                [write_fd as u64, IOV, 2, 0, 0, 0]
            ),
            9
        );

        // readv scatters the 9 bytes back into two differently-sized iovecs.
        const RBUF_A: u64 = 0x400;
        const RBUF_B: u64 = 0x410;
        const RIOV: u64 = 0x500;
        write_struct(&mut memory, RIOV, &[RBUF_A, 4u64]);
        write_struct(&mut memory, RIOV + 16, &[RBUF_B, 5u64]);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [read_fd as u64, RIOV, 2, 0, 0, 0]
            ),
            9
        );
        let mut first = [0u8; 4];
        let mut second = [0u8; 5];
        memory.read(RBUF_A, &mut first).unwrap();
        memory.read(RBUF_B, &mut second).unwrap();
        assert_eq!(&first, b"foob");
        assert_eq!(&second, b"arbaz");
    }

    #[test]
    fn flock_and_chown_are_deterministic_for_owned_files() {
        let root = TestDir::new();
        std::fs::write(root.0.join("f"), b"x").unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        write_c_string(&mut memory, 0x100, "f");
        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, 0x100, libc::O_RDWR as u64, 0, 0, 0],
        );
        assert!(fd >= 0, "open failed: {fd}");

        // flock acquire (non-blocking) and release succeed on an owned descriptor.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_flock,
                [
                    fd as u64,
                    (libc::LOCK_EX | libc::LOCK_NB) as u64,
                    0,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_flock,
                [fd as u64, libc::LOCK_UN as u64, 0, 0, 0, 0]
            ),
            0
        );
        // flock on an unknown descriptor is EBADF.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_flock,
                [999, libc::LOCK_EX as u64, 0, 0, 0, 0]
            ),
            negative_errno(libc::EBADF)
        );

        // chown/fchown validate the target then no-op to 0 (virtualized identity).
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchown,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chown,
                [0x100, 0, 0, 0, 0, 0]
            ),
            0
        );
        // A missing path still reports ENOENT; a bad fd reports EBADF.
        write_c_string(&mut memory, 0x200, "missing-file");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chown,
                [0x200, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchown,
                [999, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::EBADF)
        );
    }

    #[test]
    fn pipe_syscalls_create_owned_guest_descriptors() {
        const PIPE_FDS: u64 = 0x100;
        const PAYLOAD: u64 = 0x200;
        const READ_BUFFER: u64 = 0x300;
        const POLL_FD: u64 = 0x400;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write(PAYLOAD, b"pipe-data").unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, libc::O_APPEND as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert!(state.files.is_empty());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [u64::MAX, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert!(state.files.is_empty());

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, 1_u64 << 32, 0, 0, 0, 0],
            ),
            0
        );
        for fd in read_struct::<[libc::c_int; 2]>(&memory, PIPE_FDS) {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_close,
                    [fd as u64, 0, 0, 0, 0, 0],
                ),
                0
            );
        }

        let mut host_fds = [-1; 2];
        // SAFETY: host_fds has room for both descriptors.
        let host_result =
            unsafe { libc::pipe2(host_fds.as_mut_ptr(), libc::O_EXCL | libc::O_CLOEXEC) };
        let expected_notification_result = if host_result == 0 {
            for fd in host_fds {
                // SAFETY: pipe2 initialized both descriptors on success.
                unsafe {
                    libc::close(fd);
                }
            }
            0
        } else {
            io_error(std::io::Error::last_os_error())
        };
        let notification_result = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_pipe2,
            [PIPE_FDS, libc::O_EXCL as u64, 0, 0, 0, 0],
        );
        assert_eq!(notification_result, expected_notification_result);
        if notification_result == 0 {
            for fd in read_struct::<[libc::c_int; 2]>(&memory, PIPE_FDS) {
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_close,
                        [fd as u64, 0, 0, 0, 0, 0],
                    ),
                    0
                );
            }
        }
        assert!(state.files.is_empty());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [
                    PIPE_FDS,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            0
        );
        let pipe_fds: [libc::c_int; 2] = read_struct(&memory, PIPE_FDS);
        assert_eq!(pipe_fds, [3, 4]);

        let read_flags = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [pipe_fds[0] as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
        ) as libc::c_int;
        let write_flags = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [pipe_fds[1] as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
        ) as libc::c_int;
        assert_eq!(read_flags & libc::O_ACCMODE, libc::O_RDONLY);
        assert_eq!(write_flags & libc::O_ACCMODE, libc::O_WRONLY);
        assert_ne!(read_flags & libc::O_NONBLOCK, 0);
        assert_ne!(write_flags & libc::O_NONBLOCK, 0);
        for fd in pipe_fds {
            let host_fd = state.files.get(&fd).unwrap().as_raw_fd();
            // SAFETY: host_fd is live and F_GETFD takes no third argument.
            assert_ne!(
                unsafe { libc::fcntl(host_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }

        let poll_fd = libc::pollfd {
            fd: pipe_fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(write_struct(&mut memory, POLL_FD, &poll_fd), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_poll,
                [POLL_FD, 1, u32::MAX as u64, 0, 0, 0],
            ),
            0
        );
        let poll_fd: libc::pollfd = read_struct(&memory, POLL_FD);
        assert_eq!(poll_fd.fd, pipe_fds[0]);
        assert_eq!(poll_fd.revents, 0);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [pipe_fds[1] as u64, PAYLOAD, 9, 0, 0, 0],
            ),
            9
        );
        let poll_fd = libc::pollfd {
            fd: pipe_fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(write_struct(&mut memory, POLL_FD, &poll_fd), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_poll,
                [POLL_FD, 1, 0, 0, 0, 0],
            ),
            1
        );
        let poll_fd: libc::pollfd = read_struct(&memory, POLL_FD);
        assert_eq!(poll_fd.fd, pipe_fds[0]);
        assert_eq!(poll_fd.revents, libc::POLLIN);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [pipe_fds[0] as u64, READ_BUFFER, 9, 0, 0, 0],
            ),
            9
        );
        let mut payload = [0; 9];
        memory.read(READ_BUFFER, &mut payload).unwrap();
        assert_eq!(&payload, b"pipe-data");

        for fd in pipe_fds {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_close,
                    [fd as u64, 0, 0, 0, 0, 0],
                ),
                0
            );
        }
        assert!(state.files.is_empty());

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe,
                [PIPE_FDS, 0, 0, 0, 0, 0],
            ),
            0
        );
        let pipe_fds: [libc::c_int; 2] = read_struct(&memory, PIPE_FDS);
        assert_eq!(pipe_fds, [3, 4]);
        for &fd in &pipe_fds {
            let flags = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
            ) as libc::c_int;
            assert_eq!(flags & libc::O_NONBLOCK, 0);
            let host_fd = state.files.get(&fd).unwrap().as_raw_fd();
            // SAFETY: host_fd is live and F_GETFD takes no third argument.
            assert_ne!(
                unsafe { libc::fcntl(host_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [pipe_fds[0] as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [pipe_fds[1] as u64, PAYLOAD, 9, 0, 0, 0],
            ),
            negative_errno(libc::EPIPE)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [pipe_fds[1] as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert!(state.files.is_empty());
    }

    #[test]
    fn epoll_waits_are_nonblocking_and_pwait_validates_sigmask() {
        const EVENTS: u64 = 0x100;
        const SIGNAL_MASK: u64 = 0x200;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write(SIGNAL_MASK, &[0; KERNEL_SIGSET_SIZE]).unwrap();
        let epoll_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_epoll_create1,
            [0, 0, 0, 0, 0, 0],
        );
        assert!(epoll_fd >= 0);

        for invalid_output in [0, 1] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_epoll_wait,
                    [epoll_fd as u64, invalid_output, 1, 0, 0, 0]
                ),
                0
            );
        }

        let event_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_eventfd2,
            [0, libc::EFD_NONBLOCK as u64, 0, 0, 0, 0],
        );
        assert!(event_fd >= 0);
        let event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: event_fd as u64,
        };
        assert_eq!(write_struct(&mut memory, EVENTS, &event), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_epoll_ctl,
                [
                    epoll_fd as u64,
                    libc::EPOLL_CTL_ADD as u64,
                    event_fd as u64,
                    EVENTS,
                    0,
                    0,
                ]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_epoll_ctl,
                [
                    epoll_fd as u64,
                    libc::EPOLL_CTL_DEL as u64,
                    event_fd as u64,
                    1,
                    0,
                    0,
                ]
            ),
            0
        );

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_epoll_pwait,
                [epoll_fd as u64, EVENTS, 1, u32::MAX as u64, SIGNAL_MASK, 7]
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_epoll_pwait,
                [
                    epoll_fd as u64,
                    EVENTS,
                    1,
                    u32::MAX as u64,
                    PAGE_SIZE,
                    KERNEL_SIGSET_SIZE as u64,
                ]
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_epoll_pwait,
                [
                    epoll_fd as u64,
                    EVENTS,
                    1,
                    u32::MAX as u64,
                    SIGNAL_MASK,
                    KERNEL_SIGSET_SIZE as u64,
                ]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_epoll_wait,
                [epoll_fd as u64, EVENTS, 1, u32::MAX as u64, 0, 0]
            ),
            0
        );
    }

    #[test]
    fn guest_fd_paths_duplicate_mapped_descriptors() {
        const PATH: u64 = 0x100;
        const PIPE_FDS: u64 = 0x200;
        const PAYLOAD: u64 = 0x300;
        const READ_BUFFER: u64 = 0x400;
        const STATX: u64 = 0x500;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, 0, 0, 0, 0, 0],
            ),
            0
        );
        let pipe_fds: [libc::c_int; 2] = read_struct(&memory, PIPE_FDS);
        assert_eq!(pipe_fds, [3, 4]);

        memory.write(PATH, b"/dev/fd/3\0").unwrap();
        let duplicate = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [PATH, libc::O_RDONLY as u64, 0, 0, 0, 0],
        );
        assert_eq!(duplicate, 5);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statx,
                [
                    libc::AT_FDCWD as u64,
                    PATH,
                    0,
                    libc::STATX_BASIC_STATS as u64,
                    STATX,
                    0,
                ]
            ),
            0
        );
        let statx: libc::statx = read_struct(&memory, STATX);
        assert_eq!(statx.stx_mode & libc::S_IFMT as u16, libc::S_IFIFO as u16);
        memory.write(PAYLOAD, b"fd-path").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [pipe_fds[1] as u64, PAYLOAD, 7, 0, 0, 0],
            ),
            7
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [duplicate as u64, READ_BUFFER, 7, 0, 0, 0],
            ),
            7
        );
        let mut payload = [0; 7];
        memory.read(READ_BUFFER, &mut payload).unwrap();
        assert_eq!(&payload, b"fd-path");

        memory.write(PATH, b"/proc/self/fd/99\0").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_open,
                [PATH, libc::O_RDONLY as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statx,
                [
                    libc::AT_FDCWD as u64,
                    PATH,
                    0,
                    libc::STATX_BASIC_STATS as u64,
                    STATX,
                    0,
                ]
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(guest_fd_path(b"/proc/self/fd/3"), Some(3));
        assert_eq!(guest_fd_path(b"/dev/fd/not-a-fd"), None);
    }

    #[test]
    fn guest_fd_metadata_is_stable_and_isolated_from_supervisor() {
        const PATH: u64 = 0x100;
        const STAT: u64 = 0x400;
        const STATX: u64 = 0x800;
        const PIPE_FDS: u64 = 0xc00;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x2000).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, 0, 0, 0, 0, 0]
            ),
            0
        );

        for prefix in ["/dev/fd/", "/proc/self/fd/"] {
            write_c_string(&mut memory, PATH, &format!("{prefix}3"));
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_newfstatat,
                    [libc::AT_FDCWD as u64, PATH, STAT, 0, 0, 0]
                ),
                0
            );
            let followed: libc::stat = read_struct(&memory, STAT);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_statx,
                    [
                        libc::AT_FDCWD as u64,
                        PATH,
                        0,
                        libc::STATX_BASIC_STATS as u64,
                        STATX,
                        0,
                    ]
                ),
                0
            );
            let followed_x: libc::statx = read_struct(&memory, STATX);
            assert_eq!(followed.st_ino, followed_x.stx_ino);
            assert_eq!(libc::major(followed.st_dev), followed_x.stx_dev_major);
            assert_eq!(libc::minor(followed.st_dev), followed_x.stx_dev_minor);
            assert_eq!(followed_x.stx_dev_major, SYNTHETIC_DEV_MAJOR);
            assert_eq!(followed_x.stx_dev_minor, SYNTHETIC_GUEST_FD_DEV_MINOR);
            assert_eq!(followed.st_mode & libc::S_IFMT, libc::S_IFIFO);

            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_newfstatat,
                    [
                        libc::AT_FDCWD as u64,
                        PATH,
                        STAT,
                        libc::AT_SYMLINK_NOFOLLOW as u64,
                        0,
                        0,
                    ]
                ),
                0
            );
            let nofollow: libc::stat = read_struct(&memory, STAT);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_statx,
                    [
                        libc::AT_FDCWD as u64,
                        PATH,
                        libc::AT_SYMLINK_NOFOLLOW as u64,
                        libc::STATX_BASIC_STATS as u64,
                        STATX,
                        0,
                    ]
                ),
                0
            );
            let nofollow_x: libc::statx = read_struct(&memory, STATX);
            assert_eq!(nofollow.st_ino, nofollow_x.stx_ino);
            assert_eq!(libc::major(nofollow.st_dev), nofollow_x.stx_dev_major);
            assert_eq!(libc::minor(nofollow.st_dev), nofollow_x.stx_dev_minor);
            assert_eq!(nofollow.st_mode & libc::S_IFMT, libc::S_IFLNK);
            assert_eq!(
                nofollow_x.stx_mode & libc::S_IFMT as u16,
                libc::S_IFLNK as u16
            );

            write_c_string(&mut memory, PATH, &format!("{prefix}99"));
            for flags in [0, libc::AT_SYMLINK_NOFOLLOW as u64] {
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_newfstatat,
                        [libc::AT_FDCWD as u64, PATH, STAT, flags, 0, 0]
                    ),
                    negative_errno(libc::ENOENT)
                );
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_statx,
                        [
                            libc::AT_FDCWD as u64,
                            PATH,
                            flags,
                            libc::STATX_BASIC_STATS as u64,
                            STATX,
                            0,
                        ]
                    ),
                    negative_errno(libc::ENOENT)
                );
            }
        }

        let proc_fd = open_readonly(&mut memory, &mut state, "/proc/uptime");
        assert!(proc_fd >= 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fstat,
                [proc_fd as u64, STAT, 0, 0, 0, 0]
            ),
            0
        );
        let direct_proc: libc::stat = read_struct(&memory, STAT);
        write_c_string(&mut memory, PATH, &format!("/dev/fd/{proc_fd}"));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_newfstatat,
                [libc::AT_FDCWD as u64, PATH, STAT, 0, 0, 0]
            ),
            0
        );
        let aliased_proc: libc::stat = read_struct(&memory, STAT);
        assert_eq!(aliased_proc.st_dev, direct_proc.st_dev);
        assert_eq!(aliased_proc.st_ino, direct_proc.st_ino);
        assert_eq!(aliased_proc.st_mode, direct_proc.st_mode);
        assert_eq!(aliased_proc.st_size, direct_proc.st_size);

        let fcntl_copy = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [proc_fd as u64, libc::F_DUPFD as u64, 20, 0, 0, 0],
        );
        let dup_copy = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup,
            [proc_fd as u64, 0, 0, 0, 0, 0],
        );
        let inode = state.proc_files[&(proc_fd as libc::c_int)];
        assert_eq!(
            state.proc_files.get(&(fcntl_copy as libc::c_int)),
            Some(&inode)
        );
        assert_eq!(
            state.proc_files.get(&(dup_copy as libc::c_int)),
            Some(&inode)
        );
    }

    #[test]
    fn write_without_sigpipe_contains_default_signal() {
        const CHILD_ENV: &str = "REVERIE_KVM_SIGPIPE_CHILD";

        if std::env::var_os(CHILD_ENV).is_some() {
            let mut host_fds = [-1; 2];
            // SAFETY: host_fds has room for both descriptors.
            assert_eq!(
                unsafe { libc::pipe2(host_fds.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            // SAFETY: the read descriptor is live and owned by this child.
            assert_eq!(unsafe { libc::close(host_fds[0]) }, 0);
            // SAFETY: this process exists only for this regression and restores nothing afterward.
            unsafe {
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            }

            assert_eq!(
                write_without_sigpipe(host_fds[1], b"broken"),
                negative_errno(libc::EPIPE)
            );
            assert_eq!(signal_is_pending(libc::SIGPIPE), Ok(false));
            // SAFETY: the write descriptor is live and owned by this child.
            assert_eq!(unsafe { libc::close(host_fds[1]) }, 0);
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("executor::tests::write_without_sigpipe_contains_default_signal")
            .arg("--exact")
            .env(CHILD_ENV, "1")
            .output()
            .expect("failed to run isolated SIGPIPE regression");
        assert!(
            output.status.success(),
            "isolated SIGPIPE regression failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn getgroups_uses_fixed_guest_credentials_and_validates_output() {
        const GROUPS: u64 = 0x100;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let count = GUEST_SUPPLEMENTARY_GROUPS.len() as libc::c_int;
        assert_eq!(GUEST_SUPPLEMENTARY_GROUPS, &[65_534]);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getgroups,
                [0, u64::MAX, 0, 0, 0, 0],
            ),
            i64::from(count)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getgroups,
                [u64::MAX, GROUPS, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getgroups,
                [count as u64, GROUPS, 0, 0, 0, 0],
            ),
            i64::from(count)
        );
        assert_eq!(
            read_struct::<libc::gid_t>(&memory, GROUPS),
            GUEST_SUPPLEMENTARY_GROUPS[0]
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getgroups,
                [count as u64, u64::MAX, 0, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
    }

    #[test]
    fn filesystem_round_trip_and_metadata_syscalls() {
        const PATH_ADDRESS: u64 = 0x100;
        const LINK_ADDRESS: u64 = 0x200;
        const DOT_ADDRESS: u64 = 0x300;
        const EMPTY_ADDRESS: u64 = 0x380;
        const PAYLOAD_ADDRESS: u64 = 0x400;
        const LINK_TARGET_ADDRESS: u64 = 0x600;
        const READ_ADDRESS: u64 = 0x800;
        const STAT_ADDRESS: u64 = 0x1000;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        let payload = b"filesystem round trip\n";
        memory.write(PATH_ADDRESS, b"roundtrip\0").unwrap();
        memory.write(LINK_ADDRESS, b"link\0").unwrap();
        memory.write(DOT_ADDRESS, b".\0").unwrap();
        memory.write(EMPTY_ADDRESS, &[0]).unwrap();
        memory.write(PAYLOAD_ADDRESS, payload).unwrap();

        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [
                PATH_ADDRESS,
                (libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR) as u64,
                0xffff_ffff_0000_0180,
                0,
                0,
                0,
            ],
        );
        assert_eq!(fd, 3);
        const EMPTY_PATH: u64 = 0x580;
        write_c_string(&mut memory, EMPTY_PATH, "");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [u64::MAX, 0, 0, libc::AT_EMPTY_PATH as u64, 0, 0,],
            ),
            negative_errno(libc::EINVAL),
            "NULL-path flags are rejected before validating the descriptor"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [u64::MAX, 0, 0, 1_u64 << 32, 0, 0],
            ),
            negative_errno(libc::EBADF),
            "utimensat flags use the low 32-bit Linux int ABI"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [fd as u64, EMPTY_PATH, 0, libc::AT_EMPTY_PATH as u64, 0, 0,],
            ),
            0,
            "AT_EMPTY_PATH must update the supplied descriptor"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [fd as u64, PAYLOAD_ADDRESS, payload.len() as u64, 0, 0, 0],
            ),
            payload.len() as i64
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fstat,
                [fd as u64, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            0
        );
        let file_stat: libc::stat = read_struct(&memory, STAT_ADDRESS);
        assert_eq!(file_stat.st_size, payload.len() as libc::off_t);
        assert_eq!(file_stat.st_mode & libc::S_IFMT, libc::S_IFREG);
        assert_eq!(file_stat.st_mode & 0o777, 0o600);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );

        let read_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDRESS,
                libc::O_RDONLY as u64,
                0,
                0,
                0,
            ],
        );
        assert_eq!(read_fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [read_fd as u64, READ_ADDRESS, payload.len() as u64, 0, 0, 0,],
            ),
            payload.len() as i64
        );
        let mut actual = vec![0; payload.len()];
        memory.read(READ_ADDRESS, &mut actual).unwrap();
        assert_eq!(actual, payload);

        std::os::unix::fs::symlink("roundtrip", root.0.join("link")).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_stat,
                [LINK_ADDRESS, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            0
        );
        let followed: libc::stat = read_struct(&memory, STAT_ADDRESS);
        assert_eq!(followed.st_mode & libc::S_IFMT, libc::S_IFREG);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_lstat,
                [LINK_ADDRESS, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlink,
                [PATH_ADDRESS, LINK_TARGET_ADDRESS, 64, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        let link: libc::stat = read_struct(&memory, STAT_ADDRESS);
        assert_eq!(link.st_mode & libc::S_IFMT, libc::S_IFLNK);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlink,
                [LINK_ADDRESS, LINK_TARGET_ADDRESS, 64, 0, 0, 0],
            ),
            9
        );
        let mut link_target = [0; 9];
        memory.read(LINK_TARGET_ADDRESS, &mut link_target).unwrap();
        assert_eq!(&link_target, b"roundtrip");

        let directory_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                DOT_ADDRESS,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0,
            ],
        );
        assert_eq!(directory_fd, 4);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_newfstatat,
                [directory_fd as u64, PATH_ADDRESS, STAT_ADDRESS, 0, 0, 0,],
            ),
            0
        );
        let relative: libc::stat = read_struct(&memory, STAT_ADDRESS);
        assert_eq!(relative.st_size, payload.len() as libc::off_t);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_newfstatat,
                [libc::AT_FDCWD as u64, EMPTY_ADDRESS, STAT_ADDRESS, 0, 0, 0,],
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_newfstatat,
                [
                    libc::AT_FDCWD as u64,
                    EMPTY_ADDRESS,
                    STAT_ADDRESS,
                    libc::AT_EMPTY_PATH as u64,
                    0,
                    0,
                ],
            ),
            0
        );
        let cwd: libc::stat = read_struct(&memory, STAT_ADDRESS);
        assert_eq!(cwd.st_mode & libc::S_IFMT, libc::S_IFDIR);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statx,
                [
                    libc::AT_FDCWD as u64,
                    PATH_ADDRESS,
                    0,
                    libc::STATX_BASIC_STATS as u64,
                    STAT_ADDRESS,
                    0,
                ],
            ),
            0
        );
        let extended: libc::statx = read_struct(&memory, STAT_ADDRESS);
        assert_eq!(extended.stx_size, payload.len() as u64);
        assert_eq!(
            extended.stx_mask & libc::STATX_BASIC_STATS,
            libc::STATX_BASIC_STATS
        );
        assert_eq!(
            libc::mode_t::from(extended.stx_mode) & libc::S_IFMT,
            libc::S_IFREG
        );
        assert_eq!(std::fs::read(root.0.join("roundtrip")).unwrap(), payload);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [read_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [read_fd as u64, READ_ADDRESS, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [read_fd as u64, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
    }

    #[test]
    fn getdents64_returns_host_directory_entries() {
        const PATH_ADDRESS: u64 = 0x100;
        const DIRENTS_ADDRESS: u64 = 0x1000;
        const DIRENTS_CAPACITY: usize = 0x4000;

        let root = TestDir::new();
        std::fs::write(root.0.join("alpha"), b"a").unwrap();
        std::fs::write(root.0.join("beta"), b"b").unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x8000).unwrap();
        memory.write(PATH_ADDRESS, b".\0").unwrap();

        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDRESS,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64 | (1_u64 << 31),
                0xdead,
                0,
                0,
            ],
        );
        assert_eq!(fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [fd as u64, DIRENTS_ADDRESS, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [fd as u64, u64::MAX, 23, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [fd as u64, DIRENTS_ADDRESS, 1, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_getdents64,
            [fd as u64, DIRENTS_ADDRESS, DIRENTS_CAPACITY as u64, 0, 0, 0],
        );
        assert!(count > 0);
        let mut bytes = vec![0; count as usize];
        memory.read(DIRENTS_ADDRESS, &mut bytes).unwrap();

        let mut names = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            assert!(offset + 19 <= bytes.len());
            let record_length =
                usize::from(u16::from_ne_bytes([bytes[offset + 16], bytes[offset + 17]]));
            assert!(record_length >= 19);
            assert!(offset + record_length <= bytes.len());
            let name = &bytes[offset + 19..offset + record_length];
            let end = name.iter().position(|byte| *byte == 0).unwrap();
            names.push(name[..end].to_vec());
            offset += record_length;
        }
        assert!(names.iter().any(|name| name == b"."));
        assert!(names.iter().any(|name| name == b".."));
        assert!(names.iter().any(|name| name == b"alpha"));
        assert!(names.iter().any(|name| name == b"beta"));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [fd as u64, DIRENTS_ADDRESS, DIRENTS_CAPACITY as u64, 0, 0, 0,],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [fd as u64, u64::MAX, 1, 0, 0, 0],
            ),
            0
        );
    }

    #[test]
    fn descriptor_lifecycle_and_error_precedence_match_linux() {
        const PATH_ADDRESS: u64 = 0x100;
        const PAYLOAD_ADDRESS: u64 = 0x200;
        const STAT_ADDRESS: u64 = 0x300;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x3000).unwrap();
        memory.write(PATH_ADDRESS, b"stdout-file\0").unwrap();
        memory.write(PAYLOAD_ADDRESS, b"redirected").unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [libc::STDOUT_FILENO as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [libc::STDOUT_FILENO as u64, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fstat,
                [libc::STDOUT_FILENO as u64, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );

        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [
                PATH_ADDRESS,
                (libc::O_CREAT | libc::O_WRONLY) as u64,
                0o600,
                0,
                0,
                0,
            ],
        );
        assert_eq!(fd, libc::STDOUT_FILENO as i64);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [fd as u64, PAYLOAD_ADDRESS, 10, 0, 0, 0],
            ),
            10
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [fd as u64, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pread64,
                [fd as u64, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        let read_only_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [PATH_ADDRESS, libc::O_RDONLY as u64, 0, 0, 0, 0],
        );
        assert_eq!(read_only_fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [read_only_fd as u64, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [read_only_fd as u64, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::ENOTDIR)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [99, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [99, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pread64,
                [99, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [99, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            std::fs::read(root.0.join("stdout-file")).unwrap(),
            b"redirected"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [libc::STDIN_FILENO as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        let reused_stdin = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [PATH_ADDRESS, libc::O_RDONLY as u64, 0, 0, 0, 0],
        );
        assert_eq!(reused_stdin, libc::STDIN_FILENO as i64);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [reused_stdin as u64, 0x500, 10, 0, 0, 0],
            ),
            10
        );
        let mut reopened_input = [0; 10];
        memory.read(0x500, &mut reopened_input).unwrap();
        assert_eq!(&reopened_input, b"redirected");
    }

    #[test]
    fn rejects_supervisor_procfs_and_reports_long_paths() {
        const PATH_ADDRESS: u64 = 0x100;
        const LINK_ADDRESS: u64 = 0x400;
        const STAT_ADDRESS: u64 = 0x800;
        const LONG_PATH_ADDRESS: u64 = 0x1000;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        let proc_mem = format!("/proc/{}/mem\0", std::process::id());
        memory.write(PATH_ADDRESS, proc_mem.as_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_open,
                [PATH_ADDRESS, libc::O_RDONLY as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::EACCES)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_stat,
                [PATH_ADDRESS, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            negative_errno(libc::EACCES)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statx,
                [
                    libc::AT_FDCWD as u64,
                    PATH_ADDRESS,
                    0,
                    libc::STATX_BASIC_STATS as u64,
                    STAT_ADDRESS,
                    0,
                ],
            ),
            negative_errno(libc::EACCES)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [PATH_ADDRESS, libc::F_OK as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::EACCES)
        );

        std::os::unix::fs::symlink(&proc_mem[..proc_mem.len() - 1], root.0.join("proc-link"))
            .unwrap();
        memory.write(LINK_ADDRESS, b"proc-link\0").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_lstat,
                [LINK_ADDRESS, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_stat,
                [LINK_ADDRESS, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            negative_errno(libc::EACCES)
        );

        memory.write(LONG_PATH_ADDRESS, b"missing\0").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [LONG_PATH_ADDRESS, 8, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        memory.write(LONG_PATH_ADDRESS, &[120; 4096]).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_open,
                [LONG_PATH_ADDRESS, libc::O_RDONLY as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn relative_open_keeps_cwd_directory_identity() {
        const PATH_ADDRESS: u64 = 0x100;
        const READ_ADDRESS: u64 = 0x200;

        let root = TestDir::new();
        let original = root.0.join("original");
        let moved = root.0.join("moved");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("value"), b"original").unwrap();
        let mut state = test_state(&original);
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();

        let mut memory = GuestMemory::new(0, 0x1000).unwrap();
        memory.write(PATH_ADDRESS, b"value\0").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [PATH_ADDRESS, libc::F_OK as u64, 0, 0, 0, 0],
            ),
            0
        );
        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDRESS,
                libc::O_RDONLY as u64,
                0,
                0,
                0,
            ],
        );
        assert_eq!(fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [fd as u64, READ_ADDRESS, 8, 0, 0, 0],
            ),
            8
        );
        let mut actual = [0; 8];
        memory.read(READ_ADDRESS, &mut actual).unwrap();
        assert_eq!(&actual, b"original");
    }

    #[test]
    fn creat_creates_and_truncates_like_open_o_creat() {
        const PATH_ADDRESS: u64 = 0x100;
        const WRITE_ADDRESS: u64 = 0x200;

        let root = TestDir::new();
        let target = root.0.join("archive");
        // A pre-existing longer file proves creat applies O_TRUNC.
        std::fs::write(&target, b"stale-and-longer-than-new").unwrap();

        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x1000).unwrap();
        memory.write(PATH_ADDRESS, b"archive\0").unwrap();
        memory.write(WRITE_ADDRESS, b"tar\n").unwrap();

        // creat(path, 0o644) must open the existing file, not fall through to
        // ENOSYS as it did before this handler existed.
        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_creat,
            [PATH_ADDRESS, 0o644, 0, 0, 0, 0],
        );
        assert_eq!(fd, 3, "creat should return the first free guest fd");

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [fd as u64, WRITE_ADDRESS, 4, 0, 0, 0],
            ),
            4
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );

        // O_TRUNC replaced the stale content entirely.
        assert_eq!(std::fs::read(&target).unwrap(), b"tar\n");

        // creat on a brand-new path creates it.
        memory.write(PATH_ADDRESS, b"fresh\0").unwrap();
        let fresh_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_creat,
            [PATH_ADDRESS, 0o600, 0, 0, 0, 0],
        );
        assert!(fresh_fd >= 3, "creat on a new path should succeed");
        assert!(root.0.join("fresh").exists());
    }

    #[test]
    fn chdir_and_fchdir_update_working_directory() {
        const PATH_ADDRESS: u64 = 0x100;
        const CWD_ADDRESS: u64 = 0x200;

        let root = TestDir::new();
        let child = root.0.join("child");
        std::fs::create_dir(&child).unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x1000).unwrap();

        memory.write(PATH_ADDRESS, b".\0").unwrap();
        let root_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDRESS,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0,
            ],
        );
        assert_eq!(root_fd, 3);

        memory.write(PATH_ADDRESS, b"child\0").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_chdir,
                [PATH_ADDRESS, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(state.cwd, child);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchdir,
                [root_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(state.cwd, root.0);

        let expected_len = root.0.as_os_str().as_bytes().len() + 1;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getcwd,
                [CWD_ADDRESS, expected_len as u64, 0, 0, 0, 0],
            ),
            expected_len as i64
        );
        let mut cwd = vec![0; expected_len];
        memory.read(CWD_ADDRESS, &mut cwd).unwrap();
        assert_eq!(&cwd[..expected_len - 1], root.0.as_os_str().as_bytes());
    }

    #[test]
    fn host_read_forwards_input_without_consuming_on_guest_fault() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"hello\n").unwrap();
        drop(writer);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        assert_eq!(
            host_read(&mut memory, reader.as_raw_fd(), u64::MAX, 1),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            host_read(&mut memory, reader.as_raw_fd(), u64::MAX, 0),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(host_read(&mut memory, reader.as_raw_fd(), 0x100, 32), 6);
        let mut actual = [0; 6];
        memory.read(0x100, &mut actual).unwrap();
        assert_eq!(&actual, b"hello\n");
        assert_eq!(host_read(&mut memory, reader.as_raw_fd(), 0x200, 32), 0);

        let (reader, mut writer) = UnixStream::pair().unwrap();
        let delayed_writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            writer.write_all(b"hi").unwrap();
        });
        assert_eq!(host_read(&mut memory, reader.as_raw_fd(), 0x300, 32), 2);
        delayed_writer.join().unwrap();
        let mut delayed = [0; 2];
        memory.read(0x300, &mut delayed).unwrap();
        assert_eq!(&delayed, b"hi");
    }

    #[test]
    fn inherited_special_stdin_matches_linux_read_precedence() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        state.stdin = Some(std::fs::File::open(&root.0).unwrap());
        for (address, length, expected) in [
            (u64::MAX, 1, negative_errno(libc::EFAULT)),
            (0x100, 1, negative_errno(libc::EISDIR)),
            (u64::MAX, 0, negative_errno(libc::EFAULT)),
        ] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_read,
                    [libc::STDIN_FILENO as u64, address, length, 0, 0, 0],
                ),
                expected
            );
        }

        // SAFETY: successful descriptor creation transfers ownership to File.
        let epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(epoll >= 0);
        state.stdin = Some(unsafe { std::fs::File::from_raw_fd(epoll) });
        for length in [0, 1] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_read,
                    [libc::STDIN_FILENO as u64, u64::MAX, length, 0, 0, 0],
                ),
                negative_errno(libc::EINVAL)
            );
        }

        // SAFETY: pidfd_open either returns a new descriptor or a negative error.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        if pidfd >= 0 {
            // SAFETY: successful pidfd_open transfers descriptor ownership to File.
            state.stdin = Some(unsafe { std::fs::File::from_raw_fd(pidfd) });
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_read,
                    [libc::STDIN_FILENO as u64, u64::MAX, 1, 0, 0, 0],
                ),
                negative_errno(libc::EINVAL)
            );
        }

        // SAFETY: successful descriptor creation transfers ownership to File.
        let event = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(event >= 0);
        state.stdin = Some(unsafe { std::fs::File::from_raw_fd(event) });
        for (address, length, expected) in [
            (u64::MAX, 1, negative_errno(libc::EFAULT)),
            (0x100, 1, negative_errno(libc::EINVAL)),
            (u64::MAX, 0, negative_errno(libc::EFAULT)),
        ] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_read,
                    [libc::STDIN_FILENO as u64, address, length, 0, 0, 0],
                ),
                expected
            );
        }
    }

    #[test]
    fn standard_input_access_checks_precede_memory_validation() {
        const PAYLOAD: u64 = 0x100;

        let root = TestDir::new();
        let path = root.0.join("stdin");
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write(PAYLOAD, b"x").unwrap();

        state.stdin = Some(std::fs::File::create(&path).unwrap());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [libc::STDIN_FILENO as u64, u64::MAX, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [libc::STDIN_FILENO as u64, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [libc::STDIN_FILENO as u64, PAYLOAD, 1, 0, 0, 0],
            ),
            1
        );
        drop(state);
        assert_eq!(std::fs::read(&path).unwrap(), b"x");

        let mut state = test_state(&root.0);
        state.stdin = Some(std::fs::File::open(&path).unwrap());
        for length in [0, 1] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_write,
                    [libc::STDIN_FILENO as u64, u64::MAX, length, 0, 0, 0],
                ),
                negative_errno(libc::EBADF)
            );
        }
    }

    #[test]
    fn positioned_write_seek_truncate_and_sync_round_trip() {
        const PATH_ADDRESS: u64 = 0x100;
        const PAYLOAD_ADDRESS: u64 = 0x200;
        const PATCH_ADDRESS: u64 = 0x300;
        const READ_ADDRESS: u64 = 0x400;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write(PATH_ADDRESS, b"positioned\0").unwrap();
        memory.write(PAYLOAD_ADDRESS, b"abcdef").unwrap();
        memory.write(PATCH_ADDRESS, b"XY").unwrap();

        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [
                PATH_ADDRESS,
                (libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR) as u64,
                0o600,
                0,
                0,
                0,
            ],
        );
        assert_eq!(fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [fd as u64, PAYLOAD_ADDRESS, 6, 0, 0, 0],
            ),
            6
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pwrite64,
                [fd as u64, PATCH_ADDRESS, 2, 2, 0, 0],
            ),
            2
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_lseek,
                [fd as u64, 0, libc::SEEK_CUR as u64, 0, 0, 0],
            ),
            6,
            "pwrite64 must not change the shared file position"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_lseek,
                [fd as u64, 0, libc::SEEK_SET as u64, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [fd as u64, READ_ADDRESS, 6, 0, 0, 0],
            ),
            6
        );
        let mut actual = [0; 6];
        memory.read(READ_ADDRESS, &mut actual).unwrap();
        assert_eq!(&actual, b"abXYef");
        for syscall in [libc::SYS_fdatasync, libc::SYS_fsync] {
            assert_eq!(
                syscall_result(&mut memory, &mut state, syscall, [fd as u64, 0, 0, 0, 0, 0],),
                0
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ftruncate,
                [fd as u64, 4, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(std::fs::read(root.0.join("positioned")).unwrap(), b"abXY");

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pwrite64,
                [99, u64::MAX, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ftruncate,
                [fd as u64, u64::MAX, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
    }

    #[test]
    fn mremap_grows_moves_and_shrinks_guest_ranges() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let memory_size = BOOT_RESERVED_END + 16 * PAGE_SIZE;
        let mut memory = GuestMemory::new(0, memory_size as usize).unwrap();
        state.mmap_next = BOOT_RESERVED_END + PAGE_SIZE;
        state.mmap_limit = memory_size;
        let mmap_args = [
            0,
            PAGE_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            -1_i32 as u64,
            0,
        ];

        let first = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        memory.write(first, b"mremap-data").unwrap();
        let blocker = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        assert_eq!(blocker, first + PAGE_SIZE);

        let moved = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_mremap,
            [
                first,
                PAGE_SIZE,
                2 * PAGE_SIZE,
                libc::MREMAP_MAYMOVE as u64,
                0,
                0,
            ],
        ) as u64;
        assert_eq!(moved, blocker + PAGE_SIZE);
        let mut payload = [0; 11];
        memory.read(moved, &mut payload).unwrap();
        assert_eq!(&payload, b"mremap-data");
        let mut old = [1; 11];
        memory.read(first, &mut old).unwrap();
        assert_eq!(old, [0; 11]);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mremap,
                [moved, 2 * PAGE_SIZE, PAGE_SIZE, 0, 0, 0],
            ),
            moved as i64
        );
        let mut released = [1; 16];
        memory.read(moved + PAGE_SIZE, &mut released).unwrap();
        assert_eq!(released, [0; 16]);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mremap,
                [
                    moved,
                    PAGE_SIZE,
                    2 * PAGE_SIZE,
                    libc::MREMAP_FIXED as u64,
                    0,
                    0
                ],
            ),
            negative_errno(libc::EINVAL)
        );
    }

    #[test]
    fn gettimeofday_is_deterministic_and_validates_outputs() {
        const TIMEVAL: u64 = 0x100;
        const TIMEZONE: u64 = 0x200;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_gettimeofday,
                [TIMEVAL, TIMEZONE, 0, 0, 0, 0],
            ),
            0
        );
        let timeval: libc::timeval = read_struct(&memory, TIMEVAL);
        assert_eq!((timeval.tv_sec, timeval.tv_usec), (0, 0));
        let timezone: [libc::c_int; 2] = read_struct(&memory, TIMEZONE);
        assert_eq!(timezone, [0, 0]);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_gettimeofday,
                [0, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_gettimeofday,
                [u64::MAX, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
    }

    #[test]
    fn path_mutation_metadata_and_timestamp_syscalls_round_trip() {
        const DIRECTORY: u64 = 0x100;
        const SOURCE: u64 = 0x180;
        const HARD_LINK: u64 = 0x200;
        const SYMLINK: u64 = 0x280;
        const RENAMED: u64 = 0x300;
        const FIFO: u64 = 0x380;
        const DOT: u64 = 0x400;
        const FOLLOWED_LINK: u64 = 0x480;
        const STATFS: u64 = 0x500;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        for (address, value) in [
            (DIRECTORY, "directory"),
            (SOURCE, "source"),
            (HARD_LINK, "hard-link"),
            (SYMLINK, "symlink"),
            (RENAMED, "renamed"),
            (FIFO, "fifo"),
            (DOT, "."),
            (FOLLOWED_LINK, "followed-link"),
        ] {
            write_c_string(&mut memory, address, value);
        }
        std::fs::write(root.0.join("source"), b"payload").unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_umask,
                [0o027, 0, 0, 0, 0, 0]
            ),
            0o022
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mkdir,
                [DIRECTORY, 0o777, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            std::fs::metadata(root.0.join("directory"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_linkat,
                [
                    libc::AT_FDCWD as u64,
                    SOURCE,
                    libc::AT_FDCWD as u64,
                    HARD_LINK,
                    0,
                    0
                ],
            ),
            0
        );
        assert_eq!(std::fs::read(root.0.join("hard-link")).unwrap(), b"payload");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_symlinkat,
                [SOURCE, libc::AT_FDCWD as u64, SYMLINK, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            std::fs::read_link(root.0.join("symlink")).unwrap(),
            Path::new("source")
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_linkat,
                [
                    libc::AT_FDCWD as u64,
                    SYMLINK,
                    libc::AT_FDCWD as u64,
                    FOLLOWED_LINK,
                    libc::AT_SYMLINK_FOLLOW as u64,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            std::fs::read(root.0.join("followed-link")).unwrap(),
            b"payload"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_renameat,
                [
                    libc::AT_FDCWD as u64,
                    HARD_LINK,
                    libc::AT_FDCWD as u64,
                    RENAMED,
                    0,
                    0
                ],
            ),
            0
        );
        assert!(!root.0.join("hard-link").exists());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchmodat,
                [libc::AT_FDCWD as u64, RENAMED, 0o600, 0xdead_beef, 0, 0,],
            ),
            0
        );
        assert_eq!(
            std::fs::metadata(root.0.join("renamed")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [libc::AT_FDCWD as u64, RENAMED, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            std::fs::metadata(root.0.join("renamed")).unwrap().mtime(),
            DETERMINISTIC_UTIME_SECONDS
        );
        let fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                RENAMED,
                libc::O_RDONLY as u64,
                0,
                0,
                0,
            ],
        );
        assert_eq!(fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [fd as u64, 0, 0, 0, 0, 0],
            ),
            0,
            "fd-based utimensat with a NULL pathname must use futimens"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        const EMPTY_OPATH: u64 = 0x580;
        write_c_string(&mut memory, EMPTY_OPATH, "");
        let path_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, RENAMED, libc::O_PATH as u64, 0, 0, 0],
        );
        assert_eq!(path_fd, 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [path_fd as u64, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF),
            "NULL-path timestamp updates reject O_PATH descriptors"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [
                    path_fd as u64,
                    EMPTY_OPATH,
                    0,
                    libc::AT_EMPTY_PATH as u64,
                    0,
                    0,
                ],
            ),
            0,
            "AT_EMPTY_PATH accepts O_PATH descriptors"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [path_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );

        const OMIT_TIMES: u64 = 0x600;
        const CREATED: u64 = 0x700;
        let omit = libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        };
        assert_eq!(write_struct(&mut memory, OMIT_TIMES, &omit), 0);
        assert_eq!(
            write_struct(
                &mut memory,
                OMIT_TIMES + std::mem::size_of::<libc::timespec>() as u64,
                &omit,
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_utimensat,
                [libc::AT_FDCWD as u64, u64::MAX, OMIT_TIMES, 0, 0, 0],
            ),
            0,
            "two UTIME_OMIT values must not resolve the pathname"
        );

        write_c_string(&mut memory, CREATED, "created");
        state.umask = 0;
        let created_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                CREATED,
                (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY) as u64,
                0o666,
                0,
                0,
            ],
        );
        assert!(created_fd >= 0);
        assert_eq!(
            std::fs::metadata(root.0.join("created")).unwrap().mode() & 0o777,
            0o666,
            "the supervisor umask must not be applied after the guest umask"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [created_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_unlinkat,
                [libc::AT_FDCWD as u64, CREATED, 0, 0, 0, 0],
            ),
            0
        );

        std::os::unix::fs::symlink("created-target", root.0.join("created-link")).unwrap();
        write_c_string(&mut memory, CREATED, "created-link");
        let symlink_created_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                CREATED,
                (libc::O_CREAT | libc::O_WRONLY) as u64,
                0o666,
                0,
                0,
            ],
        );
        assert!(symlink_created_fd >= 0);
        assert_eq!(
            std::fs::metadata(root.0.join("created-target"))
                .unwrap()
                .mode()
                & 0o777,
            0o666,
            "guest umask must apply when O_CREAT follows a dangling symlink"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [symlink_created_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );

        let protected = root.0.join("protected");
        std::fs::write(&protected, b"payload").unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o600)).unwrap();
        let protected_file = std::fs::File::open(&protected).unwrap();
        write_c_string(
            &mut memory,
            CREATED,
            &format!("/proc/self/fd/{}", protected_file.as_raw_fd()),
        );
        assert!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchmodat,
                [libc::AT_FDCWD as u64, CREATED, 0o777, 0, 0, 0],
            ) < 0,
            "guest mutations must not follow supervisor procfs descriptors"
        );
        assert_eq!(std::fs::metadata(&protected).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mknodat,
                [
                    libc::AT_FDCWD as u64,
                    FIFO,
                    (libc::S_IFIFO | 0o666) as u64,
                    0,
                    0,
                    0
                ],
            ),
            0
        );
        assert!(
            std::fs::symlink_metadata(root.0.join("fifo"))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statfs,
                [DOT, STATFS, 0, 0, 0, 0],
            ),
            0
        );
        let statfs: libc::statfs = read_struct(&memory, STATFS);
        assert_ne!(statfs.f_type, 0);

        for path in [RENAMED, SYMLINK, FIFO, FOLLOWED_LINK] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_unlinkat,
                    [libc::AT_FDCWD as u64, path, 0, 0, 0, 0],
                ),
                0
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_unlinkat,
                [
                    libc::AT_FDCWD as u64,
                    DIRECTORY,
                    libc::AT_REMOVEDIR as u64,
                    0,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mkdirat,
                [99, DIRECTORY, 0o755, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
    }

    #[test]
    fn rmdir_removes_empty_directories_like_unlinkat_removedir() {
        const DIRECTORY: u64 = 0x100;
        const FILE: u64 = 0x200;
        const NONEMPTY: u64 = 0x300;
        const MISSING: u64 = 0x400;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        for (address, value) in [
            (DIRECTORY, "directory"),
            (FILE, "file"),
            (NONEMPTY, "nonempty"),
            (MISSING, "missing"),
        ] {
            write_c_string(&mut memory, address, value);
        }

        // A bare rmdir(2) removes an empty directory. Regression: this syscall
        // previously fell through to ENOSYS under the KVM backend, so coreutils
        // `rmdir` and `mktemp -d` cleanup failed even though `rm -rf` (which
        // uses unlinkat(AT_REMOVEDIR)) worked.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mkdir,
                [DIRECTORY, 0o755, 0, 0, 0, 0],
            ),
            0
        );
        assert!(root.0.join("directory").is_dir());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rmdir,
                [DIRECTORY, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert!(!root.0.join("directory").exists());

        // rmdir on a missing path reports ENOENT, not ENOSYS.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rmdir,
                [MISSING, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOENT)
        );

        // rmdir on a regular file reports ENOTDIR.
        std::fs::write(root.0.join("file"), b"payload").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rmdir,
                [FILE, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOTDIR)
        );

        // rmdir refuses a non-empty directory with ENOTEMPTY.
        std::fs::create_dir(root.0.join("nonempty")).unwrap();
        std::fs::write(root.0.join("nonempty/child"), b"payload").unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rmdir,
                [NONEMPTY, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOTEMPTY)
        );
    }

    #[test]
    fn descriptor_duplication_and_fchmod_preserve_guest_fd_semantics() {
        let root = TestDir::new();
        let path = root.0.join("descriptor");
        std::fs::write(&path, b"payload").unwrap();
        let mut state = test_state(&root.0);
        state.files.insert(
            3,
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        );
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_dup, [3, 0, 0, 0, 0, 0]),
            4
        );
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_dup2, [3, 0, 0, 0, 0, 0],),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fchmod,
                [4, 0o640, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [3, 3, libc::O_CLOEXEC as u64, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [3, 9, u64::MAX, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [u64::MAX, 9, u64::MAX, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL),
            "dup3 validates flags before the old descriptor"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [3, 10, 1_u64 << 32, 0, 0, 0],
            ),
            10,
            "dup3 flags use the low 32-bit Linux int ABI"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [u64::MAX, 11, 1_u64 << 32, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [10, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [(1_u64 << 32) | 3, 90, 0, 0, 0, 0],
            ),
            90
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [3, (1_u64 << 32) | 91, 0, 0, 0, 0],
            ),
            91
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [90, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [91, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [4, libc::F_SETFD as u64, libc::FD_CLOEXEC as u64, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [4, libc::F_GETFD as u64, 0, 0, 0, 0],
            ),
            i64::from(libc::FD_CLOEXEC)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [4, libc::F_DUPFD as u64, 10, 0, 0, 0],
            ),
            10
        );
        assert!(state.files.contains_key(&10));
        assert!(!state.cloexec_fds.contains(&10));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [4, libc::F_DUPFD_CLOEXEC as u64, 10, 0, 0, 0],
            ),
            11
        );
        assert!(state.cloexec_fds.contains(&11));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [4, libc::F_DUPFD as u64, u64::MAX, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [4, libc::F_DUPFD as u64, GUEST_NOFILE_LIMIT as u64, 0, 0, 0,],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [u64::MAX, libc::F_DUPFD as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [(1_u64 << 32) | 4, libc::F_DUPFD as u64, 12, 0, 0, 0],
            ),
            12,
            "fcntl source fds use the low 32-bit Linux ABI"
        );
        for resource in [
            libc::RLIMIT_NOFILE as u64,
            (1_u64 << 32) | libc::RLIMIT_NOFILE as u64,
        ] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_prlimit64,
                    [0, resource, 0, 0x200, 0, 0],
                ),
                0
            );
            let nofile = read_guest_bytes::<16>(&memory, 0x200).unwrap();
            assert_eq!(
                u64::from_le_bytes(nofile[..8].try_into().unwrap()),
                GUEST_NOFILE_LIMIT as u64
            );
            assert_eq!(
                u64::from_le_bytes(nofile[8..].try_into().unwrap()),
                GUEST_NOFILE_LIMIT as u64
            );
        }
        for fd in [10, 11, 12] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_close,
                    [fd, 0, 0, 0, 0, 0],
                ),
                0
            );
        }
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_close, [0, 0, 0, 0, 0, 0],),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [0, 0x100, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
    }

    #[test]
    fn signal_state_round_trips_and_filters_unmaskable_signals() {
        const ACTION: u64 = 0x100;
        const OLD_ACTION: u64 = 0x180;
        const MASK: u64 = 0x200;
        const OLD_MASK: u64 = 0x280;
        const ALT_STACK: u64 = 0x300;
        const OLD_ALT_STACK: u64 = 0x380;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut action = [0x5a; KERNEL_SIGACTION_SIZE];
        action[KERNEL_SIGACTION_SIZE - KERNEL_SIGSET_SIZE..].fill(u8::MAX);
        let mut expected_action = action;
        for signal in [libc::SIGKILL, libc::SIGSTOP] {
            let bit = (signal - 1) as usize;
            expected_action[KERNEL_SIGACTION_SIZE - KERNEL_SIGSET_SIZE + bit / 8] &=
                !(1 << (bit % 8));
        }
        memory.write(ACTION, &action).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigaction,
                [
                    libc::SIGUSR1 as u64,
                    ACTION,
                    OLD_ACTION,
                    KERNEL_SIGSET_SIZE as u64,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            read_guest_bytes::<KERNEL_SIGACTION_SIZE>(&memory, OLD_ACTION).unwrap(),
            [0; KERNEL_SIGACTION_SIZE]
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigaction,
                [
                    libc::SIGUSR1 as u64,
                    0,
                    OLD_ACTION,
                    KERNEL_SIGSET_SIZE as u64,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            read_guest_bytes::<KERNEL_SIGACTION_SIZE>(&memory, OLD_ACTION).unwrap(),
            expected_action
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigaction,
                [
                    libc::SIGKILL as u64,
                    ACTION,
                    0,
                    KERNEL_SIGSET_SIZE as u64,
                    0,
                    0,
                ],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigaction,
                [
                    libc::SIGUSR2 as u64,
                    ACTION,
                    u64::MAX,
                    KERNEL_SIGSET_SIZE as u64,
                    0,
                    0,
                ],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            state.signal_actions.get(&libc::SIGUSR2),
            Some(&expected_action),
            "new sigaction remains installed if copying old action fails"
        );

        memory.write(MASK, &[u8::MAX; KERNEL_SIGSET_SIZE]).unwrap();
        memory.write(OLD_MASK, &[0x33; KERNEL_SIGSET_SIZE]).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigprocmask,
                [99, MASK, OLD_MASK, KERNEL_SIGSET_SIZE as u64, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(state.signal_mask, [0; KERNEL_SIGSET_SIZE]);
        assert_eq!(
            read_guest_bytes::<KERNEL_SIGSET_SIZE>(&memory, OLD_MASK).unwrap(),
            [0x33; KERNEL_SIGSET_SIZE],
            "invalid how must not copy the old mask"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    MASK,
                    OLD_MASK,
                    KERNEL_SIGSET_SIZE as u64,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            read_guest_bytes::<KERNEL_SIGSET_SIZE>(&memory, OLD_MASK).unwrap(),
            [0; KERNEL_SIGSET_SIZE]
        );
        assert_eq!(state.signal_mask[1] & 1, 0, "SIGKILL must remain unblocked");
        assert_eq!(state.signal_mask[2] & 4, 0, "SIGSTOP must remain unblocked");
        memory.write(MASK, &[0; KERNEL_SIGSET_SIZE]).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    MASK,
                    u64::MAX,
                    KERNEL_SIGSET_SIZE as u64,
                    0,
                    0,
                ],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            state.signal_mask, [0; KERNEL_SIGSET_SIZE],
            "new signal mask remains installed if copying the old mask fails"
        );

        let stack = GuestStack {
            sp: 0x800,
            flags: 0,
            _padding: 0,
            size: libc::MINSIGSTKSZ as u64,
        };
        assert_eq!(write_struct(&mut memory, ALT_STACK, &stack), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sigaltstack,
                [ALT_STACK, OLD_ALT_STACK, 0, 0, 0, 0],
            ),
            0
        );
        let previous: GuestStack = read_struct(&memory, OLD_ALT_STACK);
        assert_eq!(previous.flags, libc::SS_DISABLE);
        let disabled = GuestStack {
            sp: u64::MAX,
            flags: libc::SS_DISABLE,
            _padding: 0,
            size: u64::MAX,
        };
        assert_eq!(write_struct(&mut memory, ALT_STACK, &disabled), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sigaltstack,
                [ALT_STACK, u64::MAX, 0, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert!(
            state.signal_alt_stack.is_none(),
            "disabled altstack remains applied if copying the old stack fails"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sigaltstack,
                [0, OLD_ALT_STACK, 0, 0, 0, 0],
            ),
            0
        );
        let disabled_query: GuestStack = read_struct(&memory, OLD_ALT_STACK);
        assert_eq!(disabled_query.sp, 0);
        assert_eq!(disabled_query.flags, libc::SS_DISABLE);
        assert_eq!(disabled_query.size, 0);
        let child = state.try_clone_for_fork(2).unwrap();
        assert_eq!(child.signal_actions[&libc::SIGUSR1], expected_action);
        assert_eq!(child.signal_mask, state.signal_mask);
        assert_eq!(child.signal_alt_stack, state.signal_alt_stack);
    }

    #[test]
    fn exec_closes_cloexec_descriptors_and_resets_caught_signals() {
        let root = TestDir::new();
        let path = root.0.join("descriptor");
        std::fs::write(&path, b"payload").unwrap();
        let mut previous = test_state(&root.0);
        previous
            .files
            .insert(3, std::fs::File::open(&path).unwrap());
        previous
            .files
            .insert(4, std::fs::File::open(&path).unwrap());
        previous.cloexec_fds.extend([libc::STDIN_FILENO, 4]);
        previous.signal_alt_stack = Some(vec![1; 16]);
        let mut ignored = [0x7f; KERNEL_SIGACTION_SIZE];
        ignored[..std::mem::size_of::<usize>()].copy_from_slice(&libc::SIG_IGN.to_ne_bytes());
        let mut canonical_ignored = [0; KERNEL_SIGACTION_SIZE];
        canonical_ignored[..std::mem::size_of::<usize>()]
            .copy_from_slice(&libc::SIG_IGN.to_ne_bytes());
        let mut caught = [0; KERNEL_SIGACTION_SIZE];
        caught[..std::mem::size_of::<usize>()].copy_from_slice(&2usize.to_ne_bytes());
        previous.signal_actions.insert(libc::SIGUSR1, ignored);
        previous.signal_actions.insert(libc::SIGUSR2, caught);
        let mut replacement = test_state(&root.0);
        replacement.inherit_process_state(previous);
        assert!(replacement.files.contains_key(&3));
        assert!(!replacement.files.contains_key(&4));
        assert!(replacement.stdin.is_none());
        assert!(
            replacement
                .closed_standard_fds
                .contains(&libc::STDIN_FILENO)
        );
        assert!(replacement.cloexec_fds.is_empty());
        assert_eq!(
            replacement.signal_actions.get(&libc::SIGUSR1),
            Some(&canonical_ignored)
        );
        assert!(!replacement.signal_actions.contains_key(&libc::SIGUSR2));
        assert!(replacement.signal_alt_stack.is_none());
    }

    #[test]
    fn process_clone_accepts_legacy_tid_flags_without_prevalidating_pointers() {
        const CHILD_TID: u64 = 0x100;
        const PARENT_TID: u64 = 0x108;

        let root = TestDir::new();
        let memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let flags = libc::SIGCHLD as u64
            | libc::CLONE_PARENT_SETTID as u64
            | libc::CLONE_CHILD_SETTID as u64
            | libc::CLONE_CHILD_CLEARTID as u64;
        let request = SyscallRequest::new(
            libc::SYS_clone as u64,
            [flags, 0, PARENT_TID, CHILD_TID, 0, 0],
        );
        assert_eq!(executor.execute_process_action(&request, &memory), Some(2));
        match executor.take_process_action() {
            Some(ProcessAction::Fork {
                child_pid,
                child_stack,
                parent_tid,
                child_tid,
                clear_child_tid,
                clear_sighand,
            }) => {
                assert_eq!(child_pid, 2);
                assert_eq!(child_stack, None);
                assert!(!clear_sighand);
                assert_eq!(parent_tid, Some(PARENT_TID));
                assert_eq!(child_tid, Some(CHILD_TID));
                assert_eq!(clear_child_tid, Some(CHILD_TID));
            }
            _ => panic!("clone did not produce a fork action"),
        }

        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let bad_pointer = memory.guest_end() - 1;
        let request = SyscallRequest::new(
            libc::SYS_clone as u64,
            [
                libc::SIGCHLD as u64 | libc::CLONE_CHILD_SETTID as u64,
                0,
                0,
                bad_pointer,
                0,
                0,
            ],
        );
        assert_eq!(executor.execute_process_action(&request, &memory), Some(2));
        match executor.take_process_action() {
            Some(ProcessAction::Fork {
                child_pid,
                child_tid,
                ..
            }) => {
                assert_eq!(child_pid, 2);
                assert_eq!(child_tid, Some(bad_pointer));
            }
            _ => panic!("clone with an invalid TID pointer did not create a child"),
        }

        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let shared_flags = flags | libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64;
        let request = SyscallRequest::new(
            libc::SYS_clone as u64,
            [shared_flags, 0, PARENT_TID, CHILD_TID, 0, 0],
        );
        assert_eq!(
            executor.execute_process_action(&request, &memory),
            Some(negative_errno(libc::ENOTSUP))
        );
        assert!(executor.take_process_action().is_none());
    }

    #[test]
    fn clone3_tid_flags_remain_explicitly_unsupported() {
        const CLONE3_ARGS: u64 = 0x200;

        let root = TestDir::new();
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut clone3 = [0_u8; 64];
        clone3[0..8].copy_from_slice(&(libc::CLONE_CHILD_CLEARTID as u64).to_le_bytes());
        clone3[32..40].copy_from_slice(&(libc::SIGCHLD as u64).to_le_bytes());
        memory.write(CLONE3_ARGS, &clone3).unwrap();
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let request = SyscallRequest::new(
            libc::SYS_clone3 as u64,
            [CLONE3_ARGS, clone3.len() as u64, 0, 0, 0, 0],
        );

        assert_eq!(
            executor.execute_process_action(&request, &memory),
            Some(negative_errno(libc::ENOTSUP))
        );
        assert!(executor.take_process_action().is_none());

        clone3[16..24].copy_from_slice(&1_u64.to_le_bytes());
        clone3[32..40].copy_from_slice(&255_u64.to_le_bytes());
        memory.write(CLONE3_ARGS, &clone3).unwrap();
        let request = SyscallRequest::new(
            libc::SYS_clone3 as u64,
            [CLONE3_ARGS, clone3.len() as u64, 0, 0, 0, 0],
        );
        assert_eq!(
            executor.execute_process_action(&request, &memory),
            Some(negative_errno(libc::EINVAL)),
            "malformed exit_signal takes precedence over unsupported TID flags"
        );
        assert!(executor.take_process_action().is_none());

        clone3[32..40].copy_from_slice(&(libc::SIGCHLD as u64).to_le_bytes());
        memory.write(CLONE3_ARGS, &clone3).unwrap();
        let request = SyscallRequest::new(
            libc::SYS_clone3 as u64,
            [CLONE3_ARGS, clone3.len() as u64, 0, 0, 0, 0],
        );
        assert_eq!(
            executor.execute_process_action(&request, &memory),
            Some(negative_errno(libc::ENOTSUP)),
            "a TID field remains explicitly unsupported after validation"
        );
        assert!(executor.take_process_action().is_none());
    }

    #[test]
    fn clone3_posix_spawn_vfork_with_clear_sighand_is_accepted() {
        // glibc >= 2.36 `posix_spawn` (used by `make`/`gcc` to launch recipe and
        // subprocess jobs) issues exactly this clone3: CLONE_VM|CLONE_VFORK with
        // CLONE_CLEAR_SIGHAND, an explicit child stack, and SIGCHLD as the exit
        // signal. Older glibc omitted CLONE_CLEAR_SIGHAND, so the executor must
        // accept the flag and reset caught child handlers before it runs.
        const CLONE3_ARGS: u64 = 0x200;
        const CHILD_STACK: u64 = 0x4000;
        const CHILD_STACK_SIZE: u64 = 0x9000;

        let root = TestDir::new();
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut clone3 = [0_u8; 88];
        let flags = libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64 | CLONE_CLEAR_SIGHAND;
        clone3[0..8].copy_from_slice(&flags.to_le_bytes());
        clone3[32..40].copy_from_slice(&(libc::SIGCHLD as u64).to_le_bytes());
        clone3[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
        clone3[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
        memory.write(CLONE3_ARGS, &clone3).unwrap();

        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let mut ignored = [0; KERNEL_SIGACTION_SIZE];
        ignored[..std::mem::size_of::<usize>()].copy_from_slice(&libc::SIG_IGN.to_ne_bytes());
        let mut caught = [0; KERNEL_SIGACTION_SIZE];
        caught[..std::mem::size_of::<usize>()].copy_from_slice(&2usize.to_ne_bytes());
        executor.state.signal_actions.insert(libc::SIGUSR1, ignored);
        executor.state.signal_actions.insert(libc::SIGUSR2, caught);
        let request = SyscallRequest::new(
            libc::SYS_clone3 as u64,
            [CLONE3_ARGS, clone3.len() as u64, 0, 0, 0, 0],
        );
        assert_eq!(executor.execute_process_action(&request, &memory), Some(2));
        match executor.take_process_action() {
            Some(ProcessAction::Fork {
                child_pid,
                child_stack,
                parent_tid,
                child_tid,
                clear_child_tid,
                clear_sighand,
            }) => {
                assert_eq!(child_pid, 2);
                assert_eq!(child_stack, Some(CHILD_STACK + CHILD_STACK_SIZE));
                assert!(clear_sighand);
                assert_eq!(parent_tid, None);
                assert_eq!(child_tid, None);
                assert_eq!(clear_child_tid, None);
                let child = executor.fork_child(child_pid, clear_sighand).unwrap();
                assert_eq!(
                    child.state.signal_actions.get(&libc::SIGUSR1),
                    Some(&ignored)
                );
                assert!(!child.state.signal_actions.contains_key(&libc::SIGUSR2));
                assert_eq!(
                    executor.state.signal_actions.get(&libc::SIGUSR1),
                    Some(&ignored)
                );
                assert_eq!(
                    executor.state.signal_actions.get(&libc::SIGUSR2),
                    Some(&caught)
                );
            }
            _ => panic!("clone3 with CLONE_CLEAR_SIGHAND did not create a fork action"),
        }
    }

    #[test]
    fn set_tid_address_tracks_current_pid_and_clear_pointer() {
        const CLEAR_TID: u64 = 0x100;

        let root = TestDir::new();
        let memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let request =
            SyscallRequest::new(libc::SYS_set_tid_address as u64, [CLEAR_TID, 0, 0, 0, 0, 0]);
        assert_eq!(executor.execute_process_action(&request, &memory), Some(1));
        assert_eq!(executor.take_clear_child_tid(), Some(CLEAR_TID));

        let request = SyscallRequest::new(libc::SYS_set_tid_address as u64, [0; 6]);
        assert_eq!(executor.execute_process_action(&request, &memory), Some(1));
        assert_eq!(executor.take_clear_child_tid(), None);

        let request =
            SyscallRequest::new(libc::SYS_set_tid_address as u64, [CLEAR_TID, 0, 0, 0, 0, 0]);
        assert_eq!(executor.execute_process_action(&request, &memory), Some(1));
        executor.replace_after_exec(test_state(&root.0));
        assert_eq!(executor.take_clear_child_tid(), None);
    }

    #[test]
    fn priority_and_scheduler_queries_round_trip_guest_persona() {
        const PARAM: u64 = 0x100;
        const ATTR: u64 = 0x200;
        // ioprio encoding (whoami=PROCESS, class shift, IDLE class).
        const IOPRIO_WHO_PROCESS: u64 = 1;
        const IOPRIO_CLASS_SHIFT: u32 = 13;
        const IOPRIO_CLASS_IDLE: u64 = 3;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getpriority,
                [libc::PRIO_PROCESS as u64, 0, 0, 0, 0, 0],
            ),
            20
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_setpriority,
                [libc::PRIO_PROCESS as u64, 0, 1, 0, 0, 0],
            ),
            0
        );
        assert_eq!(state.nice, 1);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getpriority,
                [libc::PRIO_PROCESS as u64, 0, 0, 0, 0, 0],
            ),
            19
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PROCESS, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_set,
                [
                    IOPRIO_WHO_PROCESS,
                    0,
                    IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
                    0,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getscheduler,
                [0, 0, 0, 0, 0, 0],
            ),
            i64::from(libc::SCHED_OTHER)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getparam,
                [0, PARAM, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            read_struct::<libc::sched_param>(&memory, PARAM).sched_priority,
            0
        );
        for size in [0, 47, PAGE_SIZE + 1] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_sched_getattr,
                    [0, ATTR, size, 0, 0, 0]
                ),
                negative_errno(libc::EINVAL)
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getattr,
                [999_999, ATTR, 48, 1, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getattr,
                [999_999, ATTR, 48, 0, 0, 0]
            ),
            negative_errno(libc::ESRCH)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getattr,
                [0, ATTR, std::mem::size_of::<SchedAttr>() as u64, 0, 0, 0],
            ),
            0
        );
        let attr: SchedAttr = read_struct(&memory, ATTR);
        assert_eq!(attr.size as usize, std::mem::size_of::<SchedAttr>());
        assert_eq!(attr.sched_policy, libc::SCHED_OTHER as u32);
        assert_eq!(attr.sched_priority, 0);
        assert_eq!(attr.sched_nice, 1);

        memory.write(ATTR + 48, &[0xa5; 8]).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getattr,
                [0, ATTR, 48, 0, 0, 0],
            ),
            0
        );
        let mut canary = [0; 8];
        memory.read(ATTR + 48, &mut canary).unwrap();
        assert_eq!(canary, [0xa5; 8]);
    }

    #[test]
    fn memory_residency_and_cpu_topology_are_deterministic() {
        const VECTOR: u64 = 4 * PAGE_SIZE;
        const CPU: u64 = 0x100;
        const NODE: u64 = 0x108;
        const AFFINITY: u64 = 0x200;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, (5 * PAGE_SIZE) as usize).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mincore,
                [PAGE_SIZE, PAGE_SIZE + 1, VECTOR, 0, 0, 0],
            ),
            0
        );
        assert_eq!(read_guest_bytes::<2>(&memory, VECTOR).unwrap(), [1, 1]);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mincore,
                [PAGE_SIZE + 1, PAGE_SIZE, VECTOR, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getcpu,
                [CPU, NODE, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(read_struct::<u32>(&memory, CPU), 0);
        assert_eq!(read_struct::<u32>(&memory, NODE), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getaffinity,
                [0, 8, AFFINITY, 0, 0, 0],
            ),
            8
        );
        assert_eq!(
            read_guest_bytes::<8>(&memory, AFFINITY).unwrap(),
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [0, 0, 0, 0, 0, 0],
            ),
            i64::from(MEMBARRIER_SUPPORTED)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [0, 0, 123, 0, 0, 0],
            ),
            i64::from(MEMBARRIER_SUPPORTED)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [1_u64 << 32, 1_u64 << 32, 123, 0, 0, 0],
            ),
            i64::from(MEMBARRIER_SUPPORTED)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [1, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [1, 0, 123, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [(1_u64 << 32) | 1, 1_u64 << 32, 123, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [3, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [0, 1, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_membarrier,
                [1 << 20, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
    }

    #[test]
    fn wait4_decodes_zero_extended_negative_one_and_reports_exit_status() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        state.children.insert(7, 3);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let status_address = 0x100;

        assert_eq!(
            wait4(
                &mut memory,
                &mut state,
                &[u64::from(u32::MAX), status_address, 0, 0, 0, 0],
            ),
            7
        );
        let mut status = [0; std::mem::size_of::<libc::c_int>()];
        memory.read(status_address, &mut status).unwrap();
        assert_eq!(libc::c_int::from_le_bytes(status), 3 << 8);
        assert!(state.children.is_empty());
    }

    #[test]
    fn deterministic_getrandom_repeats() {
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        assert_eq!(getrandom(&mut memory, 0x100, 32), 32);
        let mut first = [0; 32];
        memory.read(0x100, &mut first).unwrap();

        assert_eq!(getrandom(&mut memory, 0x200, 32), 32);
        let mut second = [0; 32];
        memory.read(0x200, &mut second).unwrap();
        assert_eq!(first, second);
    }

    fn custom_action(handler: u64) -> [u8; KERNEL_SIGACTION_SIZE] {
        let mut action = [0; KERNEL_SIGACTION_SIZE];
        action[0..8].copy_from_slice(&handler.to_le_bytes());
        action
    }

    #[test]
    fn self_directed_fatal_signal_terminates_with_conventional_status() {
        let dir = TestDir::new();
        let state = test_state(&dir.0);

        // abort() raises SIGABRT via tgkill(pid, tid, SIGABRT).
        let action = kill_signal(
            &state,
            libc::SYS_tgkill as u64,
            &[
                state.pid as u64,
                state.pid as u64,
                libc::SIGABRT as u64,
                0,
                0,
                0,
            ],
        );
        match action {
            SyscallAction::Exit(code) => assert_eq!(code, 128 + libc::SIGABRT),
            _ => panic!("expected Exit for self-directed SIGABRT"),
        }
    }

    #[test]
    fn kill_and_tkill_self_fatal_signals_terminate() {
        let dir = TestDir::new();
        let state = test_state(&dir.0);

        for (number, args) in [
            (
                libc::SYS_kill,
                [state.pid as u64, libc::SIGSEGV as u64, 0, 0, 0, 0],
            ),
            (
                libc::SYS_tkill,
                [state.pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            ),
            // kill(-1, SIGTERM) broadcasts to a set that includes ourselves.
            (
                libc::SYS_kill,
                [(-1i64) as u64, libc::SIGTERM as u64, 0, 0, 0, 0],
            ),
        ] {
            match kill_signal(&state, number as u64, &args) {
                SyscallAction::Exit(_) => {}
                _ => panic!("expected Exit for syscall {number}"),
            }
        }
    }

    #[test]
    fn ignored_and_probe_signals_do_not_terminate() {
        let dir = TestDir::new();
        let state = test_state(&dir.0);

        // Signal 0 is a liveness probe.
        assert!(matches!(
            kill_signal(
                &state,
                libc::SYS_kill as u64,
                &[state.pid as u64, 0, 0, 0, 0, 0],
            ),
            SyscallAction::Continue { result: 0, .. }
        ));
        // SIGWINCH is ignored by default.
        assert!(matches!(
            kill_signal(
                &state,
                libc::SYS_kill as u64,
                &[state.pid as u64, libc::SIGWINCH as u64, 0, 0, 0, 0],
            ),
            SyscallAction::Continue { result: 0, .. }
        ));
    }

    #[test]
    fn installed_handler_and_blocked_signal_are_not_terminating() {
        let dir = TestDir::new();
        let mut state = test_state(&dir.0);

        // A user handler that we cannot deliver must not terminate the process.
        state
            .signal_actions
            .insert(libc::SIGTERM, custom_action(0x4000));
        assert!(matches!(
            kill_signal(
                &state,
                libc::SYS_kill as u64,
                &[state.pid as u64, libc::SIGTERM as u64, 0, 0, 0, 0],
            ),
            SyscallAction::Continue { result: 0, .. }
        ));

        // A blocked fatal signal stays pending rather than terminating.
        let mut blocked = test_state(&dir.0);
        let bit = (libc::SIGINT - 1) as usize;
        blocked.signal_mask[bit / 8] |= 1 << (bit % 8);
        assert!(matches!(
            kill_signal(
                &blocked,
                libc::SYS_kill as u64,
                &[blocked.pid as u64, libc::SIGINT as u64, 0, 0, 0, 0],
            ),
            SyscallAction::Continue { result: 0, .. }
        ));

        // SIGKILL ignores both the mask and any installed handler.
        let mut unkillable = test_state(&dir.0);
        unkillable
            .signal_actions
            .insert(libc::SIGKILL, custom_action(0x1));
        let bit = (libc::SIGKILL - 1) as usize;
        unkillable.signal_mask[bit / 8] |= 1 << (bit % 8);
        assert!(matches!(
            kill_signal(
                &unkillable,
                libc::SYS_kill as u64,
                &[unkillable.pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            ),
            SyscallAction::Exit(_)
        ));
    }

    #[test]
    fn signals_to_other_processes_report_esrch() {
        let dir = TestDir::new();
        let state = test_state(&dir.0);

        match kill_signal(
            &state,
            libc::SYS_kill as u64,
            &[(state.pid + 1) as u64, libc::SIGTERM as u64, 0, 0, 0, 0],
        ) {
            SyscallAction::Continue {
                result,
                segment: None,
            } => assert_eq!(result, negative_errno(libc::ESRCH)),
            _ => panic!("expected ESRCH continue for a foreign target"),
        }
    }

    #[test]
    fn signal_disposition_honors_handlers_over_defaults() {
        let dir = TestDir::new();
        let mut state = test_state(&dir.0);

        assert_eq!(
            signal_disposition(&state, libc::SIGABRT),
            SignalDisposition::Terminate
        );
        assert_eq!(
            signal_disposition(&state, libc::SIGCHLD),
            SignalDisposition::Ignore
        );
        assert_eq!(
            signal_disposition(&state, libc::SIGTSTP),
            SignalDisposition::Stop
        );

        state
            .signal_actions
            .insert(libc::SIGABRT, custom_action(0x1)); // SIG_IGN
        assert_eq!(
            signal_disposition(&state, libc::SIGABRT),
            SignalDisposition::Ignore
        );
        state
            .signal_actions
            .insert(libc::SIGABRT, custom_action(0xdead_beef));
        assert_eq!(
            signal_disposition(&state, libc::SIGABRT),
            SignalDisposition::Handled
        );
    }

    // Non-`#!` payload; the resolver only checks that it is not a script.
    const FAKE_ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00 fake elf body";

    #[test]
    fn resolve_exec_shebang_plain_elf_is_unchanged() {
        let dir = TestDir::new();
        let prog = dir.0.join("prog");
        std::fs::write(&prog, FAKE_ELF).unwrap();

        let (path, image, argv) = resolve_exec_shebang(
            prog.clone(),
            FAKE_ELF.to_vec(),
            vec!["prog".to_owned(), "-a".to_owned()],
        )
        .unwrap();
        assert_eq!(path, prog);
        assert_eq!(image, FAKE_ELF);
        assert_eq!(argv, vec!["prog".to_owned(), "-a".to_owned()]);
    }

    #[test]
    fn resolve_exec_shebang_single_level_kernel_order() {
        let dir = TestDir::new();
        let interp = dir.0.join("fakebash");
        std::fs::write(&interp, FAKE_ELF).unwrap();
        let script = dir.0.join("script");
        let script_body = format!("#!{} -x\necho hi\n", interp.display());

        let (path, image, argv) = resolve_exec_shebang(
            script.clone(),
            script_body.into_bytes(),
            vec!["script".to_owned(), "arg1".to_owned()],
        )
        .unwrap();
        assert_eq!(path, interp);
        assert_eq!(image, FAKE_ELF);
        // Kernel order: [interp, shebang args.., script_path, original args[1..]].
        assert_eq!(
            argv,
            vec![
                interp.to_string_lossy().into_owned(),
                "-x".to_owned(),
                script.to_string_lossy().into_owned(),
                "arg1".to_owned(),
            ]
        );
    }

    #[test]
    fn resolve_exec_shebang_rejects_infinite_recursion() {
        let dir = TestDir::new();
        let a = dir.0.join("a");
        let b = dir.0.join("b");
        std::fs::write(&a, format!("#!{}\n", b.display())).unwrap();
        std::fs::write(&b, format!("#!{}\n", a.display())).unwrap();

        let err = resolve_exec_shebang(a.clone(), std::fs::read(&a).unwrap(), vec!["a".to_owned()])
            .unwrap_err();
        assert_eq!(err, negative_errno(libc::ELOOP));
    }

    #[test]
    fn xattr_model_preserves_target_and_name_errors() {
        let root = TestDir::new();
        std::fs::write(root.0.join("file"), b"content").unwrap();
        std::os::unix::fs::symlink("missing", root.0.join("dangling")).unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        write_c_string(&mut memory, 0x100, "file");
        write_c_string(&mut memory, 0x200, "security.selinux");

        for number in [libc::SYS_getxattr, libc::SYS_lgetxattr] {
            assert_eq!(
                syscall_result(&mut memory, &mut state, number, [0x100, 0x200, 0, 0, 0, 0]),
                negative_errno(libc::ENODATA)
            );
        }

        for (name, errno) in [
            ("", libc::ERANGE),
            ("foo", libc::EOPNOTSUPP),
            ("user.reverie_review", libc::ENODATA),
        ] {
            write_c_string(&mut memory, 0x200, name);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_getxattr,
                    [0x100, 0x200, 0, 0, 0, 0]
                ),
                negative_errno(errno),
                "xattr name {name:?}"
            );
        }

        write_c_string(&mut memory, 0x100, "missing");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getxattr,
                [0x100, 0x200, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOENT)
        );

        write_c_string(&mut memory, 0x100, "dangling");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getxattr,
                [0x100, 0x200, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_lgetxattr,
                [0x100, 0x200, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENODATA)
        );

        let fd = open_readonly(&mut memory, &mut state, "file");
        assert!(fd >= 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fgetxattr,
                [fd as u64, 0x200, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENODATA)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fgetxattr,
                [u64::MAX, 0x200, 0, 0, 0, 0]
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fgetxattr,
                [fd as u64, 0x5000, 0, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
    }

    #[test]
    fn prctl_capbset_read_reports_full_bounding_set() {
        // Valid capabilities are present (root holds the full bounding set).
        for cap in [0, 7, 15, 32, GUEST_CAP_LAST_CAP] {
            assert_eq!(prctl(&[PR_CAPBSET_READ, cap, 0, 0, 0, 0]), 1);
        }
        // Out-of-range capabilities are rejected exactly like Linux.
        assert_eq!(
            prctl(&[PR_CAPBSET_READ, GUEST_CAP_LAST_CAP + 1, 0, 0, 0, 0]),
            negative_errno(libc::EINVAL)
        );
        // Deterministic: repeated queries return the same answer.
        assert_eq!(
            prctl(&[PR_CAPBSET_READ, 15, 0, 0, 0, 0]),
            prctl(&[PR_CAPBSET_READ, 15, 0, 0, 0, 0])
        );
        // Unmodeled prctl options remain ENOSYS.
        assert_eq!(
            prctl(&[libc::PR_GET_NAME as u64, 0, 0, 0, 0, 0]),
            negative_errno(libc::ENOSYS)
        );
    }

    #[test]
    fn sched_priority_bounds_match_policy_class() {
        for policy in [
            libc::SCHED_OTHER,
            libc::SCHED_BATCH,
            libc::SCHED_IDLE,
            SCHED_DEADLINE,
            SCHED_EXT,
        ] {
            assert_eq!(sched_priority_bound(policy as u64, false), 0);
            assert_eq!(sched_priority_bound(policy as u64, true), 0);
        }
        for policy in [libc::SCHED_FIFO, libc::SCHED_RR] {
            assert_eq!(sched_priority_bound(policy as u64, false), 1);
            assert_eq!(sched_priority_bound(policy as u64, true), 99);
        }
        assert_eq!(
            sched_priority_bound(999, true),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(sched_priority_bound(1_u64 << 32, true), 0);
    }

    #[test]
    fn scheduler_syscalls_validate_and_round_trip_virtual_state() {
        const PARAM: u64 = 0x100;
        const OUTPUT: u64 = 0x200;

        let dir = TestDir::new();
        let mut state = test_state(&dir.0);
        let mut memory = GuestMemory::new(0, 0x1000).unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getscheduler,
                [0, 0, 0, 0, 0, 0]
            ),
            i64::from(libc::SCHED_OTHER)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getscheduler,
                [u64::MAX, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getscheduler,
                [999_999, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ESRCH)
        );

        for number in [libc::SYS_sched_setscheduler, libc::SYS_sched_setparam] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [999_999, libc::SCHED_OTHER as u64, 0, 0, 0, 0]
                ),
                negative_errno(libc::EINVAL)
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getparam,
                [999_999, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [999_999, libc::SCHED_OTHER as u64, 0x2000, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setparam,
                [999_999, 0x2000, 0, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, 12_345, 0x2000, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, u64::MAX, 0x2000, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );

        for number in [libc::SYS_sched_setscheduler, libc::SYS_sched_setparam] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [0, libc::SCHED_OTHER as u64, 0, 0, 0, 0]
                ),
                negative_errno(libc::EINVAL)
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, libc::SCHED_OTHER as u64, 0x2000, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setparam,
                [0, 0x2000, 0, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        {
            let number = libc::SYS_sched_getparam;
            assert_eq!(
                syscall_result(&mut memory, &mut state, number, [0, 0, 0, 0, 0, 0]),
                negative_errno(libc::EINVAL)
            );
            assert_eq!(
                syscall_result(&mut memory, &mut state, number, [0, 0x2000, 0, 0, 0, 0]),
                negative_errno(libc::EFAULT)
            );
        }

        memory.write(PARAM, &1_i32.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, libc::SCHED_OTHER as u64, PARAM, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        memory.write(PARAM, &0_i32.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, libc::SCHED_FIFO as u64, PARAM, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        memory.write(PARAM, &1_i32.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [
                    0,
                    (libc::SCHED_FIFO | SCHED_RESET_ON_FORK) as u64,
                    PARAM,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getscheduler,
                [0, 0, 0, 0, 0, 0]
            ),
            i64::from(libc::SCHED_FIFO | SCHED_RESET_ON_FORK)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getparam,
                [0, OUTPUT, 0, 0, 0, 0]
            ),
            0
        );
        let mut output = [0; std::mem::size_of::<i32>()];
        memory.read(OUTPUT, &mut output).unwrap();
        assert_eq!(i32::from_ne_bytes(output), 1);

        memory.write(PARAM, &2_i32.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setparam,
                [0, PARAM, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(state.sched_priority, 2);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_getparam,
                [0, OUTPUT, 0, 0, 0, 0]
            ),
            0
        );
        memory.read(OUTPUT, &mut output).unwrap();
        assert_eq!(i32::from_ne_bytes(output), 2);
        memory.write(PARAM, &0_i32.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, SCHED_DEADLINE as u64, PARAM, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, 12_345, PARAM, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sched_setscheduler,
                [0, 1_u64 << 32, PARAM, 0, 0, 0]
            ),
            0
        );
        assert_eq!(state.sched_policy, libc::SCHED_OTHER);
    }

    #[test]
    fn scheduler_and_ioprio_state_follow_fork_and_exec_rules() {
        let dir = TestDir::new();
        let mut state = test_state(&dir.0);
        state.nice = -7;
        state.sched_policy = libc::SCHED_FIFO;
        state.sched_priority = 7;
        state.sched_reset_on_fork = true;
        state.ioprio = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4;

        let child = state.try_clone_for_fork(2).unwrap();
        assert_eq!(child.nice, -7);
        assert_eq!(child.sched_policy, libc::SCHED_OTHER);
        assert_eq!(child.sched_priority, 0);
        assert!(!child.sched_reset_on_fork);
        assert_eq!(child.ioprio, state.ioprio);

        state.sched_reset_on_fork = false;
        let child = state.try_clone_for_fork(3).unwrap();
        assert_eq!(child.sched_policy, libc::SCHED_FIFO);
        assert_eq!(child.sched_priority, 7);
        assert!(!child.sched_reset_on_fork);
        assert_eq!(child.ioprio, state.ioprio);

        state.ioprio = 1 << 3;
        let child = state.try_clone_for_fork(4).unwrap();
        assert_eq!(child.ioprio, 0);
        assert_eq!(state.ioprio, 1 << 3);

        state.sched_policy = libc::SCHED_RR;
        state.sched_priority = 9;
        state.sched_reset_on_fork = true;
        let expected_ioprio = state.ioprio;
        let mut after_exec = test_state(&dir.0);
        after_exec.inherit_process_state(state);
        assert_eq!(after_exec.nice, -7);
        assert_eq!(after_exec.sched_policy, libc::SCHED_RR);
        assert_eq!(after_exec.sched_priority, 9);
        assert!(after_exec.sched_reset_on_fork);
        assert_eq!(after_exec.ioprio, expected_ioprio);
    }

    #[test]
    fn ioprio_syscalls_validate_and_round_trip_virtual_state() {
        let dir = TestDir::new();
        let mut state = test_state(&dir.0);
        let mut memory = GuestMemory::new(0, 0x1000).unwrap();
        let pid = state.pid as u64;

        for (which, who, expected) in [
            (IOPRIO_WHO_PROCESS, 0, 0),
            (
                IOPRIO_WHO_PGRP,
                pid,
                (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4,
            ),
            (
                IOPRIO_WHO_USER,
                0,
                (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4,
            ),
        ] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_ioprio_get,
                    [which as u64, who, 0, 0, 0, 0]
                ),
                i64::from(expected)
            );
        }

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [(1_u64 << 32) | IOPRIO_WHO_PROCESS as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        state.sched_policy = libc::SCHED_IDLE;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PGRP as u64, 0, 0, 0, 0, 0]
            ),
            i64::from((IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT) | 4)
        );
        state.sched_policy = libc::SCHED_OTHER;

        let best_effort = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_set,
                [
                    IOPRIO_WHO_PROCESS as u64,
                    0,
                    (1_u64 << 32) | best_effort as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PROCESS as u64, pid, 0, 0, 0, 0]
            ),
            i64::from(best_effort)
        );

        let hinted_best_effort = best_effort | (1 << 3);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_set,
                [
                    IOPRIO_WHO_PROCESS as u64,
                    0,
                    hinted_best_effort as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PROCESS as u64, 0, 0, 0, 0, 0]
            ),
            i64::from(hinted_best_effort)
        );

        let hinted_none = 1 << 3;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_set,
                [IOPRIO_WHO_PROCESS as u64, 0, hinted_none as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PROCESS as u64, 0, 0, 0, 0, 0]
            ),
            i64::from(hinted_none)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PGRP as u64, 0, 0, 0, 0, 0]
            ),
            i64::from((IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4)
        );

        let idle = (IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT) | 1;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_set,
                [IOPRIO_WHO_PGRP as u64, 0, idle as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(state.ioprio, idle);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_set,
                [IOPRIO_WHO_USER as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(state.ioprio, 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioprio_get,
                [IOPRIO_WHO_PGRP as u64, 0, 0, 0, 0, 0]
            ),
            i64::from((IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4)
        );

        for invalid_ioprio in [1_u64, 7_u64 << IOPRIO_CLASS_SHIFT] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_ioprio_set,
                    [IOPRIO_WHO_PROCESS as u64, 999_999, invalid_ioprio, 0, 0, 0]
                ),
                negative_errno(libc::EINVAL)
            );
        }

        for args in [
            [99, 0, 0, 0, 0, 0],
            [IOPRIO_WHO_PROCESS as u64, 999_999, 0, 0, 0, 0],
            [IOPRIO_WHO_PROCESS as u64, 0, 1, 0, 0, 0],
            [
                IOPRIO_WHO_PROCESS as u64,
                0,
                7 << IOPRIO_CLASS_SHIFT,
                0,
                0,
                0,
            ],
        ] {
            let expected = if args[0] == IOPRIO_WHO_PROCESS as u64 && args[1] == 999_999 {
                negative_errno(libc::ESRCH)
            } else {
                negative_errno(libc::EINVAL)
            };
            assert_eq!(
                syscall_result(&mut memory, &mut state, libc::SYS_ioprio_set, args),
                expected
            );
        }
    }

    #[test]
    fn faccessat_variants_check_permissions() {
        let dir = TestDir::new();
        std::fs::write(dir.0.join("readable"), b"hi").unwrap();
        std::fs::set_permissions(
            dir.0.join("readable"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut state = test_state(&dir.0);
        let mut memory = GuestMemory::new(0, 0x2000).unwrap();

        // access(2): an existing readable file resolves to success.
        write_c_string(&mut memory, 0x100, "readable");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [0x100, libc::R_OK as u64, 0, 0, 0, 0],
            ),
            0
        );
        // faccessat2(AT_FDCWD, path, R_OK, AT_EACCESS) is what the shell
        // `test -r` operator issues; it must succeed rather than ENOSYS.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_faccessat2,
                [
                    libc::AT_FDCWD as u64,
                    0x100,
                    libc::R_OK as u64,
                    libc::AT_EACCESS as u64,
                    0,
                    0,
                ],
            ),
            0
        );
        // faccessat(2) without a flags argument behaves like access(2).
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_faccessat,
                [libc::AT_FDCWD as u64, 0x100, libc::R_OK as u64, 0, 0, 0],
            ),
            0
        );
        // A 0o644 file is not executable for any user, including root.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_faccessat2,
                [libc::AT_FDCWD as u64, 0x100, libc::X_OK as u64, 0, 0, 0],
            ),
            negative_errno(libc::EACCES)
        );
        // A missing path reports ENOENT.
        write_c_string(&mut memory, 0x200, "missing");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_faccessat2,
                [libc::AT_FDCWD as u64, 0x200, libc::R_OK as u64, 0, 0, 0],
            ),
            negative_errno(libc::ENOENT)
        );
        // An unsupported flag is rejected with EINVAL.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_faccessat2,
                [
                    libc::AT_FDCWD as u64,
                    0x100,
                    libc::R_OK as u64,
                    0x8000,
                    0,
                    0
                ],
            ),
            negative_errno(libc::EINVAL)
        );
    }

    #[test]
    fn wait4_sign_extends_negative_pid_and_reaps_child() {
        let dir = TestDir::new();
        let mut state = test_state(&dir.0);
        let mut memory = GuestMemory::new(0, 0x2000).unwrap();
        // A child (pid 9) has already exited with code 7.
        state.children.insert(9, 7);

        // wait4(-1) arrives as 0xFFFF_FFFF in a 64-bit register; the handler
        // must sign-extend it to -1 and reap the recorded child rather than
        // treating the value as an out-of-range positive pid and returning
        // ECHILD.
        let status_addr = 0x100u64;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_wait4,
                [0xFFFF_FFFF, status_addr, 0, 0, 0, 0],
            ),
            9
        );
        // The wait status encodes a normal exit with code 7 (WIFEXITED,
        // WEXITSTATUS == 7).
        let raw: i32 = read_struct(&memory, status_addr);
        assert_eq!(raw & 0x7f, 0);
        assert_eq!((raw >> 8) & 0xff, 7);
        // The child is consumed; a subsequent reap reports ECHILD.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_wait4,
                [0xFFFF_FFFF, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::ECHILD)
        );
    }
}
