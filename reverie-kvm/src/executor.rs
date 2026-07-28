/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use crate::GuestMemory;
use crate::SyscallRequest;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::SegmentBase;
use crate::elf::GUEST_CAPABILITY_MASK;
use crate::elf::GuestFileIdentity;
use crate::elf::GuestFileIdentityEntry;
use crate::elf::LoadedStaticElf;
use crate::elf::STACK_LIMIT;
use crate::elf::load_static_elf;
use crate::runtime::SyscallExecutor;

const MAX_HOST_IO: usize = 16 * 1024 * 1024;
const MAX_CAPTURED_OUTPUT: usize = 64 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
const GUEST_NOFILE_LIMIT: libc::c_int = 1 << 20;
const KERNEL_SIGACTION_SIZE: usize = 32;
const KERNEL_SIGSET_SIZE: usize = 8;
const ROBUST_LIST_HEAD_SIZE: u64 = 3 * std::mem::size_of::<u64>() as u64;
const MEMBARRIER_SUPPORTED: libc::c_int = 0x1;
// prctl(2) PR_CAPBSET_READ option; the deterministic container runs the guest as
// root with the full capability bounding set up to a fixed CAP_LAST_CAP so the
// answer is host-independent.
const PR_CAPBSET_READ: u64 = 23;
const PR_CAPBSET_DROP: u64 = 24;
const GUEST_CAP_LAST_CAP: u64 = 40;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PROCESS_CLONE_TID_FLAGS: u64 = libc::CLONE_PARENT_SETTID as u64
    | libc::CLONE_CHILD_SETTID as u64
    | libc::CLONE_CHILD_CLEARTID as u64;
const THREAD_CLONE_REQUIRED_FLAGS: u64 = libc::CLONE_VM as u64
    | libc::CLONE_FS as u64
    | libc::CLONE_FILES as u64
    | libc::CLONE_SIGHAND as u64
    | libc::CLONE_THREAD as u64;
const THREAD_CLONE_ALLOWED_FLAGS: u64 = THREAD_CLONE_REQUIRED_FLAGS
    | libc::CLONE_SYSVSEM as u64
    | libc::CLONE_SETTLS as u64
    | libc::CLONE_PARENT_SETTID as u64
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
// TODO-HUMAN-REVIEW(PR-136): Review anonymous-object filesystem classification.
const ANON_INODE_FS_MAGIC: libc::c_long = 0x0904_1934;
const PIPEFS_MAGIC: libc::c_long = 0x5049_5045;
const SOCKFS_MAGIC: libc::c_long = 0x534f_434b;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
// Linux UAPI value from <linux/sockios.h>; libc does not expose it.
const SIOCETHTOOL: libc::c_ulong = 0x8946;
// TODO-HUMAN-REVIEW(PR-136): Review the Linux UAPI value missing from pinned libc.
const FALLOC_FL_WRITE_ZEROES: libc::c_int = 0x80;

const FALLOCATE_VALID_MODES: &[libc::c_int] = &[
    0,
    libc::FALLOC_FL_KEEP_SIZE,
    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    libc::FALLOC_FL_COLLAPSE_RANGE,
    libc::FALLOC_FL_ZERO_RANGE,
    libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
    libc::FALLOC_FL_INSERT_RANGE,
    libc::FALLOC_FL_UNSHARE_RANGE,
    libc::FALLOC_FL_UNSHARE_RANGE | libc::FALLOC_FL_KEEP_SIZE,
    FALLOC_FL_WRITE_ZEROES,
];
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
struct CapturedOutputInner {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Default)]
// TODO-HUMAN-REVIEW(PR-172): Review cross-thread captured-output ownership.
pub(crate) struct CapturedOutput {
    inner: Arc<Mutex<CapturedOutputInner>>,
}

impl CapturedOutput {
    pub(crate) fn take(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut inner = self.inner.lock().expect("captured output lock poisoned");
        (
            std::mem::take(&mut inner.stdout),
            std::mem::take(&mut inner.stderr),
        )
    }

    fn append(&self, stderr: bool, bytes: &[u8]) -> bool {
        let mut inner = self.inner.lock().expect("captured output lock poisoned");
        let destination = if stderr {
            &mut inner.stderr
        } else {
            &mut inner.stdout
        };
        if destination
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_CAPTURED_OUTPUT)
        {
            return false;
        }
        destination.extend_from_slice(bytes);
        true
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
    // TODO-HUMAN-REVIEW(PR-132): Review cooperative single-vCPU thread cloning.
    Thread {
        child_tid: i32,
        child_stack: u64,
        parent_tid: Option<u64>,
        child_tid_address: Option<u64>,
        clear_child_tid: Option<u64>,
        tls: Option<u64>,
    },
    Exec {
        image: Vec<u8>,
        argv: Vec<String>,
        envp: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessExit {
    pub code: i32,
    pub group: bool,
}

// Retain the audited process-syscall classification even though the root
// dispatcher no longer excludes these syscalls from Reverie tools.
#[allow(dead_code)]
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
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review waitid process-action classification.
        || number == libc::SYS_waitid as u64
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-216): Review direct-worker classification for CLONE_THREAD.
pub(crate) fn is_thread_clone_request(request: &SyscallRequest, memory: &GuestMemory) -> bool {
    if request.number() == libc::SYS_clone as u64 {
        return request.args()[0] & libc::CLONE_THREAD as u64 != 0;
    }
    if request.number() == libc::SYS_clone3 as u64 {
        let args = request.args();
        return read_clone3(memory, args[0], args[1])
            .is_ok_and(|clone| clone.flags & libc::CLONE_THREAD as u64 != 0);
    }
    false
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
    let capture_output = output.is_some();

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
    } else if number == libc::SYS_truncate as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        truncate(memory, state, args)
    } else if number == libc::SYS_fallocate as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fallocate(state, args)
    } else if number == libc::SYS_fsync as u64 {
        sync_file(state, args[0], false)
    } else if number == libc::SYS_fdatasync as u64 {
        sync_file(state, args[0], true)
    } else if number == libc::SYS_readahead as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review translated host readahead semantics.
        readahead(state, args)
    } else if number == libc::SYS_sync_file_range as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review translated host range-sync semantics.
        sync_file_range(state, args)
    } else if number == libc::SYS_pipe as u64 {
        pipe2(memory, state, args[0], 0)
    } else if number == libc::SYS_pipe2 as u64 {
        pipe2(memory, state, args[0], args[1])
    } else if number == libc::SYS_select as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        select(memory, state, args)
    } else if number == libc::SYS_poll as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        poll(memory, state, args)
    } else if number == libc::SYS_ppoll as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        ppoll(memory, state, args)
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
    } else if number == libc::SYS_setsockopt as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        setsockopt(memory, state, args)
    } else if number == libc::SYS_getsockopt as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-230): Review bounded SO_TYPE copy-out semantics.
        getsockopt(memory, state, args)
    } else if number == libc::SYS_bind as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        bind(memory, state, args)
    } else if number == libc::SYS_listen as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        listen(state, args)
    } else if number == libc::SYS_getsockname as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        getsockname(memory, state, args)
    } else if number == libc::SYS_socketpair as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        socketpair(memory, state, args)
    } else if number == libc::SYS_connect as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        connect(memory, state, args)
    } else if number == libc::SYS_shutdown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        shutdown(state, args)
    } else if number == libc::SYS_sendto as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sendto(memory, state, args)
    } else if number == libc::SYS_recvfrom as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        recvfrom(memory, state, args)
    } else if number == libc::SYS_recvmmsg as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        recvmmsg(memory, state, args)
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
        fcntl(memory, state, args)
    } else if number == libc::SYS_open as u64 {
        open(memory, state, args)
    } else if number == libc::SYS_openat as u64 {
        openat(memory, state, args)
    } else if number == libc::SYS_creat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        creat(memory, state, args)
    } else if number == libc::SYS_fstat as u64 {
        fstat(memory, state, args, capture_output)
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
    } else if number == libc::SYS_getpid as u64 {
        i64::from(state.pid)
    } else if number == libc::SYS_gettid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-132): Review distinct KVM thread IDs.
        i64::from(state.tid)
    } else if number == libc::SYS_getppid as u64 {
        i64::from(state.ppid)
    } else if number == libc::SYS_getpgrp as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-92): Review fixed guest process-group identity.
        i64::from(state.pid)
    } else if number == libc::SYS_wait4 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        wait4(memory, state, args)
    } else if number == libc::SYS_waitid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review serialized-child waitid emulation.
        waitid(memory, state, args)
    } else if number == libc::SYS_getuid as u64
        || number == libc::SYS_geteuid as u64
        || number == libc::SYS_getgid as u64
        || number == libc::SYS_getegid as u64
    {
        0
    } else if number == libc::SYS_getresuid as u64 || number == libc::SYS_getresgid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        get_fixed_root_ids(memory, args)
    } else if number == libc::SYS_setresuid as u64 || number == libc::SYS_setresgid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        set_fixed_root_ids(&args[..3])
    } else if number == libc::SYS_getgroups as u64 {
        getgroups(memory, args)
    } else if number == libc::SYS_capget as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        capget(memory, state, args)
    } else if number == libc::SYS_capset as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        capset(memory, state, args)
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
        prctl(state, args)
    } else if number == libc::SYS_getxattr as u64
        || number == libc::SYS_lgetxattr as u64
        || number == libc::SYS_fgetxattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        getxattr(memory, state, number, args)
    } else if number == libc::SYS_setxattr as u64
        || number == libc::SYS_lsetxattr as u64
        || number == libc::SYS_fsetxattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review deterministic xattr mutation refusal.
        setxattr(memory, state, number, args)
    } else if number == libc::SYS_removexattr as u64
        || number == libc::SYS_lremovexattr as u64
        || number == libc::SYS_fremovexattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review deterministic xattr removal result.
        removexattr(memory, state, number, args)
    } else if number == libc::SYS_brk as u64 {
        brk(memory, state, args[0])
    } else if number == libc::SYS_mmap as u64 {
        mmap(memory, state, args)
    } else if number == libc::SYS_munmap as u64 {
        munmap(memory, args[0], args[1])
    } else if number == libc::SYS_msync as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review in-memory mapping synchronization semantics.
        msync(memory, args)
    } else if number == libc::SYS_mremap as u64 {
        mremap(memory, state, args)
    } else if number == libc::SYS_mprotect as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        mprotect(memory, args)
    } else if number == libc::SYS_madvise as u64 {
        validate_range(memory, args[0], args[1])
    } else if number == libc::SYS_munlock as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        munlock_guest_range(memory, args[0], args[1])
    } else if number == libc::SYS_munlockall as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-145): Review the deterministic no-op unlock-all model.
        0
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
        getrandom(memory, state.tid, args[0], args[1])
    } else if number == libc::SYS_clock_gettime as u64 {
        write_bytes(memory, args[1], &[0; 16])
    } else if number == libc::SYS_nanosleep as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        nanosleep(memory, args)
    } else if number == libc::SYS_clock_nanosleep as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        clock_nanosleep(memory, args)
    } else if number == libc::SYS_gettimeofday as u64 {
        gettimeofday(memory, args)
    } else if number == libc::SYS_readlink as u64 {
        readlink(memory, state, args)
    } else if number == libc::SYS_readlinkat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        readlinkat(memory, state, args)
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
    } else if number == libc::SYS_futex as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        futex(memory, args)
    } else if number == libc::SYS_rseq as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-172): Review deterministic rseq feature refusal.
        negative_errno(libc::ENOSYS)
    } else if number == libc::SYS_get_robust_list as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list queries.
        get_robust_list(memory, state, args)
    } else if number == libc::SYS_set_robust_list as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list registration.
        set_robust_list(state, args)
    } else {
        negative_errno(libc::ENOSYS)
    };

    continue_with(result)
}

// TODO-HUMAN-REVIEW(PR-172): Review host-backed futex address and timeout translation.
fn futex(memory: &GuestMemory, args: &[u64; 6]) -> i64 {
    const FUTEX_CMD_MASK: libc::c_int = !(128 | 256);
    const FUTEX_WAIT: libc::c_int = 0;
    const FUTEX_REQUEUE: libc::c_int = 3;
    const FUTEX_CMP_REQUEUE: libc::c_int = 4;
    const FUTEX_WAKE_OP: libc::c_int = 5;
    const FUTEX_LOCK_PI: libc::c_int = 6;
    const FUTEX_WAIT_BITSET: libc::c_int = 9;
    const FUTEX_WAIT_REQUEUE_PI: libc::c_int = 11;
    const FUTEX_CMP_REQUEUE_PI: libc::c_int = 12;
    const FUTEX_LOCK_PI2: libc::c_int = 13;

    let Ok(uaddr) = guest_host_address(memory, args[0], std::mem::size_of::<u32>()) else {
        return negative_errno(libc::EFAULT);
    };
    let operation = args[1] as libc::c_int;
    let command = operation & FUTEX_CMD_MASK;
    let fourth = if args[3] == 0 {
        0
    } else if matches!(
        command,
        FUTEX_WAIT | FUTEX_LOCK_PI | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI | FUTEX_LOCK_PI2
    ) {
        match guest_host_address(memory, args[3], std::mem::size_of::<libc::timespec>()) {
            Ok(address) => address,
            Err(error) => return error,
        }
    } else {
        args[3] as usize
    };
    let uaddr2 = if matches!(
        command,
        FUTEX_REQUEUE
            | FUTEX_CMP_REQUEUE
            | FUTEX_WAKE_OP
            | FUTEX_WAIT_REQUEUE_PI
            | FUTEX_CMP_REQUEUE_PI
    ) {
        match guest_host_address(memory, args[4], std::mem::size_of::<u32>()) {
            Ok(address) => address,
            Err(error) => return error,
        }
    } else {
        0
    };

    // SAFETY: translated pointers remain within the shared guest mapping for
    // the duration of the syscall. The host kernel performs the atomic futex
    // operation against the same bytes mapped by every guest-thread VM.
    let result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            uaddr,
            operation,
            args[2] as u32,
            fourth,
            uaddr2,
            args[5] as u32,
        )
    };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result as i64
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list registration.
fn set_robust_list(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[1] != ROBUST_LIST_HEAD_SIZE {
        return negative_errno(libc::EINVAL);
    }
    state.robust_list_head = args[0];
    state.robust_list_len = args[1];
    0
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list queries.
fn get_robust_list(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let requested = args[0] as libc::pid_t;
    if requested != 0 && requested != state.tid && requested != state.pid {
        return negative_errno(libc::ESRCH);
    }
    if args[1] == 0 || args[2] == 0 {
        return negative_errno(libc::EFAULT);
    }
    if write_u64(memory, args[1], state.robust_list_head) != 0 {
        return negative_errno(libc::EFAULT);
    }
    write_u64(memory, args[2], state.robust_list_len)
}

fn guest_host_address(
    memory: &GuestMemory,
    guest_address: u64,
    length: usize,
) -> Result<usize, i64> {
    let mut probe = vec![0; length];
    if memory.read(guest_address, &mut probe).is_err() {
        return Err(negative_errno(libc::EFAULT));
    }
    Ok((memory.host_address() + guest_address - memory.guest_base()) as usize)
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
    address_space: Arc<std::sync::Mutex<AddressSpaceState>>,
    file_table: Arc<std::sync::Mutex<FileTableState>>,
    output: Option<CapturedOutput>,
    owns_output: bool,
    next_pid: Arc<AtomicI32>,
    process_action: Option<ProcessAction>,
    pending_segment: Option<(SegmentBase, u64)>,
    exit_code: Option<i32>,
    exit_group: bool,
    clear_child_tid: Option<u64>,
}

struct AddressSpaceState {
    program_break: u64,
    mmap_base: u64,
    mmap_next: u64,
    mmap_limit: u64,
}

struct FileTableState {
    stdin: Option<std::fs::File>,
    files: std::collections::BTreeMap<i32, std::fs::File>,
    stdout_alias_fds: std::collections::BTreeSet<i32>,
    stderr_alias_fds: std::collections::BTreeSet<i32>,
    cloexec_fds: std::collections::BTreeSet<i32>,
    closed_standard_fds: std::collections::BTreeSet<i32>,
    proc_files: std::collections::BTreeMap<i32, u64>,
    fd_object_inodes: std::collections::BTreeMap<i32, Arc<GuestFileIdentity>>,
}

impl FileTableState {
    fn try_from_elf(state: &LoadedStaticElf) -> std::io::Result<Self> {
        Ok(Self {
            stdin: state
                .stdin
                .as_ref()
                .map(std::fs::File::try_clone)
                .transpose()?,
            files: state
                .files
                .iter()
                .map(|(&fd, file)| Ok((fd, file.try_clone()?)))
                .collect::<std::io::Result<_>>()?,
            stdout_alias_fds: state.stdout_alias_fds.clone(),
            stderr_alias_fds: state.stderr_alias_fds.clone(),
            cloexec_fds: state.cloexec_fds.clone(),
            closed_standard_fds: state.closed_standard_fds.clone(),
            proc_files: state.proc_files.clone(),
            fd_object_inodes: state.fd_object_inodes.clone(),
        })
    }

    fn install(&self, state: &mut LoadedStaticElf) -> std::io::Result<()> {
        state.stdin = self
            .stdin
            .as_ref()
            .map(std::fs::File::try_clone)
            .transpose()?;
        state.files = self
            .files
            .iter()
            .map(|(&fd, file)| Ok((fd, file.try_clone()?)))
            .collect::<std::io::Result<_>>()?;
        state.stdout_alias_fds.clone_from(&self.stdout_alias_fds);
        state.stderr_alias_fds.clone_from(&self.stderr_alias_fds);
        state.cloexec_fds.clone_from(&self.cloexec_fds);
        state
            .closed_standard_fds
            .clone_from(&self.closed_standard_fds);
        state.proc_files.clone_from(&self.proc_files);
        state.fd_object_inodes.clone_from(&self.fd_object_inodes);
        Ok(())
    }
}

fn mutates_file_table(number: u64) -> bool {
    matches!(
        number,
        number if number == libc::SYS_pipe as u64
            || number == libc::SYS_pipe2 as u64
            || number == libc::SYS_epoll_create1 as u64
            || number == libc::SYS_eventfd as u64
            || number == libc::SYS_eventfd2 as u64
            || number == libc::SYS_socket as u64
            || number == libc::SYS_socketpair as u64
            || number == libc::SYS_dup as u64
            || number == libc::SYS_dup2 as u64
            || number == libc::SYS_dup3 as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-229): Review ioctl descriptor-table serialization.
            || number == libc::SYS_ioctl as u64
            || number == libc::SYS_fcntl as u64
            || number == libc::SYS_open as u64
            || number == libc::SYS_openat as u64
            || number == libc::SYS_creat as u64
            || number == libc::SYS_close as u64
    )
}

fn accept_flags(request: &SyscallRequest) -> Option<Result<libc::c_int, i64>> {
    match request.number() {
        // AUTONOMOUS-BOT-IMPLEMENTED
        number if number == libc::SYS_accept as u64 => Some(Ok(0)),
        // AUTONOMOUS-BOT-IMPLEMENTED
        number if number == libc::SYS_accept4 as u64 => {
            Some(libc::c_int::try_from(request.args()[3]).map_err(|_| negative_errno(libc::EINVAL)))
        }
        _ => None,
    }
}

impl AddressSpaceState {
    fn from_elf(state: &LoadedStaticElf) -> Self {
        Self {
            program_break: state.program_break,
            mmap_base: state.mmap_base,
            mmap_next: state.mmap_next,
            mmap_limit: state.mmap_limit,
        }
    }
}

impl ElfExecutor {
    pub(crate) fn new(state: LoadedStaticElf, capture_output: bool) -> Self {
        let next_pid = state.pid.saturating_add(1);
        let address_space = Arc::new(std::sync::Mutex::new(AddressSpaceState::from_elf(&state)));
        let file_table = Arc::new(std::sync::Mutex::new(
            FileTableState::try_from_elf(&state).expect("clone initial KVM file table"),
        ));
        Self {
            state,
            address_space,
            file_table,
            output: capture_output.then(CapturedOutput::default),
            owns_output: true,
            next_pid: Arc::new(AtomicI32::new(next_pid)),
            process_action: None,
            pending_segment: None,
            exit_code: None,
            exit_group: false,
            clear_child_tid: None,
        }
    }

    fn execute_accept(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> Option<i64> {
        let raw_flags = accept_flags(request)?;
        let flags = match raw_flags {
            Ok(flags) => flags,
            Err(error) => return Some(error),
        };
        let file_table = self.file_table.clone();
        {
            let shared_files = file_table.lock().expect("KVM file-table lock poisoned");
            if let Err(error) = shared_files.install(&mut self.state) {
                return Some(io_error(error));
            }
        }

        let mut memory = memory.clone();
        let accepted = match accept_socket(&mut memory, &self.state, request.args(), flags) {
            Ok(file) => file,
            Err(error) => return Some(error),
        };

        let mut shared_files = file_table.lock().expect("KVM file-table lock poisoned");
        if let Err(error) = shared_files.install(&mut self.state) {
            return Some(io_error(error));
        }
        let result = insert_file_with_flags(
            &mut self.state,
            accepted,
            flags & libc::SOCK_CLOEXEC != 0,
            None,
        );
        if result >= 0 {
            *shared_files =
                FileTableState::try_from_elf(&self.state).expect("clone updated KVM file table");
        }
        Some(result)
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
            return Some(i64::from(self.state.tid));
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
                args[4],
            ));
        }
        if number == libc::SYS_clone3 as u64 {
            return Some(match read_clone3(memory, args[0], args[1]) {
                Ok(request) if request.flags & libc::CLONE_THREAD as u64 != 0 => self
                    .prepare_thread(
                        request.flags,
                        request.child_stack,
                        request.parent_tid,
                        request.child_tid,
                        request.tls,
                    ),
                Ok(request) => match validate_process_clone_flags(request.flags) {
                    Err(error) => error,
                    Ok(())
                        if request.flags & PROCESS_CLONE_TID_FLAGS != 0
                            || request.parent_tid.is_some()
                            || request.child_tid.is_some() =>
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
        tls: u64,
    ) -> i64 {
        if flags & libc::CLONE_THREAD as u64 != 0 {
            return self.prepare_thread(
                flags,
                child_stack,
                (flags & libc::CLONE_PARENT_SETTID as u64 != 0).then_some(parent_tid_address),
                (flags & (libc::CLONE_CHILD_SETTID as u64 | libc::CLONE_CHILD_CLEARTID as u64)
                    != 0)
                    .then_some(child_tid_address),
                (flags & libc::CLONE_SETTLS as u64 != 0).then_some(tls),
            );
        }
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

    fn prepare_thread(
        &mut self,
        flags: u64,
        child_stack: Option<u64>,
        parent_tid: Option<u64>,
        child_tid_address: Option<u64>,
        tls: Option<u64>,
    ) -> i64 {
        if let Err(error) = validate_thread_clone_flags(flags) {
            return error;
        }
        let Some(child_stack) = child_stack else {
            return negative_errno(libc::EINVAL);
        };
        if self.process_action.is_some() {
            return negative_errno(libc::EBUSY);
        }
        let child_tid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        if child_tid <= 0 {
            return negative_errno(libc::EAGAIN);
        }
        self.process_action = Some(ProcessAction::Thread {
            child_tid,
            child_stack,
            parent_tid,
            child_tid_address: (flags & libc::CLONE_CHILD_SETTID as u64 != 0)
                .then_some(child_tid_address)
                .flatten(),
            clear_child_tid: (flags & libc::CLONE_CHILD_CLEARTID as u64 != 0)
                .then_some(child_tid_address)
                .flatten(),
            tls,
        });
        i64::from(child_tid)
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
        // TODO-HUMAN-REVIEW(PR-156): Review preflight validation before exec image replacement.
        // Loading the live image clears guest memory, so validate against an
        // isolated mapping before reporting exec success to the Reverie tool.
        let mut validation_memory = match GuestMemory::new(memory.guest_base(), memory.len()) {
            Ok(memory) => memory,
            Err(_) => return negative_errno(libc::ENOMEM),
        };
        let argv_refs = argv.iter().map(String::as_str).collect::<Vec<_>>();
        let envp_refs = envp.iter().map(String::as_str).collect::<Vec<_>>();
        if load_static_elf(
            &mut validation_memory,
            &image,
            &argv_refs,
            &envp_refs,
            &self.state.cwd,
        )
        .is_err()
        {
            return negative_errno(libc::ENOEXEC);
        }
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
            address_space: Arc::new(std::sync::Mutex::new(AddressSpaceState::from_elf(&state))),
            file_table: Arc::new(std::sync::Mutex::new(FileTableState::try_from_elf(&state)?)),
            state,
            output: self.output.is_some().then(CapturedOutput::default),
            owns_output: true,
            next_pid: self.next_pid.clone(),
            process_action: None,
            pending_segment: None,
            exit_code: None,
            exit_group: false,
            clear_child_tid: None,
        })
    }

    // TODO-HUMAN-REVIEW(PR-172): Review shared address-space and output ownership.
    pub(crate) fn thread_child(&self, child_tid: i32) -> crate::Result<Self> {
        let mut state = self.state.try_clone_for_fork(child_tid)?;
        state.pid = self.state.pid;
        state.ppid = self.state.ppid;
        Ok(Self {
            state,
            address_space: self.address_space.clone(),
            file_table: self.file_table.clone(),
            output: self.output.clone(),
            owns_output: false,
            next_pid: self.next_pid.clone(),
            process_action: None,
            pending_segment: None,
            exit_code: None,
            exit_group: false,
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

    // TODO-HUMAN-REVIEW(PR-156): Review non-returning exit injection state.
    pub(crate) fn has_pending_exit(&self) -> bool {
        self.exit_code.is_some()
    }

    pub(crate) fn replace_after_exec(&mut self, state: LoadedStaticElf) {
        let previous = std::mem::replace(&mut self.state, state);
        self.state.inherit_process_state(previous);
        *self
            .address_space
            .lock()
            .expect("KVM address-space lock poisoned") = AddressSpaceState::from_elf(&self.state);
        *self
            .file_table
            .lock()
            .expect("KVM file-table lock poisoned") =
            FileTableState::try_from_elf(&self.state).expect("clone post-exec KVM file table");
        self.pending_segment = None;
        self.exit_code = None;
        self.exit_group = false;
        self.clear_child_tid = None;
    }

    pub(crate) fn record_child_exit(&mut self, pid: i32, code: i32) {
        self.state.children.insert(pid, code);
    }

    pub(crate) fn append_output(&mut self, stdout: Vec<u8>, stderr: Vec<u8>) {
        if let Some(output) = self.output.as_mut() {
            let _ = output.append(false, &stdout);
            let _ = output.append(true, &stderr);
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

    // TODO-HUMAN-REVIEW(PR-132): Review cooperative KVM thread context updates.
    pub(crate) fn set_thread_context(&mut self, tid: i32, fs_base: u64, gs_base: u64) {
        self.state.tid = tid;
        self.state.fs_base = fs_base;
        self.state.gs_base = gs_base;
    }

    /// Returns and clears a pending FS/GS base update requested via `arch_prctl`.
    pub(crate) fn take_segment(&mut self) -> Option<(SegmentBase, u64)> {
        self.pending_segment.take()
    }

    /// Returns and clears a pending thread-local or group-wide exit.
    pub(crate) fn take_exit(&mut self) -> Option<ProcessExit> {
        self.exit_code.take().map(|code| {
            let group = std::mem::take(&mut self.exit_group);
            ProcessExit { code, group }
        })
    }

    pub(crate) fn take_output(&mut self) -> (Vec<u8>, Vec<u8>) {
        if self.owns_output {
            self.output
                .as_mut()
                .map(CapturedOutput::take)
                .unwrap_or_default()
        } else {
            (Vec::new(), Vec::new())
        }
    }
}

impl SyscallExecutor for ElfExecutor {
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        if let Some(result) = self.execute_accept(request, memory) {
            return result;
        }
        // TODO-HUMAN-REVIEW(PR-172): Review CLONE_FILES descriptor-table sharing.
        // Thread children retain private executor state, but synchronize their
        // descriptor mappings through this shared table before every syscall.
        // Descriptor-creating and descriptor-closing operations hold the lock
        // through the update; potentially blocking I/O releases it after the
        // snapshot so QEMU AIO workers can continue to make progress.
        let file_table = self.file_table.clone();
        let mut shared_files = Some(file_table.lock().expect("KVM file-table lock poisoned"));
        if let Err(error) = shared_files
            .as_ref()
            .expect("file-table guard disappeared")
            .install(&mut self.state)
        {
            return io_error(error);
        }
        let mutating_file_table = mutates_file_table(request.number());
        if !mutating_file_table {
            shared_files.take();
        }
        if let Some(result) = self.execute_process_action(request, memory) {
            return result;
        }
        // Clones share the underlying MAP_SHARED mapping, so writes through this
        // handle reach the guest; `execute_basic_syscall` needs `&mut` access.
        let mut memory = memory.clone();
        let address_space_syscall = matches!(
            request.number(),
            number if number == libc::SYS_brk as u64
                || number == libc::SYS_mmap as u64
                || number == libc::SYS_mremap as u64
        );
        let action = if address_space_syscall {
            let address_space = self.address_space.clone();
            let mut shared = address_space
                .lock()
                .expect("KVM address-space lock poisoned");
            self.state.program_break = shared.program_break;
            self.state.mmap_base = shared.mmap_base;
            self.state.mmap_next = shared.mmap_next;
            self.state.mmap_limit = shared.mmap_limit;
            let action = execute_basic_syscall_with_output(
                &mut memory,
                &mut self.state,
                request,
                self.output.as_mut(),
            );
            shared.program_break = self.state.program_break;
            shared.mmap_base = self.state.mmap_base;
            shared.mmap_next = self.state.mmap_next;
            shared.mmap_limit = self.state.mmap_limit;
            action
        } else {
            execute_basic_syscall_with_output(
                &mut memory,
                &mut self.state,
                request,
                self.output.as_mut(),
            )
        };
        if let Some(mut shared_files) = shared_files {
            *shared_files =
                FileTableState::try_from_elf(&self.state).expect("clone updated KVM file table");
        }
        match action {
            SyscallAction::Continue { result, segment } => {
                if segment.is_some() {
                    self.pending_segment = segment;
                }
                result
            }
            SyscallAction::Exit(code) => {
                self.exit_code = Some(code);
                self.exit_group = request.number() != libc::SYS_exit as u64;
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

fn fd_mode(fd: RawFd) -> Result<libc::mode_t, i64> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and fd is live.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    Ok(unsafe { stat.assume_init() }.st_mode)
}

fn file_mode(file: &std::fs::File) -> Result<libc::mode_t, i64> {
    fd_mode(file.as_raw_fd())
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
            if !output.append(matches!(output_destination, OutputAlias::Stderr), &bytes) {
                return negative_errno(libc::EFBIG);
            }
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
    let Ok(fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    if state.proc_files.contains_key(&fd) {
        return negative_errno(libc::ENOSYS);
    }
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
    let Ok(writable) = memory.user_accessible_prefix(address, length) else {
        return negative_errno(libc::EFAULT);
    };
    if writable == 0 && length != 0 {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; writable];
    // SAFETY: bytes is writable for its full length and fd is a live host descriptor.
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
    host_read(memory, file.as_raw_fd(), args[1], length)
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
    let Ok(writable) = memory.user_accessible_prefix(args[1], length) else {
        return negative_errno(libc::EFAULT);
    };
    if writable == 0 {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; writable];
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

// TODO-HUMAN-REVIEW(PR-136): Review held-descriptor path truncate delegation.
fn truncate(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let length = args[1] as libc::off_t;
    if length < 0 {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(memory, args[0], 4096) {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => return negative_errno(libc::ENOENT),
        Err(error) => return read_c_string_errno(error),
    };
    let held_file;
    let target_fd = if let Some(guest_fd) = guest_fd_path(state, &path) {
        if state.proc_files.contains_key(&guest_fd) {
            return negative_errno(libc::EACCES);
        }
        let Some(host_fd) = host_fd(state, guest_fd) else {
            return negative_errno(libc::ENOENT);
        };
        if canonical_fd_path(host_fd).is_ok_and(|target| {
            target
                .as_os_str()
                .as_bytes()
                .starts_with(b"/memfd:reverie-kvm-virtual")
        }) {
            return negative_errno(libc::EINVAL);
        }
        host_fd
    } else {
        held_file = match open_metadata_path(state, libc::AT_FDCWD, &path, false) {
            Ok(file) => file,
            Err(error) => return error,
        };
        held_file.as_raw_fd()
    };

    // Truncating through a held O_PATH descriptor preserves kernel target-type
    // validation without opening a FIFO for write and potentially blocking.
    let target = CString::new(format!("/proc/self/fd/{target_fd}"))
        .expect("host descriptor path has no NUL");
    // SAFETY: target is NUL-terminated and resolves only a held host descriptor.
    let result = unsafe { libc::truncate(target.as_ptr(), length) };
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

// TODO-HUMAN-REVIEW(PR-136): Review host fallocate delegation and flag bounds.
fn fallocate(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let mode = args[1] as libc::c_int;
    let offset = args[2] as libc::off_t;
    let length = args[3] as libc::off_t;
    if offset < 0 || length <= 0 {
        return negative_errno(libc::EINVAL);
    }
    if !FALLOCATE_VALID_MODES.contains(&mode) {
        return negative_errno(libc::EOPNOTSUPP);
    }
    if let Err(error) = ensure_writable_fd(host_fd) {
        return error;
    }
    // SAFETY: host_fd is live and writable. Linux validates the mode and range.
    let result = unsafe { libc::fallocate(host_fd, mode, offset, length) };
    if result == 0 {
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

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review translated host readahead semantics.
fn readahead(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let offset = args[1] as libc::off64_t;
    let Ok(count) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if offset < 0 {
        return negative_errno(libc::EINVAL);
    }
    // SAFETY: host_fd names the guest's live translated descriptor; the call
    // has no guest pointers, and the host kernel validates the descriptor type.
    let result = unsafe { libc::syscall(libc::SYS_readahead, host_fd, offset, count) };
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review translated host range-sync semantics.
fn sync_file_range(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let offset = args[1] as libc::off64_t;
    let length = args[2] as libc::off64_t;
    let flags = args[3] as libc::c_uint;
    let allowed_flags = (libc::SYNC_FILE_RANGE_WAIT_BEFORE
        | libc::SYNC_FILE_RANGE_WRITE
        | libc::SYNC_FILE_RANGE_WAIT_AFTER) as libc::c_uint;
    if offset < 0 || length < 0 || flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    // SAFETY: host_fd names the guest's live translated descriptor; the call
    // has no guest pointers, and ranges and flags were validated above.
    let result =
        unsafe { libc::syscall(libc::SYS_sync_file_range, host_fd, offset, length, flags) };
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
    let relative_proc_path = synthetic_proc_relative_path(state, guest_dirfd, &path);
    let path = relative_proc_path.as_deref().unwrap_or(&path);
    let flags = u64::from(raw_flags as libc::c_int as u32) & LEGACY_OPEN_FLAGS;
    let close_on_exec = flags & libc::O_CLOEXEC as u64 != 0;
    if is_synthetic_proc_directory(state, path) {
        return open_synthetic_proc_directory(state, flags, close_on_exec);
    }
    // Serve the synthetic /proc surface before touching the host filesystem, so
    // deterministic content replaces the deliberately-refused real procfs.
    if let Some(content) = synthetic_proc_content(state, path) {
        if flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 {
            return negative_errno(libc::EACCES);
        }
        let normalized =
            normalize_proc_path(state, path).expect("a synthesized /proc path always normalizes");
        return open_synthetic_proc(state, &normalized, &content, close_on_exec);
    }
    // A relative lookup beneath the synthetic directory must never fall
    // through to the harmless host directory that backs the descriptor.
    if relative_proc_path.is_some() {
        return negative_errno(libc::ENOENT);
    }
    if let Some(content) = synthetic_cpu_frequency_content(state, guest_dirfd, path) {
        return open_virtual_file(state, content, flags, close_on_exec);
    }
    let guest_cloexec = close_on_exec;
    if let Some(guest_fd) = guest_fd_path(state, path) {
        return open_guest_fd_path(state, guest_fd, flags, guest_cloexec);
    }
    if path == b"/dev/random" || path == b"/dev/urandom" {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-228): Review cross-backend random-device stream parity.
        let bytes = deterministic_random_device_bytes(state.random_seed, 64 * 1024);
        return open_virtual_file(state, &bytes, flags, guest_cloexec);
    }
    if path == b"/proc/uptime" {
        return open_virtual_file(state, b"0.00 0.00\n", flags, guest_cloexec);
    }
    if path == b"/proc/self/loginuid" {
        return open_virtual_file(state, b"0", flags, guest_cloexec);
    }
    let Ok((host_dirfd, path)) = host_dirfd_and_path(state, guest_dirfd, path) else {
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

// TODO-HUMAN-REVIEW(PR-205): Review the deterministic read-only CPU frequency surface.
fn synthetic_cpu_frequency_content(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
) -> Option<&'static [u8]> {
    const CPU_ROOT: &[u8] = b"/sys/devices/system/cpu";
    let relative = if let Some(relative) = path.strip_prefix(b"/sys/devices/system/cpu/") {
        relative
    } else if !path.starts_with(b"/") {
        let host_fd = host_fd(state, guest_dirfd)?;
        let base = canonical_fd_path(host_fd).ok()?;
        if base.as_os_str().as_bytes() != CPU_ROOT {
            return None;
        }
        path
    } else {
        return None;
    };

    if relative == b"cpufreq/boost" {
        return Some(b"1\n");
    }

    let mut components = relative.split(|byte| *byte == b'/');
    let cpu = components.next()?;
    if !cpu
        .strip_prefix(b"cpu")
        .is_some_and(|index| !index.is_empty() && index.iter().all(u8::is_ascii_digit))
        || components.next()? != b"cpufreq"
    {
        return None;
    }
    let content = match components.next()? {
        b"cpuinfo_max_freq" => b"3000000\n".as_slice(),
        b"cpuinfo_min_freq" => b"1000000\n".as_slice(),
        b"scaling_cur_freq" => b"2000000\n".as_slice(),
        _ => return None,
    };
    components.next().is_none().then_some(content)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-114): Review /proc/thread-self/fd guest descriptor resolution.
// TODO-HUMAN-REVIEW(PR-136): Review numeric guest-pid descriptor aliases.
fn guest_fd_path(state: &LoadedStaticElf, path: &[u8]) -> Option<libc::c_int> {
    let numeric_prefix = format!("/proc/{}/fd/", state.pid).into_bytes();
    let suffix = path
        .strip_prefix(b"/dev/fd/")
        .or_else(|| path.strip_prefix(b"/proc/self/fd/"))
        .or_else(|| path.strip_prefix(b"/proc/thread-self/fd/"))
        .or_else(|| path.strip_prefix(numeric_prefix.as_slice()))?;
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
    let Some(guest_fd) = guest_fd_path(state, path) else {
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

// TODO-HUMAN-REVIEW(PR-136): Review guest descriptor link-target sanitization.
fn guest_fd_link_target(state: &LoadedStaticElf, guest_fd: libc::c_int) -> Result<Vec<u8>, i64> {
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return Err(negative_errno(libc::ENOENT));
    };
    if let Some(&inode) = state.proc_files.get(&guest_fd)
        && let Some(path) = synthetic_proc_path_for_inode(inode)
    {
        if let Some(suffix) = path.strip_prefix(b"/proc/self/") {
            let mut numeric = format!("/proc/{}/", state.pid).into_bytes();
            numeric.extend_from_slice(suffix);
            return Ok(numeric);
        }
        return Ok(path.to_vec());
    }
    let target = canonical_fd_path(host_fd)?;
    let target = target.as_os_str().as_bytes();

    // Host pipe and socket link targets embed kernel-assigned inode numbers.
    // Replace only that unstable identity while retaining Linux's link shape.
    for kind in ["pipe", "socket"] {
        let prefix = format!("{kind}:[");
        if target.starts_with(prefix.as_bytes()) && target.ends_with(b"]") {
            return Ok(format!(
                "{kind}:[{}]",
                synthetic_guest_fd_object_inode(state, guest_fd)
            )
            .into_bytes());
        }
    }
    Ok(target.to_vec())
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review guest /dev/fd duplication without supervisor procfs exposure.
// TODO-HUMAN-REVIEW(PR-114): Review fresh open-file-description semantics.
// TODO-HUMAN-REVIEW(PR-136): Review procfd object-identity propagation.
fn open_guest_fd_path(
    state: &mut LoadedStaticElf,
    guest_fd: libc::c_int,
    flags: u64,
    close_on_exec: bool,
) -> i64 {
    let Some(source_host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::ENOENT);
    };
    if flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64 {
        // Keep the existing fail-closed behavior until guest mode/umask can be
        // applied to an anonymous file created through a descriptor path.
        return negative_errno(libc::EINVAL);
    }
    if flags & (libc::O_PATH | libc::O_NOFOLLOW) as u64 == (libc::O_PATH | libc::O_NOFOLLOW) as u64
    {
        // Linux would return an O_PATH handle to the magic link itself. Keeping
        // that real supervisor procfs descriptor would bypass the synthetic
        // guest-fd metadata model and expose host-specific procfs identity.
        return negative_errno(libc::ELOOP);
    }
    let source_alias = output_alias(state, guest_fd);
    let source_proc_inode = state.proc_files.get(&guest_fd).copied();
    let source_object_inode = guest_fd_object_identity(state, guest_fd);

    // Opening a proc-fd magic link creates a fresh open file description. A
    // descriptor duplication would incorrectly share the source offset and
    // status flags, and would prevent Linux-supported access-mode changes.
    // Resolve only the already-mapped host descriptor, so no supervisor-private
    // descriptor can be named by a guest path.
    let proc_path =
        CString::new(format!("/proc/self/fd/{source_host_fd}")).expect("host fd path has no NUL");
    let host_flags = (flags | libc::O_CLOEXEC as u64) as libc::c_int;
    // SAFETY: proc_path is NUL-terminated and live for the call. The source fd
    // remains owned by state, and Linux validates the requested open flags.
    let reopened = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            proc_path.as_ptr(),
            host_flags,
            0,
        )
    };
    if reopened < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(reopened as RawFd) };
    let new_fd = insert_file_with_flags(state, file, close_on_exec, source_alias);
    if new_fd >= 0 {
        state
            .fd_object_inodes
            .insert(new_fd as libc::c_int, source_object_inode);
    }
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

// TODO-HUMAN-REVIEW(PR-136): Review shared descriptor-object identity allocation.
fn cleanup_fd_object_inodes(state: &LoadedStaticElf) {
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    table.objects.retain(|_, entry| entry.is_live());
}

// TODO-HUMAN-REVIEW(PR-136): Review link-removal identity lifecycle tracking.
fn file_identity_stat(file: &std::fs::File) -> Option<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and file owns a live descriptor.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstat initialized stat on success.
    Some(unsafe { stat.assume_init() })
}

fn downgrade_file_identity(state: &LoadedStaticElf, key: (libc::dev_t, libc::ino_t)) {
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(entry) = table.objects.get_mut(&key) {
        let weak = match entry {
            GuestFileIdentityEntry::Persistent(identity) => Some(Arc::downgrade(identity)),
            GuestFileIdentityEntry::Ephemeral(_) => None,
        };
        if let Some(weak) = weak {
            *entry = GuestFileIdentityEntry::Ephemeral(weak);
        }
    }
    table.objects.retain(|_, entry| entry.is_live());
}

fn allocate_fd_object_inode(
    state: &LoadedStaticElf,
    file: &std::fs::File,
) -> Result<Arc<GuestFileIdentity>, i64> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and file owns a live descriptor.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem is writable and file owns a live descriptor.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstatfs initialized filesystem on success.
    let filesystem = unsafe { filesystem.assume_init() };
    let persistent = stat.st_nlink > 0
        && !matches!(
            filesystem.f_type,
            ANON_INODE_FS_MAGIC | PIPEFS_MAGIC | SOCKFS_MAGIC
        );

    let key = (stat.st_dev, stat.st_ino);
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    table.objects.retain(|_, entry| entry.is_live());
    if let Some(identity) = table
        .objects
        .get(&key)
        .and_then(GuestFileIdentityEntry::identity)
    {
        return Ok(identity);
    }

    let inode = table.next_inode;
    table.next_inode = inode
        .checked_add(1)
        .ok_or_else(|| negative_errno(libc::EOVERFLOW))?;
    let identity = Arc::new(GuestFileIdentity { inode });
    // Linked filesystem objects keep Linux inode identity across close/reopen.
    // Anonymous or deleted objects cannot be reopened by path, so retain them
    // only while a descriptor in any forked state holds a strong identity.
    let entry = if persistent {
        GuestFileIdentityEntry::Persistent(identity.clone())
    } else {
        GuestFileIdentityEntry::Ephemeral(Arc::downgrade(&identity))
    };
    table.objects.insert(key, entry);
    Ok(identity)
}

// TODO-HUMAN-REVIEW(PR-136): Review descriptor insertion and identity allocation.
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
    let object_inode = match allocate_fd_object_inode(state, &file) {
        Ok(inode) => inode,
        Err(error) => return error,
    };
    state.files.insert(fd, file);
    state.fd_object_inodes.insert(fd, object_inode);
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
// TODO-HUMAN-REVIEW(PR-136): Review fcntl duplicate object identity propagation.
fn duplicate_fd_at_or_above(
    state: &mut LoadedStaticElf,
    old_host_fd: RawFd,
    raw_minimum: u64,
    close_on_exec: bool,
    output_alias: Option<OutputAlias>,
    source_proc_inode: Option<u64>,
    source_object_inode: Arc<GuestFileIdentity>,
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
    state.fd_object_inodes.insert(fd, source_object_inode);
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

// TODO-HUMAN-REVIEW(PR-136): Review dup object-identity propagation.
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
    let source_object_inode = guest_fd_object_identity(state, old_fd);
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
        state.fd_object_inodes.insert(new_fd, source_object_inode);
        cleanup_fd_object_inodes(state);
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
        if new_fd >= 0 {
            state
                .fd_object_inodes
                .insert(new_fd as libc::c_int, source_object_inode);
        }
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
// TODO-HUMAN-REVIEW(PR-136): Review pipe object-identity allocation and cleanup.
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
    insert_file_pair(
        memory,
        state,
        address,
        [read_end, write_end],
        flags & libc::O_CLOEXEC != 0,
    )
}

// TODO-HUMAN-REVIEW(PR-205): Review paired guest-descriptor rollback and identity cleanup.
fn insert_file_pair(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    address: u64,
    files: [std::fs::File; 2],
    close_on_exec: bool,
) -> i64 {
    let [first_file, second_file] = files;
    let first_fd = insert_file_with_flags(state, first_file, close_on_exec, None);
    if first_fd < 0 {
        return first_fd;
    }
    let second_fd = insert_file_with_flags(state, second_file, close_on_exec, None);
    if second_fd < 0 {
        remove_inserted_file(state, first_fd as libc::c_int);
        return second_fd;
    }

    let fds = [first_fd as libc::c_int, second_fd as libc::c_int];
    let mut bytes = [0; std::mem::size_of::<[libc::c_int; 2]>()];
    bytes[..std::mem::size_of::<libc::c_int>()].copy_from_slice(&fds[0].to_ne_bytes());
    bytes[std::mem::size_of::<libc::c_int>()..].copy_from_slice(&fds[1].to_ne_bytes());
    if memory.write(address, &bytes).is_err() {
        for fd in fds {
            remove_inserted_file(state, fd);
        }
        return negative_errno(libc::EFAULT);
    }
    0
}

fn remove_inserted_file(state: &mut LoadedStaticElf, fd: libc::c_int) {
    state.files.remove(&fd);
    state.fd_object_inodes.remove(&fd);
    state.cloexec_fds.remove(&fd);
    cleanup_fd_object_inodes(state);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-205): Review deterministic select readiness and timeout semantics.
fn select(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(nfds) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EINVAL);
    };
    if !(0..=GUEST_NOFILE_LIMIT).contains(&nfds) {
        return negative_errno(libc::EINVAL);
    }
    let word_count = (nfds as usize).div_ceil(u64::BITS as usize);
    let byte_length = word_count * std::mem::size_of::<u64>();
    if byte_length > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    let mut sets = [Vec::new(), Vec::new(), Vec::new()];
    for (set, address) in sets.iter_mut().zip(&args[1..4]) {
        *set = vec![0_u64; word_count];
        if *address != 0 && byte_length != 0 {
            // SAFETY: the vector contains initialized u64 words and the byte
            // view is exactly bounded to its allocation.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(set.as_mut_ptr().cast::<u8>(), byte_length)
            };
            if memory.read(*address, bytes).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
    }

    if args[4] != 0 {
        let timeout = match read_guest_struct::<libc::timeval>(memory, args[4]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000).contains(&timeout.tv_usec) {
            return negative_errno(libc::EINVAL);
        }
    }

    let mut poll_fds = Vec::new();
    let mut requested = Vec::new();
    for guest_fd in 0..nfds {
        let membership = sets.each_ref().map(|set| fd_set_contains(set, guest_fd));
        if !membership.into_iter().any(|present| present) {
            continue;
        }
        let Some(host_fd) = host_fd(state, guest_fd) else {
            return negative_errno(libc::EBADF);
        };
        let mut events = 0;
        if membership[0] {
            events |= libc::POLLIN;
        }
        if membership[1] {
            events |= libc::POLLOUT;
        }
        if membership[2] {
            events |= libc::POLLPRI;
        }
        poll_fds.push(libc::pollfd {
            fd: host_fd,
            events,
            revents: 0,
        });
        requested.push((guest_fd, membership));
    }

    // Detcore owns guest time. Preserve readiness that exists now without
    // blocking the supervisor on host wall time for a guest timeout.
    let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, 0) };
    if ready < 0 {
        return io_error(std::io::Error::last_os_error());
    }

    let mut ready_sets = [
        vec![0_u64; word_count],
        vec![0_u64; word_count],
        vec![0_u64; word_count],
    ];
    let mut ready_count = 0_i64;
    for (poll_fd, (guest_fd, membership)) in poll_fds.iter().zip(requested) {
        let ready = [
            poll_fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0,
            poll_fd.revents & (libc::POLLOUT | libc::POLLERR) != 0,
            poll_fd.revents & libc::POLLPRI != 0,
        ];
        for index in 0..ready_sets.len() {
            if membership[index] && ready[index] {
                fd_set_insert(&mut ready_sets[index], guest_fd);
                ready_count += 1;
            }
        }
    }

    for (address, ready_set) in args[1..4].iter().zip(&ready_sets) {
        if *address == 0 || byte_length == 0 {
            continue;
        }
        // SAFETY: the vector contains initialized u64 words and the byte view
        // is exactly bounded to its allocation.
        let bytes =
            unsafe { std::slice::from_raw_parts(ready_set.as_ptr().cast::<u8>(), byte_length) };
        if memory.write(*address, bytes).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    if args[4] != 0 {
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        if write_struct(memory, args[4], &timeout) != 0 {
            return negative_errno(libc::EFAULT);
        }
    }
    ready_count
}

fn fd_set_contains(set: &[u64], fd: libc::c_int) -> bool {
    let fd = fd as usize;
    set.get(fd / u64::BITS as usize)
        .is_some_and(|word| word & (1_u64 << (fd % u64::BITS as usize)) != 0)
}

fn fd_set_insert(set: &mut [u64], fd: libc::c_int) {
    let fd = fd as usize;
    set[fd / u64::BITS as usize] |= 1_u64 << (fd % u64::BITS as usize);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review guest descriptor translation and deterministic nonblocking poll semantics.
fn poll(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    poll_with_timeout(memory, state, args, 0)
}

// TODO-HUMAN-REVIEW(PR-172): Review host-blocking KVM ppoll timeout and signal-mask semantics.
fn ppoll(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[3] != 0 {
        if args[4] != KERNEL_SIGSET_SIZE as u64 {
            return negative_errno(libc::EINVAL);
        }
        return negative_errno(libc::ENOSYS);
    }
    let timeout = if args[2] == 0 {
        -1
    } else {
        let timeout = match read_guest_struct::<libc::timespec>(memory, args[2]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000_000).contains(&timeout.tv_nsec) {
            return negative_errno(libc::EINVAL);
        }
        let milliseconds = (timeout.tv_sec as u128)
            .saturating_mul(1_000)
            .saturating_add((timeout.tv_nsec as u128).div_ceil(1_000_000));
        milliseconds.min(libc::c_int::MAX as u128) as libc::c_int
    };
    poll_with_timeout(memory, state, args, timeout)
}

fn poll_with_timeout(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    timeout: libc::c_int,
) -> i64 {
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

    // SYS_poll remains nonblocking for deterministic personality calls. The
    // concurrent KVM ppoll path may block in the host so QEMU's root event loop
    // can wait for worker eventfds without spinning on virtual clock reads.
    let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), count as libc::nfds_t, timeout) };
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
// TODO-HUMAN-REVIEW(PR-213): Review host-backed AF_INET socket creation.
fn socket(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let domain = args[0] as libc::c_int;
    if !matches!(domain, libc::AF_UNIX | libc::AF_INET) {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    let protocol = args[2] as libc::c_int;
    if domain == libc::AF_UNIX && protocol != 0 {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let socket_type = args[1] as libc::c_int;
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    if base_type != libc::SOCK_DGRAM && base_type != libc::SOCK_STREAM {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    // SAFETY: domain and type are restricted above; the kernel validates the
    // protocol and returns a new owned descriptor on success.
    let host_fd = unsafe { libc::socket(domain, socket_type | libc::SOCK_CLOEXEC, protocol) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, socket_type & libc::SOCK_CLOEXEC != 0, None)
}

// TODO-HUMAN-REVIEW(PR-213): Review bounded guest socket-option translation.
fn setsockopt(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(length) = libc::socklen_t::try_from(args[4]) else {
        return negative_errno(libc::EINVAL);
    };
    let length_usize = length as usize;
    if length_usize > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    let mut value = vec![0; length_usize];
    if length_usize != 0 && memory.read(args[3], &mut value).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let value_ptr = if value.is_empty() {
        std::ptr::null()
    } else {
        value.as_ptr().cast::<libc::c_void>()
    };
    // SAFETY: value_ptr is null for an empty option or readable for length
    // bytes; host_fd belongs to the guest descriptor table.
    zero_or_errno(unsafe {
        libc::setsockopt(
            host_fd,
            args[1] as libc::c_int,
            args[2] as libc::c_int,
            value_ptr,
            length,
        )
    })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-230): Review bounded SO_TYPE copy-out semantics.
fn getsockopt(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    if args[4] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok(mut length) = read_guest_struct::<libc::socklen_t>(memory, args[4]) else {
        return negative_errno(libc::EFAULT);
    };
    let capacity = length as usize;
    if capacity > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    if args[1] as libc::c_int != libc::SOL_SOCKET || args[2] as libc::c_int != libc::SO_TYPE {
        return negative_errno(libc::ENOPROTOOPT);
    }
    if capacity != 0 && args[3] == 0 {
        return negative_errno(libc::EFAULT);
    }

    let mut value = vec![0; capacity];
    let value_pointer = if value.is_empty() {
        std::ptr::null_mut()
    } else {
        value.as_mut_ptr().cast::<libc::c_void>()
    };
    // SAFETY: value_pointer is null for a zero-length request or writable for
    // capacity bytes; host_fd belongs to the guest descriptor table.
    if unsafe {
        libc::getsockopt(
            host_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            value_pointer,
            &mut length,
        )
    } != 0
    {
        return io_error(std::io::Error::last_os_error());
    }
    let copy_length = capacity.min(length as usize);
    if copy_length != 0 && memory.write(args[3], &value[..copy_length]).is_err() {
        return negative_errno(libc::EFAULT);
    }
    write_struct(memory, args[4], &length)
}

// TODO-HUMAN-REVIEW(PR-213): Review bounded host-backed AF_INET bind translation.
// TODO-HUMAN-REVIEW(PR-217): Review filesystem-backed AF_UNIX bind translation.
fn bind(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(length) = libc::socklen_t::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length_usize = length as usize;
    if length_usize < std::mem::size_of::<libc::sa_family_t>()
        || length_usize > std::mem::size_of::<libc::sockaddr_storage>()
    {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; length_usize];
    if memory.read(args[1], &mut address).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let family = libc::sa_family_t::from_ne_bytes(
        address[..std::mem::size_of::<libc::sa_family_t>()]
            .try_into()
            .expect("family slice has exact size"),
    );
    if !matches!(family as libc::c_int, libc::AF_INET | libc::AF_UNIX) {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    // SAFETY: address is readable for length bytes and host_fd belongs to the
    // guest descriptor table. Detcore has already determinized port zero.
    zero_or_errno(unsafe { libc::bind(host_fd, address.as_ptr().cast::<libc::sockaddr>(), length) })
}

// TODO-HUMAN-REVIEW(PR-213): Review host-backed listen translation.
fn listen(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    // SAFETY: host_fd belongs to the guest descriptor table; listen validates
    // whether it is a stream socket.
    zero_or_errno(unsafe { libc::listen(host_fd, args[1] as libc::c_int) })
}

// TODO-HUMAN-REVIEW(PR-213): Review bounded getsockname copyback semantics.
fn getsockname(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    if args[1] == 0 || args[2] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok(mut length) = read_guest_struct::<libc::socklen_t>(memory, args[2]) else {
        return negative_errno(libc::EFAULT);
    };
    let capacity = length as usize;
    if capacity > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; capacity];
    // SAFETY: address is writable for capacity bytes and length describes that
    // allocation. host_fd belongs to the guest descriptor table.
    if unsafe {
        libc::getsockname(
            host_fd,
            address.as_mut_ptr().cast::<libc::sockaddr>(),
            &mut length,
        )
    } != 0
    {
        return io_error(std::io::Error::last_os_error());
    }
    let copy_length = capacity.min(length as usize);
    if copy_length != 0 && memory.write(args[1], &address[..copy_length]).is_err() {
        return negative_errno(libc::EFAULT);
    }
    write_struct(memory, args[2], &length)
}

// TODO-HUMAN-REVIEW(PR-218): Review blocking accept outside the shared descriptor-table lock.
fn accept_socket(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    flags: libc::c_int,
) -> Result<std::fs::File, i64> {
    let allowed_flags = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    if flags & !allowed_flags != 0 {
        return Err(negative_errno(libc::EINVAL));
    }
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return Err(negative_errno(libc::EBADF));
    };

    // SAFETY: a zeroed sockaddr_storage is valid scratch space for accept4.
    let mut address =
        unsafe { std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let guest_capacity = if args[1] == 0 {
        0
    } else {
        if args[2] == 0 {
            return Err(negative_errno(libc::EFAULT));
        }
        let capacity = read_guest_struct::<libc::socklen_t>(memory, args[2])
            .map_err(|_| negative_errno(libc::EFAULT))?;
        length = length.min(capacity);
        capacity as usize
    };
    let address_pointer = if args[1] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut address).cast::<libc::sockaddr>()
    };
    let length_pointer = if args[1] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut length)
    };

    // SAFETY: host_fd belongs to the guest descriptor table. The optional
    // address and length pointers refer to initialized host storage.
    let accepted_fd = unsafe {
        libc::accept4(
            host_fd,
            address_pointer,
            length_pointer,
            flags | libc::SOCK_CLOEXEC,
        )
    };
    if accepted_fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: accept4 returned a new owned descriptor.
    let accepted = unsafe { std::fs::File::from_raw_fd(accepted_fd) };

    if args[1] != 0 {
        let copy_length = guest_capacity
            .min(length as usize)
            .min(std::mem::size_of::<libc::sockaddr_storage>());
        if copy_length != 0 {
            // SAFETY: address is initialized storage and copy_length is bounded
            // by its size.
            let bytes = unsafe {
                std::slice::from_raw_parts(std::ptr::from_ref(&address).cast::<u8>(), copy_length)
            };
            if memory.write(args[1], bytes).is_err() {
                return Err(negative_errno(libc::EFAULT));
            }
        }
        let result = write_struct(memory, args[2], &length);
        if result < 0 {
            return Err(result);
        }
    }
    Ok(accepted)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-205): Review AF_UNIX socketpair descriptor ownership.
fn socketpair(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let domain = args[0] as libc::c_int;
    let socket_type = args[1] as libc::c_int;
    let protocol = args[2] as libc::c_int;
    if domain != libc::AF_UNIX {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    if protocol != 0 {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    if !matches!(base_type, libc::SOCK_DGRAM | libc::SOCK_STREAM) {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let mut host_fds = [-1; 2];
    // SAFETY: host_fds has room for both descriptors and the socket arguments
    // were validated above.
    if unsafe {
        libc::socketpair(
            domain,
            socket_type | libc::SOCK_CLOEXEC,
            protocol,
            host_fds.as_mut_ptr(),
        )
    } != 0
    {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: socketpair initialized both owned descriptors on success.
    let first = unsafe { std::fs::File::from_raw_fd(host_fds[0]) };
    // SAFETY: socketpair initialized both owned descriptors on success.
    let second = unsafe { std::fs::File::from_raw_fd(host_fds[1]) };
    insert_file_pair(
        memory,
        state,
        args[3],
        [first, second],
        socket_type & libc::SOCK_CLOEXEC != 0,
    )
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-217): Review filesystem-backed AF_UNIX connect translation.
fn connect(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(length) = libc::socklen_t::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length_usize = length as usize;
    if length_usize < std::mem::size_of::<libc::sa_family_t>()
        || length_usize > std::mem::size_of::<libc::sockaddr_un>()
    {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; length_usize];
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
    // SAFETY: address is readable for length bytes and host_fd belongs to the
    // guest descriptor table. The host kernel validates the Unix address.
    zero_or_errno(unsafe {
        libc::connect(host_fd, address.as_ptr().cast::<libc::sockaddr>(), length)
    })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-205): Review host-backed AF_UNIX shutdown semantics.
fn shutdown(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let how = args[1] as libc::c_int;
    if !matches!(how, libc::SHUT_RD | libc::SHUT_WR | libc::SHUT_RDWR) {
        return negative_errno(libc::EINVAL);
    }
    // SAFETY: host_fd is a live guest-owned descriptor; shutdown validates
    // whether it refers to a socket.
    zero_or_errno(unsafe { libc::shutdown(host_fd, how) })
}

// TODO-HUMAN-REVIEW(PR-218): Review bounded guest sendto translation and SIGPIPE suppression.
fn sendto(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(flags) = libc::c_int::try_from(args[3]) else {
        return negative_errno(libc::EINVAL);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let mut bytes = vec![0; length];
    if length != 0 && memory.read(args[1], &mut bytes).is_err() {
        return negative_errno(libc::EFAULT);
    }

    let Ok(address_length) = libc::socklen_t::try_from(args[5]) else {
        return negative_errno(libc::EINVAL);
    };
    if address_length as usize > std::mem::size_of::<libc::sockaddr_storage>() {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; address_length as usize];
    if args[4] != 0 && address_length != 0 && memory.read(args[4], &mut address).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let address_pointer = if args[4] == 0 {
        std::ptr::null()
    } else {
        address.as_ptr().cast::<libc::sockaddr>()
    };

    // SAFETY: the payload and optional address are readable host buffers and
    // host_fd belongs to the guest descriptor table. MSG_NOSIGNAL keeps a
    // guest EPIPE from delivering SIGPIPE to the supervisor.
    let result = unsafe {
        libc::sendto(
            host_fd,
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
            flags | libc::MSG_NOSIGNAL,
            address_pointer,
            address_length,
        )
    };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result as i64
    }
}

// TODO-HUMAN-REVIEW(PR-218): Review bounded recvfrom buffer and peer-address copyback semantics.
fn recvfrom(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(flags) = libc::c_int::try_from(args[3]) else {
        return negative_errno(libc::EINVAL);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if !range_is_valid(memory, args[1], args[2]) {
        return negative_errno(libc::EFAULT);
    }
    let length = requested_length.min(MAX_HOST_IO);
    let Ok(writable) = memory.user_accessible_prefix(args[1], length) else {
        return negative_errno(libc::EFAULT);
    };
    if writable == 0 && requested_length != 0 {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; writable];

    // SAFETY: a zeroed sockaddr_storage is valid scratch space for recvfrom.
    let mut address =
        unsafe { std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let guest_address_capacity = if args[4] == 0 {
        0
    } else {
        if args[5] == 0 {
            return negative_errno(libc::EFAULT);
        }
        let capacity = match read_guest_struct::<libc::socklen_t>(memory, args[5]) {
            Ok(capacity) => capacity,
            Err(_) => return negative_errno(libc::EFAULT),
        };
        address_length = address_length.min(capacity);
        capacity as usize
    };
    let address_pointer = if args[4] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut address).cast::<libc::sockaddr>()
    };
    let length_pointer = if args[4] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut address_length)
    };

    // SAFETY: bytes is writable for its full length, the optional peer address
    // points to initialized host storage, and host_fd is guest-owned.
    let result = unsafe {
        libc::recvfrom(
            host_fd,
            bytes.as_mut_ptr().cast::<libc::c_void>(),
            bytes.len(),
            flags,
            address_pointer,
            length_pointer,
        )
    };
    if result < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let copy_length = (result as usize).min(bytes.len());
    if copy_length != 0 && memory.write(args[1], &bytes[..copy_length]).is_err() {
        return negative_errno(libc::EFAULT);
    }

    if args[4] != 0 {
        let address_copy_length = guest_address_capacity
            .min(address_length as usize)
            .min(std::mem::size_of::<libc::sockaddr_storage>());
        if address_copy_length != 0 {
            // SAFETY: address is initialized storage and address_copy_length
            // is bounded by its size.
            let address_bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::from_ref(&address).cast::<u8>(),
                    address_copy_length,
                )
            };
            if memory.write(args[4], address_bytes).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
        let copy_result = write_struct(memory, args[5], &address_length);
        if copy_result < 0 {
            return copy_result;
        }
    }
    result as i64
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-210): Review guest mmsghdr translation and nonblocking receive semantics.
fn recvmmsg(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(message_count) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if message_count == 0 || message_count > libc::UIO_MAXIOV as usize {
        return negative_errno(libc::EINVAL);
    }

    let message_size = std::mem::size_of::<libc::mmsghdr>();
    let Some(total_header_bytes) = message_count.checked_mul(message_size) else {
        return negative_errno(libc::EINVAL);
    };
    if total_header_bytes > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    let mut delivered = 0usize;
    for index in 0..message_count {
        let Some(message_address) = args[1].checked_add((index * message_size) as u64) else {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        };
        let mut message: libc::mmsghdr = match read_guest_struct(memory, message_address) {
            Ok(message) => message,
            Err(error) => {
                return if delivered == 0 {
                    error
                } else {
                    delivered as i64
                };
            }
        };
        let iov_count = message.msg_hdr.msg_iovlen;
        if iov_count > libc::UIO_MAXIOV as usize {
            return if delivered == 0 {
                negative_errno(libc::EMSGSIZE)
            } else {
                delivered as i64
            };
        }

        let guest_iov_address = message.msg_hdr.msg_iov as usize as u64;
        let mut guest_iovecs = Vec::with_capacity(iov_count);
        let mut payload_length = 0usize;
        for iov_index in 0..iov_count {
            let Some(iov_address) = guest_iov_address
                .checked_add((iov_index * std::mem::size_of::<libc::iovec>()) as u64)
            else {
                return if delivered == 0 {
                    negative_errno(libc::EFAULT)
                } else {
                    delivered as i64
                };
            };
            let iov: libc::iovec = match read_guest_struct(memory, iov_address) {
                Ok(iov) => iov,
                Err(error) => {
                    return if delivered == 0 {
                        error
                    } else {
                        delivered as i64
                    };
                }
            };
            let Some(next_length) = payload_length.checked_add(iov.iov_len) else {
                return if delivered == 0 {
                    negative_errno(libc::EINVAL)
                } else {
                    delivered as i64
                };
            };
            if next_length > MAX_HOST_IO {
                return if delivered == 0 {
                    negative_errno(libc::EINVAL)
                } else {
                    delivered as i64
                };
            }
            if iov.iov_len != 0 {
                let mut probe = vec![0; iov.iov_len];
                if memory
                    .read(iov.iov_base as usize as u64, &mut probe)
                    .is_err()
                {
                    return if delivered == 0 {
                        negative_errno(libc::EFAULT)
                    } else {
                        delivered as i64
                    };
                }
            }
            payload_length = next_length;
            guest_iovecs.push(iov);
        }

        let name_capacity = message.msg_hdr.msg_namelen as usize;
        let control_capacity = message.msg_hdr.msg_controllen;
        if name_capacity > MAX_HOST_IO || control_capacity > MAX_HOST_IO {
            return if delivered == 0 {
                negative_errno(libc::EINVAL)
            } else {
                delivered as i64
            };
        }
        let mut payload = vec![0u8; payload_length];
        let mut name = vec![0u8; name_capacity];
        let mut control = vec![0u8; control_capacity];
        if name_capacity != 0
            && memory
                .read(message.msg_hdr.msg_name as usize as u64, &mut name)
                .is_err()
        {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        if control_capacity != 0
            && memory
                .read(message.msg_hdr.msg_control as usize as u64, &mut control)
                .is_err()
        {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }

        let mut host_iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut host_header = libc::msghdr {
            msg_name: if name.is_empty() {
                std::ptr::null_mut()
            } else {
                name.as_mut_ptr().cast()
            },
            msg_namelen: name.len() as libc::socklen_t,
            msg_iov: std::ptr::from_mut(&mut host_iov),
            msg_iovlen: usize::from(!payload.is_empty()),
            msg_control: if control.is_empty() {
                std::ptr::null_mut()
            } else {
                control.as_mut_ptr().cast()
            },
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let flags = args[3] as libc::c_int & !libc::MSG_WAITFORONE;
        // Keep the VM executor cooperative. Detcore retries EAGAIN through its
        // scheduler, while already queued datagrams are returned immediately.
        let received = unsafe {
            libc::recvmsg(
                host_fd,
                std::ptr::from_mut(&mut host_header),
                flags | libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            let error = io_error(std::io::Error::last_os_error());
            return if delivered == 0 {
                error
            } else {
                delivered as i64
            };
        }

        let copied_length = (received as usize).min(payload.len());
        let mut copied = 0usize;
        for iov in &guest_iovecs {
            let length = iov.iov_len.min(copied_length.saturating_sub(copied));
            if length != 0
                && memory
                    .write(
                        iov.iov_base as usize as u64,
                        &payload[copied..copied + length],
                    )
                    .is_err()
            {
                return if delivered == 0 {
                    negative_errno(libc::EFAULT)
                } else {
                    delivered as i64
                };
            }
            copied += length;
        }
        if name_capacity != 0
            && memory
                .write(
                    message.msg_hdr.msg_name as usize as u64,
                    &name[..name_capacity.min(host_header.msg_namelen as usize)],
                )
                .is_err()
        {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        if control_capacity != 0
            && memory
                .write(
                    message.msg_hdr.msg_control as usize as u64,
                    &control[..control_capacity.min(host_header.msg_controllen)],
                )
                .is_err()
        {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        message.msg_hdr.msg_namelen = host_header.msg_namelen;
        message.msg_hdr.msg_controllen = host_header.msg_controllen;
        message.msg_hdr.msg_flags = host_header.msg_flags;
        message.msg_len = received as libc::c_uint;
        if write_struct(memory, message_address, &message) != 0 {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        delivered += 1;
    }
    delivered as i64
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
fn ioctl(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    if host_fd(state, guest_fd).is_none() {
        return negative_errno(libc::EBADF);
    }
    match args[1] as libc::c_ulong {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-229): Review virtual FIOCLEX/FIONCLEX descriptor flags.
        libc::FIOCLEX => {
            state.cloexec_fds.insert(guest_fd);
            0
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-229): Review virtual FIOCLEX/FIONCLEX descriptor flags.
        libc::FIONCLEX => {
            state.cloexec_fds.remove(&guest_fd);
            0
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-230): Review the no-guest-NIC ioctl model.
        SIOCETHTOOL => negative_errno(libc::ENODEV),
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

// TODO-HUMAN-REVIEW(PR-145): Review fixed-root saved-ID output and fault ordering.
fn get_fixed_root_ids(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    let root_id = libc::uid_t::from(0_u8).to_ne_bytes();
    for address in &args[..3] {
        if memory.write(*address, &root_id).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    0
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

fn fstat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
) -> i64 {
    let Ok(fd) = i32::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    if capture_output && output_alias(state, fd).is_some() {
        let stat = synthetic_captured_output_stat(state, fd);
        return write_struct(memory, args[1], &stat);
    }
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
    } else {
        sanitize_stat_timestamps(&mut stat);
    }
    write_struct(memory, args[1], &stat)
}

// TODO-HUMAN-REVIEW(PR-205): Review synthetic metadata for in-memory captured output.
fn synthetic_captured_output_stat(state: &LoadedStaticElf, fd: libc::c_int) -> libc::stat {
    // Captured writes never reach the host descriptor, so exposing that
    // descriptor's type, size, or inode leaks the invoking shell into the
    // guest. Model the capture sink as the pipe used by process-based backends.
    // SAFETY: libc::stat is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_dev = synthetic_dev(SYNTHETIC_GUEST_FD_DEV_MINOR);
    stat.st_ino = synthetic_guest_fd_object_inode(state, fd);
    stat.st_mode = libc::S_IFIFO | 0o600;
    stat.st_nlink = 1;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_blksize = PAGE_SIZE as libc::blksize_t;
    sanitize_stat_timestamps(&mut stat);
    stat
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
        } else {
            sanitize_stat_timestamps(&mut stat);
        }
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
        sanitize_statx_timestamps(&mut stat);
    }
    write_struct(memory, args[4], &stat)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-183): Review fixed host-backed metadata timestamps.
fn sanitize_stat_timestamps(stat: &mut libc::stat) {
    stat.st_atime = DETERMINISTIC_METADATA_SECONDS;
    stat.st_atime_nsec = 0;
    stat.st_mtime = DETERMINISTIC_METADATA_SECONDS;
    stat.st_mtime_nsec = 0;
    stat.st_ctime = DETERMINISTIC_METADATA_SECONDS;
    stat.st_ctime_nsec = 0;
}

fn sanitize_statx_timestamps(stat: &mut libc::statx) {
    for timestamp in [
        &mut stat.stx_atime,
        &mut stat.stx_btime,
        &mut stat.stx_ctime,
        &mut stat.stx_mtime,
    ] {
        timestamp.tv_sec = DETERMINISTIC_METADATA_SECONDS;
        timestamp.tv_nsec = 0;
    }
}

// TODO-HUMAN-REVIEW(PR-114): Review guest descriptor path resolution for statfs.
fn statfs(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(memory, args[0], 4096) {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => return negative_errno(libc::ENOENT),
        Err(error) => return read_c_string_errno(error),
    };
    let guest_path = match guest_fd_metadata(state, &path, false) {
        Ok(metadata) => metadata,
        Err(error) => return error,
    };
    let opened_file;
    let host_fd = if let Some(metadata) = guest_path {
        metadata.host_fd
    } else {
        opened_file = match open_metadata_path(state, libc::AT_FDCWD, &path, false) {
            Ok(file) => file,
            Err(error) => return error,
        };
        opened_file.as_raw_fd()
    };
    fstatfs_host(memory, host_fd, args[1])
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
    let mut stat = unsafe { stat.assume_init() };
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-225): the raw host statfs leaks
    // nondeterministic values (free blocks/inodes drift as the host disk is
    // written, and f_fsid identifies the host filesystem), which breaks
    // --verify for any statfs consumer (df, tar, stat -f). Canonicalize the
    // host-varying fields exactly as the ptrace/detcore backend does in
    // detcore/src/syscalls/files.rs::canonicalize_statfs_buf, so both statfs()
    // and fstatfs() present the same stable, deterministic view.
    canonicalize_statfs(&mut stat);
    write_struct(memory, output, &stat)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-225): mirror of detcore's statfs canonicalization
// (FREE_BLOCKS_CAP / FREE_INODES_CAP, clamp free to totals, zero f_fsid) so
// the KVM backend matches ptrace L2 determinism for statfs.
fn canonicalize_statfs(sf: &mut libc::statfs) {
    const FREE_BLOCKS_CAP: libc::fsblkcnt_t = 1_000_000;
    const FREE_INODES_CAP: libc::fsfilcnt_t = 500_000;
    let free_blocks = FREE_BLOCKS_CAP.min(sf.f_blocks);
    sf.f_bfree = free_blocks;
    sf.f_bavail = free_blocks;
    sf.f_ffree = if sf.f_files == 0 {
        0
    } else {
        FREE_INODES_CAP.min(sf.f_files)
    };
    // SAFETY: libc::fsid_t is a plain integer-array POD; zeroing it is valid.
    sf.f_fsid = unsafe { std::mem::zeroed() };
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
// TODO-HUMAN-REVIEW(PR-114): Review guest descriptor path resolution for access checks.
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
    let guest_path = match guest_fd_metadata(state, &path, flags & libc::AT_SYMLINK_NOFOLLOW != 0) {
        Ok(metadata) => metadata,
        Err(error) => return error,
    };
    if let Some(metadata) = guest_path
        && metadata.no_follow
    {
        // Linux symlinks are always treated as mode 0777. F_OK and every valid
        // access bit therefore succeed when faccessat2 checks the magic link
        // itself rather than its target.
        return 0;
    }
    let opened_file;
    let host_fd = if let Some(metadata) = guest_path {
        metadata.host_fd
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
    let empty_path = b"\0";
    // Forward AT_EACCESS so an effective-ID probe keeps its meaning; the O_PATH
    // fd is addressed with AT_EMPTY_PATH.
    let host_flags = libc::AT_EMPTY_PATH | (flags & libc::AT_EACCESS);
    // SAFETY: empty_path is NUL-terminated and host_fd is live for the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            host_fd,
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

// TODO-HUMAN-REVIEW(PR-136): Review last-link identity downgrade semantics.
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
    let removes_directory = raw_flags & libc::AT_REMOVEDIR as u64 != 0;
    let removed_file = open_host_metadata_path(host_dirfd, &path, true).ok();
    let removed_key = removed_file
        .as_ref()
        .and_then(file_identity_stat)
        .and_then(|stat| {
            if removes_directory || stat.st_nlink <= 1 {
                Some((stat.st_dev, stat.st_ino))
            } else {
                None
            }
        });
    // SAFETY: path is NUL-terminated and flags were validated.
    let result = unsafe { libc::unlinkat(host_dirfd, path.as_ptr(), raw_flags as libc::c_int) };
    if result == 0 {
        if let Some(key) = removed_key {
            downgrade_file_identity(state, key);
        }
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
}

// TODO-HUMAN-REVIEW(PR-136): Review rename-replacement identity downgrade semantics.
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
    let old_file = if raw_flags == 0 {
        open_host_metadata_path(old_host_dirfd, &old_path, true).ok()
    } else {
        None
    };
    let replaced_file = if raw_flags == 0 {
        open_host_metadata_path(new_host_dirfd, &new_path, true).ok()
    } else {
        None
    };
    let replaced_key = match (
        old_file.as_ref().and_then(file_identity_stat),
        replaced_file.as_ref().and_then(file_identity_stat),
    ) {
        (Some(old), Some(replaced))
            if (old.st_dev, old.st_ino) != (replaced.st_dev, replaced.st_ino)
                && ((replaced.st_mode & libc::S_IFMT) == libc::S_IFDIR
                    || replaced.st_nlink <= 1) =>
        {
            Some((replaced.st_dev, replaced.st_ino))
        }
        _ => None,
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
        if let Some(key) = replaced_key {
            downgrade_file_identity(state, key);
        }
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
// Keep virtual metadata inside the timestamp range supported by common host
// filesystems while remaining independent of host wall time.
const DETERMINISTIC_METADATA_SECONDS: libc::time_t = 1_640_995_199;

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
            tv_sec: DETERMINISTIC_METADATA_SECONDS,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: DETERMINISTIC_METADATA_SECONDS,
            tv_nsec: 0,
        },
    ]);
    for time in &mut times {
        if time.tv_nsec == libc::UTIME_NOW {
            time.tv_sec = DETERMINISTIC_METADATA_SECONDS;
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

// TODO-HUMAN-REVIEW(PR-136): Review synthetic procfd link reconstruction.
fn synthetic_proc_path_for_inode(inode: u64) -> Option<&'static [u8]> {
    const PATHS: &[&[u8]] = &[
        b"/proc",
        b"/proc/uptime",
        b"/proc/loadavg",
        b"/proc/version",
        b"/proc/filesystems",
        b"/proc/mounts",
        b"/proc/self/mounts",
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-225): /proc/self/mountinfo added to the
        // synthetic surface so fstat/statx on its descriptor resolves to the
        // same stable synthetic inode as the other served /proc files.
        b"/proc/self/mountinfo",
        b"/proc/stat",
        b"/proc/meminfo",
        b"/proc/cpuinfo",
        b"/proc/locks",
        b"/proc/self/stat",
        b"/proc/self/status",
        b"/proc/self/cmdline",
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-224): paths added to the synthetic
        // /proc/vmstat and /proc/sys/kernel/osrelease surface so fstat/statx on
        // their descriptors resolve to the same stable synthetic inode.
        b"/proc/vmstat",
        b"/proc/sys/kernel/osrelease",
    ];
    PATHS
        .iter()
        .copied()
        .find(|path| synthetic_proc_inode(path) == inode)
}

fn is_synthetic_proc_directory_inode(inode: u64) -> bool {
    inode == synthetic_proc_inode(b"/proc")
}

fn is_synthetic_proc_directory(state: &LoadedStaticElf, path: &[u8]) -> bool {
    normalize_proc_path(state, path).is_some_and(|path| path == b"/proc")
}

// TODO-HUMAN-REVIEW(PR-202): Review descriptor-relative synthetic procfs
// resolution and its fail-closed handling of unlisted children.
fn synthetic_proc_relative_path(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
) -> Option<Vec<u8>> {
    if path.starts_with(b"/") {
        return None;
    }
    let inode = state.proc_files.get(&guest_dirfd).copied()?;
    if !is_synthetic_proc_directory_inode(inode) {
        return None;
    }
    let mut resolved = b"/proc/".to_vec();
    resolved.extend_from_slice(path);
    Some(resolved)
}

/// Rewrite a `/proc/<pid>` path (for this guest's own pid) to the canonical
/// `/proc/self` form so both spellings resolve to the same synthetic content.
fn normalize_proc_path(state: &LoadedStaticElf, path: &[u8]) -> Option<Vec<u8>> {
    if path != b"/proc" && !path.starts_with(b"/proc/") {
        return None;
    }
    if path == b"/proc/self/../locks" {
        return Some(b"/proc/locks".to_vec());
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
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-225): /proc/self/mountinfo is the primary
        // mount table modern gnulib/coreutils read (df reads it before falling
        // back to /etc/mtab). Serve a single deterministic rootfs entry
        // consistent with the /proc/mounts surface above. Fields:
        // mount_id parent_id major:minor root mount_point options - fstype src super_opts
        b"/proc/self/mountinfo" => b"1 0 0:1 / / rw - rootfs rootfs rw\n".to_vec(),
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
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-231): Review parity with Hermit's configured memory persona.
        b"/proc/meminfo" => concat!(
            "MemTotal:         976562 kB\n",
            "MemFree:          976562 kB\n",
            "MemAvailable:     976562 kB\n",
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
        b"/proc/locks" => proc_locks_content(state),
        b"/proc/self/stat" => proc_self_stat_content(state),
        b"/proc/self/status" => proc_self_status_content(state),
        b"/proc/self/cmdline" => proc_self_cmdline_content(state),
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-224): deterministic /proc/vmstat surface so
        // procps `vmstat` reads its counters synthetically instead of hitting
        // the fail-closed real-procfs refusal. All counters are fixed at 0
        // (memory is not virtualized under KVM), matching the zeroed
        // /proc/stat and /proc/meminfo surfaces above.
        b"/proc/vmstat" => concat!(
            "nr_free_pages 262144\n",
            "nr_inactive_anon 0\n",
            "nr_active_anon 0\n",
            "nr_inactive_file 0\n",
            "nr_active_file 0\n",
            "nr_unevictable 0\n",
            "nr_mlock 0\n",
            "nr_anon_pages 0\n",
            "nr_mapped 0\n",
            "nr_file_pages 0\n",
            "nr_dirty 0\n",
            "nr_writeback 0\n",
            "nr_slab_reclaimable 0\n",
            "nr_slab_unreclaimable 0\n",
            "pgpgin 0\n",
            "pgpgout 0\n",
            "pswpin 0\n",
            "pswpout 0\n",
            "pgfault 0\n",
            "pgmajfault 0\n",
        )
        .as_bytes()
        .to_vec(),
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-224): deterministic
        // /proc/sys/kernel/osrelease so `sysctl -n kernel.osrelease` resolves
        // synthetically. The value matches the KVM `uname(2)` release field
        // ("6.0.0", see fn uname) and /proc/version above.
        b"/proc/sys/kernel/osrelease" => b"6.0.0\n".to_vec(),
        _ => return None,
    };
    Some(content)
}

// TODO-HUMAN-REVIEW(PR-211): Review guest-owned /proc/locks filtering.
fn proc_locks_content(state: &LoadedStaticElf) -> Vec<u8> {
    let mut seen = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for file in state.files.values() {
        let Ok(fdinfo) = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        else {
            continue;
        };
        for line in fdinfo.lines() {
            let Some(details) = line
                .strip_prefix("lock:")
                .map(str::trim)
                .and_then(|line| line.split_once(' ').map(|(_, details)| details))
            else {
                continue;
            };
            if !seen.insert(details.to_owned()) {
                continue;
            }
            let mut fields = details.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 7 || fields[4].split(':').count() != 3 {
                continue;
            }
            let object = format!("00:00:{}", rows.len() + 1);
            fields[4] = &object;
            rows.push(format!("{}: {}\n", rows.len() + 1, fields.join(" ")));
        }
    }
    rows.concat().into_bytes()
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

// TODO-HUMAN-REVIEW(PR-202): Review the empty synthetic /proc directory used
// solely as an openat anchor for allowlisted deterministic children.
fn open_synthetic_proc_directory(
    state: &mut LoadedStaticElf,
    flags: u64,
    close_on_exec: bool,
) -> i64 {
    let unsupported = (libc::O_CREAT | libc::O_EXCL | libc::O_PATH | libc::O_TRUNC) as u64;
    if flags & unsupported != 0 {
        return negative_errno(libc::EINVAL);
    }
    if flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64 {
        return negative_errno(libc::EINVAL);
    }
    if flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 {
        return negative_errno(libc::EISDIR);
    }
    let file = match std::fs::File::open("/") {
        Ok(file) => file,
        Err(error) => return io_error(error),
    };
    let guest_fd = insert_file_with_flags(state, file, close_on_exec, None);
    if guest_fd >= 0 {
        state
            .proc_files
            .insert(guest_fd as libc::c_int, synthetic_proc_inode(b"/proc"));
    }
    guest_fd
}

/// Overwrite the nondeterministic fields of a memfd `stat` with the stable
/// synthetic identity of a /proc file, keeping the (deterministic) size.
fn sanitize_proc_stat(stat: &mut libc::stat, inode: u64) {
    let is_directory = is_synthetic_proc_directory_inode(inode);
    stat.st_dev = synthetic_dev(SYNTHETIC_PROC_DEV_MINOR);
    stat.st_ino = inode;
    stat.st_mode = if is_directory {
        libc::S_IFDIR | 0o555
    } else {
        libc::S_IFREG | 0o444
    };
    stat.st_nlink = if is_directory { 2 } else { 1 };
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_rdev = 0;
    stat.st_blksize = PAGE_SIZE as libc::blksize_t;
    if is_directory {
        stat.st_size = 0;
    }
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
    let is_directory = is_synthetic_proc_directory_inode(inode);
    stx.stx_nlink = if is_directory { 2 } else { 1 };
    stx.stx_uid = 0;
    stx.stx_gid = 0;
    stx.stx_mode = if is_directory {
        (libc::S_IFDIR | 0o555) as u16
    } else {
        (libc::S_IFREG | 0o444) as u16
    };
    stx.stx_ino = inode;
    stx.stx_size = if is_directory { 0 } else { size };
    stx.stx_blocks = (stx.stx_size + 511) >> 9;
    stx.stx_dev_major = SYNTHETIC_DEV_MAJOR;
    stx.stx_dev_minor = SYNTHETIC_PROC_DEV_MINOR;
    stx
}

// TODO-HUMAN-REVIEW(PR-92): Review deterministic guest-fd alias metadata.
fn synthetic_guest_fd_inode(guest_fd: libc::c_int, symlink: bool) -> u64 {
    0x2000_0000 + (guest_fd as u64 * 2) + u64::from(symlink)
}

// TODO-HUMAN-REVIEW(PR-136): Review deterministic open-file object grouping.
fn guest_fd_object_identity(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
) -> Arc<GuestFileIdentity> {
    state
        .fd_object_inodes
        .get(&guest_fd)
        .cloned()
        .unwrap_or_else(|| {
            Arc::new(GuestFileIdentity {
                inode: synthetic_guest_fd_inode(guest_fd, false),
            })
        })
}

fn synthetic_guest_fd_object_inode(state: &LoadedStaticElf, guest_fd: libc::c_int) -> u64 {
    guest_fd_object_identity(state, guest_fd).inode
}

fn sanitize_guest_fd_stat(state: &LoadedStaticElf, guest_fd: libc::c_int, stat: &mut libc::stat) {
    if let Some(&inode) = state.proc_files.get(&guest_fd) {
        sanitize_proc_stat(stat, inode);
        return;
    }
    stat.st_dev = synthetic_dev(SYNTHETIC_GUEST_FD_DEV_MINOR);
    stat.st_ino = synthetic_guest_fd_object_inode(state, guest_fd);
    sanitize_stat_timestamps(stat);
}

fn sanitize_guest_fd_statx(state: &LoadedStaticElf, guest_fd: libc::c_int, stat: &mut libc::statx) {
    if let Some(&inode) = state.proc_files.get(&guest_fd) {
        *stat = synthetic_proc_statx(inode, stat.stx_size);
        return;
    }
    stat.stx_ino = synthetic_guest_fd_object_inode(state, guest_fd);
    stat.stx_dev_major = SYNTHETIC_DEV_MAJOR;
    stat.stx_dev_minor = SYNTHETIC_GUEST_FD_DEV_MINOR;
    sanitize_statx_timestamps(stat);
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
    let mut length = requested_length.min(MAX_HOST_IO);
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_directory(file) {
        return error;
    }
    if state
        .proc_files
        .get(&fd)
        .is_some_and(|inode| is_synthetic_proc_directory_inode(*inode))
    {
        return 0;
    }
    if length >= 24 && !range_is_valid(memory, args[1], length as u64) {
        return negative_errno(libc::EFAULT);
    }
    if length >= 24 {
        let Ok(writable) = memory.user_accessible_prefix(args[1], length) else {
            return negative_errno(libc::EFAULT);
        };
        if writable < 24 {
            return negative_errno(libc::EFAULT);
        }
        length = writable;
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
fn fcntl(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    let source_alias = output_alias(state, guest_fd);
    let source_proc_inode = state.proc_files.get(&guest_fd).copied();
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    let source_object_inode = guest_fd_object_identity(state, guest_fd);
    match args[1] as libc::c_int {
        libc::F_DUPFD => duplicate_fd_at_or_above(
            state,
            host_fd,
            args[2],
            false,
            source_alias,
            source_proc_inode,
            source_object_inode,
        ),
        libc::F_DUPFD_CLOEXEC => duplicate_fd_at_or_above(
            state,
            host_fd,
            args[2],
            true,
            source_alias,
            source_proc_inode,
            source_object_inode,
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
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-211): Review KVM advisory-lock forwarding.
        command @ (libc::F_SETLK | libc::F_SETLKW | libc::F_OFD_SETLK | libc::F_OFD_SETLKW) => {
            let mut lock = match read_guest_struct::<libc::flock>(memory, args[2]) {
                Ok(lock) => lock,
                Err(error) => return error,
            };
            // FileTableState synchronizes descriptors with dup(2). Closing any
            // duplicate releases process-associated POSIX locks, whereas OFD
            // locks correctly remain attached to the shared open description.
            let host_command = match command {
                libc::F_SETLK => {
                    lock.l_pid = 0;
                    libc::F_OFD_SETLK
                }
                libc::F_SETLKW => {
                    lock.l_pid = 0;
                    libc::F_OFD_SETLKW
                }
                command => command,
            };
            // SAFETY: host_fd is live and lock is a fully initialized flock value.
            zero_or_errno(unsafe { libc::fcntl(host_fd, host_command, &lock) })
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

// TODO-HUMAN-REVIEW(PR-136): Review descriptor object-identity cleanup.
fn close(state: &mut LoadedStaticElf, raw_fd: u64) -> i64 {
    let Ok(fd) = i32::try_from(raw_fd) else {
        return negative_errno(libc::EBADF);
    };
    if state.files.remove(&fd).is_some() {
        state.cloexec_fds.remove(&fd);
        state.proc_files.remove(&fd);
        state.fd_object_inodes.remove(&fd);
        cleanup_fd_object_inodes(state);
        set_output_alias(state, fd, None);
        return 0;
    }
    if is_open_standard(state, fd) {
        if fd == libc::STDIN_FILENO {
            state.stdin.take();
        }
        state.closed_standard_fds.insert(fd);
        state.cloexec_fds.remove(&fd);
        state.fd_object_inodes.remove(&fd);
        cleanup_fd_object_inodes(state);
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
// Capability-control prctls use virtual guest state so privilege-dropping
// launchers can inspect and mutate their persona without touching supervisor
// credentials.
// TODO-HUMAN-REVIEW(PR-181): Review deterministic capability prctls.
fn prctl(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    match args[0] {
        PR_CAPBSET_READ => {
            if args[1] <= GUEST_CAP_LAST_CAP {
                i64::from(state.capability_bounding & (1_u64 << args[1]) != 0)
            } else {
                negative_errno(libc::EINVAL)
            }
        }
        PR_CAPBSET_DROP => {
            if args[1] <= GUEST_CAP_LAST_CAP {
                state.capability_bounding &= !(1_u64 << args[1]);
                0
            } else {
                negative_errno(libc::EINVAL)
            }
        }
        option if option == libc::PR_SET_KEEPCAPS as u64 => match args[1] {
            0 => {
                state.keep_capabilities = false;
                0
            }
            1 => {
                state.keep_capabilities = true;
                0
            }
            _ => negative_errno(libc::EINVAL),
        },
        option if option == libc::PR_GET_KEEPCAPS as u64 => i64::from(state.keep_capabilities),
        option if option == libc::PR_CAP_AMBIENT as u64 => {
            prctl_cap_ambient(state, args[1], args[2])
        }
        // Other prctl operations are not modeled yet.
        _ => negative_errno(libc::ENOSYS),
    }
}

fn prctl_cap_ambient(state: &mut LoadedStaticElf, operation: u64, capability: u64) -> i64 {
    if operation == libc::PR_CAP_AMBIENT_CLEAR_ALL as u64 {
        state.capability_ambient = 0;
        return 0;
    }
    if capability > GUEST_CAP_LAST_CAP {
        return negative_errno(libc::EINVAL);
    }
    let bit = 1_u64 << capability;
    match operation {
        option if option == libc::PR_CAP_AMBIENT_IS_SET as u64 => {
            i64::from(state.capability_ambient & bit != 0)
        }
        option if option == libc::PR_CAP_AMBIENT_RAISE as u64 => {
            if state.capability_permitted & bit == 0 || state.capability_inheritable & bit == 0 {
                negative_errno(libc::EPERM)
            } else {
                state.capability_ambient |= bit;
                0
            }
        }
        option if option == libc::PR_CAP_AMBIENT_LOWER as u64 => {
            state.capability_ambient &= !bit;
            0
        }
        _ => negative_errno(libc::EINVAL),
    }
}

// TODO-HUMAN-REVIEW(PR-181): Review the virtual capability ABI and masks.
fn capget(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[0] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok((version, pid)) = read_capability_header(memory, args[0]) else {
        return negative_errno(libc::EFAULT);
    };
    if version != LINUX_CAPABILITY_VERSION_3 {
        if memory
            .write(args[0], &LINUX_CAPABILITY_VERSION_3.to_ne_bytes())
            .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
        return if version == 0 && args[1] == 0 {
            0
        } else {
            negative_errno(libc::EINVAL)
        };
    }
    if !is_capability_self(pid, state) {
        return negative_errno(libc::ESRCH);
    }
    if args[1] == 0 {
        return 0;
    }
    let bytes = capability_data_bytes(
        state.capability_effective,
        state.capability_permitted,
        state.capability_inheritable,
    );
    match memory.write(args[1], &bytes) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-181): Review deterministic capability mutation.
fn capset(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[0] == 0 || args[1] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok((version, pid)) = read_capability_header(memory, args[0]) else {
        return negative_errno(libc::EFAULT);
    };
    if version != LINUX_CAPABILITY_VERSION_3 {
        return negative_errno(libc::EINVAL);
    }
    if !is_capability_self(pid, state) {
        return negative_errno(libc::ESRCH);
    }
    let Ok((effective, permitted, inheritable)) = read_capability_data(memory, args[1]) else {
        return negative_errno(libc::EFAULT);
    };
    if effective & !permitted != 0
        || permitted & !state.capability_permitted != 0
        || inheritable & !state.capability_bounding != 0
    {
        return negative_errno(libc::EPERM);
    }
    state.capability_effective = effective & GUEST_CAPABILITY_MASK;
    state.capability_permitted = permitted & GUEST_CAPABILITY_MASK;
    state.capability_inheritable = inheritable & GUEST_CAPABILITY_MASK;
    state.capability_ambient &= state.capability_permitted & state.capability_inheritable;
    0
}

fn read_capability_header(memory: &GuestMemory, address: u64) -> Result<(u32, i32), ()> {
    let mut bytes = [0; 8];
    memory.read(address, &mut bytes).map_err(|_| ())?;
    Ok((
        u32::from_ne_bytes(bytes[..4].try_into().expect("capability version size")),
        i32::from_ne_bytes(bytes[4..].try_into().expect("capability pid size")),
    ))
}

fn is_capability_self(pid: i32, state: &LoadedStaticElf) -> bool {
    pid == 0 || pid == state.pid || pid == state.tid
}

fn capability_data_bytes(effective: u64, permitted: u64, inheritable: u64) -> [u8; 24] {
    let mut bytes = [0; 24];
    for (index, value) in [
        effective as u32,
        permitted as u32,
        inheritable as u32,
        (effective >> 32) as u32,
        (permitted >> 32) as u32,
        (inheritable >> 32) as u32,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}

fn read_capability_data(memory: &GuestMemory, address: u64) -> Result<(u64, u64, u64), ()> {
    let mut bytes = [0; 24];
    memory.read(address, &mut bytes).map_err(|_| ())?;
    let field = |index: usize| {
        u64::from(u32::from_ne_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("capability data field size"),
        ))
    };
    Ok((
        field(0) | field(3) << 32,
        field(1) | field(4) << 32,
        field(2) | field(5) << 32,
    ))
}

// TODO-HUMAN-REVIEW(PR-116): Review the no-xattr KVM guest model and errors.
//
// The deterministic container models no extended attributes, but Linux still
// validates the target and attribute name before reporting the modeled result.
// Preserve those observable path/fd/memory errors without exposing host xattr
// contents.
fn validate_xattr_target_and_name(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> Result<(), i64> {
    if number == libc::SYS_fgetxattr as u64
        || number == libc::SYS_fsetxattr as u64
        || number == libc::SYS_fremovexattr as u64
    {
        let Ok(guest_fd) = libc::c_int::try_from(args[0]) else {
            return Err(negative_errno(libc::EBADF));
        };
        if host_fd(state, guest_fd).is_none() {
            return Err(negative_errno(libc::EBADF));
        }
    } else {
        let path = match read_c_string(memory, args[0], 4096) {
            Ok(path) => path,
            Err(error) => return Err(read_c_string_errno(error)),
        };
        if path.is_empty() {
            return Err(negative_errno(libc::ENOENT));
        }
        if synthetic_proc_content(state, &path).is_none() {
            let nofollow = number == libc::SYS_lgetxattr as u64
                || number == libc::SYS_lsetxattr as u64
                || number == libc::SYS_lremovexattr as u64;
            open_metadata_path(state, libc::AT_FDCWD, &path, nofollow)?;
        }
    }

    match read_c_string(memory, args[1], 256) {
        Ok(name) if name.is_empty() => Err(negative_errno(libc::ERANGE)),
        Ok(name) => {
            let empty_namespace =
                [b"user.".as_slice(), b"trusted.", b"security."].contains(&name.as_slice());
            if empty_namespace {
                return Err(negative_errno(libc::EINVAL));
            }
            let supported_namespace = [b"user.".as_slice(), b"trusted.", b"security."]
                .iter()
                .any(|prefix| name.starts_with(prefix));
            let supported_system_name = matches!(
                name.as_slice(),
                b"system.posix_acl_access" | b"system.posix_acl_default"
            );
            if supported_namespace || supported_system_name {
                Ok(())
            } else {
                Err(negative_errno(libc::EOPNOTSUPP))
            }
        }
        Err(ReadCStringError::Fault) => Err(negative_errno(libc::EFAULT)),
        Err(ReadCStringError::NameTooLong) => Err(negative_errno(libc::ERANGE)),
    }
}

fn getxattr(memory: &GuestMemory, state: &LoadedStaticElf, number: u64, args: &[u64; 6]) -> i64 {
    match validate_xattr_target_and_name(memory, state, number, args) {
        Ok(()) => negative_errno(libc::ENODATA),
        Err(error) => error,
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review no-xattr mutation validation and refusal.
fn setxattr(memory: &GuestMemory, state: &LoadedStaticElf, number: u64, args: &[u64; 6]) -> i64 {
    if let Err(error) = validate_xattr_target_and_name(memory, state, number, args) {
        return error;
    }
    let flags = args[4] as libc::c_int;
    let allowed_flags = libc::XATTR_CREATE | libc::XATTR_REPLACE;
    if flags & !allowed_flags != 0 || flags == allowed_flags {
        return negative_errno(libc::EINVAL);
    }
    let Ok(value_length) = usize::try_from(args[3]) else {
        return negative_errno(libc::E2BIG);
    };
    const XATTR_SIZE_MAX: usize = 65_536;
    if value_length > XATTR_SIZE_MAX {
        return negative_errno(libc::E2BIG);
    }
    if value_length != 0 {
        let mut value = vec![0; value_length];
        if memory.read(args[2], &mut value).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    negative_errno(libc::EOPNOTSUPP)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review no-xattr removal validation and result.
fn removexattr(memory: &GuestMemory, state: &LoadedStaticElf, number: u64, args: &[u64; 6]) -> i64 {
    match validate_xattr_target_and_name(memory, state, number, args) {
        Ok(()) => negative_errno(libc::ENODATA),
        Err(error) => error,
    }
}

fn brk(memory: &mut GuestMemory, state: &mut LoadedStaticElf, requested: u64) -> i64 {
    if requested == 0 {
        return state.program_break as i64;
    }
    if requested < BOOT_RESERVED_END || requested >= state.brk_limit {
        return state.program_break as i64;
    }
    let previous = state.program_break;
    if requested > previous {
        let Ok(length) = usize::try_from(requested - previous) else {
            return state.program_break as i64;
        };
        if memory.zero_raw(previous, length).is_err()
            || memory
                .map_user_range(previous, requested - previous, false)
                .is_err()
        {
            return state.program_break as i64;
        }
    } else if requested < previous {
        let Some(unmap_start) = align_up(requested, PAGE_SIZE) else {
            return state.program_break as i64;
        };
        let Some(unmap_end) = align_up(previous, PAGE_SIZE) else {
            return state.program_break as i64;
        };
        if unmap_end > unmap_start
            && memory
                .unmap_user_range(unmap_start, unmap_end - unmap_start)
                .is_err()
        {
            return state.program_break as i64;
        }
    }
    state.program_break = requested;
    requested as i64
}

fn find_mmap_address(memory: &GuestMemory, state: &LoadedStaticElf, length: u64) -> Option<u64> {
    let next = state.mmap_next.clamp(state.mmap_base, state.mmap_limit);
    memory
        .find_unmapped_user_range(next, state.mmap_limit, length)
        .or_else(|| memory.find_unmapped_user_range(state.mmap_base, next, length))
}

fn mmap(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[1] == 0 {
        return negative_errno(libc::EINVAL);
    }
    let flags = args[3];
    let is_anonymous = flags & libc::MAP_ANONYMOUS as u64 != 0;
    let is_private = flags & libc::MAP_PRIVATE as u64 != 0;
    let is_shared = flags & libc::MAP_SHARED as u64 != 0;
    let allowed_protection = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    if args[2] & !allowed_protection != 0 {
        return negative_errno(libc::EINVAL);
    }
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
    let address = if fixed {
        args[0]
    } else {
        let Some(address) = find_mmap_address(memory, state, length) else {
            return negative_errno(libc::ENOMEM);
        };
        address
    };
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

    if memory.zero_raw(address, length).is_err() {
        return negative_errno(libc::ENOMEM);
    }
    if let Some(bytes) = file_bytes
        && memory.write_raw(address, &bytes).is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    if memory
        .map_user_range(address, length as u64, args[2] == libc::PROT_NONE as u64)
        .is_err()
    {
        return negative_errno(libc::ENOMEM);
    }

    if !fixed {
        state.mmap_next = state.mmap_next.max(end);
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
    match memory.zero_raw(address, length) {
        Ok(()) => match memory.unmap_user_range(address, length as u64) {
            Ok(()) => 0,
            Err(_) => negative_errno(libc::EINVAL),
        },
        Err(_) => negative_errno(libc::EINVAL),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review in-memory mapping synchronization semantics.
fn msync(memory: &GuestMemory, args: &[u64; 6]) -> i64 {
    let address = args[0];
    let requested_length = args[1];
    let flags = args[2] as libc::c_int;
    let allowed_flags = libc::MS_ASYNC | libc::MS_SYNC | libc::MS_INVALIDATE;
    if !address.is_multiple_of(PAGE_SIZE)
        || flags & !allowed_flags != 0
        || flags & libc::MS_ASYNC != 0 && flags & libc::MS_SYNC != 0
    {
        return negative_errno(libc::EINVAL);
    }
    if requested_length == 0 {
        return 0;
    }
    let Some(length) = align_up(requested_length, PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    if !range_is_valid(memory, address, length) || !memory.user_range_is_mapped(address, length) {
        return negative_errno(libc::ENOMEM);
    }

    // File-backed mappings are deterministic snapshots copied into guest
    // memory by mmap. There is no host page cache to flush, so a valid msync
    // completes once the mapped-range contract above has been checked.
    0
}

// TODO-HUMAN-REVIEW(PR-132): Review KVM mprotect user-copy enforcement.
fn mprotect(memory: &GuestMemory, args: &[u64; 6]) -> i64 {
    let address = args[0];
    let requested_length = args[1];
    let protection = args[2];
    let allowed_protection = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    if !address.is_multiple_of(PAGE_SIZE) || protection & !allowed_protection != 0 {
        return negative_errno(libc::EINVAL);
    }
    if requested_length == 0 {
        return 0;
    }
    let Some(length) = align_up(requested_length, PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    if !range_is_valid(memory, address, length) || !memory.user_range_is_mapped(address, length) {
        return negative_errno(libc::ENOMEM);
    }
    match memory.map_user_range(address, length, protection == libc::PROT_NONE as u64) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::ENOMEM),
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
        || !memory.user_range_is_mapped(old_address, old_length)
    {
        return negative_errno(libc::EINVAL);
    }

    if flags & libc::MREMAP_FIXED as u64 == 0 && new_length <= old_length {
        if new_length < old_length {
            let tail = old_address + new_length;
            let Ok(length) = usize::try_from(old_length - new_length) else {
                return negative_errno(libc::ENOMEM);
            };
            if memory.zero_raw(tail, length).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
        if memory
            .remap_user_range(old_address, old_length, old_address, new_length)
            .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
        return old_address as i64;
    }

    let old_end = old_address + old_length;
    if flags & libc::MREMAP_FIXED as u64 == 0 {
        let Some(new_end) = old_address.checked_add(new_length) else {
            return negative_errno(libc::ENOMEM);
        };
        let extension_length = new_length - old_length;
        if new_end <= state.mmap_limit
            && memory.find_unmapped_user_range(old_end, new_end, extension_length) == Some(old_end)
        {
            let Ok(extension) = usize::try_from(new_length - old_length) else {
                return negative_errno(libc::ENOMEM);
            };
            if memory.zero_raw(old_end, extension).is_err() {
                return negative_errno(libc::ENOMEM);
            }
            if memory
                .remap_user_range(old_address, old_length, old_address, new_length)
                .is_err()
            {
                return negative_errno(libc::ENOMEM);
            }
            state.mmap_next = state.mmap_next.max(new_end);
            return old_address as i64;
        }
    }

    if flags & libc::MREMAP_MAYMOVE as u64 == 0 {
        return negative_errno(libc::ENOMEM);
    }
    let destination = if flags & libc::MREMAP_FIXED as u64 != 0 {
        args[4]
    } else {
        let Some(destination) = find_mmap_address(memory, state, new_length) else {
            return negative_errno(libc::ENOMEM);
        };
        destination
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
    if memory.read_raw(old_address, &mut bytes).is_err()
        || memory.zero_raw(destination, new_length_usize).is_err()
        || memory.write_raw(destination, &bytes).is_err()
        || memory.zero_raw(old_address, old_length_usize).is_err()
        || memory
            .remap_user_range(old_address, old_length, destination, new_length)
            .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    if flags & libc::MREMAP_FIXED as u64 == 0 {
        state.mmap_next = state.mmap_next.max(destination_end);
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

// TODO-HUMAN-REVIEW(PR-145): Review flat guest-memory munlock validation semantics.
fn munlock_guest_range(memory: &GuestMemory, address: u64, length: u64) -> i64 {
    let page_start = address & !(PAGE_SIZE - 1);
    let page_offset = address - page_start;
    let page_length =
        length.wrapping_add(page_offset).wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_end = page_start.wrapping_add(page_length);
    if page_end < page_start {
        return negative_errno(libc::EINVAL);
    }
    if page_length != 0 && !range_is_valid(memory, page_start, page_length) {
        return negative_errno(libc::ENOMEM);
    }
    0
}

fn mincore(memory: &mut GuestMemory, args: &[u64; 6]) -> i64 {
    let address = args[0];
    let length = args[1];
    if length == 0 || !address.is_multiple_of(PAGE_SIZE) || !range_is_valid(memory, address, length)
    {
        return negative_errno(libc::EINVAL);
    }
    if !memory.user_range_is_mapped(address, length) {
        return negative_errno(libc::ENOMEM);
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

// TODO-HUMAN-REVIEW(PR-180): Review virtual-TID random stream separation.
fn getrandom(memory: &mut GuestMemory, tid: i32, address: u64, length: u64) -> i64 {
    let Ok(length) = usize::try_from(length) else {
        return negative_errno(libc::EINVAL);
    };
    if length > MAX_HOST_IO {
        return negative_errno(libc::E2BIG);
    }
    let bytes = deterministic_random_bytes(tid, length, 17, 0x5a);
    match memory.write(address, &bytes) {
        Ok(()) => length as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

fn deterministic_random_bytes(tid: i32, length: usize, byte_stride: u8, first_byte: u8) -> Vec<u8> {
    // Keep TID 1 byte-for-byte compatible; the odd multiplier gives every
    // other 32-bit virtual TID a distinct eight-byte salt.
    let thread_stream = u64::from(tid as u32)
        .wrapping_sub(1)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (0..length)
        .map(|index| {
            let thread_byte = thread_stream.rotate_right(((index % 8) * 8) as u32) as u8;
            (index as u8)
                .wrapping_mul(byte_stride)
                .wrapping_add(first_byte)
                ^ thread_byte
        })
        .collect()
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-228): Review cross-backend random-device stream parity.
fn deterministic_random_device_bytes(seed: u64, length: usize) -> Vec<u8> {
    const BYTE_STRIDE: u8 = 73;
    const FIRST_BYTE: u8 = 41;

    (0..length)
        .map(|index| {
            let index = index as u64;
            let seed_byte = seed.rotate_right(((index % 8) * 8) as u32) as u8;
            (index as u8)
                .wrapping_mul(BYTE_STRIDE)
                .wrapping_add(FIRST_BYTE)
                ^ seed_byte
        })
        .collect()
}

// Child processes and guest workers bypass Detcore's virtual scheduler. Validate
// their sleep requests, but do not block the supervisor on host wall time;
// subscribed root-process sleeps continue to use Detcore's time model.
// TODO-HUMAN-REVIEW(PR-182): Review nonblocking KVM child sleeps.
fn nanosleep(memory: &GuestMemory, args: &[u64; 6]) -> i64 {
    validate_sleep_request(memory, args[0])
}

fn clock_nanosleep(memory: &GuestMemory, args: &[u64; 6]) -> i64 {
    let clock_id = args[0] as libc::clockid_t;
    if clock_id == libc::CLOCK_THREAD_CPUTIME_ID {
        return negative_errno(libc::EOPNOTSUPP);
    }
    if !matches!(
        clock_id,
        libc::CLOCK_REALTIME
            | libc::CLOCK_MONOTONIC
            | libc::CLOCK_PROCESS_CPUTIME_ID
            | libc::CLOCK_BOOTTIME
            | libc::CLOCK_TAI
    ) {
        return negative_errno(libc::EINVAL);
    }
    validate_sleep_request(memory, args[2])
}

fn validate_sleep_request(memory: &GuestMemory, address: u64) -> i64 {
    if address == 0 {
        return negative_errno(libc::EFAULT);
    }
    let request = match read_guest_struct::<libc::timespec>(memory, address) {
        Ok(request) => request,
        Err(error) => return error,
    };
    if request.tv_sec < 0 || !(0..1_000_000_000).contains(&request.tv_nsec) {
        negative_errno(libc::EINVAL)
    } else {
        0
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

// TODO-HUMAN-REVIEW(PR-136): Review shared readlink guest path handling.
fn readlink(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    readlink_at_impl(memory, state, libc::AT_FDCWD, args[0], args[1], args[2])
}

// TODO-HUMAN-REVIEW(PR-136): Review readlinkat guest-dirfd and procfd semantics.
fn readlinkat(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    readlink_at_impl(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2],
        args[3],
    )
}

// TODO-HUMAN-REVIEW(PR-136): Review shared readlinkat implementation semantics.
fn readlink_at_impl(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    output_address: u64,
    raw_capacity: u64,
) -> i64 {
    let path = match read_c_string(memory, path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    let Ok(requested_capacity) = usize::try_from(raw_capacity) else {
        return negative_errno(libc::EINVAL);
    };
    if requested_capacity == 0 {
        return negative_errno(libc::EINVAL);
    }
    let capacity = requested_capacity.min(MAX_HOST_IO);

    if let Some(guest_fd) = guest_fd_path(state, &path) {
        let target = match guest_fd_link_target(state, guest_fd) {
            Ok(target) => target,
            Err(error) => return error,
        };
        let count = capacity.min(target.len());
        return match memory.write(output_address, &target[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }

    let normalized = normalize_proc_path(state, &path);
    let proc_link_target: Option<&[u8]> = match normalized.as_deref() {
        Some(b"/proc/self/exe") => Some(&state.argv0),
        Some(b"/proc/self/cwd") => Some(state.cwd.as_os_str().as_bytes()),
        Some(b"/proc/self/root") => Some(b"/"),
        _ => None,
    };
    if let Some(target) = proc_link_target {
        let count = capacity.min(target.len());
        return match memory.write(output_address, &target[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }
    // /proc/self (and /proc/<pid>) is a symlink to the numeric pid directory.
    if path == b"/proc/self" || path == format!("/proc/{}", state.pid).as_bytes() {
        let target = state.pid.to_string().into_bytes();
        let count = capacity.min(target.len());
        return match memory.write(output_address, &target[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }

    let opened_file;
    let link_fd = if path.is_empty() {
        if guest_dirfd == libc::AT_FDCWD {
            return negative_errno(libc::ENOENT);
        }
        let Some(host_fd) = host_fd(state, guest_dirfd) else {
            return negative_errno(libc::EBADF);
        };
        host_fd
    } else {
        opened_file = match open_metadata_path(state, guest_dirfd, &path, true) {
            Ok(file) => file,
            Err(error) => return error,
        };
        opened_file.as_raw_fd()
    };
    match fd_mode(link_fd) {
        Ok(mode) if mode & libc::S_IFMT == libc::S_IFLNK => {}
        Ok(_) if path.is_empty() => return negative_errno(libc::ENOENT),
        Ok(_) => return negative_errno(libc::EINVAL),
        Err(error) => return error,
    }
    let empty_path = b"\0";
    let mut bytes = vec![0; capacity];
    // SAFETY: empty_path is NUL-terminated, link_fd is an O_PATH descriptor for
    // the symlink itself, and bytes is writable for capacity bytes.
    let count = unsafe {
        libc::readlinkat(
            link_fd,
            empty_path.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let count = count as usize;
    match memory.write(output_address, &bytes[..count]) {
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

#[repr(C)]
struct GuestWaitidSiginfo {
    si_signo: libc::c_int,
    si_errno: libc::c_int,
    si_code: libc::c_int,
    _union_alignment: libc::c_int,
    si_pid: libc::pid_t,
    si_uid: libc::uid_t,
    si_status: libc::c_int,
    _clock_alignment: libc::c_int,
    si_utime: libc::c_long,
    si_stime: libc::c_long,
    _padding: [u8; std::mem::size_of::<libc::siginfo_t>() - 48],
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review serialized-child waitid ABI emulation.
fn waitid(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    const EVENT_OPTIONS: u64 = libc::WEXITED as u64;
    const ALLOWED_OPTIONS: u64 = EVENT_OPTIONS | libc::WNOHANG as u64 | libc::WNOWAIT as u64;

    if args[2] == 0 {
        return negative_errno(libc::EFAULT);
    }
    if args[3] & EVENT_OPTIONS == 0 || args[3] & !ALLOWED_OPTIONS != 0 {
        return negative_errno(libc::EINVAL);
    }

    let child_pid = match args[0] as libc::idtype_t {
        libc::P_PID => libc::pid_t::try_from(args[1])
            .ok()
            .filter(|pid| state.children.contains_key(pid)),
        libc::P_ALL | libc::P_PGID => state.children.keys().next().copied(),
        _ => return negative_errno(libc::EINVAL),
    };
    let Some(child_pid) = child_pid else {
        return negative_errno(libc::ECHILD);
    };
    let status = state.children[&child_pid] & 0xff;
    let info = GuestWaitidSiginfo {
        si_signo: libc::SIGCHLD,
        si_errno: 0,
        si_code: libc::CLD_EXITED,
        _union_alignment: 0,
        si_pid: child_pid,
        si_uid: 0,
        si_status: status,
        _clock_alignment: 0,
        si_utime: 0,
        si_stime: 0,
        _padding: [0; std::mem::size_of::<libc::siginfo_t>() - 48],
    };
    let result = write_struct(memory, args[2], &info);
    if result != 0 {
        return result;
    }
    if args[4] != 0 {
        let result = memory
            .zero(args[4], std::mem::size_of::<libc::rusage>())
            .map(|()| 0)
            .unwrap_or_else(|_| negative_errno(libc::EFAULT));
        if result != 0 {
            return result;
        }
    }
    if args[3] & libc::WNOWAIT as u64 == 0 {
        state.children.remove(&child_pid);
    }
    0
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

// TODO-HUMAN-REVIEW(PR-132): Review the accepted glibc pthread clone flag profile.
fn validate_thread_clone_flags(flags: u64) -> Result<(), i64> {
    if flags & 0xff != 0 {
        return Err(negative_errno(libc::EINVAL));
    }
    if flags & THREAD_CLONE_REQUIRED_FLAGS != THREAD_CLONE_REQUIRED_FLAGS {
        return Err(negative_errno(libc::EINVAL));
    }
    if flags & !THREAD_CLONE_ALLOWED_FLAGS != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    Ok(())
}

struct CloneRequest {
    flags: u64,
    child_stack: Option<u64>,
    parent_tid: Option<u64>,
    child_tid: Option<u64>,
    tls: Option<u64>,
}

fn read_clone3(memory: &GuestMemory, address: u64, size: u64) -> Result<CloneRequest, i64> {
    const REQUIRED_SIZE: usize = 64;
    const MAX_SIZE: usize = 88;

    let Ok(size) = usize::try_from(size) else {
        return Err(negative_errno(libc::E2BIG));
    };
    if size < REQUIRED_SIZE {
        return Err(negative_errno(libc::EINVAL));
    }
    if size > PAGE_SIZE as usize {
        return Err(negative_errno(libc::E2BIG));
    }
    let mut bytes = [0; MAX_SIZE];
    memory
        .read(address, &mut bytes[..size.min(MAX_SIZE)])
        .map_err(|_| negative_errno(libc::EFAULT))?;
    if size > MAX_SIZE {
        let mut extension = vec![0; size - MAX_SIZE];
        memory
            .read(address + MAX_SIZE as u64, &mut extension)
            .map_err(|_| negative_errno(libc::EFAULT))?;
        if extension.iter().any(|byte| *byte != 0) {
            return Err(negative_errno(libc::E2BIG));
        }
    }
    let field = |offset: usize| {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("u64 clone3 field"),
        )
    };
    // clone3 ignores pidfd unless CLONE_PIDFD is set. glibc leaves that union
    // slot nonzero for pthread clones even though the flag is absent.
    if field(64) != 0 || field(72) != 0 || field(80) != 0 {
        return Err(negative_errno(libc::ENOTSUP));
    }
    let flags = field(0) | field(32);
    let stack = field(40);
    let stack_size = field(48);
    if (stack == 0) != (stack_size == 0) {
        return Err(negative_errno(libc::EINVAL));
    }
    let child_stack = if stack == 0 {
        None
    } else {
        stack.checked_add(stack_size)
    };
    if stack != 0 && child_stack.is_none() {
        return Err(negative_errno(libc::EINVAL));
    }
    Ok(CloneRequest {
        flags,
        child_stack,
        parent_tid: (field(24) != 0).then(|| field(24)),
        child_tid: (field(16) != 0).then(|| field(16)),
        tls: (flags & libc::CLONE_SETTLS as u64 != 0).then(|| field(56)),
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

    use reverie::syscalls::AddrMut;
    use reverie::syscalls::MemoryAccess;

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
            mmap_base: BOOT_RESERVED_END + PAGE_SIZE,
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
            tid: 1,
            ppid: 0,
            umask: 0o022,
            random_seed: 0,
            keep_capabilities: false,
            capability_effective: GUEST_CAPABILITY_MASK,
            capability_permitted: GUEST_CAPABILITY_MASK,
            capability_inheritable: 0,
            capability_bounding: GUEST_CAPABILITY_MASK,
            capability_ambient: 0,
            nice: 0,
            sched_policy: libc::SCHED_OTHER,
            sched_priority: 0,
            sched_reset_on_fork: false,
            ioprio: 0,
            signal_actions: BTreeMap::new(),
            signal_mask: [0; KERNEL_SIGSET_SIZE],
            signal_alt_stack: None,
            robust_list_head: 0,
            robust_list_len: 0,
            files: BTreeMap::new(),
            stdout_alias_fds: BTreeSet::new(),
            stderr_alias_fds: BTreeSet::new(),
            cloexec_fds: BTreeSet::new(),
            closed_standard_fds: BTreeSet::new(),
            children: BTreeMap::new(),
            proc_files: BTreeMap::new(),
            fd_object_inodes: BTreeMap::new(),
            file_identity_table: Arc::new(std::sync::Mutex::new(
                crate::elf::GuestFileIdentityTable {
                    next_inode: 0x2100_0000,
                    objects: BTreeMap::new(),
                },
            )),
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
        assert!(
            content
                .windows(b"MemTotal:         976562 kB\n".len())
                .any(|line| { line == b"MemTotal:         976562 kB\n" })
        );
        assert!(
            content
                .windows(b"MemFree:          976562 kB\n".len())
                .any(|line| { line == b"MemFree:          976562 kB\n" })
        );
        assert!(
            content
                .windows(b"MemAvailable:     976562 kB\n".len())
                .any(|line| line == b"MemAvailable:     976562 kB\n")
        );
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-225): regression for the /proc/self/mountinfo
    // synthetic surface (content bytes, read path, and inode round-trip) added
    // for df compatibility under --backend kvm.
    #[test]
    fn synthetic_proc_self_mountinfo_is_served_and_stable() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();

        const EXPECTED: &[u8] = b"1 0 0:1 / / rw - rootfs rootfs rw\n";

        // The direct content accessor returns the deterministic entry.
        assert_eq!(
            synthetic_proc_content(&state, b"/proc/self/mountinfo").as_deref(),
            Some(EXPECTED)
        );

        // A guest read through openat yields the same bytes.
        let fd = open_readonly(&mut memory, &mut state, "/proc/self/mountinfo");
        assert!(fd >= 0, "open /proc/self/mountinfo failed: {fd}");
        assert_eq!(read_fd_to_end(&mut memory, &mut state, fd), EXPECTED);

        // fstat/newfstatat resolve to the same stable synthetic inode so that
        // gnulib's fstat-then-read of the mount table stays deterministic.
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
        assert_eq!(stat.st_ino, synthetic_proc_inode(b"/proc/self/mountinfo"));
        assert_eq!(
            synthetic_proc_path_for_inode(stat.st_ino),
            Some(b"/proc/self/mountinfo".as_slice())
        );
        assert_eq!(stat.st_size, EXPECTED.len() as libc::off_t);
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-225): regression for statfs canonicalization,
    // matching detcore's canonicalize_statfs_buf so KVM statfs/fstatfs is
    // bitwise-deterministic across runs (df, tar, stat -f).
    #[test]
    fn canonicalize_statfs_zeroes_host_varying_fields() {
        // A statfs whose free counts and fsid vary from run to run.
        let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
        sf.f_blocks = 10_000_000;
        sf.f_bfree = 7_123_456;
        sf.f_bavail = 6_987_654;
        sf.f_files = 2_000_000;
        sf.f_ffree = 1_234_567;
        sf.f_fsid = unsafe { std::mem::transmute::<[i32; 2], libc::fsid_t>([0x1234, 0x5678]) };

        canonicalize_statfs(&mut sf);

        // Free blocks are capped at 1_000_000 and clamped to the total.
        assert_eq!(sf.f_bfree, 1_000_000);
        assert_eq!(sf.f_bavail, 1_000_000);
        // Free inodes are capped at 500_000 and clamped to the total.
        assert_eq!(sf.f_ffree, 500_000);
        // The filesystem identity is zeroed so it cannot leak host state.
        assert_eq!(
            unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(sf.f_fsid) },
            [0, 0]
        );
        // Totals are untouched.
        assert_eq!(sf.f_blocks, 10_000_000);
        assert_eq!(sf.f_files, 2_000_000);

        // Small totals clamp free values down to the total, and a zero inode
        // total yields zero free inodes (never the cap).
        let mut small: libc::statfs = unsafe { std::mem::zeroed() };
        small.f_blocks = 42;
        small.f_files = 0;
        canonicalize_statfs(&mut small);
        assert_eq!(small.f_bfree, 42);
        assert_eq!(small.f_bavail, 42);
        assert_eq!(small.f_ffree, 0);
    }

    #[test]
    fn synthetic_proc_directory_resolves_relative_allowlisted_files() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();

        write_c_string(&mut memory, 0x100, "/proc");
        let proc_fd = syscall_result(
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
        assert!(proc_fd >= 0, "open /proc failed: {proc_fd}");

        let stat_address = 0x1000;
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fstat,
                [proc_fd as u64, stat_address, 0, 0, 0, 0]
            ),
            0
        );
        let stat: libc::stat = read_struct(&memory, stat_address);
        assert_eq!(stat.st_mode, libc::S_IFDIR | 0o555);

        write_c_string(&mut memory, 0x100, "cpuinfo");
        let cpuinfo_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_openat,
            [proc_fd as u64, 0x100, libc::O_RDONLY as u64, 0, 0, 0],
        );
        assert!(cpuinfo_fd >= 0, "openat cpuinfo failed: {cpuinfo_fd}");
        let content = read_fd_to_end(&mut memory, &mut state, cpuinfo_fd);
        assert!(
            content.starts_with(b"processor\t: 0\n"),
            "{}",
            String::from_utf8_lossy(&content)
        );

        for path in ["self/maps", "../etc/passwd"] {
            write_c_string(&mut memory, 0x100, path);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_openat,
                    [proc_fd as u64, 0x100, libc::O_RDONLY as u64, 0, 0, 0],
                ),
                negative_errno(libc::ENOENT),
                "unlisted relative proc path leaked through: {path}"
            );
        }

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [proc_fd as u64, 0x2000, 0x400, 0, 0, 0]
            ),
            0,
            "the intentionally unenumerable synthetic directory must appear empty"
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
    fn captured_output_fstat_is_synthetic_and_stable() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        let mut output = CapturedOutput::default();
        let mut stats = Vec::new();

        for (fd, address) in [(libc::STDOUT_FILENO, 0x1000), (libc::STDERR_FILENO, 0x1200)] {
            let action = execute_basic_syscall_with_output(
                &mut memory,
                &mut state,
                &SyscallRequest::new(libc::SYS_fstat as u64, [fd as u64, address, 0, 0, 0, 0]),
                Some(&mut output),
            );
            assert!(matches!(
                action,
                SyscallAction::Continue {
                    result: 0,
                    segment: None
                }
            ));
            let stat: libc::stat = read_struct(&memory, address);
            assert_eq!(stat.st_dev, synthetic_dev(SYNTHETIC_GUEST_FD_DEV_MINOR));
            assert_eq!(stat.st_ino, synthetic_guest_fd_object_inode(&state, fd));
            assert_eq!(stat.st_mode, libc::S_IFIFO | 0o600);
            assert_eq!(stat.st_size, 0);
            assert_eq!(stat.st_blocks, 0);
            assert_eq!(stat.st_mtime, DETERMINISTIC_METADATA_SECONDS);
            stats.push(stat);
        }

        assert_ne!(stats[0].st_ino, stats[1].st_ino);
    }

    #[test]
    fn cpu_frequency_surface_is_fixed_for_absolute_and_relative_paths() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);

        for (path, expected) in [
            (
                b"/sys/devices/system/cpu/cpu7/cpufreq/cpuinfo_max_freq".as_slice(),
                b"3000000\n".as_slice(),
            ),
            (
                b"/sys/devices/system/cpu/cpu7/cpufreq/cpuinfo_min_freq".as_slice(),
                b"1000000\n".as_slice(),
            ),
            (
                b"/sys/devices/system/cpu/cpu7/cpufreq/scaling_cur_freq".as_slice(),
                b"2000000\n".as_slice(),
            ),
            (
                b"/sys/devices/system/cpu/cpufreq/boost".as_slice(),
                b"1\n".as_slice(),
            ),
        ] {
            assert_eq!(
                synthetic_cpu_frequency_content(&state, libc::AT_FDCWD, path),
                Some(expected)
            );
        }

        let cpu_root = std::fs::File::open("/sys/devices/system/cpu").unwrap();
        state.files.insert(3, cpu_root);
        assert_eq!(
            synthetic_cpu_frequency_content(&state, 3, b"cpu19/cpufreq/scaling_cur_freq"),
            Some(b"2000000\n".as_slice())
        );
        assert_eq!(
            synthetic_cpu_frequency_content(&state, 3, b"cpuX/cpufreq/scaling_cur_freq"),
            None
        );
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

        let fd = open_readonly(&mut memory, &mut state, "/proc/uptime");
        assert!(fd >= 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [fd as u64, 0x200, 1, 0, 0, 0]
            ),
            negative_errno(libc::ENOSYS)
        );
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-224): regression coverage for the /proc/vmstat
    // and /proc/sys/kernel/osrelease synthetic surfaces.
    #[test]
    fn synthetic_proc_vmstat_and_osrelease_are_served_deterministically() {
        let root = TestDir::new();
        let state = test_state(&root.0);

        // /proc/vmstat is served with fixed, zeroed counters and round-trips
        // through the deterministic-inode path table.
        let vmstat = synthetic_proc_content(&state, b"/proc/vmstat").unwrap();
        assert!(vmstat.starts_with(b"nr_free_pages "));
        assert!(
            vmstat
                .windows(b"pgpgin 0\n".len())
                .any(|w| w == b"pgpgin 0\n")
        );
        assert_eq!(
            synthetic_proc_content(&state, b"/proc/vmstat").unwrap(),
            vmstat,
            "vmstat content must be stable across reads"
        );
        assert_eq!(
            synthetic_proc_path_for_inode(synthetic_proc_inode(b"/proc/vmstat")),
            Some(b"/proc/vmstat".as_slice())
        );

        // /proc/sys/kernel/osrelease matches the KVM uname(2) release field.
        assert_eq!(
            synthetic_proc_content(&state, b"/proc/sys/kernel/osrelease").unwrap(),
            b"6.0.0\n"
        );
        assert_eq!(
            synthetic_proc_path_for_inode(synthetic_proc_inode(b"/proc/sys/kernel/osrelease")),
            Some(b"/proc/sys/kernel/osrelease".as_slice())
        );
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
            if path == "/dev/urandom" {
                write_c_string(&mut memory, 0x100, &format!("/proc/self/fd/{fd}"));
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_truncate,
                        [0x100, 0, 0, 0, 0, 0],
                    ),
                    negative_errno(libc::EINVAL)
                );
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_read,
                        [fd as u64, 0x200, 1, 0, 0, 0],
                    ),
                    1
                );
            }
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
    fn fcntl_advisory_locks_apply_to_host_descriptors() {
        const LOCK: u64 = 0x100;

        let root = TestDir::new();
        let path = root.0.join("locked");
        let first = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut state = test_state(&root.0);
        state.files.insert(3, first);
        state.files.insert(4, second);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            // POSIX SETLK ignores this output-only field; OFD SETLK requires
            // zero, so translation must not pass a caller's stale value.
            l_pid: 1234,
        };
        assert_eq!(write_struct(&mut memory, LOCK, &lock), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [3, libc::F_SETLK as u64, LOCK, 0, 0, 0],
            ),
            0
        );
        let locks = synthetic_proc_content(&state, b"/proc/locks").unwrap();
        assert_eq!(locks, b"1: OFDLCK ADVISORY WRITE -1 00:00:1 0 EOF\n");
        assert_eq!(
            synthetic_proc_content(&state, b"/proc/self/../locks").unwrap(),
            locks
        );
        lock.l_pid = 0;
        assert_eq!(write_struct(&mut memory, LOCK, &lock), 0);
        let conflict = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [4, libc::F_OFD_SETLK as u64, LOCK, 0, 0, 0],
        );
        assert!(
            conflict == negative_errno(libc::EAGAIN) || conflict == negative_errno(libc::EACCES),
            "unexpected conflicting lock result: {conflict}"
        );

        lock.l_type = libc::F_UNLCK as libc::c_short;
        assert_eq!(write_struct(&mut memory, LOCK, &lock), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [3, libc::F_SETLK as u64, LOCK, 0, 0, 0],
            ),
            0
        );
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
        const POLL_TIMEOUT: u64 = 0x500;

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
            write_struct(
                &mut memory,
                POLL_TIMEOUT,
                &libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ppoll,
                [POLL_FD, 1, POLL_TIMEOUT, 0, KERNEL_SIGSET_SIZE as u64, 0],
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
        assert_eq!(write_struct(&mut memory, POLL_FD, &poll_fd), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ppoll,
                [POLL_FD, 1, POLL_TIMEOUT, 0, KERNEL_SIGSET_SIZE as u64, 0],
            ),
            1
        );
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
        assert!(
            state
                .file_identity_table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .objects
                .is_empty()
        );
    }

    #[test]
    fn unix_listener_bind_and_connect_use_guest_paths() {
        const ADDRESS: u64 = 0x100;

        let root = TestDir::new();
        let socket_path = root.0.join("listener.sock");
        let path = socket_path.as_os_str().as_bytes();
        let mut address = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };
        assert!(path.len() < address.sun_path.len());
        for (destination, source) in address.sun_path.iter_mut().zip(path) {
            *destination = *source as libc::c_char;
        }
        let address_length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;

        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        assert_eq!(write_struct(&mut memory, ADDRESS, &address), 0);
        let server = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_socket,
            [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        let client = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_socket,
            [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert_eq!((server, client), (3, 4));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_bind,
                [server as u64, ADDRESS, address_length as u64, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_listen,
                [server as u64, 1, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_connect,
                [client as u64, ADDRESS, address_length as u64, 0, 0, 0],
            ),
            0
        );
        for fd in [client, server] {
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

    #[test]
    fn elf_executor_accepts_unix_listener_connection() {
        const ADDRESS: u64 = 0x100;
        const PAYLOAD: u64 = 0x300;

        let root = TestDir::new();
        let socket_path = root.0.join("accept.sock");
        let path = socket_path.as_os_str().as_bytes();
        let mut address = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };
        assert!(path.len() < address.sun_path.len());
        for (destination, source) in address.sun_path.iter_mut().zip(path) {
            *destination = *source as libc::c_char;
        }
        let address_length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;

        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        assert_eq!(write_struct(&mut memory, ADDRESS, &address), 0);
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let server = executor.execute(
            &SyscallRequest::new(
                libc::SYS_socket as u64,
                [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
            ),
            &memory,
        );
        assert_eq!(server, 3);
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_bind as u64,
                    [server as u64, ADDRESS, address_length as u64, 0, 0, 0],
                ),
                &memory,
            ),
            0
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_listen as u64, [server as u64, 1, 0, 0, 0, 0],),
                &memory,
            ),
            0
        );
        let client = executor.execute(
            &SyscallRequest::new(
                libc::SYS_socket as u64,
                [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
            ),
            &memory,
        );
        assert_eq!(client, 4);
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_connect as u64,
                    [client as u64, ADDRESS, address_length as u64, 0, 0, 0],
                ),
                &memory,
            ),
            0
        );
        let accepted = executor.execute(
            &SyscallRequest::new(
                libc::SYS_accept4 as u64,
                [server as u64, 0, 0, libc::SOCK_CLOEXEC as u64, 0, 0],
            ),
            &memory,
        );
        assert_eq!(accepted, 5);

        memory.write(PAYLOAD, b"hello").unwrap();
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_sendto as u64,
                    [client as u64, PAYLOAD, 5, libc::MSG_NOSIGNAL as u64, 0, 0,],
                ),
                &memory,
            ),
            5
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_recvfrom as u64,
                    [accepted as u64, PAYLOAD + 8, 5, 0, 0, 0],
                ),
                &memory,
            ),
            5
        );
        let mut payload = [0; 5];
        memory.read(PAYLOAD + 8, &mut payload).unwrap();
        assert_eq!(&payload, b"hello");
    }

    #[test]
    fn inet_listener_translates_guest_socket_arguments() {
        const BIND_ADDRESS: u64 = 0x100;
        const REUSE_ADDRESS: u64 = 0x200;
        const RESULT_ADDRESS: u64 = 0x300;
        const RESULT_LENGTH: u64 = 0x400;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        assert_eq!(write_struct(&mut memory, BIND_ADDRESS, &address), 0);
        assert_eq!(write_struct(&mut memory, REUSE_ADDRESS, &1_i32), 0);

        let socket_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_socket,
            [
                libc::AF_INET as u64,
                (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(socket_fd, 3);
        assert!(state.cloexec_fds.contains(&(socket_fd as libc::c_int)));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_setsockopt,
                [
                    socket_fd as u64,
                    libc::SOL_SOCKET as u64,
                    libc::SO_REUSEADDR as u64,
                    u64::MAX,
                    std::mem::size_of::<i32>() as u64,
                    0,
                ],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_setsockopt,
                [
                    socket_fd as u64,
                    libc::SOL_SOCKET as u64,
                    libc::SO_REUSEADDR as u64,
                    REUSE_ADDRESS,
                    std::mem::size_of::<i32>() as u64,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_bind,
                [
                    socket_fd as u64,
                    BIND_ADDRESS,
                    std::mem::size_of::<libc::sockaddr_in>() as u64,
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
                libc::SYS_listen,
                [socket_fd as u64, 1, 0, 0, 0, 0],
            ),
            0
        );
        let address_length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(write_struct(&mut memory, RESULT_LENGTH, &address_length), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getsockname,
                [socket_fd as u64, RESULT_ADDRESS, u64::MAX, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getsockname,
                [socket_fd as u64, RESULT_ADDRESS, RESULT_LENGTH, 0, 0, 0,],
            ),
            0
        );
        let returned_length: libc::socklen_t = read_struct(&memory, RESULT_LENGTH);
        let returned_address: libc::sockaddr_in = read_struct(&memory, RESULT_ADDRESS);
        assert_eq!(returned_length as usize, std::mem::size_of_val(&address));
        assert_eq!(
            returned_address.sin_family,
            libc::AF_INET as libc::sa_family_t
        );
        assert_ne!(returned_address.sin_port, 0);
        assert_eq!(returned_address.sin_addr.s_addr, address.sin_addr.s_addr);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [socket_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
    }

    #[test]
    fn getsockopt_so_type_supports_bounded_and_zero_length_results() {
        const RESULT: u64 = 0x100;
        const RESULT_LENGTH: u64 = 0x200;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let socket_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_socket,
            [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert_eq!(socket_fd, 3);

        assert_eq!(write_struct(&mut memory, RESULT_LENGTH, &0_u32), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getsockopt,
                [
                    socket_fd as u64,
                    libc::SOL_SOCKET as u64,
                    libc::SO_TYPE as u64,
                    0,
                    RESULT_LENGTH,
                    0,
                ],
            ),
            0
        );
        assert_eq!(read_struct::<libc::socklen_t>(&memory, RESULT_LENGTH), 0);

        let full_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        assert_eq!(write_struct(&mut memory, RESULT_LENGTH, &full_length), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getsockopt,
                [
                    socket_fd as u64,
                    libc::SOL_SOCKET as u64,
                    libc::SO_TYPE as u64,
                    RESULT,
                    RESULT_LENGTH,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            read_struct::<libc::socklen_t>(&memory, RESULT_LENGTH),
            full_length
        );
        assert_eq!(
            read_struct::<libc::c_int>(&memory, RESULT),
            libc::SOCK_STREAM
        );

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getsockopt,
                [
                    socket_fd as u64,
                    libc::SOL_SOCKET as u64,
                    libc::SO_TYPE as u64,
                    RESULT,
                    u64::MAX,
                    0,
                ],
            ),
            negative_errno(libc::EFAULT)
        );
    }

    #[test]
    fn select_socketpair_and_shutdown_cover_ready_and_half_close_paths() {
        const PAIR_FDS: u64 = 0x100;
        const PAYLOAD: u64 = 0x200;
        const READ_BUFFER: u64 = 0x300;
        const READ_SET: u64 = 0x400;
        const TIMEOUT: u64 = 0x500;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write(PAYLOAD, b"ping").unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    libc::SOCK_STREAM as u64,
                    0,
                    u64::MAX,
                    0,
                    0,
                ],
            ),
            negative_errno(libc::EFAULT)
        );
        assert!(state.files.is_empty());

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64,
                    0,
                    PAIR_FDS,
                    0,
                    0,
                ],
            ),
            0
        );
        let socket_fds: [libc::c_int; 2] = read_struct(&memory, PAIR_FDS);
        assert_eq!(socket_fds, [3, 4]);
        assert!(socket_fds.iter().all(|fd| state.cloexec_fds.contains(fd)));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [socket_fds[0] as u64, PAYLOAD, 4, 0, 0, 0],
            ),
            4
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [socket_fds[1] as u64, READ_BUFFER, 4, 0, 0, 0],
            ),
            4
        );
        let mut payload = [0; 4];
        memory.read(READ_BUFFER, &mut payload).unwrap();
        assert_eq!(&payload, b"ping");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_shutdown,
                [socket_fds[0] as u64, libc::SHUT_WR as u64, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [socket_fds[1] as u64, READ_BUFFER, 4, 0, 0, 0],
            ),
            0
        );
        for fd in socket_fds {
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

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe,
                [PAIR_FDS, 0, 0, 0, 0, 0],
            ),
            0
        );
        let pipe_fds: [libc::c_int; 2] = read_struct(&memory, PAIR_FDS);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [pipe_fds[1] as u64, PAYLOAD, 4, 0, 0, 0],
            ),
            4
        );
        let read_bit = 1_u64 << pipe_fds[0];
        memory.write(READ_SET, &read_bit.to_ne_bytes()).unwrap();
        assert_eq!(
            write_struct(
                &mut memory,
                TIMEOUT,
                &libc::timeval {
                    tv_sec: 5,
                    tv_usec: 0,
                },
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_select,
                [pipe_fds[0] as u64 + 1, READ_SET, 0, 0, TIMEOUT, 0],
            ),
            1
        );
        assert_eq!(read_struct::<u64>(&memory, READ_SET), read_bit);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [pipe_fds[0] as u64, READ_BUFFER, 4, 0, 0, 0],
            ),
            4
        );

        memory.write(READ_SET, &read_bit.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_select,
                [pipe_fds[0] as u64 + 1, READ_SET, 0, 0, TIMEOUT, 0],
            ),
            0
        );
        assert_eq!(read_struct::<u64>(&memory, READ_SET), 0);
        assert_eq!(read_struct::<libc::timeval>(&memory, TIMEOUT).tv_sec, 0);

        let invalid_fd = 9;
        let invalid_bit = 1_u64 << invalid_fd;
        memory.write(READ_SET, &invalid_bit.to_ne_bytes()).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_select,
                [invalid_fd + 1, READ_SET, 0, 0, TIMEOUT, 0],
            ),
            negative_errno(libc::EBADF)
        );
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
    }

    #[test]
    fn recvmmsg_translates_guest_headers_and_receives_multiple_datagrams() {
        const PAIR_FDS: u64 = 0x100;
        const FIRST_PAYLOAD: u64 = 0x200;
        const SECOND_PAYLOAD: u64 = 0x220;
        const MESSAGES: u64 = 0x300;
        const FIRST_IOV: u64 = 0x400;
        const SECOND_IOV: u64 = 0x420;
        const FIRST_BUFFER: u64 = 0x500;
        const SECOND_BUFFER: u64 = 0x540;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write(FIRST_PAYLOAD, b"hello").unwrap();
        memory.write(SECOND_PAYLOAD, b"world!").unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    libc::SOCK_DGRAM as u64,
                    0,
                    PAIR_FDS,
                    0,
                    0,
                ],
            ),
            0
        );
        let socket_fds: [libc::c_int; 2] = read_struct(&memory, PAIR_FDS);
        for (address, length) in [(FIRST_PAYLOAD, 5), (SECOND_PAYLOAD, 6)] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_write,
                    [socket_fds[0] as u64, address, length, 0, 0, 0],
                ),
                length as i64
            );
        }

        for (index, (iov_address, buffer_address)) in
            [(FIRST_IOV, FIRST_BUFFER), (SECOND_IOV, SECOND_BUFFER)]
                .into_iter()
                .enumerate()
        {
            let iov = libc::iovec {
                iov_base: buffer_address as usize as *mut libc::c_void,
                iov_len: 32,
            };
            assert_eq!(write_struct(&mut memory, iov_address, &iov), 0);
            let mut message = unsafe { std::mem::zeroed::<libc::mmsghdr>() };
            message.msg_hdr.msg_iov = iov_address as usize as *mut libc::iovec;
            message.msg_hdr.msg_iovlen = 1;
            assert_eq!(
                write_struct(
                    &mut memory,
                    MESSAGES + (index * std::mem::size_of::<libc::mmsghdr>()) as u64,
                    &message,
                ),
                0
            );
        }

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_recvmmsg,
                [
                    socket_fds[1] as u64,
                    MESSAGES,
                    2,
                    libc::MSG_DONTWAIT as u64,
                    0,
                    0,
                ],
            ),
            2
        );
        let first: libc::mmsghdr = read_struct(&memory, MESSAGES);
        let second: libc::mmsghdr = read_struct(
            &memory,
            MESSAGES + std::mem::size_of::<libc::mmsghdr>() as u64,
        );
        assert_eq!(first.msg_len, 5);
        assert_eq!(second.msg_len, 6);
        assert_eq!(
            read_guest_bytes::<5>(&memory, FIRST_BUFFER).unwrap(),
            *b"hello"
        );
        assert_eq!(
            read_guest_bytes::<6>(&memory, SECOND_BUFFER).unwrap(),
            *b"world!"
        );
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

        for fd in [event_fd, epoll_fd] {
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
        assert!(
            state
                .file_identity_table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .objects
                .is_empty()
        );
    }

    #[test]
    fn guest_fd_paths_reopen_mapped_descriptors() {
        const PATH: u64 = 0x100;
        const PIPE_FDS: u64 = 0x200;
        const PAYLOAD: u64 = 0x300;
        const READ_BUFFER: u64 = 0x400;
        const STATX: u64 = 0x500;
        const STATFS: u64 = 0x600;

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
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [PATH, libc::F_OK as u64, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statfs,
                [PATH, STATFS, 0, 0, 0, 0],
            ),
            0
        );
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
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_access,
                [PATH, libc::F_OK as u64, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_statfs,
                [PATH, STATFS, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(guest_fd_path(&state, b"/proc/self/fd/3"), Some(3));
        assert_eq!(guest_fd_path(&state, b"/proc/thread-self/fd/3"), Some(3));
        assert_eq!(guest_fd_path(&state, b"/proc/1/fd/3"), Some(3));
        assert_eq!(guest_fd_path(&state, b"/dev/fd/not-a-fd"), None);
    }

    #[test]
    fn guest_proc_fd_links_and_readlinkat_are_guest_owned() {
        const PATH: u64 = 0x100;
        const OUTPUT: u64 = 0x400;
        const PIPE_FDS: u64 = 0x800;
        const STAT: u64 = 0xc00;

        let root = TestDir::new();
        let payload = root.0.join("payload");
        std::fs::write(&payload, b"contents").unwrap();
        std::os::unix::fs::symlink("payload", root.0.join("link")).unwrap();
        let mut state = test_state(&root.0);
        state
            .files
            .insert(9, std::fs::File::open(&payload).unwrap());
        let mut memory = GuestMemory::new(0, 0x2000).unwrap();

        write_c_string(&mut memory, PATH, "/proc/1/fd/9");
        let expected = payload.as_os_str().as_bytes();
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readlink,
            [PATH, OUTPUT, 4096, 0, 0, 0],
        );
        assert_eq!(count, expected.len() as i64);
        let mut actual = vec![0; count as usize];
        memory.read(OUTPUT, &mut actual).unwrap();
        assert_eq!(actual, expected);

        // readlinkat returns a truncated byte count and never appends a NUL.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlinkat,
                [libc::AT_FDCWD as u64, PATH, OUTPUT, 4, 0, 0],
            ),
            4
        );
        let mut prefix = [0; 4];
        memory.read(OUTPUT, &mut prefix).unwrap();
        assert_eq!(&prefix, &expected[..4]);

        // Numeric guest-pid links normalize to the same synthetic process.
        write_c_string(&mut memory, PATH, "/proc/1/cwd");
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readlinkat,
            [libc::AT_FDCWD as u64, PATH, OUTPUT, 4096, 0, 0],
        );
        let expected_cwd = root.0.as_os_str().as_bytes();
        assert_eq!(count, expected_cwd.len() as i64);
        let mut actual = vec![0; count as usize];
        memory.read(OUTPUT, &mut actual).unwrap();
        assert_eq!(actual, expected_cwd);

        // Relative readlinkat resolves against the guest cwd descriptor.
        write_c_string(&mut memory, PATH, "link");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlinkat,
                [libc::AT_FDCWD as u64, PATH, OUTPUT, 4096, 0, 0],
            ),
            7
        );
        let mut relative_target = [0; 7];
        memory.read(OUTPUT, &mut relative_target).unwrap();
        assert_eq!(&relative_target, b"payload");

        // Linux permits an empty readlinkat path when dirfd is an O_PATH
        // descriptor for the symlink itself.
        write_c_string(&mut memory, PATH, "link");
        let symlink_fd = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [
                PATH,
                (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(symlink_fd, 3);
        write_c_string(&mut memory, PATH, "");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlinkat,
                [symlink_fd as u64, PATH, OUTPUT, 4096, 0, 0],
            ),
            7
        );
        let mut empty_path_target = [0; 7];
        memory.read(OUTPUT, &mut empty_path_target).unwrap();
        assert_eq!(&empty_path_target, b"payload");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [symlink_fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );

        // A synthetic proc descriptor links back to its guest-visible proc
        // path, never to the implementation's memfd backing file.
        let proc_fd = open_readonly(&mut memory, &mut state, "/proc/self/status");
        assert_eq!(proc_fd, 3);
        write_c_string(&mut memory, PATH, "/proc/self/fd/3");
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readlink,
            [PATH, OUTPUT, 4096, 0, 0, 0],
        );
        assert_eq!(count, b"/proc/1/status".len() as i64);
        let mut actual = vec![0; count as usize];
        memory.read(OUTPUT, &mut actual).unwrap();
        assert_eq!(actual, b"/proc/1/status");
        assert_eq!(close(&mut state, proc_fd as u64), 0);

        // Independent opens of one file must report one target inode, just as
        // native procfd links do, even though their file offsets are separate.
        let first = open_readonly(&mut memory, &mut state, "payload");
        let second = open_readonly(&mut memory, &mut state, "payload");
        assert_eq!(
            [first, second],
            [3, 4],
            "live guest fds: {:?}",
            state.files.keys().collect::<Vec<_>>()
        );
        let mut regular_inodes = Vec::new();
        for fd in [first, second] {
            write_c_string(&mut memory, PATH, &format!("/proc/self/fd/{fd}"));
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_newfstatat,
                    [libc::AT_FDCWD as u64, PATH, STAT, 0, 0, 0],
                ),
                0
            );
            let stat: libc::stat = read_struct(&memory, STAT);
            regular_inodes.push(stat.st_ino);
        }
        assert_eq!(regular_inodes[0], regular_inodes[1]);
        assert_eq!(close(&mut state, first as u64), 0);
        assert_eq!(close(&mut state, second as u64), 0);

        write_c_string(&mut memory, PATH, "/proc/self/fd/99");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlink,
                [PATH, OUTPUT, 4096, 0, 0, 0],
            ),
            negative_errno(libc::ENOENT)
        );

        // Kernel pipe inode numbers are host-specific; expose a guest-stable link.
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
        let duplicate = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup,
            [pipe_fds[0] as u64, 0, 0, 0, 0, 0],
        );
        assert_eq!(duplicate, 5);

        let mut targets = Vec::new();
        let mut inodes = Vec::new();
        for fd in [pipe_fds[0], pipe_fds[1], duplicate as libc::c_int] {
            write_c_string(&mut memory, PATH, &format!("/proc/self/fd/{fd}"));
            let count = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlink,
                [PATH, OUTPUT, 4096, 0, 0, 0],
            );
            let mut target = vec![0; count as usize];
            memory.read(OUTPUT, &mut target).unwrap();
            targets.push(target);

            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_newfstatat,
                    [libc::AT_FDCWD as u64, PATH, STAT, 0, 0, 0],
                ),
                0
            );
            let stat: libc::stat = read_struct(&memory, STAT);
            inodes.push(stat.st_ino);
        }

        let stable_pipe = format!("pipe:[{}]", inodes[0]);
        assert!(
            targets
                .iter()
                .all(|target| target == stable_pipe.as_bytes())
        );
        assert!(inodes.iter().all(|inode| *inode == inodes[0]));

        let stable_inode = inodes[0];
        assert_eq!(close(&mut state, pipe_fds[0] as u64), 0);
        for fd in [pipe_fds[1], duplicate as libc::c_int] {
            write_c_string(&mut memory, PATH, &format!("/proc/self/fd/{fd}"));
            let count = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readlink,
                [PATH, OUTPUT, 4096, 0, 0, 0],
            );
            let mut target = vec![0; count as usize];
            memory.read(OUTPUT, &mut target).unwrap();
            assert_eq!(target, stable_pipe.as_bytes());

            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_newfstatat,
                    [libc::AT_FDCWD as u64, PATH, STAT, 0, 0, 0],
                ),
                0
            );
            let stat: libc::stat = read_struct(&memory, STAT);
            assert_eq!(
                stat.st_ino, stable_inode,
                "closing the first pipe fd must not change surviving identity"
            );
        }

        // Reusing closed fd 3 for a new pipe must not alias the still-live old
        // pipe object held by fds 4 and 5.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pipe2,
                [PIPE_FDS, 0, 0, 0, 0, 0],
            ),
            0
        );
        let second_pipe_fds: [libc::c_int; 2] = read_struct(&memory, PIPE_FDS);
        assert_eq!(second_pipe_fds, [3, 6]);
        let new_inode = state
            .fd_object_inodes
            .get(&second_pipe_fds[0])
            .map(|identity| identity.inode)
            .unwrap();
        assert_eq!(
            state
                .fd_object_inodes
                .get(&second_pipe_fds[1])
                .map(|identity| identity.inode),
            Some(new_inode)
        );
        assert_ne!(
            new_inode, stable_inode,
            "descriptor reuse must allocate a distinct live pipe identity"
        );
        assert_eq!(
            state
                .fd_object_inodes
                .get(&pipe_fds[1])
                .map(|identity| identity.inode),
            Some(stable_inode)
        );
        write_c_string(
            &mut memory,
            PATH,
            &format!("/proc/self/fd/{}", second_pipe_fds[0]),
        );
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readlink,
            [PATH, OUTPUT, 4096, 0, 0, 0],
        );
        let mut target = vec![0; count as usize];
        memory.read(OUTPUT, &mut target).unwrap();
        assert_eq!(target, format!("pipe:[{new_inode}]").as_bytes());
    }

    #[test]
    fn forked_states_share_file_object_identity_namespace() {
        let root = TestDir::new();
        std::fs::write(root.0.join("child-file"), b"child").unwrap();
        std::fs::write(root.0.join("parent-file"), b"parent").unwrap();
        let mut parent = test_state(&root.0);
        let mut child = parent.try_clone_for_fork(2).unwrap();
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        let child_fd = open_readonly(&mut memory, &mut child, "child-file");
        let child_inode = synthetic_guest_fd_object_inode(&child, child_fd as libc::c_int);
        assert_eq!(close(&mut child, child_fd as u64), 0);
        drop(child);

        let parent_fd = open_readonly(&mut memory, &mut parent, "parent-file");
        let parent_inode = synthetic_guest_fd_object_inode(&parent, parent_fd as libc::c_int);

        let reopened_fd = open_readonly(&mut memory, &mut parent, "child-file");
        let reopened_inode = synthetic_guest_fd_object_inode(&parent, reopened_fd as libc::c_int);

        assert_ne!(
            child_inode, parent_inode,
            "forked states must not allocate one identity to distinct live files"
        );
        assert_eq!(
            child_inode, reopened_inode,
            "the parent must reuse the persistent identity after child exit"
        );

        assert_eq!(close(&mut parent, parent_fd as u64), 0);
        assert_eq!(close(&mut parent, reopened_fd as u64), 0);
        let reopened_after_close = open_readonly(&mut memory, &mut parent, "child-file");
        let reopened_after_close_inode =
            synthetic_guest_fd_object_inode(&parent, reopened_after_close as libc::c_int);
        assert_eq!(
            child_inode, reopened_after_close_inode,
            "a linked file must retain identity after every descriptor closes"
        );
        assert_eq!(close(&mut parent, reopened_after_close as u64), 0);
        let table = parent
            .file_identity_table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(table.objects.len(), 2);
        assert!(
            table
                .objects
                .values()
                .all(|entry| matches!(entry, GuestFileIdentityEntry::Persistent(_)))
        );
    }

    #[test]
    fn removed_link_identities_are_reclaimed() {
        const PATH: u64 = 0x100;
        const NEW_PATH: u64 = 0x300;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        for index in 0..64 {
            let name = format!("removed-{index}");
            std::fs::write(root.0.join(&name), b"payload").unwrap();
            let fd = open_readonly(&mut memory, &mut state, &name);
            assert!(fd >= 0);
            write_c_string(&mut memory, PATH, &name);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_unlink,
                    [PATH, 0, 0, 0, 0, 0],
                ),
                0
            );
            assert_eq!(close(&mut state, fd as u64), 0);
        }
        assert!(
            state
                .file_identity_table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .objects
                .is_empty()
        );

        std::fs::write(root.0.join("source"), b"source").unwrap();
        std::fs::write(root.0.join("target"), b"target").unwrap();
        let target_fd = open_readonly(&mut memory, &mut state, "target");
        assert_eq!(close(&mut state, target_fd as u64), 0);
        write_c_string(&mut memory, PATH, "source");
        write_c_string(&mut memory, NEW_PATH, "target");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_rename,
                [PATH, NEW_PATH, 0, 0, 0, 0],
            ),
            0
        );
        assert!(
            state
                .file_identity_table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .objects
                .is_empty()
        );
    }

    #[test]
    fn guest_fd_reopen_uses_fresh_description_and_native_flags() {
        const PATH: u64 = 0x100;
        const BUFFER: u64 = 0x200;

        let root = TestDir::new();
        let path = root.0.join("payload");
        std::fs::write(&path, b"abc").unwrap();
        let mut state = test_state(&root.0);
        state.files.insert(
            3,
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        );
        set_output_alias(&mut state, 3, Some(OutputAlias::Stdout));
        state.proc_files.insert(3, 0x1234);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [3, BUFFER, 1, 0, 0, 0],
            ),
            1
        );
        assert_eq!(read_guest_bytes::<1>(&memory, BUFFER).unwrap(), *b"a");

        write_c_string(&mut memory, PATH, "/proc/thread-self/fd/3");
        let reopened = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_open,
            [PATH, (libc::O_RDONLY | libc::O_CLOEXEC) as u64, 0, 0, 0, 0],
        );
        assert_eq!(reopened, 4, "O_RDWR source may be reopened O_RDONLY");
        assert!(state.cloexec_fds.contains(&(reopened as libc::c_int)));
        assert!(matches!(
            output_alias(&state, reopened as libc::c_int),
            Some(OutputAlias::Stdout)
        ));
        assert_eq!(
            state.proc_files.get(&(reopened as libc::c_int)),
            Some(&0x1234)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [reopened as u64, BUFFER, 1, 0, 0, 0],
            ),
            1
        );
        assert_eq!(
            read_guest_bytes::<1>(&memory, BUFFER).unwrap(),
            *b"a",
            "the reopened file description starts at an independent offset"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [3, BUFFER, 1, 0, 0, 0],
            ),
            1
        );
        assert_eq!(read_guest_bytes::<1>(&memory, BUFFER).unwrap(), *b"b");

        write_c_string(&mut memory, PATH, "/proc/self/fd/3");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_open,
                [PATH, (libc::O_RDONLY | libc::O_NOFOLLOW) as u64, 0, 0, 0, 0,],
            ),
            negative_errno(libc::ELOOP),
            "O_NOFOLLOW applies to the descriptor magic link"
        );
        let file_count = state.files.len();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_open,
                [PATH, (libc::O_PATH | libc::O_NOFOLLOW) as u64, 0, 0, 0, 0,],
            ),
            negative_errno(libc::ELOOP),
            "the guest must not retain a supervisor procfs magic-link fd"
        );
        assert_eq!(state.files.len(), file_count);
        assert!(
            state
                .files
                .values()
                .all(|file| ensure_not_procfs(file).is_ok())
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_open,
                [
                    PATH,
                    (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            negative_errno(libc::ENOTDIR)
        );
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

        for prefix in ["/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"] {
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
    fn saved_ids_are_fixed_root_and_validate_every_output() {
        const REAL: u64 = 0x100;
        const EFFECTIVE: u64 = 0x108;
        const SAVED: u64 = 0x110;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        for syscall in [libc::SYS_getresuid, libc::SYS_getresgid] {
            memory.write(REAL, &[0xa5; 4]).unwrap();
            memory.write(EFFECTIVE, &[0xa5; 4]).unwrap();
            memory.write(SAVED, &[0xa5; 4]).unwrap();
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    syscall,
                    [REAL, EFFECTIVE, SAVED, 0, 0, 0],
                ),
                0
            );
            assert_eq!(read_struct::<u32>(&memory, REAL), 0);
            assert_eq!(read_struct::<u32>(&memory, EFFECTIVE), 0);
            assert_eq!(read_struct::<u32>(&memory, SAVED), 0);

            memory.write(REAL, &[0xa5; 4]).unwrap();
            memory.write(EFFECTIVE, &[0xa5; 4]).unwrap();
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    syscall,
                    [REAL, EFFECTIVE, u64::MAX, 0, 0, 0],
                ),
                negative_errno(libc::EFAULT)
            );
            assert_eq!(read_struct::<u32>(&memory, REAL), 0);
            assert_eq!(read_struct::<u32>(&memory, EFFECTIVE), 0);

            memory.write(REAL, &[0xa5; 4]).unwrap();
            memory.write(SAVED, &[0xa5; 4]).unwrap();
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    syscall,
                    [REAL, u64::MAX, SAVED, 0, 0, 0],
                ),
                negative_errno(libc::EFAULT)
            );
            assert_eq!(read_struct::<u32>(&memory, REAL), 0);
            assert_eq!(read_guest_bytes::<4>(&memory, SAVED).unwrap(), [0xa5; 4]);

            memory.write(EFFECTIVE, &[0xa5; 4]).unwrap();
            memory.write(SAVED, &[0xa5; 4]).unwrap();
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    syscall,
                    [u64::MAX, EFFECTIVE, SAVED, 0, 0, 0],
                ),
                negative_errno(libc::EFAULT)
            );
            assert_eq!(
                read_guest_bytes::<4>(&memory, EFFECTIVE).unwrap(),
                [0xa5; 4]
            );
            assert_eq!(read_guest_bytes::<4>(&memory, SAVED).unwrap(), [0xa5; 4]);
        }
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
        assert_eq!(file_stat.st_atime, DETERMINISTIC_METADATA_SECONDS);
        assert_eq!(file_stat.st_mtime, DETERMINISTIC_METADATA_SECONDS);
        assert_eq!(file_stat.st_ctime, DETERMINISTIC_METADATA_SECONDS);
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
        assert_eq!(extended.stx_atime.tv_sec, DETERMINISTIC_METADATA_SECONDS);
        assert_eq!(extended.stx_btime.tv_sec, DETERMINISTIC_METADATA_SECONDS);
        assert_eq!(extended.stx_ctime.tv_sec, DETERMINISTIC_METADATA_SECONDS);
        assert_eq!(extended.stx_mtime.tv_sec, DETERMINISTIC_METADATA_SECONDS);
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
    fn getdents64_does_not_advance_directory_on_guest_fault() {
        let root = TestDir::new();
        std::fs::write(root.0.join("entry"), b"x").unwrap();
        let mut state = test_state(&root.0);
        state.files.insert(3, std::fs::File::open(&root.0).unwrap());
        let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
        memory.map_user_range(0, PAGE_SIZE, false).unwrap();
        memory.map_user_range(PAGE_SIZE, PAGE_SIZE, true).unwrap();
        memory.enable_user_access();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [3, PAGE_SIZE, PAGE_SIZE, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [3, 0, PAGE_SIZE, 0, 0, 0],
            ) > 0
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
    fn read_limits_host_consumption_to_the_accessible_guest_prefix() {
        let root = TestDir::new();
        let path = root.0.join("input");
        std::fs::write(&path, b"abcdefgh").unwrap();
        let mut state = test_state(&root.0);
        state.files.insert(3, std::fs::File::open(&path).unwrap());
        state.files.insert(4, std::fs::File::open(&path).unwrap());
        let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
        memory.map_user_range(0, PAGE_SIZE, false).unwrap();
        memory.map_user_range(PAGE_SIZE, PAGE_SIZE, true).unwrap();
        memory.enable_user_access();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [3, PAGE_SIZE - 4, 8, 0, 0, 0],
            ),
            4
        );
        let mut first = [0; 4];
        memory.read(PAGE_SIZE - 4, &mut first).unwrap();
        assert_eq!(&first, b"abcd");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [3, 0x100, 4, 0, 0, 0],
            ),
            4
        );
        let mut second = [0; 4];
        memory.read(0x100, &mut second).unwrap();
        assert_eq!(&second, b"efgh");

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [4, PAGE_SIZE, 4, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [4, 0x200, 4, 0, 0, 0],
            ),
            4
        );
        let mut unconsumed = [0; 4];
        memory.read(0x200, &mut unconsumed).unwrap();
        assert_eq!(&unconsumed, b"abcd");
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
                libc::SYS_readahead,
                [fd as u64, 0, 4096, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sync_file_range,
                [fd as u64, 0, 4096, libc::SYNC_FILE_RANGE_WRITE as u64, 0, 0,],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readahead,
                [u64::MAX, 0, 1, 0, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_sync_file_range,
                [
                    fd as u64,
                    0,
                    1,
                    (libc::SYNC_FILE_RANGE_WAIT_BEFORE
                        | libc::SYNC_FILE_RANGE_WRITE
                        | libc::SYNC_FILE_RANGE_WAIT_AFTER
                        | 8) as u64,
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
                libc::SYS_ftruncate,
                [fd as u64, 4, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(std::fs::read(root.0.join("positioned")).unwrap(), b"abXY");

        let fallocate_result = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fallocate,
            [fd as u64, 0, 0, 8192, 0, 0],
        );
        assert!(
            fallocate_result == 0 || fallocate_result == negative_errno(libc::EOPNOTSUPP),
            "fallocate returned {fallocate_result}"
        );
        if fallocate_result == 0 {
            assert_eq!(
                std::fs::metadata(root.0.join("positioned")).unwrap().len(),
                8192
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_truncate,
                [PATH_ADDRESS, 2, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(std::fs::read(root.0.join("positioned")).unwrap(), b"ab");
        assert_eq!(
            state.files.len(),
            1,
            "truncate must not change the guest fd table"
        );

        state
            .files
            .insert(9, std::fs::File::open(root.0.join("positioned")).unwrap());
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fallocate,
                [9, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL),
            "range validation precedes writable-access validation"
        );
        for mode in [
            libc::FALLOC_FL_PUNCH_HOLE,
            libc::FALLOC_FL_COLLAPSE_RANGE | libc::FALLOC_FL_KEEP_SIZE,
            libc::FALLOC_FL_INSERT_RANGE | libc::FALLOC_FL_KEEP_SIZE,
            FALLOC_FL_WRITE_ZEROES | libc::FALLOC_FL_KEEP_SIZE,
        ] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_fallocate,
                    [9, mode as u64, 0, 1, 0, 0],
                ),
                negative_errno(libc::EOPNOTSUPP),
                "invalid mode combination validation precedes writable access"
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fallocate,
                [9, FALLOC_FL_WRITE_ZEROES as u64, 0, 1, 0, 0],
            ),
            negative_errno(libc::EBADF),
            "valid write-zeroes mode reaches writable-access validation"
        );

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fallocate,
                [9, 1_u64 << 30, 0, 1, 0, 0],
            ),
            negative_errno(libc::EOPNOTSUPP),
            "unknown mode validation precedes writable-access validation"
        );
        state.files.remove(&9);

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_truncate,
                [u64::MAX, u64::MAX, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL),
            "negative length validation precedes path access"
        );
        write_c_string(&mut memory, PATH_ADDRESS, "");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_truncate,
                [PATH_ADDRESS, u64::MAX, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );

        let fifo = root.0.join("fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_c is NUL-terminated and names a path in the test directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        write_c_string(&mut memory, PATH_ADDRESS, "fifo");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_truncate,
                [PATH_ADDRESS, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL),
            "path truncate must not open a FIFO and block"
        );

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fallocate,
                [99, 0, 0, 1, 0, 0],
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fallocate,
                [fd as u64, 0, u64::MAX, 1, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );

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
    fn mmap_reuses_unmapped_holes_after_cursor_exhaustion() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let memory_size = BOOT_RESERVED_END + 8 * PAGE_SIZE;
        let mut memory = GuestMemory::new(0, memory_size as usize).unwrap();
        state.mmap_base = BOOT_RESERVED_END + PAGE_SIZE;
        state.mmap_next = state.mmap_base;
        state.mmap_limit = state.mmap_base + 3 * PAGE_SIZE;
        let mmap_args = [
            0,
            PAGE_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            -1_i32 as u64,
            0,
        ];

        let first = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        let second = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        let third = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        assert_eq!(second, first + PAGE_SIZE);
        assert_eq!(third, second + PAGE_SIZE);
        assert_eq!(state.mmap_next, state.mmap_limit);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munmap,
                [first, PAGE_SIZE, 0, 0, 0, 0],
            ),
            0
        );

        let reused = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        assert_eq!(reused, first);
        assert_eq!(state.mmap_next, state.mmap_limit);
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args),
            negative_errno(libc::ENOMEM)
        );
    }

    #[test]
    fn msync_validates_mapped_ranges_and_flags() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let memory_size = BOOT_RESERVED_END + 8 * PAGE_SIZE;
        let mut memory = GuestMemory::new(0, memory_size as usize).unwrap();
        state.mmap_next = BOOT_RESERVED_END + PAGE_SIZE;
        state.mmap_limit = memory_size;
        let mapping = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_mmap,
            [
                0,
                PAGE_SIZE,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_SHARED | libc::MAP_ANONYMOUS) as u64,
                -1_i32 as u64,
                0,
            ],
        ) as u64;

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_msync,
                [mapping, PAGE_SIZE, libc::MS_SYNC as u64, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_msync,
                [mapping + 1, PAGE_SIZE, libc::MS_SYNC as u64, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_msync,
                [
                    mapping,
                    PAGE_SIZE,
                    (libc::MS_ASYNC | libc::MS_SYNC) as u64,
                    0,
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
                libc::SYS_msync,
                [
                    mapping + PAGE_SIZE,
                    PAGE_SIZE,
                    libc::MS_SYNC as u64,
                    0,
                    0,
                    0,
                ],
            ),
            negative_errno(libc::ENOMEM)
        );
    }

    #[test]
    fn mremap_grows_a_reused_hole_into_adjacent_space() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let memory_size = BOOT_RESERVED_END + 8 * PAGE_SIZE;
        let mut memory = GuestMemory::new(0, memory_size as usize).unwrap();
        state.mmap_base = BOOT_RESERVED_END + PAGE_SIZE;
        state.mmap_next = state.mmap_base;
        state.mmap_limit = state.mmap_base + 3 * PAGE_SIZE;
        let mmap_args = [
            0,
            PAGE_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            -1_i32 as u64,
            0,
        ];

        let first = syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args) as u64;
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args),
            (first + PAGE_SIZE) as i64
        );
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args),
            (first + 2 * PAGE_SIZE) as i64
        );
        assert_eq!(state.mmap_next, state.mmap_limit);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munmap,
                [first, 2 * PAGE_SIZE, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_mmap, mmap_args),
            first as i64
        );

        assert_eq!(
            syscall_result(
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
            ),
            first as i64
        );
        assert_eq!(state.mmap_next, state.mmap_limit);
        assert!(memory.user_range_is_mapped(first, 2 * PAGE_SIZE));
    }

    #[test]
    fn thread_executors_share_mmap_allocation_cursor() {
        let root = TestDir::new();
        let memory_size = BOOT_RESERVED_END + 8 * PAGE_SIZE;
        let mut state = test_state(&root.0);
        state.mmap_next = BOOT_RESERVED_END + PAGE_SIZE;
        state.mmap_limit = memory_size;
        let memory = GuestMemory::new(0, memory_size as usize).unwrap();
        let mut parent = ElfExecutor::new(state, false);
        let mut child = parent.thread_child(2).unwrap();
        let request = SyscallRequest::new(
            libc::SYS_mmap as u64,
            [
                0,
                PAGE_SIZE,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                -1_i32 as u64,
                0,
            ],
        );

        let first = parent.execute(&request, &memory) as u64;
        let second = child.execute(&request, &memory) as u64;
        assert_eq!(first, BOOT_RESERVED_END + PAGE_SIZE);
        assert_eq!(second, first + PAGE_SIZE);
    }

    #[test]
    fn thread_executors_share_descriptor_replacement() {
        let root = TestDir::new();
        let old_path = root.0.join("old");
        let new_path = root.0.join("new");
        std::fs::write(&old_path, b"old").unwrap();
        std::fs::write(&new_path, b"new").unwrap();

        let mut state = test_state(&root.0);
        state
            .files
            .insert(3, std::fs::File::open(old_path).unwrap());
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut parent = ElfExecutor::new(state, false);
        let mut child = parent.thread_child(2).unwrap();

        assert_eq!(
            parent.execute(
                &SyscallRequest::new(libc::SYS_close as u64, [3, 0, 0, 0, 0, 0]),
                &memory,
            ),
            0
        );
        write_c_string(&mut memory, 0x100, new_path.to_str().unwrap());
        assert_eq!(
            parent.execute(
                &SyscallRequest::new(
                    libc::SYS_openat as u64,
                    [libc::AT_FDCWD as u64, 0x100, libc::O_RDONLY as u64, 0, 0, 0],
                ),
                &memory,
            ),
            3
        );

        assert_eq!(
            child.execute(
                &SyscallRequest::new(libc::SYS_read as u64, [3, 0x200, 3, 0, 0, 0]),
                &memory,
            ),
            3
        );
        let mut bytes = [0; 3];
        memory.read(0x200, &mut bytes).unwrap();
        assert_eq!(&bytes, b"new");
    }

    #[test]
    fn mprotect_and_munmap_bound_tool_user_copies() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let memory_size = BOOT_RESERVED_END + 8 * PAGE_SIZE;
        let mut memory = GuestMemory::new(0, memory_size as usize).unwrap();
        state.mmap_next = BOOT_RESERVED_END + PAGE_SIZE;
        state.mmap_limit = memory_size;
        let mapping = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_mmap,
            [
                0,
                2 * PAGE_SIZE,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                -1_i32 as u64,
                0,
            ],
        ) as u64;
        memory.enable_user_access();

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mprotect,
                [
                    mapping + PAGE_SIZE,
                    PAGE_SIZE,
                    libc::PROT_NONE as u64,
                    0,
                    0,
                    0,
                ],
            ),
            0
        );
        let boundary = AddrMut::from_raw((mapping + PAGE_SIZE - 8) as usize).unwrap();
        assert_eq!(
            MemoryAccess::write(&mut memory, boundary, &[0x5a; 16]).unwrap(),
            8
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mprotect,
                [
                    mapping + PAGE_SIZE,
                    PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    0,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            MemoryAccess::write(&mut memory, boundary, &[0x33; 16]).unwrap(),
            16
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munmap,
                [mapping, 2 * PAGE_SIZE, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mprotect,
                [mapping, PAGE_SIZE, libc::PROT_READ as u64, 0, 0, 0],
            ),
            negative_errno(libc::ENOMEM)
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
    fn child_sleep_syscalls_validate_requests_without_host_waiting() {
        const REQUEST: u64 = 0x100;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        assert_eq!(
            write_struct(
                &mut memory,
                REQUEST,
                &libc::timespec {
                    tv_sec: 60,
                    tv_nsec: 123,
                },
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_nanosleep,
                [REQUEST, u64::MAX, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_clock_nanosleep,
                [libc::CLOCK_REALTIME as u64, 0, REQUEST, u64::MAX, 0, 0,],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_clock_nanosleep,
                [
                    libc::CLOCK_MONOTONIC as u64,
                    libc::TIMER_ABSTIME as u64,
                    REQUEST,
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
                libc::SYS_clock_nanosleep,
                [libc::CLOCK_PROCESS_CPUTIME_ID as u64, 0, REQUEST, 0, 0, 0,],
            ),
            0
        );

        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_nanosleep,
                [0, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_clock_nanosleep,
                [libc::CLOCK_REALTIME as u64, 0, u64::MAX, 0, 0, 0,],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            write_struct(
                &mut memory,
                REQUEST,
                &libc::timespec {
                    tv_sec: -1,
                    tv_nsec: 0,
                },
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_nanosleep,
                [REQUEST, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            write_struct(
                &mut memory,
                REQUEST,
                &libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000_000,
                },
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_clock_nanosleep,
                [libc::CLOCK_REALTIME as u64, 0, REQUEST, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_clock_nanosleep,
                [u64::MAX, 0, REQUEST, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_clock_nanosleep,
                [libc::CLOCK_THREAD_CPUTIME_ID as u64, 0, REQUEST, 0, 0, 0,],
            ),
            negative_errno(libc::EOPNOTSUPP)
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
            DETERMINISTIC_METADATA_SECONDS
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
    fn ioctl_cloexec_commands_update_guest_descriptor_flags() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        state
            .files
            .insert(3, std::fs::File::open("/dev/null").unwrap());
        let memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut executor = ElfExecutor::new(state, false);

        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_ioctl as u64, [3, libc::FIOCLEX, 0, 0, 0, 0],),
                &memory,
            ),
            0
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_fcntl as u64,
                    [3, libc::F_GETFD as u64, 0, 0, 0, 0],
                ),
                &memory,
            ),
            i64::from(libc::FD_CLOEXEC)
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_ioctl as u64, [3, libc::FIONCLEX, 0, 0, 0, 0],),
                &memory,
            ),
            0
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_fcntl as u64,
                    [3, libc::F_GETFD as u64, 0, 0, 0, 0],
                ),
                &memory,
            ),
            0
        );
        // The host descriptor remains private even when the guest clears its
        // independently modeled close-on-exec bit.
        let host_fd = executor.state.files.get(&3).unwrap().as_raw_fd();
        assert_ne!(
            unsafe { libc::fcntl(host_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_ioctl as u64, [99, libc::FIOCLEX, 0, 0, 0, 0],),
                &memory,
            ),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_ioctl as u64, [3, SIOCETHTOOL, 0, 0, 0, 0],),
                &memory,
            ),
            negative_errno(libc::ENODEV)
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
    fn clone3_accepts_glibc_pthread_profile_with_tls_and_tid_addresses() {
        const CLONE3_ARGS: u64 = 0x200;
        const CHILD_TID_ADDRESS: u64 = 0x300;
        const PARENT_TID_ADDRESS: u64 = 0x308;
        const CHILD_STACK: u64 = 0x4000;
        const CHILD_STACK_SIZE: u64 = 0x9000;
        const TLS: u64 = 0x1_234_000;

        let root = TestDir::new();
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut clone3 = [0_u8; 88];
        let flags = THREAD_CLONE_REQUIRED_FLAGS
            | libc::CLONE_SYSVSEM as u64
            | libc::CLONE_SETTLS as u64
            | libc::CLONE_PARENT_SETTID as u64
            | libc::CLONE_CHILD_CLEARTID as u64;
        clone3[0..8].copy_from_slice(&flags.to_le_bytes());
        // glibc leaves clone_args.pidfd aliased to the thread descriptor even
        // though CLONE_PIDFD is absent; Linux ignores the slot in that case.
        clone3[8..16].copy_from_slice(&CHILD_TID_ADDRESS.to_le_bytes());
        clone3[16..24].copy_from_slice(&CHILD_TID_ADDRESS.to_le_bytes());
        clone3[24..32].copy_from_slice(&PARENT_TID_ADDRESS.to_le_bytes());
        clone3[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
        clone3[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
        clone3[56..64].copy_from_slice(&TLS.to_le_bytes());
        memory.write(CLONE3_ARGS, &clone3).unwrap();
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let request = SyscallRequest::new(
            libc::SYS_clone3 as u64,
            [CLONE3_ARGS, clone3.len() as u64, 0, 0, 0, 0],
        );

        assert!(is_thread_clone_request(&request, &memory));
        let legacy_thread = SyscallRequest::new(
            libc::SYS_clone as u64,
            [THREAD_CLONE_REQUIRED_FLAGS, CHILD_STACK, 0, 0, TLS, 0],
        );
        assert!(is_thread_clone_request(&legacy_thread, &memory));
        let process_clone = SyscallRequest::new(
            libc::SYS_clone as u64,
            [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
        );
        assert!(!is_thread_clone_request(&process_clone, &memory));

        assert_eq!(executor.execute_process_action(&request, &memory), Some(2));
        match executor.take_process_action() {
            Some(ProcessAction::Thread {
                child_tid,
                child_stack,
                parent_tid,
                child_tid_address,
                clear_child_tid,
                tls,
            }) => {
                assert_eq!(child_tid, 2);
                assert_eq!(child_stack, CHILD_STACK + CHILD_STACK_SIZE);
                assert_eq!(parent_tid, Some(PARENT_TID_ADDRESS));
                assert_eq!(child_tid_address, None);
                assert_eq!(clear_child_tid, Some(CHILD_TID_ADDRESS));
                assert_eq!(tls, Some(TLS));
            }
            _ => panic!("glibc pthread clone3 did not produce a thread action"),
        }
    }

    #[test]
    fn clone3_validates_nonzero_extensions_and_paired_stack_fields() {
        const CLONE3_ARGS: u64 = 0x200;

        let root = TestDir::new();
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut clone3 = [0_u8; 96];
        clone3[95] = 1;
        memory.write(CLONE3_ARGS, &clone3).unwrap();
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let request = SyscallRequest::new(
            libc::SYS_clone3 as u64,
            [CLONE3_ARGS, clone3.len() as u64, 0, 0, 0, 0],
        );
        assert_eq!(
            executor.execute_process_action(&request, &memory),
            Some(negative_errno(libc::E2BIG))
        );

        clone3[95] = 0;
        clone3[40..48].copy_from_slice(&0x1000_u64.to_le_bytes());
        memory.write(CLONE3_ARGS, &clone3).unwrap();
        let request = SyscallRequest::new(libc::SYS_clone3 as u64, [CLONE3_ARGS, 88, 0, 0, 0, 0]);
        assert_eq!(
            executor.execute_process_action(&request, &memory),
            Some(negative_errno(libc::EINVAL))
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
        assert!(!is_thread_clone_request(&request, &memory));
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
        memory
            .map_user_range(PAGE_SIZE, 2 * PAGE_SIZE, false)
            .unwrap();
        memory.map_user_range(VECTOR, PAGE_SIZE, false).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [PAGE_SIZE + 1, PAGE_SIZE - 1, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [PAGE_SIZE, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [5 * PAGE_SIZE + 1, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOMEM)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [5 * PAGE_SIZE - 1, 2, 0, 0, 0, 0],
            ),
            negative_errno(libc::ENOMEM)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [1, u64::MAX, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [0, u64::MAX, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [u64::MAX - 1, 4, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [u64::MAX, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_munlock,
                [u64::MAX - (PAGE_SIZE - 1), 1, 0, 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_munlockall, [u64::MAX; 6],),
            0
        );
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
                [3 * PAGE_SIZE, PAGE_SIZE, VECTOR, 0, 0, 0],
            ),
            negative_errno(libc::ENOMEM)
        );
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
    fn waitid_reports_status_supports_wnowait_and_reaps() {
        const INFO: u64 = 0x100;
        const USAGE: u64 = 0x200;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        state.children.insert(7, 3);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory
            .write(USAGE, &[0xa5; std::mem::size_of::<libc::rusage>()])
            .unwrap();

        assert_eq!(
            waitid(
                &mut memory,
                &mut state,
                &[
                    libc::P_PID as u64,
                    7,
                    INFO,
                    (libc::WEXITED | libc::WNOWAIT) as u64,
                    USAGE,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            std::mem::size_of::<GuestWaitidSiginfo>(),
            std::mem::size_of::<libc::siginfo_t>()
        );
        let info: libc::siginfo_t = read_struct(&memory, INFO);
        assert_eq!(info.si_signo, libc::SIGCHLD);
        assert_eq!(info.si_code, libc::CLD_EXITED);
        // SAFETY: waitid writes the SIGCHLD variant of siginfo_t.
        unsafe {
            assert_eq!(info.si_pid(), 7);
            assert_eq!(info.si_uid(), 0);
            assert_eq!(info.si_status(), 3);
            assert_eq!(info.si_utime(), 0);
            assert_eq!(info.si_stime(), 0);
        }
        let mut usage = vec![0xff; std::mem::size_of::<libc::rusage>()];
        memory.read(USAGE, &mut usage).unwrap();
        assert!(usage.iter().all(|byte| *byte == 0));
        assert_eq!(state.children.get(&7), Some(&3));

        assert_eq!(
            waitid(
                &mut memory,
                &mut state,
                &[libc::P_PID as u64, 7, INFO, libc::WEXITED as u64, 0, 0],
            ),
            0
        );
        assert!(state.children.is_empty());
        assert_eq!(
            waitid(
                &mut memory,
                &mut state,
                &[libc::P_PID as u64, 7, INFO, libc::WEXITED as u64, 0, 0],
            ),
            negative_errno(libc::ECHILD)
        );
    }

    #[test]
    fn robust_list_registration_round_trips_and_resets_on_fork() {
        const HEAD_OUTPUT: u64 = 0x100;
        const LENGTH_OUTPUT: u64 = 0x108;
        const REGISTERED_HEAD: u64 = 0x300;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        assert_eq!(
            set_robust_list(
                &mut state,
                &[REGISTERED_HEAD, ROBUST_LIST_HEAD_SIZE, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            get_robust_list(
                &mut memory,
                &state,
                &[0, HEAD_OUTPUT, LENGTH_OUTPUT, 0, 0, 0],
            ),
            0
        );
        assert_eq!(read_struct::<u64>(&memory, HEAD_OUTPUT), REGISTERED_HEAD);
        assert_eq!(
            read_struct::<u64>(&memory, LENGTH_OUTPUT),
            ROBUST_LIST_HEAD_SIZE
        );
        assert_eq!(
            get_robust_list(
                &mut memory,
                &state,
                &[99, HEAD_OUTPUT, LENGTH_OUTPUT, 0, 0, 0],
            ),
            negative_errno(libc::ESRCH)
        );
        assert_eq!(
            set_robust_list(&mut state, &[REGISTERED_HEAD, 8, 0, 0, 0, 0]),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(state.robust_list_head, REGISTERED_HEAD);

        let child = state.try_clone_for_fork(2).unwrap();
        assert_eq!(child.robust_list_head, 0);
        assert_eq!(child.robust_list_len, 0);
    }

    #[test]
    fn deterministic_getrandom_repeats_per_thread_and_separates_threads() {
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();

        assert_eq!(getrandom(&mut memory, 1, 0x100, 32), 32);
        let mut first = [0; 32];
        memory.read(0x100, &mut first).unwrap();

        assert_eq!(getrandom(&mut memory, 1, 0x200, 32), 32);
        let mut second = [0; 32];
        memory.read(0x200, &mut second).unwrap();
        assert_eq!(first, second);

        assert_eq!(getrandom(&mut memory, 2, 0x300, 32), 32);
        let mut worker = [0; 32];
        memory.read(0x300, &mut worker).unwrap();
        assert_ne!(first, worker);
    }

    #[test]
    fn deterministic_random_device_repeats_and_changes_with_seed() {
        let root = deterministic_random_device_bytes(0, 32);
        assert_eq!(root, deterministic_random_device_bytes(0, 32));
        assert_eq!(root[0], 41);
        assert_ne!(root, deterministic_random_device_bytes(17, 32));
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

        write_c_string(&mut memory, 0x100, "file");
        write_c_string(&mut memory, 0x200, "user.reverie_review");
        memory.write(0x300, b"value").unwrap();
        for number in [libc::SYS_setxattr, libc::SYS_lsetxattr] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [0x100, 0x200, 0x300, 5, 0, 0]
                ),
                negative_errno(libc::EOPNOTSUPP)
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fsetxattr,
                [fd as u64, 0x200, 0x300, 5, 0, 0]
            ),
            negative_errno(libc::EOPNOTSUPP)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_setxattr,
                [0x100, 0x200, 0x5000, 1, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_setxattr,
                [
                    0x100,
                    0x200,
                    0x300,
                    5,
                    (libc::XATTR_CREATE | libc::XATTR_REPLACE) as u64,
                    0,
                ]
            ),
            negative_errno(libc::EINVAL)
        );
        for number in [libc::SYS_removexattr, libc::SYS_lremovexattr] {
            assert_eq!(
                syscall_result(&mut memory, &mut state, number, [0x100, 0x200, 0, 0, 0, 0]),
                negative_errno(libc::ENODATA)
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fremovexattr,
                [fd as u64, 0x200, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENODATA)
        );
    }

    #[test]
    fn prctl_capbset_read_reports_full_bounding_set() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        // Valid capabilities are present (root holds the full bounding set).
        for cap in [0, 7, 15, 32, GUEST_CAP_LAST_CAP] {
            assert_eq!(prctl(&mut state, &[PR_CAPBSET_READ, cap, 0, 0, 0, 0]), 1);
        }
        // Out-of-range capabilities are rejected exactly like Linux.
        assert_eq!(
            prctl(
                &mut state,
                &[PR_CAPBSET_READ, GUEST_CAP_LAST_CAP + 1, 0, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        // Deterministic: repeated queries return the same answer.
        assert_eq!(
            prctl(&mut state, &[PR_CAPBSET_READ, 15, 0, 0, 0, 0]),
            prctl(&mut state, &[PR_CAPBSET_READ, 15, 0, 0, 0, 0])
        );
        // Unmodeled prctl options remain ENOSYS.
        assert_eq!(
            prctl(&mut state, &[libc::PR_GET_NAME as u64, 0, 0, 0, 0, 0]),
            negative_errno(libc::ENOSYS)
        );
    }

    #[test]
    fn prctl_keepcaps_round_trips_inherits_on_fork_and_resets_on_exec() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let get = [libc::PR_GET_KEEPCAPS as u64, 0, 0, 0, 0, 0];
        let set = |value| [libc::PR_SET_KEEPCAPS as u64, value, 0, 0, 0, 0];

        assert_eq!(prctl(&mut state, &get), 0);
        assert_eq!(prctl(&mut state, &set(1)), 0);
        assert_eq!(prctl(&mut state, &get), 1);
        assert_eq!(prctl(&mut state, &set(2)), negative_errno(libc::EINVAL));
        assert_eq!(prctl(&mut state, &get), 1);

        let mut child = state.try_clone_for_fork(2).unwrap();
        assert_eq!(prctl(&mut child, &get), 1);

        let mut after_exec = test_state(&root.0);
        after_exec.inherit_process_state(state);
        assert_eq!(prctl(&mut after_exec, &get), 0);
    }

    #[test]
    fn capability_syscalls_round_trip_and_bound_the_exec_persona() {
        const HEADER: u64 = 0x100;
        const DATA: u64 = 0x200;
        const CAP_SYS_TIME: u64 = 25;

        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let write_header = |memory: &mut GuestMemory, version: u32, pid: i32| {
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&version.to_ne_bytes());
            bytes[4..].copy_from_slice(&pid.to_ne_bytes());
            memory.write(HEADER, &bytes).unwrap();
        };

        write_header(&mut memory, 0, 0);
        assert_eq!(capget(&mut memory, &state, &[HEADER, 0, 0, 0, 0, 0]), 0);
        let mut version = [0; 4];
        memory.read(HEADER, &mut version).unwrap();
        assert_eq!(u32::from_ne_bytes(version), LINUX_CAPABILITY_VERSION_3);

        write_header(&mut memory, LINUX_CAPABILITY_VERSION_3, state.pid);
        assert_eq!(capget(&mut memory, &state, &[HEADER, DATA, 0, 0, 0, 0]), 0);
        let reduced = GUEST_CAPABILITY_MASK & !(1_u64 << CAP_SYS_TIME);
        memory
            .write(DATA, &capability_data_bytes(reduced, reduced, 1))
            .unwrap();
        assert_eq!(capset(&memory, &mut state, &[HEADER, DATA, 0, 0, 0, 0]), 0);
        assert_eq!(state.capability_effective, reduced);
        assert_eq!(state.capability_permitted, reduced);
        assert_eq!(state.capability_inheritable, 1);

        assert_eq!(
            prctl_cap_ambient(&mut state, libc::PR_CAP_AMBIENT_RAISE as u64, 0),
            0
        );
        assert_eq!(
            prctl_cap_ambient(&mut state, libc::PR_CAP_AMBIENT_IS_SET as u64, 0),
            1
        );

        memory
            .write(DATA, &capability_data_bytes(reduced, reduced, 0))
            .unwrap();
        assert_eq!(capset(&memory, &mut state, &[HEADER, DATA, 0, 0, 0, 0]), 0);
        assert_eq!(state.capability_ambient, 0);
        memory
            .write(DATA, &capability_data_bytes(reduced, reduced, 1))
            .unwrap();
        assert_eq!(capset(&memory, &mut state, &[HEADER, DATA, 0, 0, 0, 0]), 0);
        assert_eq!(
            prctl_cap_ambient(&mut state, libc::PR_CAP_AMBIENT_RAISE as u64, 0),
            0
        );

        assert_eq!(
            prctl(&mut state, &[PR_CAPBSET_DROP, CAP_SYS_TIME, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            prctl(&mut state, &[PR_CAPBSET_READ, CAP_SYS_TIME, 0, 0, 0, 0]),
            0
        );
        assert_eq!(prctl(&mut state, &[PR_CAPBSET_READ, 0, 0, 0, 0, 0]), 1);

        let child = state.try_clone_for_fork(2).unwrap();
        assert_eq!(child.capability_bounding, reduced);
        let mut after_exec = test_state(&root.0);
        after_exec.inherit_process_state(state);
        assert_eq!(after_exec.capability_effective, reduced);
        assert_eq!(after_exec.capability_permitted, reduced);
        assert_eq!(after_exec.capability_bounding, reduced);
        assert_eq!(after_exec.capability_ambient, 1);
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
