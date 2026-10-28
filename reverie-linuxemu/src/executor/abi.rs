/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Linux ABI constants (gVisor: pkg/abi/linux).

use super::*;

pub(super) const GUEST_NOFILE_LIMIT: libc::c_int = 1 << 20;
pub(super) const ROBUST_LIST_HEAD_SIZE: u64 = 3 * std::mem::size_of::<u64>() as u64;
// prctl(2) PR_CAPBSET_READ and PR_CAPBSET_DROP options.
pub(super) const PR_CAPBSET_READ: u64 = 23;
pub(super) const PR_CAPBSET_DROP: u64 = 24;
pub(super) const CAP_SYS_PTRACE: u64 = 19;
pub(super) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub(super) const PROCESS_CLONE_TID_FLAGS: u64 = libc::CLONE_PARENT_SETTID as u64
    | libc::CLONE_CHILD_SETTID as u64
    | libc::CLONE_CHILD_CLEARTID as u64;
pub(super) const THREAD_CLONE_REQUIRED_FLAGS: u64 = libc::CLONE_VM as u64
    | libc::CLONE_FS as u64
    | libc::CLONE_FILES as u64
    | libc::CLONE_SIGHAND as u64
    | libc::CLONE_THREAD as u64;
pub(super) const THREAD_CLONE_ALLOWED_FLAGS: u64 = THREAD_CLONE_REQUIRED_FLAGS
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
pub(super) const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
pub(super) const ARCH_SET_GS: u64 = 0x1001;
pub(super) const ARCH_SET_FS: u64 = 0x1002;
pub(super) const ARCH_GET_FS: u64 = 0x1003;
pub(super) const ARCH_GET_GS: u64 = 0x1004;
pub(super) const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
// Linux UAPI value added with executable memfd policy. Keep the literal so
// this crate continues to build with libc versions that predate the binding.
pub(super) const LINUX_F_SEAL_EXEC: libc::c_int = 0x0020;
// x86_64 Linux fcntl UAPI commands not exported by the libc crate. These
// values also match reverie-syscalls/src/args/fcntl.rs:
// https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/include/uapi/asm-generic/fcntl.h
pub(super) const LINUX_F_SETSIG: libc::c_int = 10;
pub(super) const LINUX_F_GETSIG: libc::c_int = 11;
pub(super) const LINUX_F_SETOWN_EX: libc::c_int = 15;
pub(super) const LINUX_F_GETOWN_EX: libc::c_int = 16;
pub(super) const SYNTHETIC_PROC_REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
pub(super) const SYNTHETIC_PROC_PRESERVED_STATUS_FLAGS: libc::c_int = libc::O_APPEND
    | libc::O_ASYNC
    | libc::O_DSYNC
    | libc::O_NOATIME
    | libc::O_NONBLOCK
    | libc::O_SYNC;
// TODO-HUMAN-REVIEW(PR-136): Review anonymous-object filesystem classification.
pub(super) const ANON_INODE_FS_MAGIC: libc::c_long = 0x0904_1934;
pub(super) const PIPEFS_MAGIC: libc::c_long = 0x5049_5045;
pub(super) const SOCKFS_MAGIC: libc::c_long = 0x534f_434b;
pub(super) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
// Linux UAPI value from <linux/sockios.h>; libc does not expose it.
pub(super) const SIOCETHTOOL: libc::c_ulong = 0x8946;
// TODO-HUMAN-REVIEW(PR-136): Review the Linux UAPI value missing from pinned libc.
pub(super) const FALLOC_FL_WRITE_ZEROES: libc::c_int = 0x80;
// Linux UAPI values not exposed by every supported libc release.
pub(super) const SCM_PIDFD: libc::c_int = 0x04;
pub(super) const SCM_TIMESTAMP_OLD: libc::c_int = 29;
pub(super) const SCM_TIMESTAMPNS_OLD: libc::c_int = 35;
pub(super) const SCM_TIMESTAMPING_OLD: libc::c_int = 37;
pub(super) const SCM_TIMESTAMP_NEW: libc::c_int = 63;
pub(super) const SCM_TIMESTAMPNS_NEW: libc::c_int = 64;
pub(super) const SCM_TIMESTAMPING_NEW: libc::c_int = 65;
// Linux 7.1 adds RWF_NOSIGNAL after the flags exposed by pinned libc.
pub(super) const RWF_NOSIGNAL: libc::c_int = 0x0000_0100;
pub(super) const RWF_SUPPORTED_MASK: libc::c_int = libc::RWF_HIPRI
    | libc::RWF_DSYNC
    | libc::RWF_SYNC
    | libc::RWF_NOWAIT
    | libc::RWF_APPEND
    | libc::RWF_NOAPPEND
    | libc::RWF_ATOMIC
    | libc::RWF_DONTCACHE
    | RWF_NOSIGNAL;

pub(super) const FALLOCATE_VALID_MODES: &[libc::c_int] = &[
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
pub(super) const LEGACY_OPEN_FLAGS: u64 = (libc::O_ACCMODE
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
pub(super) const LEGACY_O_PATH_FLAGS: u64 =
    (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
pub(super) const LEGACY_O_TMPFILE_PRIVATE: u64 = (libc::O_TMPFILE & !libc::O_DIRECTORY) as u64;

pub(super) fn invalid_legacy_tmpfile_flags(flags: u64) -> bool {
    if flags & libc::O_PATH as u64 != 0 || flags & LEGACY_O_TMPFILE_PRIVATE == 0 {
        return false;
    }
    let access_mode = flags & libc::O_ACCMODE as u64;
    let write_capable = access_mode == libc::O_WRONLY as u64
        || access_mode == libc::O_RDWR as u64
        || access_mode == libc::O_ACCMODE as u64;
    flags & libc::O_DIRECTORY as u64 == 0 || flags & libc::O_CREAT as u64 != 0 || !write_capable
}

pub(super) fn synthetic_proc_create_directory_errno(
    policy: RegularCreateDirectoryPolicy,
    flags: u64,
) -> libc::c_int {
    match policy {
        RegularCreateDirectoryPolicy::EarlyEinval => libc::EINVAL,
        RegularCreateDirectoryPolicy::LegacyLookup if flags & libc::O_EXCL as u64 != 0 => {
            libc::EEXIST
        }
        // Linux v6.3 fs/namei.c:3543 applies LOOKUP_DIRECTORY to the resolved
        // final dentry before may_open, so an existing regular file is
        // ENOTDIR here; O_EXCL above still yields EEXIST.
        RegularCreateDirectoryPolicy::LegacyLookup => libc::ENOTDIR,
    }
}
