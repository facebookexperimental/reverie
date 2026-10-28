/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! stat, statx and statfs (gVisor: pkg/sentry/syscalls/linux/sys_stat.go).

use super::*;

pub(super) fn fstat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture: Option<CaptureMetadata>,
) -> i64 {
    // Linux descriptor lookup consumes only the low 32-bit word.
    let fd = args[0] as libc::c_int;
    match guest_object_stat(state, fd, capture) {
        Ok(stat) => write_struct(&mut ProviderMemory(memory), args[1], &stat),
        Err(error) => error,
    }
}

pub(super) fn guest_object_stat(
    state: &LoadedStaticElf,
    fd: libc::c_int,
    capture: Option<CaptureMetadata>,
) -> Result<libc::stat, i64> {
    if let (Some(capture), Some(alias)) = (capture, output_alias(state, fd)) {
        return Ok(synthetic_captured_output_stat(capture.identity(alias)));
    }
    let Some(host_fd) = host_fd(state, fd) else {
        return Err(negative_errno(libc::EBADF));
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and host_fd is a standard or owned descriptor.
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    let mut stat = unsafe { stat.assume_init() };
    sanitize_guest_fd_stat(state, fd, &mut stat);
    Ok(stat)
}

// TODO-HUMAN-REVIEW(PR-205): Review synthetic metadata for in-memory captured output.
fn synthetic_captured_output_stat(identity: CaptureObjectIdentity) -> libc::stat {
    // Captured writes never reach the host descriptor, so exposing that
    // descriptor's type, size, or inode leaks the invoking shell into the
    // guest. Model the capture sink as the pipe used by process-based backends.
    // SAFETY: libc::stat is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_dev = identity.device;
    stat.st_ino = identity.inode;
    stat.st_mode = libc::S_IFIFO | 0o600;
    stat.st_nlink = 1;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_blksize = PAGE_SIZE as libc::blksize_t;
    sanitize_stat_timestamps(&mut stat);
    stat
}

fn synthetic_captured_output_statx(identity: CaptureObjectIdentity) -> libc::statx {
    let stat = synthetic_captured_output_stat(identity);
    // SAFETY: libc::statx is plain-old-data; a zeroed value is valid.
    let mut extended = unsafe { std::mem::zeroed::<libc::statx>() };
    extended.stx_mask = libc::STATX_BASIC_STATS;
    extended.stx_blksize = stat.st_blksize as u32;
    extended.stx_nlink = stat.st_nlink as u32;
    extended.stx_uid = stat.st_uid;
    extended.stx_gid = stat.st_gid;
    extended.stx_mode = stat.st_mode as u16;
    extended.stx_ino = stat.st_ino;
    extended.stx_dev_major = libc::major(stat.st_dev);
    extended.stx_dev_minor = libc::minor(stat.st_dev);
    extended.stx_atime.tv_sec = stat.st_atime;
    extended.stx_mtime.tv_sec = stat.st_mtime;
    extended.stx_ctime.tv_sec = stat.st_ctime;
    extended
}

pub(super) fn path_stat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    flags: libc::c_int,
    capture: Option<CaptureMetadata>,
) -> i64 {
    fstatat_impl(
        memory,
        state,
        libc::AT_FDCWD,
        args[0],
        args[1],
        flags,
        capture,
    )
}

pub(super) fn newfstatat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture: Option<CaptureMetadata>,
) -> i64 {
    fstatat_impl(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2],
        args[3] as libc::c_int,
        capture,
    )
}

fn fstatat_impl(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    output_address: u64,
    flags: libc::c_int,
    capture: Option<CaptureMetadata>,
) -> i64 {
    let path = match read_c_string(&ProviderMemory(memory), path_address, 4096) {
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
    if let Some(target) = fdinfo_path_target(state, &path) {
        let (tid, fd) = match target {
            FdinfoPathTarget::Target { tid, fd } => (tid, fd),
            FdinfoPathTarget::MissingFinal { .. }
            | FdinfoPathTarget::EmptyFinal { .. }
            | FdinfoPathTarget::InvalidTask => return negative_errno(libc::ENOENT),
        };
        if let Err(error) = fdinfo_target_generation(state, tid, fd) {
            return error;
        }
        let path = format!("/proc/{tid}/fdinfo/{fd}");
        return write_struct(
            &mut ProviderMemory(memory),
            output_address,
            &synthetic_proc_stat(synthetic_proc_inode(path.as_bytes()), 0),
        );
    }
    // Path-addressed synthetic /proc file: synthesize deterministic metadata.
    // synthetic_proc_content returns None for an empty path, so no explicit
    // AT_EMPTY_PATH guard is needed here.
    if let Some(content) = synthetic_proc_content(state, &path) {
        let normalized =
            normalize_proc_path(state, &path).expect("a synthesized /proc path always normalizes");
        let stat = synthetic_proc_stat(
            synthetic_proc_inode(&normalized),
            synthetic_proc_path_size(&normalized, &content),
        );
        return write_struct(&mut ProviderMemory(memory), output_address, &stat);
    }

    let guest_path = match guest_fd_metadata(state, &path, flags & libc::AT_SYMLINK_NOFOLLOW != 0) {
        Ok(metadata) => metadata,
        Err(error) => return error,
    };
    if let Some(metadata) = guest_path
        && metadata.no_follow
    {
        let stat = synthetic_guest_fd_symlink_stat(metadata.guest_fd);
        return write_struct(&mut ProviderMemory(memory), output_address, &stat);
    }
    let descriptor = guest_path
        .map(|metadata| metadata.guest_fd)
        .or_else(|| (path.is_empty() && guest_dirfd != libc::AT_FDCWD).then_some(guest_dirfd));
    if let Some(fd) = descriptor
        && let Some(capture) = capture
        && let Some(alias) = output_alias(state, fd)
    {
        return write_struct(
            &mut ProviderMemory(memory),
            output_address,
            &synthetic_captured_output_stat(capture.identity(alias)),
        );
    }
    let executable = if flags & libc::AT_SYMLINK_NOFOLLOW == 0 {
        match guest_proc_exe_path(state, &path) {
            Some(true) => match state.executable_file.as_ref() {
                Some(file) => Some(file.as_raw_fd()),
                None => return negative_errno(libc::ENOENT),
            },
            Some(false) => return negative_errno(libc::ENOENT),
            None => None,
        }
    } else {
        None
    };
    let opened_file;
    let host_fd = if let Some(metadata) = guest_path {
        metadata.host_fd
    } else if let Some(descriptor) = executable {
        descriptor
    } else if path.is_empty() {
        let Ok((host_fd, _)) = host_dirfd_and_path(state, guest_dirfd, &path) else {
            return negative_errno(libc::EBADF);
        };
        if let Err(error) = ensure_fd_not_procfs(host_fd) {
            return error;
        }
        host_fd
    } else {
        opened_file = match open_stat_path(
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
    if let Some(fd) = descriptor {
        sanitize_guest_fd_stat(state, fd, &mut stat);
    } else {
        // AT_EMPTY_PATH stat of a synthetic /proc descriptor.
        let empty_path_proc_inode = path
            .is_empty()
            .then(|| state.proc_files.get(&guest_dirfd).copied())
            .flatten();
        if let Some(inode) = empty_path_proc_inode {
            sanitize_proc_stat(&mut stat, inode);
        }
    }
    if executable.is_some() {
        copy_executable_stat(memory, state, output_address, &stat)
    } else {
        write_struct(&mut ProviderMemory(memory), output_address, &stat)
    }
}

/// Copies a `stat` result for the retained executable. As in Linux, a copy
/// that faults leaves the bytes before the fault in guest memory and fails
/// with `EFAULT`.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/924):
// Review host metadata timestamps for Tool runs.
// A failed call is not rewritten by the Tool, so the prefix a faulting copy
// leaves must not hold a stored host timestamp. A run that reports host
// timestamps therefore copies the fixed timestamps first, and copies the
// stored ones only after that copy has shown the whole buffer is writable.
fn copy_executable_stat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    output_address: u64,
    stat: &libc::stat,
) -> i64 {
    let copy = |memory: &mut GuestMemory, stat: &libc::stat| {
        // SAFETY: libc::stat is initialized plain data. The byte view is
        // bounded to stat and copied into guest memory before stat is dropped.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(stat).cast::<u8>(),
                std::mem::size_of::<libc::stat>(),
            )
        };
        memory.user().copy_to_user(output_address, bytes).is_ok()
    };
    if !state.host_metadata_timestamps {
        return if copy(memory, stat) {
            0
        } else {
            negative_errno(libc::EFAULT)
        };
    }
    let mut fixed = *stat;
    sanitize_stat_timestamps(&mut fixed);
    if !copy(memory, &fixed) {
        return negative_errno(libc::EFAULT);
    }
    if !copy(memory, stat) {
        // The buffer stopped being writable between the two copies. Put the
        // fixed timestamps back over whatever prefix the second copy left.
        copy(memory, &fixed);
        return negative_errno(libc::EFAULT);
    }
    0
}

pub(super) fn statx(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture: Option<CaptureMetadata>,
) -> i64 {
    let path = match read_c_string(&ProviderMemory(memory), args[1], 4096) {
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
    if let Some(target) = fdinfo_path_target(state, &path) {
        if args[3] as libc::c_uint & 0x8000_0000 != 0
            || flags & libc::AT_STATX_SYNC_TYPE == libc::AT_STATX_SYNC_TYPE
        {
            return negative_errno(libc::EINVAL);
        }
        let (tid, fd) = match target {
            FdinfoPathTarget::Target { tid, fd } => (tid, fd),
            FdinfoPathTarget::MissingFinal { .. }
            | FdinfoPathTarget::EmptyFinal { .. }
            | FdinfoPathTarget::InvalidTask => return negative_errno(libc::ENOENT),
        };
        if let Err(error) = fdinfo_target_generation(state, tid, fd) {
            return error;
        }
        let path = format!("/proc/{tid}/fdinfo/{fd}");
        return write_struct(
            &mut ProviderMemory(memory),
            args[4],
            &synthetic_proc_statx(synthetic_proc_inode(path.as_bytes()), 0),
        );
    }
    // Path-addressed synthetic /proc file: synthesize deterministic metadata.
    if !path.is_empty() {
        if let Some(content) = synthetic_proc_content(state, &path) {
            let normalized = normalize_proc_path(state, &path)
                .expect("a synthesized /proc path always normalizes");
            let stx = synthetic_proc_statx(
                synthetic_proc_inode(&normalized),
                synthetic_proc_path_size(&normalized, &content) as u64,
            );
            return write_struct(&mut ProviderMemory(memory), args[4], &stx);
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
        return write_struct(&mut ProviderMemory(memory), args[4], &stx);
    }

    let guest_path = match guest_fd_metadata(state, &path, flags & libc::AT_SYMLINK_NOFOLLOW != 0) {
        Ok(metadata) => metadata,
        Err(error) => return error,
    };
    if let Some(metadata) = guest_path
        && metadata.no_follow
    {
        let stat = synthetic_guest_fd_symlink_statx(metadata.guest_fd);
        return write_struct(&mut ProviderMemory(memory), args[4], &stat);
    }
    let descriptor = guest_path.map(|metadata| metadata.guest_fd).or_else(|| {
        (path.is_empty() && args[0] as libc::c_int != libc::AT_FDCWD)
            .then_some(args[0] as libc::c_int)
    });
    if let Some(fd) = descriptor
        && let Some(capture) = capture
        && let Some(alias) = output_alias(state, fd)
    {
        // Ordinary objects continue through the native statx call below. The
        // capture sink synthesizes fields beyond its reserved identity; validate the kernel's
        // reserved mask bit and mutually exclusive synchronization flags here.
        if args[3] as libc::c_uint & 0x8000_0000 != 0
            || flags & libc::AT_STATX_SYNC_TYPE == libc::AT_STATX_SYNC_TYPE
        {
            return negative_errno(libc::EINVAL);
        }
        return write_struct(
            &mut ProviderMemory(memory),
            args[4],
            &synthetic_captured_output_statx(capture.identity(alias)),
        );
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
    if let Some(fd) = descriptor {
        sanitize_guest_fd_statx(state, fd, &mut stat);
    }
    write_struct(&mut ProviderMemory(memory), args[4], &stat)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-183): Review fixed host-backed metadata timestamps.
pub(super) fn sanitize_stat_timestamps(stat: &mut libc::stat) {
    set_stat_timestamps(stat, DETERMINISTIC_METADATA_SECONDS);
}

/// Sets every timestamp of a `stat` result to `seconds`.
pub(super) fn set_stat_timestamps(stat: &mut libc::stat, seconds: libc::time_t) {
    stat.st_atime = seconds;
    stat.st_atime_nsec = 0;
    stat.st_mtime = seconds;
    stat.st_mtime_nsec = 0;
    stat.st_ctime = seconds;
    stat.st_ctime_nsec = 0;
}

/// Sets every timestamp of a `statx` result, birth time included, to `seconds`.
pub(super) fn set_statx_timestamps(stat: &mut libc::statx, seconds: libc::time_t) {
    for timestamp in [
        &mut stat.stx_atime,
        &mut stat.stx_btime,
        &mut stat.stx_ctime,
        &mut stat.stx_mtime,
    ] {
        timestamp.tv_sec = seconds;
        timestamp.tv_nsec = 0;
    }
}

// TODO-HUMAN-REVIEW(PR-114): Review guest descriptor path resolution for statfs.
pub(super) fn statfs(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(&ProviderMemory(memory), args[0], 4096) {
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

pub(super) fn fstatfs(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Linux descriptor lookup consumes only the low 32-bit word.
    let guest_fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    fstatfs_host(memory, host_fd, args[1])
}

fn fstatfs_host(memory: &mut GuestMemory, host_fd: RawFd, output: u64) -> i64 {
    if let Err(error) = ensure_fd_not_procfs(host_fd) {
        return error;
    }
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: stat is writable and host_fd names a live descriptor.
    if unsafe { libc::fstatfs(host_fd, stat.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    // The host's answer, as the kernel gives it to a ptrace guest. The Tool
    // decides what the guest sees: Detcore canonicalizes the free counts and
    // zeroes `f_fsid` (`canonicalize_statfs_buf`) on every backend, once the
    // call has completed. Two windows hold the host's values first, as on
    // ptrace: a sibling that runs between this write and Detcore's rewrite
    // (only with unsequentialized threads), and a copy into writable
    // MAP_SHARED pages whose second page faults (its backing file truncated)
    // after the first was written. The run then stops before Detcore sees the
    // result, and the host values already in the first page stay in the file.
    // A buffer that is not accessible fails before anything is written.
    write_struct(&mut ProviderMemory(memory), output, &stat)
}

pub(super) fn access(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
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
pub(super) fn faccessat(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
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
pub(super) fn faccessat2(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
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
    let path = match read_c_string(&ProviderMemory(memory), path_address, 4096) {
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
