/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Opening files, paths, directories and file control (gVisor: pkg/sentry/syscalls/linux/sys_file.go, pkg/sentry/vfs).

use super::*;

// TODO-HUMAN-REVIEW(#322): Review memfd_create name/flag forwarding and guest
// descriptor registration. The anonymous file's contents are guest-controlled
// and its guest fd is allocated deterministically, so the result carries no host
// pid/address/time; the host kernel validates flags and the name length.
pub(super) fn memfd_create(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    // The kernel bounds the name at 249 bytes (excluding NUL) and prepends
    // "memfd:"; read a little past that so an over-long name reaches the host,
    // which returns EINVAL just as a native call would.
    let name = match read_c_string(&ProviderMemory(memory), args[0], 256) {
        Ok(name) => name,
        Err(error) => return read_c_string_errno(error),
    };
    let Ok(name) = std::ffi::CString::new(name) else {
        // A NUL byte cannot occur inside a C string read stops at NUL, but guard
        // defensively; the kernel would reject an embedded NUL with EINVAL.
        return negative_errno(libc::EINVAL);
    };
    let Ok(flags) = u32::try_from(args[1]) else {
        return negative_errno(libc::EINVAL);
    };
    // Forward flags verbatim; the host kernel validates unknown bits (EINVAL).
    // Force MFD_CLOEXEC on the host descriptor so the supervisor never leaks it,
    // and track the guest-visible close-on-exec bit separately from the guest's
    // requested flags.
    let host_flags = flags | libc::MFD_CLOEXEC;
    // SAFETY: name is a valid NUL-terminated C string; the kernel validates
    // flags and returns a new owned descriptor on success.
    let host_fd = unsafe { libc::memfd_create(name.as_ptr(), host_flags) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    let close_on_exec = flags & libc::MFD_CLOEXEC != 0;
    insert_file_with_flags(state, file, close_on_exec, None)
}

pub(super) fn lseek(state: &LoadedStaticElf, args: &[u64; 6], capture_output: bool) -> i64 {
    // Linux syscall `int` arguments consume only the low descriptor word.
    let fd = args[0] as libc::c_int;
    if let Some(description) = state.fdinfo_files.get(&fd) {
        return description.seek(args);
    }
    if capture_output && output_alias(state, fd).is_some() {
        // Captured stdout/stderr are modeled as pipes: writes go to the
        // in-memory capture sink, and fstat exposes S_IFIFO. Do not leak the
        // unrelated file position of the supervisor's inherited descriptor.
        return negative_errno(libc::ESPIPE);
    }
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

pub(super) fn ftruncate(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let length = args[1] as libc::off_t;
    if length < 0 {
        return negative_errno(libc::EINVAL);
    }
    // Linux syscall argument decoding consumes only the low descriptor word.
    let fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let status = match fd_status_flags(host_fd) {
        Ok(status) => status,
        Err(error) => return error,
    };
    if status & libc::O_PATH != 0 {
        return negative_errno(libc::EBADF);
    }
    if status & libc::O_ACCMODE == libc::O_RDONLY {
        // Unlike write(2), Linux reports EINVAL when ftruncate receives an
        // otherwise-live regular-file description that is not open for write.
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
pub(super) fn truncate(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let length = args[1] as libc::off_t;
    if length < 0 {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(&ProviderMemory(memory), args[0], 4096) {
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
pub(super) fn fallocate(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Linux consumes only the low int descriptor word from the syscall register.
    let fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = refuse_o_path_descriptor(host_fd) {
        return error;
    }
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

pub(super) fn sync_file(state: &LoadedStaticElf, raw_fd: u64, data_only: bool) -> i64 {
    // Linux consumes only the low unsigned-int descriptor word.
    let fd = raw_fd as libc::c_int;
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

include!("syncfs.rs");
include!("inotify.rs");

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review translated host readahead semantics.
pub(super) fn readahead(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Linux consumes only the low int descriptor word from the syscall register.
    let fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = refuse_o_path_descriptor(host_fd) {
        return error;
    }
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
pub(super) fn sync_file_range(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Linux consumes only the low int descriptor word from the syscall register.
    let fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = refuse_o_path_descriptor(host_fd) {
        return error;
    }
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

pub(super) fn open(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
) -> i64 {
    open_file(
        memory,
        state,
        libc::AT_FDCWD,
        args[0],
        args[1],
        args[2],
        capture_output,
    )
}

pub(super) fn openat(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
) -> i64 {
    open_file(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2],
        args[3],
        capture_output,
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
pub(super) fn creat(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
) -> i64 {
    let flags = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
    open_file(
        memory,
        state,
        libc::AT_FDCWD,
        args[0],
        flags,
        args[1],
        capture_output,
    )
}

fn open_file(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_flags: u64,
    raw_mode: u64,
    capture_output: bool,
) -> i64 {
    let flags = u64::from(raw_flags as libc::c_int as u32) & LEGACY_OPEN_FLAGS;
    let path_only = flags & libc::O_PATH as u64 != 0;
    // Legacy open/openat validates every non-O_PATH __O_TMPFILE spelling before
    // copying the pathname: O_DIRECTORY is required, O_CREAT is forbidden, and
    // the access mode must include write permission (including mode 3).
    if invalid_legacy_tmpfile_flags(flags) {
        return negative_errno(libc::EINVAL);
    }
    if !path_only
        && state.regular_create_directory_policy == RegularCreateDirectoryPolicy::EarlyEinval
        && flags & (libc::O_CREAT | libc::O_DIRECTORY) as u64
            == (libc::O_CREAT | libc::O_DIRECTORY) as u64
    {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(&ProviderMemory(memory), path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() {
        return negative_errno(libc::ENOENT);
    }
    let path = path.as_slice();
    let close_on_exec = flags & libc::O_CLOEXEC as u64 != 0;
    if let Some(target) = fdinfo_path_target(state, path) {
        return match target {
            FdinfoPathTarget::Target { tid, fd } => {
                open_fdinfo(state, (tid, fd), flags, capture_output)
            }
            FdinfoPathTarget::EmptyFinal { tid } => {
                if let Err(error) = fdinfo_task_generation(state, tid) {
                    return error;
                }
                if !path_only
                    && state.regular_create_directory_policy
                        == RegularCreateDirectoryPolicy::LegacyLookup
                    && flags & (libc::O_CREAT | libc::O_DIRECTORY) as u64
                        == (libc::O_CREAT | libc::O_DIRECTORY) as u64
                {
                    // Linux v6.3 fs/namei.c:3460-3469 preserves the trailing
                    // slash and rejects O_CREAT on the fdinfo directory itself.
                    negative_errno(libc::EISDIR)
                } else {
                    negative_errno(libc::ENOENT)
                }
            }
            FdinfoPathTarget::MissingFinal { tid } => fdinfo_task_generation(state, tid)
                .map_or_else(|error| error, |_| negative_errno(libc::ENOENT)),
            FdinfoPathTarget::InvalidTask => negative_errno(libc::ENOENT),
        };
    }
    // Serve the synthetic /proc surface before touching the host filesystem, so
    // deterministic content replaces the deliberately-refused real procfs.
    if let Some(content) = synthetic_proc_content(state, path) {
        if !path_only
            && flags & (libc::O_CREAT | libc::O_DIRECTORY) as u64
                == (libc::O_CREAT | libc::O_DIRECTORY) as u64
        {
            return negative_errno(synthetic_proc_create_directory_errno(
                state.regular_create_directory_policy,
                flags,
            ));
        }
        if flags & libc::O_DIRECTORY as u64 != 0 {
            return negative_errno(libc::ENOTDIR);
        }
        if !path_only {
            if flags & (libc::O_CREAT | libc::O_EXCL) as u64
                == (libc::O_CREAT | libc::O_EXCL) as u64
            {
                return negative_errno(libc::EEXIST);
            }
            if flags & libc::O_TRUNC as u64 != 0
                || flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64
            {
                return negative_errno(libc::EACCES);
            }
            if flags & libc::O_DIRECT as u64 != 0 {
                return negative_errno(libc::EINVAL);
            }
        }
        let normalized =
            normalize_proc_path(state, path).expect("a synthesized /proc path always normalizes");
        if let Some(file) = ProcessProcFile::from_normalized_path(&normalized) {
            if !path_only {
                return open_process_proc(state, &normalized, file, flags, close_on_exec);
            }
            // An O_PATH handle has no content. Keep its backing empty, like
            // the readable description's, so fstat agrees with path stat.
            return open_synthetic_proc(
                state,
                &normalized,
                b"",
                close_on_exec,
                true,
                flags as libc::c_int,
            );
        }
        return open_synthetic_proc(
            state,
            &normalized,
            &content,
            close_on_exec,
            path_only,
            flags as libc::c_int,
        );
    }
    let guest_cloexec = close_on_exec;
    if let Some(guest_fd) = guest_fd_path(state, path) {
        return open_guest_fd_path(state, guest_fd, flags, guest_cloexec);
    }
    let guest_path = path;
    let Ok((host_dirfd, path)) = host_dirfd_and_path(state, guest_dirfd, path) else {
        return negative_errno(libc::EBADF);
    };
    // Legacy open/openat reduce every O_PATH request to O_PATH_FLAGS before
    // strict openat2 validation, as Linux's build_open_how does ("O_PATH
    // beats everything else"), so such an open creates nothing. Do this only
    // after guest path/dirfd resolution so EFAULT/ENOENT/EBADF precedence
    // remains observable.
    let host_flags = if path_only {
        flags & LEGACY_O_PATH_FLAGS
    } else {
        flags
    };
    let tmpfile = host_flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64;
    let named_create = host_flags & libc::O_CREAT as u64 != 0 && !tmpfile;
    let uses_mode = named_create || tmpfile;
    let mode = if uses_mode {
        u64::from(raw_mode as libc::mode_t & 0o7777 & !state.umask)
    } else {
        0
    };
    // The Tool's reserved directory, opened by exactly its path as a
    // directory, is the one open of it the executor admits, and only where
    // that path still reaches it.
    let admits_tool_directory = host_flags & libc::O_DIRECTORY as u64 != 0
        && !uses_mode
        && state
            .tool_directory
            .as_ref()
            .is_some_and(|reserved| reserved.is_spelled(guest_path));
    // A creation in the Tool's reserved directory is refused before the
    // kernel looks: a named creation whose spelled parent is the directory,
    // and an O_TMPFILE in it (`ensure_not_creating_in_tool_directory`).
    if uses_mode
        && let Err(error) =
            ensure_not_creating_in_tool_directory(state, host_dirfd, &path, host_flags, tmpfile)
    {
        return error;
    }
    // Hermit requires a stable external filesystem. This follow-target probe
    // distinguishes an existing target from a dangling symlink before the
    // atomic O_EXCL create attempt below. A creating open whose spelling
    // reaches the reserved directory itself is refused as every other route
    // to it is; a procfs target is left to the check of the opened object.
    // With O_EXCL or O_NOFOLLOW the probe stops at a final link, as the open
    // itself does (O_EXCL implies O_NOFOLLOW), so a link to the directory
    // answers as a link: EEXIST or ELOOP. The open can then create only the
    // final name, in the spelled parent the check above covers.
    let target_existed = if named_create {
        let nofollow = host_flags & (libc::O_EXCL | libc::O_NOFOLLOW) as u64 != 0;
        match open_host_path(host_dirfd, &path, nofollow)
            .and_then(|object| classify_path_object(state, object.as_raw_fd()))
        {
            Ok(PathObject::Ordinary) => true,
            Ok(PathObject::ToolDirectory) => return PathObject::ToolDirectory.refusal(),
            Ok(PathObject::Procfs) | Err(_) => false,
        }
    } else {
        false
    };
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
        let exclusive_fd = open_with_flags(host_flags | libc::O_EXCL as u64);
        if exclusive_fd >= 0 {
            (exclusive_fd, true)
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) || host_flags & libc::O_EXCL as u64 != 0 {
                return io_error(error);
            }
            let host_fd = open_with_flags(host_flags);
            if host_fd < 0 {
                return io_error(std::io::Error::last_os_error());
            }
            (host_fd, !target_existed)
        }
    } else {
        let host_fd = open_with_flags(host_flags);
        if host_fd < 0 {
            let error = std::io::Error::last_os_error();
            // The kernel refuses some opens for the directory it found (a
            // write mode or O_TRUNC: EISDIR; O_DIRECT: EINVAL) before the
            // object check below could. Where that directory is the reserved
            // one, the open fails as every other route to it does. One O_PATH
            // probe, on this failure path only, follows the final link
            // exactly as the open did.
            let nofollow = host_flags & libc::O_NOFOLLOW as u64 != 0;
            if !path_only
                && !admits_tool_directory
                && reaches_tool_directory(state, host_dirfd, &path, nofollow)
            {
                return PathObject::ToolDirectory.refusal();
            }
            return io_error(error);
        }
        (
            host_fd,
            host_flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64,
        )
    };
    // SAFETY: openat2 returned a new owned descriptor on success.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd as RawFd) };
    finish_open_file(
        state,
        file,
        uses_mode && created,
        mode,
        guest_cloexec,
        admits_tool_directory,
    )
}

/// Check the object an open reached, apply the guest's mode to a file this
/// call created, and install the descriptor. The object is refused where a
/// guest path may not reach it ([`ensure_path_object_allowed`]); an admitted
/// open of the Tool's reserved directory by its exact path must reach that
/// very directory ([`ensure_is_tool_directory`]).
fn finish_open_file(
    state: &mut LoadedStaticElf,
    file: std::fs::File,
    created: bool,
    mode: u64,
    guest_cloexec: bool,
    admits_tool_directory: bool,
) -> i64 {
    let checked = if admits_tool_directory {
        ensure_is_tool_directory(state, &file)
    } else {
        ensure_path_object_allowed(state, &file)
    };
    if let Err(error) = checked {
        return error;
    }
    if created {
        // Override the supervisor umask only for a file created by this call.
        // SAFETY: file is a live owned descriptor and mode is bounded above.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return io_error(std::io::Error::last_os_error());
        }
    }
    insert_file_with_flags(state, file, guest_cloexec, None)
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-114): Review /proc/thread-self/fd guest descriptor resolution.
// TODO-HUMAN-REVIEW(PR-136): Review numeric guest-pid descriptor aliases.
pub(super) fn guest_fd_path(state: &LoadedStaticElf, path: &[u8]) -> Option<libc::c_int> {
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
pub(super) struct GuestFdMetadata {
    pub(super) guest_fd: libc::c_int,
    pub(super) host_fd: RawFd,
    pub(super) no_follow: bool,
}

pub(super) fn guest_fd_metadata(
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
fn guest_fd_link_target(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
    capture: Option<CaptureMetadata>,
) -> Result<Vec<u8>, i64> {
    if let (Some(capture), Some(alias)) = (capture, output_alias(state, guest_fd)) {
        return Ok(format!("pipe:[{}]", capture.identity(alias).inode).into_bytes());
    }
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return Err(negative_errno(libc::ENOENT));
    };
    if let Some(description) = state.fdinfo_files.get(&guest_fd) {
        return Ok(description.path.clone());
    }
    if signalfd_mask(state, guest_fd).is_some() {
        return Ok(b"anon_inode:[signalfd]".to_vec());
    }
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

    // A followed proc-fd path names the same object as fstat. Keep anonymous
    // link targets consistent with that object's identity as well.
    for kind in ["pipe", "socket"] {
        let prefix = format!("{kind}:[");
        if target.starts_with(prefix.as_bytes()) && target.ends_with(b"]") {
            return Ok(format!(
                "{kind}:[{}]",
                guest_object_stat(state, guest_fd, capture)?.st_ino
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
pub(super) fn open_host_fd_path(source_host_fd: RawFd, flags: u64) -> Result<std::fs::File, i64> {
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
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(reopened as RawFd) })
    }
}

pub(super) fn open_guest_fd_path(
    state: &mut LoadedStaticElf,
    guest_fd: libc::c_int,
    flags: u64,
    close_on_exec: bool,
) -> i64 {
    let Some(source_host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::ENOENT);
    };
    let source_proc_inode = state.proc_files.get(&guest_fd).copied();
    // Every synthetic /proc descriptor is a regular file.
    let regular_proc = source_proc_inode.is_some();
    let path_only = flags & libc::O_PATH as u64 != 0;
    let create_exclusive = !path_only
        && flags & (libc::O_CREAT | libc::O_EXCL) as u64 == (libc::O_CREAT | libc::O_EXCL) as u64;
    if regular_proc
        && (flags & (libc::O_DIRECTORY | libc::O_NOFOLLOW) as u64 != 0 || create_exclusive)
    {
        // These flags are resolved against the proc-fd magic link or target
        // before target access policy. Probe with the real host descriptor so
        // combinations retain Linux's ENOTDIR/ELOOP/EEXIST precedence.
        match open_host_fd_path(source_host_fd, flags) {
            Err(error) => return error,
            Ok(probe) => drop(probe),
        }
        // Bare O_PATH|O_NOFOLLOW is the only supported host-success shape in
        // this group. Refuse its supervisor procfs magic-link inode explicitly.
        if flags & libc::O_DIRECTORY as u64 != 0 {
            return negative_errno(libc::ENOTDIR);
        }
        if flags & libc::O_NOFOLLOW as u64 != 0 {
            return negative_errno(libc::ELOOP);
        }
        return negative_errno(libc::EEXIST);
    }
    if source_proc_inode.is_some_and(|inode| inode == synthetic_proc_inode(b"/proc/self/status")) {
        // Its content is rendered from the opener's process cells, which an
        // O_PATH backing does not carry. Refuse rather than expose its empty
        // backing file.
        return negative_errno(libc::ENOSYS);
    }
    if state.fdinfo_files.contains_key(&guest_fd) {
        // A private fdinfo carrier would lose its stream metadata and permit
        // writable reopening. Refuse that unsupported route.
        return negative_errno(libc::ENOSYS);
    }
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
    if flags & libc::O_PATH as u64 != 0 && signalfd_mask(state, guest_fd).is_some() {
        // Reopening the private eventfd carrier as O_PATH would discard the
        // virtual signalfd identity. Refuse before allocating a guest or host
        // descriptor; ordinary access modes retain Linux's EACCES result.
        return negative_errno(libc::ENOSYS);
    }
    let source_alias = output_alias(state, guest_fd);
    if regular_proc && !path_only {
        if flags & libc::O_TRUNC as u64 != 0
            || flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64
        {
            // Enforce the synthetic regular proc file's read-only access
            // without relying on supervisor DAC capabilities or carrier mode.
            return negative_errno(libc::EACCES);
        }
        if flags & libc::O_DIRECT as u64 != 0 {
            return negative_errno(libc::EINVAL);
        }
    }
    let source_object_inode = guest_fd_object_identity(state, guest_fd);
    // The fresh description of a guest pipe end carries no pipe-owner record,
    // so its later export could not be seen: the pipe stops counting as
    // private, and writes to it keep the SIGPIPE check.
    if let Some(owner) = state.pipe_owners.get(&guest_fd) {
        owner.forfeit_privacy();
    }

    // Opening a proc-fd magic link creates a fresh open file description. A
    // descriptor duplication would incorrectly share the source offset and
    // status flags, and would prevent Linux-supported access-mode changes.
    // Resolve only the already-mapped host descriptor, so no supervisor-private
    // descriptor can be named by a guest path.
    let file = match open_host_fd_path(source_host_fd, flags) {
        Ok(file) => file,
        Err(error) => return error,
    };
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

pub(super) fn ensure_not_procfs(file: &std::fs::File) -> Result<(), i64> {
    ensure_fd_not_procfs(file.as_raw_fd())
}

pub(super) fn ensure_fd_not_procfs(fd: RawFd) -> Result<(), i64> {
    if fd_is_procfs(fd)? {
        return Err(negative_errno(libc::EACCES));
    }
    Ok(())
}

pub(super) fn fd_is_procfs(fd: RawFd) -> Result<bool, i64> {
    Ok(fd_filesystem_type(fd)? == PROC_SUPER_MAGIC)
}

/// The file system type (`fstatfs`'s `f_type`) of the object `fd` is open on.
fn fd_filesystem_type(fd: RawFd) -> Result<libc::c_long, i64> {
    let mut statfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs is writable and fd is live.
    if unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstatfs initialized statfs on success.
    Ok(unsafe { statfs.assume_init() }.f_type as libc::c_long)
}

/// Whether the object `fd` is open on, of file system type `filesystem`, is
/// the Tool's reserved directory (`LoadedStaticElf::tool_directory`). Only
/// an object on a file system of the directory's type has its identity read.
fn fd_is_tool_directory(
    state: &LoadedStaticElf,
    fd: RawFd,
    filesystem: libc::c_long,
) -> Result<bool, i64> {
    let Some(reserved) = state
        .tool_directory
        .as_ref()
        .filter(|reserved| reserved.may_be_on(filesystem))
    else {
        return Ok(false);
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and fd is live.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    Ok(reserved.is(filesystem, stat.st_dev, stat.st_ino))
}

/// What a guest path's lookup reached, for the procfs backstop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathObject {
    /// Neither of the two below.
    Ordinary,
    /// An object on procfs.
    Procfs,
    /// The Tool's reserved directory (`LoadedStaticElf::tool_directory`).
    ToolDirectory,
}

impl PathObject {
    /// The answer to a guest path call that reaches the object: none for an
    /// ordinary one; `EACCES` for procfs (see [`ensure_not_procfs`]); and
    /// `ENOENT` for the reserved directory, which the guest is to see as
    /// absent: the call fails as a lookup of a name that does not exist.
    fn refusal(self) -> i64 {
        match self {
            PathObject::Ordinary => 0,
            PathObject::Procfs => negative_errno(libc::EACCES),
            PathObject::ToolDirectory => negative_errno(libc::ENOENT),
        }
    }

    fn allowed(self) -> Result<(), i64> {
        match self {
            PathObject::Ordinary => Ok(()),
            refused => Err(refused.refusal()),
        }
    }
}

/// Which [`PathObject`] the object `fd` is open on is.
fn classify_path_object(state: &LoadedStaticElf, fd: RawFd) -> Result<PathObject, i64> {
    let filesystem = fd_filesystem_type(fd)?;
    if filesystem == PROC_SUPER_MAGIC {
        return Ok(PathObject::Procfs);
    }
    if fd_is_tool_directory(state, fd, filesystem)? {
        return Ok(PathObject::ToolDirectory);
    }
    Ok(PathObject::Ordinary)
}

/// The procfs backstop for an object a guest path resolved to: `EACCES` for
/// procfs and `ENOENT` for the Tool's reserved directory, which a guest path
/// reaches only by a spelling the Tool does not hide ([`PathObject`]).
pub(super) fn ensure_path_object_allowed(
    state: &LoadedStaticElf,
    file: &std::fs::File,
) -> Result<(), i64> {
    classify_path_object(state, file.as_raw_fd())?.allowed()
}

/// The check for an admitted open or stat of the Tool's reserved directory
/// by its exact path: the object must be that very directory, so that a path
/// remounted or replaced since the reservation fails closed (`ENOENT`, or
/// `EACCES` for a procfs object).
pub(super) fn ensure_is_tool_directory(
    state: &LoadedStaticElf,
    file: &std::fs::File,
) -> Result<(), i64> {
    match classify_path_object(state, file.as_raw_fd())? {
        PathObject::ToolDirectory => Ok(()),
        PathObject::Procfs => Err(PathObject::Procfs.refusal()),
        PathObject::Ordinary => Err(PathObject::ToolDirectory.refusal()),
    }
}

/// Refuse with `ENOENT` a call whose `path`, looked up from `host_dirfd`
/// (following a final link unless `nofollow`), names the Tool's reserved
/// directory itself, which the call would remove, rename or replace, or
/// create a name in. A lookup that fails decides nothing: the call then
/// fails as Linux fails it.
fn ensure_not_naming_tool_directory(
    state: &LoadedStaticElf,
    host_dirfd: RawFd,
    path: &CStr,
    nofollow: bool,
) -> Result<(), i64> {
    if state.tool_directory.is_none() {
        return Ok(());
    }
    let Ok(object) = open_host_path(host_dirfd, path, nofollow) else {
        return Ok(());
    };
    let filesystem = fd_filesystem_type(object.as_raw_fd())?;
    if fd_is_tool_directory(state, object.as_raw_fd(), filesystem)? {
        return Err(PathObject::ToolDirectory.refusal());
    }
    Ok(())
}

/// Whether `path`, looked up from `host_dirfd` (following a final link
/// unless `nofollow`), resolves to the Tool's reserved directory. A lookup
/// that fails, or an object whose identity cannot be read, says no.
fn reaches_tool_directory(
    state: &LoadedStaticElf,
    host_dirfd: RawFd,
    path: &CStr,
    nofollow: bool,
) -> bool {
    state.tool_directory.is_some()
        && open_host_path(host_dirfd, path, nofollow)
            .and_then(|object| classify_path_object(state, object.as_raw_fd()))
            == Ok(PathObject::ToolDirectory)
}

/// Refuse with `ENOENT` a creating open in the Tool's reserved directory
/// (`LoadedStaticElf::tool_directory`): for a named creation, the directory
/// its spelled parent resolves to; for `O_TMPFILE`, the directory `path`
/// names, whose final link is followed unless the call has `O_NOFOLLOW`, as
/// the kernel resolves it. A creation through a final symbolic link into
/// the directory is not caught here: the kernel follows the link and
/// answers for the read-only file system the reservation requires
/// (`EROFS`).
fn ensure_not_creating_in_tool_directory(
    state: &LoadedStaticElf,
    host_dirfd: RawFd,
    path: &CStr,
    host_flags: u64,
    tmpfile: bool,
) -> Result<(), i64> {
    if state.tool_directory.is_none() {
        return Ok(());
    }
    if tmpfile {
        let nofollow = host_flags & libc::O_NOFOLLOW as u64 != 0;
        return ensure_not_naming_tool_directory(state, host_dirfd, path, nofollow);
    }
    ensure_not_naming_tool_directory(state, host_dirfd, &mutation_parent(path)?, false)
}

pub(super) fn open_metadata_path(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
    nofollow: bool,
) -> Result<std::fs::File, i64> {
    let file = open_metadata_path_unchecked(state, guest_dirfd, path, nofollow)?;
    ensure_path_object_allowed(state, &file)?;
    Ok(file)
}

/// [`open_metadata_path`] for the newfstatat family (newfstatat, and its
/// legacy stat and lstat forms), which reaches the Tool's reserved directory
/// where it names exactly its path and that path still reaches it
/// (`LoadedStaticElf::tool_directory`).
pub(super) fn open_stat_path(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
    nofollow: bool,
) -> Result<std::fs::File, i64> {
    let file = open_metadata_path_unchecked(state, guest_dirfd, path, nofollow)?;
    if state
        .tool_directory
        .as_ref()
        .is_some_and(|reserved| reserved.is_spelled(path))
    {
        ensure_is_tool_directory(state, &file)?;
    } else {
        ensure_path_object_allowed(state, &file)?;
    }
    Ok(file)
}

fn open_metadata_path_unchecked(
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
    Ok(unsafe { std::fs::File::from_raw_fd(fd as RawFd) })
}

// AUTONOMOUS-BOT-IMPLEMENTED: Resolve mutation targets without host magic links.
// TODO-HUMAN-REVIEW(#86): Review procfs isolation and Linux mutation semantics.
fn open_host_metadata_path(
    state: &LoadedStaticElf,
    host_dirfd: RawFd,
    path: &CStr,
    nofollow: bool,
) -> Result<std::fs::File, i64> {
    let file = open_host_path(host_dirfd, path, nofollow)?;
    ensure_path_object_allowed(state, &file)?;
    Ok(file)
}

/// An `O_PATH` descriptor on `path`, looked up from `host_dirfd` without
/// following a magic link (or, with `nofollow`, a final link), unchecked.
fn open_host_path(host_dirfd: RawFd, path: &CStr, nofollow: bool) -> Result<std::fs::File, i64> {
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
    Ok(unsafe { std::fs::File::from_raw_fd(fd as RawFd) })
}

fn ensure_mutation_parent_not_procfs(
    state: &LoadedStaticElf,
    host_dirfd: RawFd,
    path: &CStr,
) -> Result<(), i64> {
    if path.to_bytes().is_empty() {
        return Ok(());
    }
    let parent = mutation_parent(path)?;
    let parent = open_host_metadata_path(state, host_dirfd, &parent, false)?;
    if !parent.metadata().map_err(io_error)?.is_dir() {
        return Err(negative_errno(libc::ENOTDIR));
    }
    Ok(())
}

/// The directory a call that creates or removes the final name of the
/// nonempty `path` changes.
fn mutation_parent(path: &CStr) -> Result<CString, i64> {
    let bytes = path.to_bytes();
    // Trailing slashes constrain how Linux resolves the target, but they are
    // not part of its name. Ignore them only while locating the parent for
    // this safety check; read_path_at still returns the original path to the
    // host syscall.
    let target_end = bytes
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |index| index + 1);
    let target = &bytes[..target_end];
    let parent = if target.is_empty() {
        b"/".as_slice()
    } else {
        match target.iter().rposition(|byte| *byte == b'/') {
            Some(0) => b"/".as_slice(),
            Some(index) => &target[..index],
            None => b".".as_slice(),
        }
    };
    CString::new(parent).map_err(|_| negative_errno(libc::EINVAL))
}

fn ensure_mutation_dirfd_not_synthetic_procfs(
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path: &[u8],
) -> Result<(), i64> {
    if path.starts_with(b"/") {
        return Ok(());
    }
    if !state.proc_files.contains_key(&guest_dirfd) {
        return Ok(());
    }
    if path.is_empty() {
        return Err(negative_errno(libc::EACCES));
    }
    Ok(())
}

pub(super) fn read_path_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    address: u64,
    allow_empty: bool,
) -> Result<(RawFd, CString), i64> {
    let path =
        read_c_string(&ProviderMemory(memory), address, 4096).map_err(read_c_string_errno)?;
    if path.is_empty() && !allow_empty {
        return Err(negative_errno(libc::ENOENT));
    }
    ensure_mutation_dirfd_not_synthetic_procfs(state, guest_dirfd, &path)?;
    let (host_dirfd, path) = host_dirfd_and_path(state, guest_dirfd, &path)?;
    ensure_mutation_parent_not_procfs(state, host_dirfd, &path)?;
    Ok((host_dirfd, path))
}

pub(super) fn mkdir_at(
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
pub(super) fn unlink_at(
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
    if let Err(error) = ensure_not_naming_tool_directory(state, host_dirfd, &path, true) {
        return error;
    }
    let removes_directory = raw_flags & libc::AT_REMOVEDIR as u64 != 0;
    let removed_file = open_host_metadata_path(state, host_dirfd, &path, true).ok();
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
pub(super) fn rename_at(
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
    for (host_dirfd, path) in [(old_host_dirfd, &old_path), (new_host_dirfd, &new_path)] {
        if let Err(error) = ensure_not_naming_tool_directory(state, host_dirfd, path, true) {
            return error;
        }
    }
    let old_file = if raw_flags == 0 {
        open_host_metadata_path(state, old_host_dirfd, &old_path, true).ok()
    } else {
        None
    };
    let replaced_file = if raw_flags == 0 {
        open_host_metadata_path(state, new_host_dirfd, &new_path, true).ok()
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

pub(super) fn link_at(
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
    let old_file = match open_host_metadata_path(state, old_host_dirfd, &old_path, !follows_source)
    {
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

pub(super) fn symlink_at(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    target_address: u64,
    new_guest_dirfd: libc::c_int,
    new_path_address: u64,
) -> i64 {
    let target = match read_c_string(&ProviderMemory(memory), target_address, 4096) {
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

pub(super) fn fchmod(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Linux syscall argument decoding consumes only the low descriptor word.
    let guest_fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    let status = match fd_status_flags(host_fd) {
        Ok(status) => status,
        Err(error) => return error,
    };
    if status & libc::O_PATH != 0 {
        return negative_errno(libc::EBADF);
    }
    if state.proc_files.contains_key(&guest_fd) {
        // A classified procfs object must retain the mode that protects its
        // private carrier, independent of the supervisor's DAC credentials.
        // The guest models uid 0, for which native procfs mutation results can
        // differ from a non-root supervisor; this fail-closed guard is the
        // deliberate immutable-snapshot policy rather than a credential oracle.
        return negative_errno(libc::EPERM);
    }
    if mode_locked_carrier(state, guest_fd) {
        return negative_errno(libc::EPERM);
    }
    let mode = args[1] as libc::mode_t & 0o7777;
    // SAFETY: host_fd names a live descriptor and mode is bounded to permission bits.
    zero_or_errno(unsafe { libc::fchmod(host_fd, mode) })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/933):
// Review the fixed-timestamp classes of backend-made carriers.
/// Whether `guest_fd` is a `/proc` snapshot carrier in a run that reports
/// host metadata timestamps, whose mode a guest may not change.
/// The receiver of an O_PATH right for such a carrier reopens it to read its
/// seals (see `carrier_seals`), which a mode without read permission would
/// prevent, and the carrier would then report its host timestamps. Linux
/// refuses a mode change on a `/proc` file with EPERM. A received snapshot
/// has no `proc_files` entry, so its identity answers here.
fn mode_locked_carrier(state: &LoadedStaticElf, guest_fd: libc::c_int) -> bool {
    state.host_metadata_timestamps
        && state
            .fd_object_inodes
            .get(&guest_fd)
            .is_some_and(|identity| identity.timestamps == IdentityTimestamps::ProcSnapshot)
}

pub(super) fn fchmodat(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    raw_mode: u64,
    raw_flags: u64,
) -> i64 {
    // TODO-HUMAN-REVIEW(PR-532): Review fchmodat2 flag handling, guest path
    // translation, and held-target mutation against Linux semantics.
    let flags = raw_flags as libc::c_int;
    let allowed_flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    if flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    let allow_empty = flags & libc::AT_EMPTY_PATH != 0;
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/933):
    // Review the errno of an empty-path mode change on a live /proc file.
    // Linux refuses a mode change on a live process /proc file with EPERM, as
    // fchmod reports here; the empty-path check in read_path_at would report
    // EACCES. A run with the setting off keeps the EACCES it always had.
    if allow_empty && state.host_metadata_timestamps && state.proc_files.contains_key(&guest_dirfd)
    {
        match read_c_string(&ProviderMemory(memory), path_address, 4096) {
            Ok(path) if path.is_empty() => return negative_errno(libc::EPERM),
            Ok(_) => {}
            Err(error) => return read_c_string_errno(error),
        }
    }
    let (host_dirfd, path) =
        match read_path_at(memory, state, guest_dirfd, path_address, allow_empty) {
            Ok(path) => path,
            Err(error) => return error,
        };
    let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
    let opened_file = if path.to_bytes().is_empty() {
        if state.proc_files.contains_key(&guest_dirfd) {
            return negative_errno(libc::EACCES);
        }
        if mode_locked_carrier(state, guest_dirfd) {
            return negative_errno(libc::EPERM);
        }
        if let Err(error) = ensure_fd_not_procfs(host_dirfd) {
            return error;
        }
        None
    } else {
        match open_host_metadata_path(state, host_dirfd, &path, nofollow) {
            Ok(file) => Some(file),
            Err(error) => return error,
        }
    };
    let target_fd = match opened_file.as_ref() {
        Some(file) => file.as_raw_fd(),
        None => host_dirfd,
    };
    let mode = raw_mode as libc::mode_t & 0o7777;
    let empty_path = b"\0";
    let host_flags = libc::AT_EMPTY_PATH | (flags & libc::AT_SYMLINK_NOFOLLOW);
    // Mutate the checked inode rather than re-resolving the guest pathname.
    // SAFETY: target_fd is live through opened_file or guest descriptor state,
    // and empty_path is terminated.
    let mut result = unsafe {
        libc::syscall(
            libc::SYS_fchmodat2,
            target_fd,
            empty_path.as_ptr(),
            mode,
            host_flags,
        )
    };
    if result < 0
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL)
        )
    {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: target_fd is live and stat is writable.
        if unsafe { libc::fstat(target_fd, stat.as_mut_ptr()) } != 0 {
            return io_error(std::io::Error::last_os_error());
        }
        // SAFETY: fstat initialized stat on success.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return negative_errno(libc::EOPNOTSUPP);
        }
        // Hosts before fchmodat2 can still mutate the held, checked inode
        // through a supervisor-generated descriptor path. This never
        // re-resolves guest-controlled path components.
        let proc_path = CString::new(format!("/proc/self/fd/{target_fd}"))
            .expect("supervisor fd path has no NUL");
        // SAFETY: proc_path identifies the descriptor held above.
        result = unsafe { libc::fchmodat(libc::AT_FDCWD, proc_path.as_ptr(), mode, 0) } as _;
    }
    zero_or_errno(result as libc::c_int)
}

pub(super) fn mknod_at(
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
pub(super) const DETERMINISTIC_METADATA_SECONDS: libc::time_t = 1_640_995_199;

pub(super) fn utimensat(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let raw_flags = args[3] as libc::c_int;
    let allowed_flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    if raw_flags & !allowed_flags != 0 {
        return negative_errno(libc::EINVAL);
    }
    let requested_times = if args[2] == 0 {
        None
    } else {
        match read_guest_struct::<[libc::timespec; 2]>(&ProviderMemory(memory), args[2]) {
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
        if let Err(error) = ensure_mutation_dirfd_not_synthetic_procfs(state, guest_fd, b"") {
            return error;
        }
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
            let file = match open_host_metadata_path(state, host_dirfd, &path, nofollow) {
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

/// Linux's getcwd walks the working directory at the call
/// (https://github.com/torvalds/linux/blob/v6.18/fs/d_path.c#L412), so a
/// renamed directory reports its new name and a removed one gets ENOENT,
/// before any size check. The host kernel's d_path of the cwd handle is the
/// same walk; it marks a removed directory, Linux's d_unlinked test, with a
/// " (deleted)" suffix, and a zero link count tells that from a directory
/// really named that way.
pub(super) fn getcwd(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let fd = state.cwd_fd.as_raw_fd();
    let path = canonical_fd_path(fd);
    let maybe_removed = match &path {
        Ok(path) => path.as_os_str().as_bytes().ends_with(b" (deleted)"),
        Err(error) => *error == negative_errno(libc::ENAMETOOLONG),
    };
    if maybe_removed {
        // SAFETY: an all-zero stat is a valid output buffer.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fd is the live cwd handle and stat is writable.
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return io_error(std::io::Error::last_os_error());
        }
        if stat.st_nlink == 0 {
            return negative_errno(libc::ENOENT);
        }
    }
    let path = match path {
        Ok(path) => path,
        Err(error) => return error,
    };
    let bytes = path.as_os_str().as_bytes();
    let required = bytes.len() + 1;
    if (args[1] as usize) < required {
        return negative_errno(libc::ERANGE);
    }
    let mut terminated = Vec::with_capacity(required);
    terminated.extend_from_slice(bytes);
    terminated.push(0);
    // copy_to_user: respects guest write permissions and keeps the copied
    // prefix when a later page faults.
    match memory.user().copy_to_user(args[0], &terminated) {
        Ok(()) => required as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(reverie-kvm): Review KVM guest chdir/fchdir cwd semantics.
//
// `chdir`/`fchdir` update the emulated working directory that `getcwd` reports
// and that relative-path resolution (`host_dirfd_and_path`) resolves against.
// Both replace `state.cwd_fd` with a fresh `O_PATH|O_DIRECTORY` handle so cwd
// identity survives host renames (the same invariant `cwd_fd` had at load).
// `getcwd` walks that handle at each call; `state.cwd` keeps the path at the
// last change for exec's relative paths and the synthetic /proc/self/cwd.
pub(super) fn chdir(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let path = match read_c_string(&ProviderMemory(memory), args[0], 4096) {
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
    let directory = match open_cwd_directory(state, host_dirfd, &path) {
        Ok(directory) => directory,
        Err(error) => return error,
    };
    set_cwd(state, directory)
}

pub(super) fn fchdir(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Linux consumes the low descriptor word, ignoring the upper register bits.
    // Allocated guest fds are in 0..GUEST_NOFILE_LIMIT, so signed-negative low
    // words miss this table just like Linux's out-of-range unsigned descriptors.
    let fd = args[0] as libc::c_int;
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    // Rejects non-directories (ENOTDIR) and O_PATH descriptors (EBADF), matching
    // this backend's current readable-directory restriction, not Linux's
    // O_PATH fchdir behavior.
    if let Err(error) = ensure_directory(file) {
        return error;
    }
    // Reopen the directory itself ("." relative to the guest's own descriptor)
    // as an independent O_PATH cwd handle so a later guest `close(fd)` cannot
    // invalidate the working directory.
    let directory = match open_cwd_directory(state, file.as_raw_fd(), c".") {
        Ok(directory) => directory,
        Err(error) => return error,
    };
    set_cwd(state, directory)
}

/// Open `path` (relative to `host_dirfd`) as an `O_PATH|O_DIRECTORY` handle
/// suitable for use as `state.cwd_fd`. `O_DIRECTORY` yields `ENOTDIR` for a
/// non-directory, and procfs (`EACCES`) and the Tool's reserved directory
/// (`ENOENT`) are refused, keeping cwd within the same isolation boundary as
/// [`open_file`].
fn open_cwd_directory(
    state: &LoadedStaticElf,
    host_dirfd: RawFd,
    path: &CStr,
) -> Result<std::fs::File, i64> {
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
    ensure_path_object_allowed(state, &file)?;
    Ok(file)
}

/// Commit `directory` as the new working directory, recording its canonical
/// path in `state.cwd` for the callers that still read the string.
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
pub(super) fn canonical_fd_path(fd: RawFd) -> Result<std::path::PathBuf, i64> {
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    let count = read_fd_link_into(fd, &mut buffer)?;
    buffer.truncate(count);
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
        buffer,
    )))
}

/// Whether `/proc/self/fd/<fd>` names exactly `expected`: the answer of
/// `canonical_fd_path(fd).is_ok_and(|target| target == expected)`, from the
/// same `readlink`, into a stack buffer instead of a `PATH_MAX` heap one.
/// The buffer is longer than `expected`, so a longer target, which
/// `readlink` truncates to the buffer, never reads as equal; a failed read
/// is no match, as it is for `canonical_fd_path`.
pub(super) fn fd_link_target_is<const N: usize>(fd: RawFd, expected: &[u8; N]) -> bool {
    const CAPACITY: usize = 64;
    const { assert!(N < CAPACITY) };
    let mut buffer = [0u8; CAPACITY];
    read_fd_link_into(fd, &mut buffer).is_ok_and(|count| buffer[..count] == expected[..])
}

/// `readlink` of the supervisor's `/proc/self/fd/<fd>` into `buffer`,
/// returning the number of bytes it stored (truncated to the buffer, as
/// `readlink` truncates).
pub(super) fn read_fd_link_into(fd: RawFd, buffer: &mut [u8]) -> Result<usize, i64> {
    let proc_path = ProcSelfFdPath::new(fd);
    // SAFETY: proc_path is NUL-terminated and buffer is writable for its length.
    let count = unsafe {
        libc::readlink(
            proc_path.as_c_str().as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
        )
    };
    if count < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(count as usize)
}

pub(super) fn getdents64<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    // Linux consumes both descriptor and count as unsigned 32-bit arguments.
    // Narrow count before applying our host I/O cap: high register bits must
    // not turn a zero or undersized Linux buffer into a 16 MiB request.
    let fd = args[0] as libc::c_int;
    let requested_length = (args[2] as u32) as usize;
    let length = requested_length.min(MAX_HOST_IO);
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_directory(file) {
        return error;
    }
    // Let the kernel write through a protected shared alias. A snapshot/copyback
    // would clobber concurrent guest writes to untouched padding or the tail,
    // including when EOF produces no output at all.
    let alias = match memory.lend_mut(args[1], length) {
        Ok(alias) => alias,
        // Construction finalizes ownership and releases memory locks before
        // publishing any infrastructure failure to the gate. The driver must
        // observe that terminal cause before guest/Tool continuation; do not
        // publish it a second time merely because its cleanup was retained.
        Err(_) => return negative_errno(libc::EFAULT),
    };
    // SAFETY: file owns a live descriptor; alias retains the current backing,
    // permissions and host-copy locks for the requested bounded kernel operand.
    let count = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            file.as_raw_fd(),
            alias.host_pointer(),
            length,
        )
    };
    // Capture errno before dropping the alias invokes munmap.
    let result = if count < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        count as i64
    };
    if alias.finish().is_err() {
        // Refused physical retirement is already a sticky backend failure,
        // including after a successful host syscall. This placeholder errno
        // cannot authorize guest/Tool continuation past the driver's recheck.
        return negative_errno(libc::EFAULT);
    }
    result
}

pub(super) fn is_open_standard(state: &LoadedStaticElf, guest_fd: libc::c_int) -> bool {
    (0..=2).contains(&guest_fd)
        && (guest_fd != libc::STDIN_FILENO || state.stdin.is_some())
        && !state.closed_standard_fds.contains(&guest_fd)
        && !state.files.contains_key(&guest_fd)
}

pub(super) fn host_fd(state: &LoadedStaticElf, guest_fd: libc::c_int) -> Option<RawFd> {
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
/// EBADF for an O_PATH descriptor, refused where Linux's filtered descriptor
/// lookup refuses it, before any operand is checked or copied: fcntl lets an
/// O_PATH descriptor run only its descriptor-flag, status-flag and
/// duplication commands (every lock command fails before its flock structure
/// is copied), and fallocate, readahead and sync_file_range look their
/// descriptor up with fdget before checking their ranges.
fn refuse_o_path_descriptor(host_fd: RawFd) -> Result<(), i64> {
    if fd_status_flags(host_fd)? & libc::O_PATH != 0 {
        Err(negative_errno(libc::EBADF))
    } else {
        Ok(())
    }
}

pub(super) fn fcntl(memory: &GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    let source_alias = output_alias(state, guest_fd);
    let source_proc_inode = state.proc_files.get(&guest_fd).copied();
    let source_synthetic_proc_nofollow = state.synthetic_proc_nofollow_fds.contains(&guest_fd);
    let source_fdinfo = state.fdinfo_files.get(&guest_fd).cloned();
    let source_native_poll = native_poll_description(state, guest_fd);
    let source_signalfd_mask = signalfd_mask(state, guest_fd);
    let source_pipe_owner = state.pipe_owners.get(&guest_fd).cloned();
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    let source_object_inode = guest_fd_object_identity(state, guest_fd);
    match args[1] as libc::c_int {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-910): Review bounded pipe-owner configuration dispatch.
        command @ (libc::F_SETOWN
        | libc::F_GETOWN
        | LINUX_F_SETOWN_EX
        | LINUX_F_GETOWN_EX
        | LINUX_F_SETSIG
        | LINUX_F_GETSIG) => pipe_owner::fcntl(memory, state, guest_fd, host_fd, command, args[2]),
        libc::F_DUPFD => duplicate_fd_at_or_above(
            state,
            host_fd,
            args[2],
            false,
            DuplicateFdSource {
                output_alias: source_alias,
                proc_inode: source_proc_inode,
                synthetic_proc_nofollow: source_synthetic_proc_nofollow,
                fdinfo: source_fdinfo,
                object_inode: source_object_inode,
                signalfd_mask: source_signalfd_mask,
                native_poll: source_native_poll,
                pipe_owner: source_pipe_owner,
            },
        ),
        libc::F_DUPFD_CLOEXEC => duplicate_fd_at_or_above(
            state,
            host_fd,
            args[2],
            true,
            DuplicateFdSource {
                output_alias: source_alias,
                proc_inode: source_proc_inode,
                synthetic_proc_nofollow: source_synthetic_proc_nofollow,
                fdinfo: source_fdinfo,
                object_inode: source_object_inode,
                signalfd_mask: source_signalfd_mask,
                native_poll: source_native_poll,
                pipe_owner: source_pipe_owner,
            },
        ),
        libc::F_GETFL => match fd_status_flags(host_fd) {
            Ok(flags) => i64::from(
                match signalfd_carrier(state, guest_fd) {
                    // The host keeper is always nonblocking; report the
                    // guest description's own mode.
                    Some(carrier) if carrier.guest_blocking() => flags & !libc::O_NONBLOCK,
                    Some(_) => flags | libc::O_NONBLOCK,
                    None => flags,
                } | if source_synthetic_proc_nofollow {
                    libc::O_NOFOLLOW
                } else {
                    0
                } | if source_fdinfo
                    .as_ref()
                    .is_some_and(|info| info.nofollow_status)
                {
                    libc::O_NOFOLLOW
                } else {
                    0
                },
            ),
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
            if source_fdinfo.is_some() && flags & libc::O_DIRECT != 0 {
                // proc fdinfo lacks FMODE_CAN_ODIRECT, unlike its private
                // memfd carrier. Reject before applying any requested status
                // changes, including changes shared by descriptor aliases.
                return negative_errno(libc::EINVAL);
            }
            if source_signalfd_mask.is_some() {
                // The guest's O_NONBLOCK belongs to the keeper, shared by
                // every alias; the host keeper itself stays nonblocking.
                let Some(carrier) = signalfd_carrier(state, guest_fd) else {
                    return negative_errno(libc::EBADF);
                };
                // SAFETY: host_fd names a live descriptor; F_SETFL consumes one int flag word.
                let result = zero_or_errno(unsafe {
                    libc::fcntl(host_fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
                });
                if result == 0 {
                    carrier.set_guest_blocking(flags & libc::O_NONBLOCK == 0);
                }
                return result;
            }
            if flags & libc::O_NONBLOCK == 0 {
                // Blocking inotify waits are refused the same way.
                match host_fd_is_inotify(host_fd) {
                    Ok(true) => return negative_errno(libc::ENOSYS),
                    Ok(false) => {}
                    Err(error) => return error,
                }
            }
            // SAFETY: host_fd names a live descriptor; F_SETFL consumes one int flag word.
            if let Some(owner) = source_pipe_owner {
                owner.set_flags(host_fd, flags)
            } else {
                zero_or_errno(unsafe { libc::fcntl(host_fd, libc::F_SETFL, flags) })
            }
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-211): Review KVM advisory-lock forwarding.
        command @ (libc::F_SETLK | libc::F_SETLKW | libc::F_OFD_SETLK | libc::F_OFD_SETLKW) => {
            if let Err(error) = refuse_o_path_descriptor(host_fd) {
                return error;
            }
            let mut lock = match read_guest_struct::<libc::flock>(&ProviderMemory(memory), args[2])
            {
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
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-1016): Review KVM advisory-lock queries.
        // The lock model above installs every guest lock as an OFD lock on the
        // shared open description, so a query asks the same question of the
        // host: F_GETLK becomes F_OFD_GETLK. The host answers with the first
        // conflicting lock or F_UNLCK, and the result is copied back as
        // fcntl(2) does. A conflicting holder is an OFD lock, which Linux
        // reports with l_pid -1, so a guest F_GETLK never sees a host pid.
        command @ (libc::F_GETLK | libc::F_OFD_GETLK) => {
            if let Err(error) = refuse_o_path_descriptor(host_fd) {
                return error;
            }
            let mut lock = match read_guest_struct::<libc::flock>(&ProviderMemory(memory), args[2])
            {
                Ok(lock) => lock,
                Err(error) => return error,
            };
            let host_command = if command == libc::F_GETLK {
                lock.l_pid = 0;
                libc::F_OFD_GETLK
            } else {
                command
            };
            // SAFETY: host_fd is live and lock is a fully initialized flock
            // value the kernel overwrites in place.
            let result = zero_or_errno(unsafe { libc::fcntl(host_fd, host_command, &mut lock) });
            if result != 0 {
                return result;
            }
            // SAFETY: flock is initialized plain data; the view is bounded to it.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::from_ref(&lock).cast::<u8>(),
                    std::mem::size_of::<libc::flock>(),
                )
            };
            match memory.user().write(args[2], bytes) {
                Ok(()) => 0,
                Err(_) => negative_errno(libc::EFAULT),
            }
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(rrnewton/reverie#318): Review KVM guest pipe-capacity
        // fcntl forwarding. F_GETPIPE_SZ/F_SETPIPE_SZ read and set the capacity
        // of the real host pipe that backs the guest pipe, matching the golden
        // ptrace backend's syscall behavior. Initial capacity and permission to
        // grow are host-global properties affected by per-user pipe quotas, so
        // deterministic tools must establish their own capacity before exposing
        // it. Without this route the executor fell through to ENOSYS, so a guest
        // querying or setting pipe capacity could not implement that policy.
        libc::F_GETPIPE_SZ => {
            // SAFETY: host_fd names a live descriptor; F_GETPIPE_SZ takes no third argument.
            let result = unsafe { libc::fcntl(host_fd, libc::F_GETPIPE_SZ) };
            if result < 0 {
                io_error(std::io::Error::last_os_error())
            } else {
                i64::from(result)
            }
        }
        libc::F_SETPIPE_SZ => {
            let size = args[2] as libc::c_int;
            // SAFETY: host_fd names a live descriptor; F_SETPIPE_SZ consumes one int size.
            let result = unsafe { libc::fcntl(host_fd, libc::F_SETPIPE_SZ, size) };
            if result < 0 {
                io_error(std::io::Error::last_os_error())
            } else {
                i64::from(result)
            }
        }
        _ => negative_errno(libc::ENOSYS),
    }
}

pub(super) fn host_dirfd_and_path(
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
pub(super) fn close(state: &mut LoadedStaticElf, raw_fd: u64) -> i64 {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    // Linux consumes the low unsigned-int descriptor word from the syscall
    // register. The guest table uses c_int keys, so preserve those exact bits.
    let fd = raw_fd as libc::c_int;
    if let Some(retired) = state.remove_file(fd) {
        // A removed guest stdio slot must not revive the supervisor stream.
        if (0..=2).contains(&fd) {
            state.closed_standard_fds.insert(fd);
        }
        state.cloexec_fds.remove(&fd);
        replace_signalfd_mask(state, fd, None);
        state.proc_files.remove(&fd);
        state.synthetic_proc_nofollow_fds.remove(&fd);
        state.fdinfo_files.remove(&fd);
        state.fd_object_inodes.remove(&fd);
        cleanup_fd_object_inodes(state);
        set_output_alias(state, fd, None);
        drop(_transaction);
        state.file_retirement.retire([retired]);
        return 0;
    }
    if is_open_standard(state, fd) {
        let retired = if fd == libc::STDIN_FILENO {
            state.take_stdin()
        } else {
            None
        };
        state.closed_standard_fds.insert(fd);
        state.cloexec_fds.remove(&fd);
        replace_signalfd_mask(state, fd, None);
        state.fd_object_inodes.remove(&fd);
        cleanup_fd_object_inodes(state);
        set_output_alias(state, fd, None);
        drop(_transaction);
        state.file_retirement.retire(retired);
        return 0;
    }
    negative_errno(libc::EBADF)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#340): close_range(2) closes every open guest
// descriptor in the inclusive interval [first, last]. The KVM guest owns one
// logical descriptor table per process. CLOSE_RANGE_UNSHARE is currently
// accepted as a process-wide approximation, not Linux per-caller unsharing; a
// live CLONE_FILES sibling therefore remains an explicit unsupported parity
// case. CLOSE_RANGE_CLOEXEC marks the range close-on-exec instead of closing it.
// The scan is bounded to the descriptors actually open (keys of `state.files`
// plus any open standard fd), so a `last == U32::MAX` request never walks a
// four-billion-wide interval.
pub(super) fn close_range(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

    // All three syscall arguments are unsigned int on Linux. Ignore register
    // high bits before validating bounds and flags or selecting descriptors.
    let first = args[0] as u32;
    let last = args[1] as u32;
    let flags = args[2] as u32;
    if first > last {
        return negative_errno(libc::EINVAL);
    }
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return negative_errno(libc::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        // This backend's existing close_range path does not split CLONE_FILES.
        // Preserve that syscall's outcome, but do not admit new epoll waits or
        // pipe-owner configuration after this unmodeled table history,
        // including CLOEXEC-only requests. Permanent pipe export/async guards
        // remain attached to their shared descriptions independently.
        let _domain = state
            .epoll_domain
            .lock()
            .expect("KVM epoll provenance lock poisoned");
        state
            .poll_table_id
            .unsafe_history
            .store(true, Ordering::SeqCst);
    }

    let in_range = |fd: libc::c_int| {
        let fd = fd as u32;
        first <= fd && fd <= last
    };
    let mut targets: Vec<libc::c_int> = state
        .files
        .keys()
        .copied()
        .filter(|&fd| in_range(fd))
        .collect();
    for standard in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if in_range(standard) && is_open_standard(state, standard) {
            targets.push(standard);
        }
    }

    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        for fd in targets {
            state.cloexec_fds.insert(fd);
        }
        return 0;
    }

    for fd in targets {
        // Reuse the single-fd close path so every descriptor side table stays
        // consistent. Each fd is known open here, so close never returns EBADF.
        close(state, u64::from(fd as u32));
    }
    0
}

pub(super) fn arch_prctl(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> SyscallAction {
    match args[0] {
        ARCH_SET_FS | ARCH_SET_GS
            if args[1] < memory.guest_end()
                || range_is_valid(&ProviderMemory(memory), args[1], 1) =>
        {
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
        ARCH_GET_FS => continue_with(write_u64(
            &mut ProviderMemory(memory),
            args[1],
            state.fs_base,
        )),
        ARCH_GET_GS => continue_with(write_u64(
            &mut ProviderMemory(memory),
            args[1],
            state.gs_base,
        )),
        _ => continue_with(negative_errno(libc::EINVAL)),
    }
}

// TODO-HUMAN-REVIEW(PR-136): Review shared readlink guest path handling.
pub(super) fn readlink(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture: Option<CaptureMetadata>,
) -> i64 {
    readlink_at_impl(
        memory,
        state,
        libc::AT_FDCWD,
        args[0],
        args[1],
        args[2],
        capture,
    )
}

// TODO-HUMAN-REVIEW(PR-136): Review readlinkat guest-dirfd and procfd semantics.
pub(super) fn readlinkat(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture: Option<CaptureMetadata>,
) -> i64 {
    readlink_at_impl(
        memory,
        state,
        args[0] as libc::c_int,
        args[1],
        args[2],
        args[3],
        capture,
    )
}

// TODO-HUMAN-REVIEW(PR-136): Review shared readlinkat implementation semantics.
pub(super) fn readlink_at_impl(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    output_address: u64,
    raw_capacity: u64,
    capture: Option<CaptureMetadata>,
) -> i64 {
    let path = match read_c_string(&ProviderMemory(memory), path_address, 4096) {
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
        let target = match guest_fd_link_target(state, guest_fd, capture) {
            Ok(target) => target,
            Err(error) => return error,
        };
        let count = capacity.min(target.len());
        return match memory.user().write(output_address, &target[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }

    let normalized = normalize_proc_path(state, &path);
    let executable_target = match guest_proc_exe_path(state, &path) {
        Some(true) => match state.executable_file.as_ref() {
            Some(file) => match canonical_fd_path(file.as_raw_fd()) {
                Ok(path) => Some(path.into_os_string().into_vec()),
                Err(error) => return error,
            },
            None => Some(state.executable_path.as_os_str().as_bytes().to_vec()),
        },
        Some(false) => return negative_errno(libc::ENOENT),
        None => None,
    };
    let proc_link_target: Option<&[u8]> = if let Some(target) = executable_target.as_deref() {
        Some(target)
    } else {
        match normalized.as_deref() {
            Some(b"/proc/self/cwd") => Some(state.cwd.as_os_str().as_bytes()),
            Some(b"/proc/self/root") => Some(b"/"),
            _ => None,
        }
    };
    if let Some(target) = proc_link_target {
        let count = capacity.min(target.len());
        let copied = if executable_target.is_some() {
            memory.user().copy_to_user(output_address, &target[..count])
        } else {
            memory.user().write(output_address, &target[..count])
        };
        return match copied {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        };
    }
    // Any other procfs link, `/proc/self` included, is the supervisor's, not
    // the guest's: open_metadata_path refuses it with EACCES. The Tool
    // decides the guest's links (Detcore renders `/proc/self` itself).
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
    match memory.user().write(output_address, &bytes[..count]) {
        Ok(()) => count as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}
