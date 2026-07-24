/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CString;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

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
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
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
    } else if number == libc::SYS_pread64 as u64 {
        pread64(memory, state, args)
    } else if number == libc::SYS_open as u64 {
        open(memory, state, args)
    } else if number == libc::SYS_openat as u64 {
        openat(memory, state, args)
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
    } else if number == libc::SYS_access as u64 {
        access(memory, state, args)
    } else if number == libc::SYS_getcwd as u64 {
        getcwd(memory, state, args)
    } else if number == libc::SYS_getdents64 as u64 {
        getdents64(memory, state, args)
    } else if number == libc::SYS_getpid as u64
        || number == libc::SYS_gettid as u64
        || number == libc::SYS_getppid as u64
    {
        1
    } else if number == libc::SYS_getuid as u64
        || number == libc::SYS_geteuid as u64
        || number == libc::SYS_getgid as u64
        || number == libc::SYS_getegid as u64
    {
        0
    } else if number == libc::SYS_arch_prctl as u64 {
        return arch_prctl(memory, state, args);
    } else if number == libc::SYS_brk as u64 {
        brk(memory, state, args[0])
    } else if number == libc::SYS_mmap as u64 {
        mmap(memory, state, args)
    } else if number == libc::SYS_munmap as u64 {
        munmap(memory, args[0], args[1])
    } else if number == libc::SYS_mprotect as u64 || number == libc::SYS_madvise as u64 {
        validate_range(memory, args[0], args[1])
    } else if number == libc::SYS_getrandom as u64 {
        getrandom(memory, args[0], args[1])
    } else if number == libc::SYS_clock_gettime as u64 {
        write_bytes(memory, args[1], &[0; 16])
    } else if number == libc::SYS_readlink as u64 {
        readlink(memory, state, args)
    } else if number == libc::SYS_uname as u64 {
        uname(memory, args[0])
    } else if number == libc::SYS_prlimit64 as u64 {
        prlimit64(memory, args)
    } else if number == libc::SYS_rt_sigaction as u64 {
        if args[2] == 0 {
            0
        } else {
            write_bytes(memory, args[2], &[0; 32])
        }
    } else if number == libc::SYS_rt_sigprocmask as u64 {
        if args[2] == 0 {
            0
        } else {
            write_bytes(memory, args[2], &[0; 8])
        }
    } else if number == libc::SYS_set_tid_address as u64 {
        1
    } else if number == libc::SYS_close as u64 {
        close(state, args[0])
    } else if number == libc::SYS_set_robust_list as u64
        || number == libc::SYS_sigaltstack as u64
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
    pending_segment: Option<(SegmentBase, u64)>,
    exit_code: Option<i32>,
}

impl ElfExecutor {
    pub(crate) fn new(state: LoadedStaticElf, capture_output: bool) -> Self {
        Self {
            state,
            output: capture_output.then(CapturedOutput::default),
            pending_segment: None,
            exit_code: None,
        }
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

fn file_status_flags(file: &std::fs::File) -> Result<libc::c_int, i64> {
    // SAFETY: file owns a live descriptor and F_GETFL takes no third argument.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        Ok(flags)
    }
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
    let flags = file_status_flags(file)?;
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

    if standard && (fd == libc::STDOUT_FILENO || fd == libc::STDERR_FILENO) {
        if let Some(output) = output {
            let destination = if fd == libc::STDOUT_FILENO {
                &mut output.stdout
            } else {
                &mut output.stderr
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
        return host_write(fd, &bytes);
    }
    if standard {
        return state
            .stdin
            .as_mut()
            .expect("open standard input disappeared")
            .write(&bytes)
            .map_or_else(io_error, |count| count as i64);
    }

    state
        .files
        .get_mut(&fd)
        .expect("owned descriptor disappeared")
        .write(&bytes)
        .map_or_else(io_error, |count| count as i64)
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
    let Ok((host_dirfd, path)) = host_dirfd_and_path(state, guest_dirfd, &path) else {
        return negative_errno(libc::EBADF);
    };
    let flags = u64::from(raw_flags as libc::c_int as u32) & LEGACY_OPEN_FLAGS;
    let uses_mode = flags & libc::O_CREAT as u64 != 0
        || flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64;
    let mode = if uses_mode {
        u64::from(raw_mode as libc::mode_t & 0o7777)
    } else {
        0
    };
    let how = OpenHow {
        flags,
        mode,
        resolve: RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: path and how are live for the call. Linux validates the supplied
    // descriptor, flags, mode, and openat2 resolve policy.
    let host_fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            host_dirfd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: openat2 returned a new owned descriptor on success.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd as RawFd) };
    if let Err(error) = ensure_not_procfs(&file) {
        return error;
    }
    insert_file(state, file)
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

fn insert_file(state: &mut LoadedStaticElf, file: std::fs::File) -> i64 {
    let Some(fd) =
        (0..=i32::MAX).find(|fd| !is_open_standard(state, *fd) && !state.files.contains_key(fd))
    else {
        return negative_errno(libc::EMFILE);
    };
    state.files.insert(fd, file);
    i64::from(fd)
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
    write_struct(memory, args[1], &unsafe { stat.assume_init() })
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

    let opened_file;
    let host_fd = if path.is_empty() {
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
    write_struct(memory, output_address, &unsafe { stat.assume_init() })
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

    let opened_file;
    let host_fd = if path.is_empty() {
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
    write_struct(memory, args[4], &unsafe { stat.assume_init() })
}

fn access(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let mode = args[1] as libc::c_int;
    if mode & !(libc::R_OK | libc::W_OK | libc::X_OK) != 0 {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(memory, args[0], 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() {
        return negative_errno(libc::ENOENT);
    }
    let file = match open_metadata_path(state, libc::AT_FDCWD, &path, false) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let empty_path = b"\0";
    // SAFETY: empty_path is NUL-terminated and file owns a live O_PATH fd.
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            file.as_raw_fd(),
            empty_path.as_ptr(),
            mode,
            libc::AT_EMPTY_PATH,
        )
    };
    if result == 0 {
        0
    } else {
        io_error(std::io::Error::last_os_error())
    }
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
        return 0;
    }
    if is_open_standard(state, fd) {
        if fd == libc::STDIN_FILENO {
            state.stdin.take();
        }
        state.closed_standard_fds.insert(fd);
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

fn validate_range(memory: &GuestMemory, address: u64, length: u64) -> i64 {
    if length == 0 || !range_is_valid(memory, address, length) {
        negative_errno(libc::EINVAL)
    } else {
        0
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
    let limit = STACK_LIMIT;
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&limit.to_le_bytes());
    bytes[8..].copy_from_slice(&limit.to_le_bytes());
    write_bytes(memory, args[3], &bytes)
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
            files: BTreeMap::new(),
            closed_standard_fds: BTreeSet::new(),
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
}
