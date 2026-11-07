/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! read, write and their positioned, vectored and sendfile forms (gVisor: pkg/sentry/syscalls/linux/sys_read_write.go).

use super::*;

pub(super) fn fd_status_flags(fd: RawFd) -> Result<libc::c_int, i64> {
    // SAFETY: fd names a live descriptor and F_GETFL takes no third argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        Ok(flags)
    }
}

pub(super) fn file_status_flags(file: &std::fs::File) -> Result<libc::c_int, i64> {
    fd_status_flags(file.as_raw_fd())
}

pub(super) fn fd_mode(fd: RawFd) -> Result<libc::mode_t, i64> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and fd is live.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    Ok(unsafe { stat.assume_init() }.st_mode)
}

pub(super) fn file_mode(file: &std::fs::File) -> Result<libc::mode_t, i64> {
    fd_mode(file.as_raw_fd())
}

/// Linux's random character devices, /dev/random (1:8) and /dev/urandom
/// (1:9), recognized by device number, as Linux binds their operations. Used
/// only to route their reads to the Tool (see `is_tool_visible_read`).
pub(super) fn is_random_character_device(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    metadata.file_type().is_char_device()
        && libc::major(metadata.rdev()) == 1
        && matches!(libc::minor(metadata.rdev()), 8 | 9)
}

/// Whether a description's status flags grant read access. Linux's open gives
/// FMODE_READ only to O_RDONLY and O_RDWR: access mode 3 (O_ACCMODE) grants
/// neither read nor write, and an O_PATH descriptor grants no I/O at all.
fn status_grants_read(flags: libc::c_int) -> bool {
    flags & libc::O_PATH == 0 && matches!(flags & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR)
}

/// Whether a description's status flags grant write access (FMODE_WRITE):
/// only O_WRONLY and O_RDWR, as for [`status_grants_read`].
fn status_grants_write(flags: libc::c_int) -> bool {
    flags & libc::O_PATH == 0 && matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
}

fn ensure_read_access_fd(fd: RawFd) -> Result<(), i64> {
    let flags = fd_status_flags(fd)?;
    if !status_grants_read(flags) {
        return Err(negative_errno(libc::EBADF));
    }
    Ok(())
}

fn ensure_read_access(file: &std::fs::File) -> Result<(), i64> {
    ensure_read_access_fd(file.as_raw_fd())
}

pub(super) fn ensure_readable(file: &std::fs::File) -> Result<(), i64> {
    ensure_readable_fd(file.as_raw_fd())
}

fn ensure_readable_fd(fd: RawFd) -> Result<(), i64> {
    ensure_read_access_fd(fd)?;
    if fd_mode(fd)? & libc::S_IFMT == libc::S_IFDIR {
        return Err(negative_errno(libc::EISDIR));
    }
    Ok(())
}

/// `ensure_writable`, with the access mode recorded on `entry` when there is
/// one (it cannot change for the entry's description).
pub(super) fn ensure_writable_entry(
    entry: Option<&crate::elf::FdEntry>,
    file: &std::fs::File,
) -> Result<(), i64> {
    let Some(entry) = entry else {
        return ensure_writable(file);
    };
    let flags = entry.access(|| file_status_flags(file))?;
    if !status_grants_write(flags) {
        Err(negative_errno(libc::EBADF))
    } else {
        Ok(())
    }
}

/// `ensure_read_capable`, with the access mode and the read-capability probe
/// recorded on `entry` when there is one.
pub(super) fn ensure_read_capable_entry(
    entry: Option<&crate::elf::FdEntry>,
    file: &std::fs::File,
) -> Result<(), i64> {
    let Some(entry) = entry else {
        return ensure_read_capable(file);
    };
    let flags = entry.access(|| file_status_flags(file))?;
    if !status_grants_read(flags) {
        return Err(negative_errno(libc::EBADF));
    }
    entry.read_capable(|| read_capability_probe(file))
}

pub(super) fn ensure_writable(file: &std::fs::File) -> Result<(), i64> {
    ensure_writable_fd(file.as_raw_fd())
}

pub(super) fn ensure_writable_fd(fd: RawFd) -> Result<(), i64> {
    let flags = fd_status_flags(fd)?;
    if !status_grants_write(flags) {
        Err(negative_errno(libc::EBADF))
    } else {
        Ok(())
    }
}

pub(super) fn ensure_directory(file: &std::fs::File) -> Result<(), i64> {
    if file_status_flags(file)? & libc::O_PATH != 0 {
        return Err(negative_errno(libc::EBADF));
    }
    if file_mode(file)? & libc::S_IFMT != libc::S_IFDIR {
        return Err(negative_errno(libc::ENOTDIR));
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct ResolvedExecutable {
    pub(super) path: std::path::PathBuf,
    pub(super) file: Option<Arc<std::fs::File>>,
    pub(super) image: Vec<u8>,
}

pub(super) fn read_executable_file(
    state: &LoadedStaticElf,
    path: &std::path::Path,
) -> Result<ResolvedExecutable, i64> {
    use std::io::Read;
    let pinned = open_metadata_path(state, libc::AT_FDCWD, path.as_os_str().as_bytes(), false)?;
    let mut file =
        std::fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd())).map_err(io_error)?;
    let mut image = Vec::new();
    file.read_to_end(&mut image).map_err(io_error)?;
    Ok(ResolvedExecutable {
        path: path.to_owned(),
        file: Some(Arc::new(file)),
        image,
    })
}

pub(super) fn resolve_guest_exec_image(
    state: &LoadedStaticElf,
    path: Vec<u8>,
    envp: &[String],
) -> Result<ResolvedExecutable, i64> {
    match guest_proc_exe_path(state, &path) {
        Some(true) => {
            let file = state
                .executable_file
                .as_ref()
                .ok_or_else(|| negative_errno(libc::ENOENT))?;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_faccessat2,
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    libc::X_OK,
                    libc::AT_EMPTY_PATH | libc::AT_EACCESS,
                )
            };
            if result != 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            return Ok(ResolvedExecutable {
                path: std::path::PathBuf::from(std::ffi::OsString::from_vec(path)),
                file: Some(file.clone()),
                image: state.executable_image.to_vec(),
            });
        }
        Some(false) => return Err(negative_errno(libc::ENOENT)),
        None => {}
    }
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(path));
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-kvm-execve-path): PATH resolution for a
    // slash-less execve program name. A bare name such as
    // `execve("bash", ...)` must be searched on PATH the same way the
    // initial ELF loader (elf::resolve_executable_path) and libc's execvp
    // do; joining a bare name onto cwd yields ENOENT and breaks every
    // KVM-backend corpus example launched by bare name (bash/python3).
    // Under the ptrace backend the initial launcher resolves the program
    // via execvp before the guest starts, so this restores parity for the
    // initial exec that Detcore re-injects with a rewritten path pointer.
    // Names that already contain a slash keep exact execve(2) semantics
    // (absolute used as-is, relative resolved against cwd) and are NOT
    // PATH-searched.
    let path = if path.is_absolute() || path.components().count() > 1 {
        if path.is_absolute() {
            path
        } else {
            state.cwd.join(path)
        }
    } else {
        let envp_refs = envp.iter().map(String::as_str).collect::<Vec<_>>();
        match resolve_executable_path(&path.to_string_lossy(), &envp_refs, &state.cwd) {
            Ok(resolved) => resolved,
            Err(_) => return Err(negative_errno(libc::ENOENT)),
        }
    };
    read_executable_file(state, &path)
}

/// Maximum `#!` interpreter indirection levels, matching the Linux kernel's
/// `BINPRM_MAX_RECURSION` limit for chained script interpreters.
pub(super) const MAX_SHEBANG_DEPTH: usize = 4;

/// Resolve `#!` interpreter scripts for in-guest `execve(2)`, mirroring the
/// kernel's `binfmt_script` loader (`fs/binfmt_script.c`).
///
/// The reverie-kvm ELF loader can only map ELF images, so a guest that execs a
/// `#!`-script (for example a `sh` wrapper that execs another wrapper) must have
/// its interpreter resolved here. On success the returned image is the
/// interpreter's file contents and `argv` is rewritten in kernel order:
/// `[interp, shebang_args.., script_path, <original argv[1..]>]`. Errors are
/// returned as negative errnos.
pub(super) fn resolve_exec_shebang(
    mut path: std::path::PathBuf,
    mut image: Vec<u8>,
    mut argv: Vec<String>,
    mut read_interpreter: impl FnMut(&std::path::Path) -> Result<Vec<u8>, i64>,
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
        image = read_interpreter(&path)?;
    }
    Ok((path, image, argv))
}

pub(super) fn ensure_read_capable(file: &std::fs::File) -> Result<(), i64> {
    ensure_read_access(file)?;
    read_capability_probe(file)
}

fn read_capability_probe(file: &std::fs::File) -> Result<(), i64> {
    // A zero-iovec readv tests FMODE_CAN_READ without consuming input or
    // invoking the descriptor's file-specific read implementation.
    let result = unsafe { libc::readv(file.as_raw_fd(), std::ptr::null::<libc::iovec>(), 0) };
    if result < 0 {
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub(super) fn write(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    output: Option<&mut CapturedOutput>,
) -> i64 {
    // Linux write consumes the low 32 descriptor bits, as vectored I/O does.
    let fd = args[0] as libc::c_int;
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
    let entry = (!standard)
        .then(|| state.fd_entry_ids.get(&fd))
        .flatten()
        .map(|entry| &**entry);
    if let Some(descriptor) = descriptor
        && let Err(error) = ensure_writable_entry(entry, descriptor)
    {
        return error;
    }
    // vfs_write checks the buffer's address range (access_ok) for the whole
    // count after the access mode and before anything is written, even when
    // the count is zero.
    if let Err(error) = validate_guest_iovec_address(args[1], requested_length) {
        return error;
    }
    if length == 0 {
        return 0;
    }

    // An owned descriptor writes through the host unless captured output
    // takes its bytes.
    if !standard && (output_destination.is_none() || output.is_none()) {
        let host_fd = state
            .files
            .get(&fd)
            .expect("owned descriptor disappeared")
            .as_raw_fd();
        let mut staged = match stage_guest_write(memory, host_fd, args[1], length) {
            Ok(staged) => staged,
            Err(error) => return error,
        };
        let (buffer, buffer_length) = staged.host_buffer();
        let private_pipe = private_pipe_owner(state, fd);
        let still_private = || private_pipe.is_some_and(|owner| owner.pair_never_exported());
        let pipe_requested = private_pipe.map(|_| (length, &still_private as &dyn Fn() -> bool));
        let (written, sigpipe) = suppress_host_sigpipe_reporting(pipe_requested, || {
            // SAFETY: the staged buffer is `length` live host bytes (a partly
            // readable one has its unreadable suffix PROT_NONE), and host_fd
            // is a live backing descriptor.
            unsafe { libc::write(host_fd, buffer, buffer_length) as i64 }
        });
        return with_guest_sigpipe(state, written, sigpipe);
    }

    let mut bytes = vec![0; length];
    if memory.user().read(args[1], &mut bytes).is_err() {
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
    debug_assert!(
        standard,
        "an owned descriptor writes through the staged path"
    );
    state
        .stdin
        .as_mut()
        .expect("open standard input disappeared")
        .write(&bytes)
        .map_or_else(io_error, |count| count as i64)
}

/// A guest write buffer staged for one host write.
pub(super) enum StagedWrite {
    /// The whole buffer was readable.
    Whole(Vec<u8>),
    /// Only a prefix was: see [`stage_guest_write`].
    Partial(StagedIoVector),
}

impl StagedWrite {
    /// The host buffer and its length, which is always the guest's length.
    fn host_buffer(&mut self) -> (*const libc::c_void, usize) {
        match self {
            Self::Whole(bytes) => (bytes.as_ptr().cast(), bytes.len()),
            Self::Partial(staged) => {
                let iovec = staged.host_iovec();
                (iovec.iov_base.cast_const(), iovec.iov_len)
            }
        }
    }
}

/// Stages a guest write buffer for one host write of `length` bytes, from one
/// snapshot of guest memory: the readable prefix is copied under a single
/// admission and permission transaction (`copy_from_user_prefix`), so the
/// bytes and the point where the buffer stops being readable come from the
/// same state. A buffer readable throughout is written as it is. One that
/// stops being readable part way is staged as that prefix in a private arena
/// whose remaining pages are PROT_NONE, so it reaches the host kernel with the
/// shape it had in the guest, and the kernel decides the result for its
/// object (a short count for a random device, EFAULT for some filesystems and
/// for a pipe, for example), as for vectored writes.
fn stage_guest_write(
    memory: &GuestMemory,
    host_fd: RawFd,
    address: u64,
    length: usize,
) -> Result<StagedWrite, i64> {
    let mut bytes = vec![0; length];
    let prefix = match memory.user().copy_from_user_prefix(address, &mut bytes) {
        Ok(prefix) => prefix,
        Err(
            crate::Error::InvalidGuestAddress { .. } | crate::Error::GuestMemoryAccessDenied { .. },
        ) => 0,
        Err(_) => return Err(negative_errno(libc::EFAULT)),
    };
    if prefix == length {
        return Ok(StagedWrite::Whole(bytes));
    }
    let vector = GuestIoVec {
        base: address,
        length,
    };
    let mut staged = StagedIoVector::new(vector, prefix, direct_io_memory_alignment(host_fd))?;
    if prefix != 0 {
        staged
            .accessible_slice_mut(prefix)
            .copy_from_slice(&bytes[..prefix]);
    }
    Ok(StagedWrite::Partial(staged))
}

/// The pipe-owner record of `fd` if it is a guest pipe end (pipe/pipe2 or a
/// duplicate; remove_file drops the record when the descriptor closes) whose
/// pipe is still private to the guest: neither end exported, nor reopened
/// through /proc/self/fd. Once one has been, a host fasync owner can make a
/// complete write raise SIGPIPE.
pub(super) fn private_pipe_owner(
    state: &LoadedStaticElf,
    fd: libc::c_int,
) -> Option<&Arc<pipe_owner::PipeOwner>> {
    state
        .pipe_owners
        .get(&fd)
        .filter(|owner| owner.pair_never_exported())
}

/// Linux raises SIGPIPE in the writing thread when a write fails because the
/// reading side is gone (`pipe_write`, `sk_stream_error`), even after a
/// partial count: `send_sig(SIGPIPE, current, 0)`, an SI_USER signal from the
/// caller's own process. The real kernel made that decision for the host
/// write `suppress_host_sigpipe_reporting` contained; this queues the guest's
/// copy for its next return to user, then returns the write's result.
// TODO-HUMAN-REVIEW(PR-1018): Review guest SIGPIPE synthesis.
fn with_guest_sigpipe(state: &LoadedStaticElf, result: i64, sigpipe: bool) -> i64 {
    if sigpipe && let Err(error) = raise_guest_sigpipe(state) {
        return error;
    }
    result
}

fn raise_guest_sigpipe(state: &LoadedStaticElf) -> Result<(), i64> {
    let signal = libc::SIGPIPE;
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    {
        let process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let disposition = signal_disposition_with_action(
            process_signals.dispositions.get(&signal).copied(),
            signal,
        );
        let mut thread_signals = state.thread_signals.lock();
        // An ignored, unblocked signal is discarded at generation, as Linux
        // does, unless a Tool observes ignored signals.
        if disposition == SignalDisposition::Ignore
            && !thread_signals.blocked.contains(signal)
            && !thread_signals.observe_ignored
        {
            return Ok(());
        }
        let event = reverie::SignalEvent::new(
            signal,
            crate::signal::signal_info_user(signal, state.pid, 0, libc::SI_USER),
            reverie::SignalTarget::Thread {
                pid: reverie::Pid::from_raw(state.pid),
                tid: reverie::Pid::from_raw(state.tid),
            },
        )
        .map_err(|errno| negative_errno(errno.into_raw()))?;
        thread_signals
            .pending
            .enqueue(event, process_signals.pending_generation(signal))
            .map_err(|errno| negative_errno(errno.into_raw()))?;
    }
    // A signalfd's eventfd keeper shows only the shared queue, so a private
    // signal changes none; the writer reads its own queue at its next probe.
    Ok(())
}

pub(super) fn signal_is_pending(signal: libc::c_int) -> Result<bool, libc::c_int> {
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

#[cfg(test)]
pub(super) fn write_without_sigpipe(fd: RawFd, bytes: &[u8]) -> i64 {
    suppress_host_sigpipe(None, || {
        // SAFETY: bytes is a live host buffer and fd is a live backing descriptor.
        unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) as i64 }
    })
}

#[cfg(test)]
fn suppress_host_sigpipe(
    pipe_requested: Option<(usize, &dyn Fn() -> bool)>,
    operation: impl FnOnce() -> i64,
) -> i64 {
    suppress_host_sigpipe_reporting(pipe_requested, operation).0
}

/// `suppress_host_sigpipe`, also reporting whether the host kernel raised
/// SIGPIPE for this operation: the decision Linux would have made for the
/// guest. `pipe_requested` is, for a pipe known to be private to the guest,
/// the byte count the operation asked to write and a recheck of that privacy
/// after the write (another guest thread can export an end while the write
/// blocks); None for any other descriptor.
pub(super) fn suppress_host_sigpipe_reporting(
    pipe_requested: Option<(usize, &dyn Fn() -> bool)>,
    operation: impl FnOnce() -> i64,
) -> (i64, bool) {
    // A guest backing pipe must not deliver SIGPIPE into the supervisor. Block it in this thread,
    // then synchronously consume the signal generated by this write while preserving a signal that
    // was already pending before the write.
    let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: blocked is writable and sigemptyset initializes it on success.
    if unsafe { libc::sigemptyset(blocked.as_mut_ptr()) } != 0 {
        return (io_error(std::io::Error::last_os_error()), false);
    }
    // SAFETY: sigemptyset initialized blocked, and SIGPIPE is a valid signal.
    if unsafe { libc::sigaddset(blocked.as_mut_ptr(), libc::SIGPIPE) } != 0 {
        return (io_error(std::io::Error::last_os_error()), false);
    }
    // SAFETY: both calls above initialized blocked.
    let blocked = unsafe { blocked.assume_init() };
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: blocked is initialized, previous is writable, and pthread_sigmask copies the old mask.
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous.as_mut_ptr()) };
    if mask_result != 0 {
        return (negative_errno(mask_result), false);
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
            return (negative_errno(error), false);
        }
    };

    let written = operation();
    let error = (written < 0).then(std::io::Error::last_os_error);

    let mut drain_error = None;
    let mut generated = false;
    // A pipe write can return a positive partial count and still generate
    // SIGPIPE if its reader closes before the remaining bytes are written.
    // Drain any newly pending SIGPIPE, not only an EPIPE result. A pipe write
    // that transferred everything it asked for raised none: pipe_write sends
    // SIGPIPE only when it stops with bytes left because the last reader is
    // gone, and then returns a short count or an error (a partial count can be
    // replaced by a file_update_time error). So for a pipe only those results
    // need the check, which saves one host syscall per complete pipe write.
    // Other descriptors keep it: a socket's upper-layer protocol (espintcp,
    // software kTLS) can raise SIGPIPE and still return the full count.
    let complete = pipe_requested.is_some_and(|(requested, still_private)| {
        written >= 0 && written as u64 >= requested as u64 && still_private()
    });
    if !had_pending_sigpipe && !complete {
        match signal_is_pending(libc::SIGPIPE) {
            Ok(true) => {
                let mut signal = 0;
                loop {
                    // SAFETY: blocked contains only SIGPIPE and signal is writable.
                    let wait_result = unsafe { libc::sigwait(&blocked, &mut signal) };
                    if wait_result == 0 {
                        debug_assert_eq!(signal, libc::SIGPIPE);
                        generated = true;
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
        return (negative_errno(restore_result), false);
    }
    if let Some(error) = drain_error {
        return (negative_errno(error), false);
    }
    // With a host SIGPIPE already pending, a new one cannot be told apart;
    // EPIPE is then the evidence Linux's write paths raise it on.
    let generated = generated
        || (had_pending_sigpipe
            && error
                .as_ref()
                .is_some_and(|error| error.raw_os_error() == Some(libc::EPIPE)));
    (error.map_or(written, io_error), generated)
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

fn prepare_host_read<M: GuestMemoryAccess<Error = crate::Error> + AddressSpace>(
    memory: &M,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, i64> {
    if !range_is_valid(memory, address, length as u64) {
        return Err(negative_errno(libc::EFAULT));
    }
    let Ok(writable) = memory.accessible_prefix(address, length, Access::Read) else {
        return Err(negative_errno(libc::EFAULT));
    };
    if writable == 0 && length != 0 {
        return Err(negative_errno(libc::EFAULT));
    }
    Ok(vec![0; writable])
}

// Keep the established four-level guest address policy across host kernels.
// Linux 6.12 sets USER_PTR_MAX to TASK_SIZE_MAX - 1, so a four-level host
// rejects the exact ceiling that our zero-length guest operand admits. Use
// host address zero for that boundary; no bytes are copied. Let the kernel
// reject an invalid operand at access_ok, after its descriptor/mode checks,
// rather than returning EFAULT before those checks. The guest request stays
// unchanged.
fn zero_read_host_address(address: u64) -> usize {
    if address > X86_64_GUEST_USER_LIMIT {
        usize::MAX
    } else if address == X86_64_GUEST_USER_LIMIT {
        0
    } else {
        address as usize
    }
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // Lifecycle controls deliberately exercise a blocked read through the real
    // dispatcher. Only their exact owned host fd is admitted, on their test
    // thread, for the lifetime of a panic-safe guard. No production bypass.
    pub(super) static TEST_ZERO_READ_ADMISSION: std::cell::Cell<Option<RawFd>> = const {
        std::cell::Cell::new(None)
    };
}

/// Refuse unsupported external waits before creating a reader or injecting a
/// host read. Detcore currently retains its runnable turn around zero-count
/// injection, so a guest peer cannot supply data or commit group exit:
/// https://github.com/rrnewton/hermit/issues/3498.
///
/// This checks the owned endpoint selected by the shared-table snapshot, not
/// its guest fd number or modeled stdin type. O_NONBLOCK is deliberately not an
/// admission proof: another alias of the same open-file description can change
/// it after F_GETFL. Even a currently nonblocking inotify is therefore
/// outside this supported surface. Known local regular files retain the
/// backend's existing filesystem-I/O contract; arbitrary pseudo/FUSE files and
/// unknown drivers are not assumed to have regular-file zero-read semantics.
/// Whether the host's random pool is initialized, so that reading
/// /dev/random cannot wait: getrandom of zero bytes with GRND_NONBLOCK fails
/// with EAGAIN until then.
fn host_random_pool_ready() -> bool {
    // SAFETY: a zero-length request writes nothing.
    unsafe { libc::getrandom(std::ptr::null_mut(), 0, libc::GRND_NONBLOCK) == 0 }
}

fn admit_host_read_zero(file: &std::fs::File, guest_fd: i32, address: u64) -> crate::Result<()> {
    let host_fd = file.as_raw_fd();
    #[cfg(any(test, feature = "test-support"))]
    if TEST_ZERO_READ_ADMISSION.with(|admitted| admitted.get() == Some(host_fd)) {
        return Ok(());
    }
    // O_PATH cannot change through F_SETFL and fdget rejects it before taking
    // a file-position lock. Other native errors are not a universal admission
    // proof: fdget_pos can wait on a shared regular-file position before
    // vfs_read checks access mode and access_ok.
    let flags = unsafe { libc::fcntl(host_fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if flags & libc::O_PATH != 0 {
        return Ok(());
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: the snapshot owns host_fd; stat is writable for fstat.
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    // fdget_pos takes a position lock only for regular files and directories.
    // For any other object a descriptor without read access fails vfs_read's
    // FMODE_READ check (EBADF) before anything can wait.
    if !matches!(stat.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
        && !status_grants_read(flags)
    {
        return Ok(());
    }
    match stat.st_mode & libc::S_IFMT {
        // pipe_read returns before taking its mutex for a zero-sized iterator.
        libc::S_IFIFO => return Ok(()),
        // sock_read_iter returns zero for an empty iterator before sock_recvmsg,
        // independently of O_NONBLOCK. The host still checks numeric-address
        // errors first; there is no protocol receive or payload consumption.
        // Linux v6.12 net/socket.c, sock_read_iter:
        // https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/net/socket.c#L1126
        libc::S_IFSOCK => return Ok(()),
        libc::S_IFCHR
            if libc::major(stat.st_rdev) == 1 && matches!(libc::minor(stat.st_rdev), 3 | 5) =>
        {
            // Linux's /dev/null and /dev/zero implementations need no data.
            return Ok(());
        }
        // urandom_read_iter never waits. random_read_iter waits only until
        // the host's random pool is initialized, which getrandom with
        // GRND_NONBLOCK reports without waiting.
        libc::S_IFCHR
            if libc::major(stat.st_rdev) == 1
                && (libc::minor(stat.st_rdev) == 9
                    || (libc::minor(stat.st_rdev) == 8 && host_random_pool_ready())) =>
        {
            return Ok(());
        }
        _ => {}
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: query the same live owned endpoint, never a guest pathname.
    if unsafe { libc::fstatfs(host_fd, filesystem.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let filesystem = unsafe { filesystem.assume_init() };
    if matches!(stat.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
        && matches!(
            filesystem.f_type,
            libc::TMPFS_MAGIC | libc::EXT4_SUPER_MAGIC | libc::BTRFS_SUPER_MAGIC
        )
    {
        return Ok(());
    }
    if filesystem.f_type == ANON_INODE_FS_MAGIC {
        let target = std::fs::read_link(format!("/proc/self/fd/{host_fd}"))?;
        if matches!(
            target.as_os_str().as_bytes(),
            b"anon_inode:[eventfd]" | b"anon_inode:[timerfd]" | b"anon_inode:[signalfd]"
        ) {
            // These built-in fixed-record readers reject a zero byte count
            // before waiting, independently of their mutable nonblocking flag.
            return Ok(());
        }
        if target.as_os_str().as_bytes() == b"anon_inode:[eventpoll]" {
            // eventpoll_fops has no read/read_iter, so alloc_file leaves
            // FMODE_CAN_READ unset and vfs_read rejects with EINVAL before
            // checking the address or invoking an endpoint operation.
            // https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/eventpoll.c#L1067
            return Ok(());
        }
        if target.as_os_str().as_bytes() == b"anon_inode:inotify"
            && address > X86_64_GUEST_USER_LIMIT
        {
            // Inotify has no atomic file position; invalid numeric operands
            // fail before its data-dependent wait. Valid operands still refuse.
            return Ok(());
        }
    }
    Err(crate::Error::PotentiallyBlockingZeroRead { fd: guest_fd })
}

// A zero-length scalar read still invokes the endpoint and validates the
// numeric user address. Only actual host endpoints may use this helper.
fn host_read_zero(fd: RawFd, address: u64) -> i64 {
    // SAFETY: this relies on the endpoint honoring count zero without copying
    // through the buffer. Apply the guest numeric-address policy without
    // creating a slice, probing guest memory, or using an empty allocation's
    // pointer. The all-ones substitute is outside every host user address range.
    let result = unsafe { libc::read(fd, zero_read_host_address(address) as *mut libc::c_void, 0) };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result as i64
    }
}

pub(super) fn host_read(memory: &mut GuestMemory, fd: RawFd, address: u64, length: usize) -> i64 {
    let mut bytes = match prepare_host_read(&ProviderMemory(memory), address, length) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    // SAFETY: bytes is writable for its full length and fd is a live host descriptor.
    let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len()) };
    if count < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    finish_host_read(memory, address, &bytes, count)
}

fn finish_host_read(memory: &mut GuestMemory, address: u64, bytes: &[u8], count: isize) -> i64 {
    let count = count as usize;
    if count == 0 {
        return 0;
    }
    match memory.user().write(address, &bytes[..count]) {
        Ok(()) => count as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

/// Lend the existing private-snapshot descriptor to the terminal reader. Its
/// inner owner returns the File only after physical retirement. Restore that
/// exact File on success, error, or unwind without changing entry metadata or
/// publishing a stale entry back into the authoritative shared file table.
pub(super) struct ReadEndpoint<'a> {
    pub(super) files: &'a mut std::collections::BTreeMap<i32, std::fs::File>,
    pub(super) fd: i32,
    pub(super) endpoint: Option<std::fs::File>,
}

impl<'a> ReadEndpoint<'a> {
    pub(super) fn take(
        files: &'a mut std::collections::BTreeMap<i32, std::fs::File>,
        fd: i32,
    ) -> Self {
        let endpoint = Some(
            files
                .remove(&fd)
                .expect("prechecked read descriptor disappeared"),
        );
        Self {
            files,
            fd,
            endpoint,
        }
    }
}

impl Drop for ReadEndpoint<'_> {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            // The exclusive map borrow prevents a competing local insertion.
            self.files.insert(self.fd, endpoint);
        }
        // None means the registry still owns the actual File because physical
        // retirement was not proven. Never duplicate, close, or replace it.
    }
}

pub(super) fn read(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
    terminal_read: Option<(
        &mut crate::terminal_read::ReadContext,
        reverie::SignalTaskIdentity,
    )>,
) -> crate::Result<i64> {
    let args = request.args();
    // Linux consumes only the low 32-bit descriptor word.
    let fd = args[0] as libc::c_int;
    if let Some(description) = state.fdinfo_files.get(&fd).cloned() {
        return Ok(description.read(&mut ProviderMemory(memory), args, false));
    }
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return Ok(negative_errno(libc::EINVAL));
    };
    let length = requested_length.min(MAX_HOST_IO);
    if is_open_standard(state, fd) {
        if fd != libc::STDIN_FILENO {
            return Ok(negative_errno(libc::EBADF));
        }
        let Some(stdin) = state.stdin.as_ref() else {
            return Ok(negative_errno(libc::EBADF));
        };
        if requested_length == 0 {
            admit_host_read_zero(stdin, fd, args[1])?;
            if let Some((context, identity)) = terminal_read {
                // Preserve the owned C reader's cancellation and join protocol.
                // Adapt only its host operand; retain the original request and
                // let the kernel enforce descriptor-before-address ordering.
                let returned = context.read(
                    &mut state.stdin,
                    identity,
                    *request,
                    zero_read_host_address(args[1]),
                    0,
                )?;
                return Ok(if returned.count < 0 {
                    io_error(std::io::Error::from_raw_os_error(returned.errno))
                } else {
                    returned.count as i64
                });
            }
            return Ok(host_read_zero(stdin.as_raw_fd(), args[1]));
        }
        if let Err(error) = ensure_read_capable(stdin) {
            return Ok(error);
        }
        if !range_is_valid(&ProviderMemory(memory), args[1], args[2]) {
            return Ok(negative_errno(libc::EFAULT));
        }
        return Ok(host_read(memory, stdin.as_raw_fd(), args[1], length));
    }
    let Some(file) = state.files.get(&fd) else {
        return Ok(negative_errno(libc::EBADF));
    };
    if requested_length == 0
        && !state.proc_files.contains_key(&fd)
        && signalfd_mask(state, fd).is_none()
    {
        // Only actual host endpoints decide zero-count error ordering here.
        // Synthetic descriptions retain their existing dispatch and ownership.
        admit_host_read_zero(file, fd, args[1])?;
        if let Some((context, identity)) = terminal_read {
            let mut endpoint = ReadEndpoint::take(&mut state.files, fd);
            let returned = context.read(
                &mut endpoint.endpoint,
                identity,
                *request,
                zero_read_host_address(args[1]),
                0,
            )?;
            return Ok(if returned.count < 0 {
                io_error(std::io::Error::from_raw_os_error(returned.errno))
            } else {
                returned.count as i64
            });
        }
        return Ok(host_read_zero(file.as_raw_fd(), args[1]));
    }
    let entry = state.fd_entry_ids.get(&fd).map(|entry| &**entry);
    if let Err(error) = ensure_read_capable_entry(entry, file) {
        return Ok(error);
    }
    let host_fd = file.as_raw_fd();
    // ensure_readable without its second access-mode query, which
    // ensure_read_capable just made. The file type also serves the inotify
    // probe below; it is recorded on the entry, so a later read of this
    // description makes no fstat.
    let mode = match entry.map_or_else(
        || fd_mode(host_fd),
        |entry| entry.file_type(|| fd_mode(host_fd)),
    ) {
        Ok(mode) => mode,
        Err(error) => return Ok(error),
    };
    if mode & libc::S_IFMT == libc::S_IFDIR {
        return Ok(negative_errno(libc::EISDIR));
    }
    if let Some(result) = signalfd_read(memory, state, fd, args[1], requested_length) {
        return Ok(result);
    }
    if !range_is_valid(&ProviderMemory(memory), args[1], args[2]) {
        return Ok(negative_errno(libc::EFAULT));
    }
    if requested_length == 0 {
        return Ok(0);
    }
    match host_fd_mode_is_inotify(host_fd, mode) {
        // Linux's readv calls inotify's read once with the same buffer and
        // count, so the staged readv path applies scalar read semantics.
        Ok(true) => {
            return Ok(staged_vectored_transfer(
                &mut ProviderMemory(memory),
                state,
                libc::SYS_readv,
                host_fd,
                &[GuestIoVec {
                    base: args[1],
                    length,
                }],
                &[0; 6],
                true,
            ));
        }
        Ok(false) => {}
        Err(error) => return Ok(error),
    }
    Ok(host_read(memory, host_fd, args[1], length))
}

pub(super) fn pread64<M: GuestMemoryAccess<Error = crate::Error> + AddressSpace>(
    memory: &mut M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    if (args[3] as libc::off_t) < 0 {
        return negative_errno(libc::EINVAL);
    }
    // Linux consumes only the low 32-bit descriptor word.
    let fd = args[0] as libc::c_int;
    if let Some(description) = state.fdinfo_files.get(&fd).cloned() {
        return description.read(memory, args, true);
    }
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
    let Ok(writable) = memory.accessible_prefix(args[1], length, Access::Read) else {
        return negative_errno(libc::EFAULT);
    };
    if writable == 0 {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; writable];
    match file.read_at(&mut bytes, args[3]) {
        Ok(count) => match memory.write_exact(args[1], &bytes[..count]) {
            Ok(()) => count as i64,
            Err(_) => negative_errno(libc::EFAULT),
        },
        Err(error) => io_error(error),
    }
}

pub(super) fn pwrite64(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if (args[3] as libc::off_t) < 0 {
        return negative_errno(libc::EINVAL);
    }
    // Linux syscall argument decoding consumes only the low descriptor word.
    let fd = args[0] as libc::c_int;
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let Some(file) = state.files.get(&fd) else {
        return negative_errno(libc::EBADF);
    };
    if state.proc_files.contains_key(&fd) {
        // The synthetic regular procfs files are seq_files, which Linux opens
        // without FMODE_PWRITE (ESPIPE). After the global signed-offset
        // check, O_PATH access precedes that refusal.
        return match file_status_flags(file) {
            Ok(status) if status & libc::O_PATH != 0 => negative_errno(libc::EBADF),
            Ok(_) => negative_errno(libc::ESPIPE),
            Err(error) => error,
        };
    }
    // ksys_pwrite64 refuses an object without positioned writes (a pipe,
    // socket or FIFO: ESPIPE) before vfs_write checks the access mode and the
    // buffer. A zero-vector host pwritev at the same offset applies that
    // order: do_pwritev checks FMODE_PWRITE, and vfs_writev the access mode,
    // before it returns for a zero total, so no write callback of the object
    // runs (a zero-length pwrite64 would call it: /dev/full answers ENOSPC,
    // and /dev/kmsg emits an empty record).
    // SAFETY: a zero vector count reads nothing from the null vector array.
    let preflight = unsafe {
        libc::syscall(
            libc::SYS_pwritev,
            file.as_raw_fd() as libc::c_long,
            std::ptr::null::<libc::iovec>(),
            0_usize,
            args[3] as libc::c_ulong,
            0_usize,
        )
    };
    if preflight < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    if let Err(error) = ensure_writable(file) {
        return error;
    }
    // As write: vfs_write's access_ok covers the whole count, even zero.
    if let Err(error) = validate_guest_iovec_address(args[1], requested_length) {
        return error;
    }
    if length == 0 {
        return 0;
    }
    let mut staged = match stage_guest_write(memory, file.as_raw_fd(), args[1], length) {
        Ok(staged) => staged,
        Err(error) => return error,
    };
    let (buffer, buffer_length) = staged.host_buffer();
    // SAFETY: the staged buffer is `length` live host bytes (a partly
    // readable one has its unreadable suffix PROT_NONE), and file owns a live
    // backing descriptor.
    let written = unsafe {
        libc::pwrite(
            file.as_raw_fd(),
            buffer,
            buffer_length,
            args[3] as libc::off_t,
        )
    };
    if written < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        written as i64
    }
}

pub(super) struct AlignedIoArena {
    pub(super) mapping: *mut libc::c_void,
    pub(super) mapping_length: usize,
    pub(super) data: *mut u8,
    pub(super) data_length: usize,
}

impl AlignedIoArena {
    pub(super) fn new(length: usize, alignment: usize) -> Result<Self, i64> {
        debug_assert_ne!(length, 0);
        debug_assert_ne!(alignment, 0);
        let requested = length
            .checked_add(alignment - 1)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let page_size = PAGE_SIZE as usize;
        let mapping_length = requested
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        // SAFETY: the mapping is anonymous, private, and owned by the returned
        // value until Drop. MAP_NORESERVE keeps vector-alignment padding from
        // consuming physical memory.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        let mapping_address = mapping as usize;
        let padding = (alignment - mapping_address % alignment) % alignment;
        // SAFETY: mapping_length includes alignment - 1 bytes of padding.
        let data = unsafe { mapping.cast::<u8>().add(padding) };
        Ok(Self {
            mapping,
            mapping_length,
            data,
            data_length: length,
        })
    }

    pub(super) fn as_mut_ptr(&mut self, offset: usize) -> *mut libc::c_void {
        debug_assert!(offset <= self.data_length);
        // SAFETY: callers compute offset within the aligned data range.
        unsafe { self.data.add(offset).cast() }
    }

    #[cfg(test)]
    pub(super) fn protect_after_data(&mut self) -> Result<(), i64> {
        let page_size = PAGE_SIZE as usize;
        let guard = (self.data as usize)
            .checked_add(self.data_length)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let mapping_end = (self.mapping as usize)
            .checked_add(self.mapping_length)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        if !guard.is_multiple_of(page_size)
            || guard
                .checked_add(page_size)
                .is_none_or(|end| end > mapping_end)
        {
            return Err(negative_errno(libc::EFAULT));
        }
        // SAFETY: guard is page-aligned and covers one page wholly contained
        // in this arena's live anonymous mapping.
        if unsafe { libc::mprotect(guard as *mut libc::c_void, page_size, libc::PROT_NONE) } != 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn protect_vector_suffix(
        &mut self,
        vector_offset: usize,
        accessible_length: usize,
    ) -> Result<(), i64> {
        let fault_offset = vector_offset
            .checked_add(accessible_length)
            .filter(|offset| *offset < self.data_length)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let fault = (self.data as usize)
            .checked_add(fault_offset)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let page_size = PAGE_SIZE as usize;
        let protection_start = fault & !(page_size - 1);
        // A nonempty accessible guest prefix always ends on a guest page
        // boundary. The staged base has the same low address bits, so its
        // fault boundary must also be page-aligned. For a wholly inaccessible
        // vector, protecting the padding before its unaligned base is safe.
        if accessible_length != 0 && protection_start != fault {
            return Err(negative_errno(libc::EFAULT));
        }
        let mapping_end = (self.mapping as usize)
            .checked_add(self.mapping_length)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let protection_length = mapping_end
            .checked_sub(protection_start)
            .filter(|length| *length != 0)
            .ok_or_else(|| negative_errno(libc::EFAULT))?;
        // SAFETY: protection_start is page-aligned and the range ends at this
        // arena's page-aligned mapping boundary.
        if unsafe {
            libc::mprotect(
                protection_start as *mut libc::c_void,
                protection_length,
                libc::PROT_NONE,
            )
        } != 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn as_slice(&self, offset: usize, length: usize) -> &[u8] {
        debug_assert!(offset.saturating_add(length) <= self.data_length);
        // SAFETY: callers compute offset + length within the aligned data range.
        unsafe { std::slice::from_raw_parts(self.data.add(offset), length) }
    }

    pub(super) fn as_mut_slice(&mut self, offset: usize, length: usize) -> &mut [u8] {
        debug_assert!(offset.saturating_add(length) <= self.data_length);
        // SAFETY: this mutable borrow uniquely covers a range in the aligned data range.
        unsafe { std::slice::from_raw_parts_mut(self.data.add(offset), length) }
    }
}

impl Drop for AlignedIoArena {
    fn drop(&mut self) {
        // SAFETY: mapping and mapping_length are the values returned by mmap.
        unsafe {
            libc::munmap(self.mapping, self.mapping_length);
        }
    }
}

pub(super) struct StagedIoVector {
    pub(super) guest: GuestIoVec,
    pub(super) accessible_length: usize,
    pub(super) arena: Option<AlignedIoArena>,
    pub(super) buffer_offset: usize,
}

impl StagedIoVector {
    pub(super) fn new(
        guest: GuestIoVec,
        accessible_length: usize,
        alignment: usize,
    ) -> Result<Self, i64> {
        debug_assert!(accessible_length <= guest.length);
        if guest.length == 0 {
            return Ok(Self {
                guest,
                accessible_length: 0,
                arena: None,
                buffer_offset: 0,
            });
        }
        let (buffer_offset, allocation_length) =
            aligned_staging_range(0, guest.base, guest.length, alignment)?;
        let mut arena = AlignedIoArena::new(allocation_length, alignment)?;
        if accessible_length < guest.length {
            arena.protect_vector_suffix(buffer_offset, accessible_length)?;
        }
        Ok(Self {
            guest,
            accessible_length,
            arena: Some(arena),
            buffer_offset,
        })
    }

    fn host_iovec(&mut self) -> libc::iovec {
        libc::iovec {
            iov_base: self
                .arena
                .as_mut()
                .map_or_else(std::ptr::dangling_mut::<libc::c_void>, |arena| {
                    arena.as_mut_ptr(self.buffer_offset)
                }),
            iov_len: self.guest.length,
        }
    }

    pub(super) fn accessible_slice(&self, length: usize) -> &[u8] {
        debug_assert!(length <= self.accessible_length);
        self.arena
            .as_ref()
            .expect("accessible staged vector has no arena")
            .as_slice(self.buffer_offset, length)
    }

    pub(super) fn accessible_slice_mut(&mut self, length: usize) -> &mut [u8] {
        debug_assert!(length <= self.accessible_length);
        self.arena
            .as_mut()
            .expect("accessible staged vector has no arena")
            .as_mut_slice(self.buffer_offset, length)
    }
}

pub(super) fn staged_host_iovecs(staged_vectors: &mut [StagedIoVector]) -> Vec<libc::iovec> {
    let mut host_iovecs = Vec::with_capacity(staged_vectors.len());
    for vector in staged_vectors {
        host_iovecs.push(vector.host_iovec());
    }
    host_iovecs
}

pub(super) fn direct_io_memory_alignment(host_fd: RawFd) -> usize {
    if fd_status_flags(host_fd).is_ok_and(|flags| flags & libc::O_DIRECT == 0) {
        return PAGE_SIZE as usize;
    }
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: the empty path is NUL terminated, AT_EMPTY_PATH selects host_fd,
    // and stat is writable. Kernels without STATX_DIOALIGN leave the fallback.
    let result = unsafe {
        libc::statx(
            host_fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_DIOALIGN,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return PAGE_SIZE as usize;
    }
    // SAFETY: statx initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_DIOALIGN == 0 || stat.stx_dio_mem_align == 0 {
        PAGE_SIZE as usize
    } else {
        (stat.stx_dio_mem_align as usize).max(PAGE_SIZE as usize)
    }
}

fn aligned_staging_range(
    next_offset: usize,
    guest_address: u64,
    length: usize,
    alignment: usize,
) -> Result<(usize, usize), i64> {
    debug_assert_ne!(length, 0);
    debug_assert_ne!(alignment, 0);
    let desired_remainder = guest_address as usize % alignment;
    let current_remainder = next_offset % alignment;
    let padding = (desired_remainder + alignment - current_remainder) % alignment;
    let offset = next_offset
        .checked_add(padding)
        .ok_or_else(|| negative_errno(libc::EINVAL))?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| negative_errno(libc::EINVAL))?;
    Ok((offset, end))
}

#[derive(Clone, Copy)]
pub(super) struct GuestIoVec {
    pub(super) base: u64,
    pub(super) length: usize,
}

pub(super) fn validate_guest_iovec_address(address: u64, length: usize) -> Result<(), i64> {
    let limit = X86_64_GUEST_USER_LIMIT;
    let length = u64::try_from(length).map_err(|_| negative_errno(libc::EFAULT))?;
    // This is Linux x86-64's access_ok rule: size <= TASK_SIZE_MAX and
    // address <= TASK_SIZE_MAX - size. It rejects noncanonical addresses,
    // arithmetic wrap, and the architecture's final guard page. A zero-length
    // entry still requires its base to be at or below TASK_SIZE_MAX.
    if length > limit || address > limit - length {
        Err(negative_errno(libc::EFAULT))
    } else {
        Ok(())
    }
}

pub(super) fn decode_guest_iovecs(
    memory: &GuestMemory,
    address: u64,
    raw_count: u64,
) -> Result<(Vec<GuestIoVec>, usize, usize), i64> {
    let Ok(count) = usize::try_from(raw_count) else {
        return Err(negative_errno(libc::EINVAL));
    };
    if count > libc::UIO_MAXIOV as usize {
        return Err(negative_errno(libc::EINVAL));
    }
    // Linux checks the complete array's address range before copying entries.
    // This is not a mapping-presence check: a negative length in an earlier
    // copied entry takes precedence over an inaccessible later structure.
    if count != 0 {
        validate_guest_iovec_address(address, count * std::mem::size_of::<libc::iovec>())?;
    }

    let mut original_vectors = Vec::with_capacity(count);
    for index in 0..count {
        let Some(entry_address) =
            address.checked_add((index * std::mem::size_of::<libc::iovec>()) as u64)
        else {
            return Err(negative_errno(libc::EFAULT));
        };
        let entry: libc::iovec = read_guest_struct(&ProviderMemory(memory), entry_address)?;
        // Reject each signed-length overflow as soon as its structure has
        // been copied, before reading the next structure. Data addresses are
        // checked only after all structures and signed lengths are imported.
        if entry.iov_len > isize::MAX as usize {
            return Err(negative_errno(libc::EINVAL));
        }
        original_vectors.push(GuestIoVec {
            base: entry.iov_base as usize as u64,
            length: entry.iov_len,
        });
    }

    let mut vectors = Vec::with_capacity(count);
    let mut total = 0usize;
    let mut kernel_total = 0usize;
    for entry in original_vectors {
        // Linux's single-entry import_ubuf path clamps before access_ok. The
        // multi-entry path checks each original range before shortening it to
        // the remaining aggregate, including entries after MAX_RW_COUNT.
        let validated_length = if count == 1 {
            entry.length.min(MAX_RW_COUNT)
        } else {
            entry.length
        };
        validate_guest_iovec_address(entry.base, validated_length)?;
        let kernel_length = entry.length.min(MAX_RW_COUNT.saturating_sub(kernel_total));
        kernel_total += kernel_length;
        // MAX_HOST_IO bounds supervisor allocation, not the Linux ABI. A
        // valid larger request may complete partially, so retain the bounded
        // prefix instead of inventing EINVAL at the private staging limit.
        let length = kernel_length.min(MAX_HOST_IO.saturating_sub(total));
        vectors.push(GuestIoVec {
            base: entry.base,
            length,
        });
        total += length;
    }
    Ok((vectors, total, kernel_total))
}

fn validate_positioned_vectored_offset(number: libc::c_long, args: &[u64; 6]) -> Result<(), i64> {
    // On x86-64 the fourth argument is the full signed offset. The fifth
    // register is present in the generic syscall shape, but Linux ignores it
    // on this architecture. glibc initializes it to zero.
    let offset = args[3] as i64;
    let version_two = number == libc::SYS_preadv2 || number == libc::SYS_pwritev2;
    if offset < if version_two { -1 } else { 0 } {
        return Err(negative_errno(libc::EINVAL));
    }
    Ok(())
}

fn validate_positioned_vectored_flags(
    number: libc::c_long,
    args: &[u64; 6],
    total: usize,
) -> Result<(), i64> {
    let version_two = number == libc::SYS_preadv2 || number == libc::SYS_pwritev2;
    if !version_two || total == 0 {
        return Ok(());
    }

    let flags = args[5] as libc::c_int;
    if flags & !RWF_SUPPORTED_MASK != 0 {
        return Err(negative_errno(libc::EOPNOTSUPP));
    }
    if flags & libc::RWF_APPEND != 0 && flags & libc::RWF_NOAPPEND != 0 {
        return Err(negative_errno(libc::EINVAL));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn invoke_vectored_write(
    number: libc::c_long,
    host_fd: RawFd,
    host_iovecs: &mut [libc::iovec],
    args: &[u64; 6],
) -> i64 {
    invoke_vectored_write_reporting(number, host_fd, host_iovecs, args).0
}

fn invoke_vectored_write_reporting(
    number: libc::c_long,
    host_fd: RawFd,
    host_iovecs: &mut [libc::iovec],
    args: &[u64; 6],
) -> (i64, bool) {
    suppress_host_sigpipe_reporting(None, || {
        // SAFETY: every host iovec points into a live buffer for its declared
        // length, and host_fd belongs to the translated guest descriptor. The
        // positioned syscalls receive their complete x86-64 argument shape.
        unsafe {
            if number == libc::SYS_writev {
                return libc::writev(
                    host_fd,
                    host_iovecs.as_ptr(),
                    host_iovecs.len() as libc::c_int,
                ) as i64;
            }
            libc::syscall(
                number,
                host_fd as libc::c_long,
                host_iovecs.as_mut_ptr(),
                host_iovecs.len() as libc::c_ulong,
                args[3] as libc::c_ulong,
                args[4] as libc::c_ulong,
                args[5] as libc::c_ulong,
            ) as i64
        }
    })
}

fn invoke_vectored_read(
    number: libc::c_long,
    host_fd: RawFd,
    host_iovecs: &mut [libc::iovec],
    args: &[u64; 6],
) -> i64 {
    // SAFETY: every host iovec points into a live writable buffer for its
    // declared length, and host_fd belongs to the translated guest descriptor.
    let result = unsafe {
        if number == libc::SYS_readv {
            libc::readv(
                host_fd,
                host_iovecs.as_ptr(),
                host_iovecs.len() as libc::c_int,
            ) as i64
        } else {
            libc::syscall(
                number,
                host_fd as libc::c_long,
                host_iovecs.as_mut_ptr(),
                host_iovecs.len() as libc::c_ulong,
                args[3] as libc::c_ulong,
                args[4] as libc::c_ulong,
                args[5] as libc::c_ulong,
            ) as i64
        }
    };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result
    }
}

fn capture_vectored_write(
    memory: &GuestMemory,
    iovecs: &[GuestIoVec],
    destination: OutputAlias,
    output: &CapturedOutput,
) -> i64 {
    let mut bytes = Vec::new();
    for iovec in iovecs {
        if iovec.length == 0 {
            continue;
        }
        let start = bytes.len();
        let Some(end) = start.checked_add(iovec.length) else {
            return negative_errno(libc::EINVAL);
        };
        bytes.resize(end, 0);
        if memory.user().read(iovec.base, &mut bytes[start..]).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    if !output.append(matches!(destination, OutputAlias::Stderr), &bytes) {
        negative_errno(libc::EFBIG)
    } else {
        bytes.len() as i64
    }
}

// TODO-HUMAN-REVIEW(PR-538): Review ordinary and positioned vectored I/O
// mediation, including aggregate host calls, bounded staging, virtual signalfd
// routing, direct-I/O alignment, partial guest-memory faults, captured output,
// and SIGPIPE containment.
pub(super) fn vectored_io(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    number: libc::c_long,
    output: Option<&mut CapturedOutput>,
) -> i64 {
    let reading = matches!(
        number,
        libc::SYS_readv | libc::SYS_preadv | libc::SYS_preadv2
    );
    let positioned = !matches!(number, libc::SYS_readv | libc::SYS_writev);
    debug_assert!(
        reading
            || matches!(
                number,
                libc::SYS_writev | libc::SYS_pwritev | libc::SYS_pwritev2
            )
    );
    if positioned {
        // Linux validates a positioned operation's signed offset before looking
        // up the descriptor.
        if let Err(error) = validate_positioned_vectored_offset(number, args) {
            return error;
        }
    }
    // Linux descriptor lookup consumes the low 32 bits of the raw register,
    // including for the positioned syscalls whose entry argument is unsigned
    // long. Nonzero upper bits do not invalidate an otherwise valid fd.
    let guest_fd = args[0] as libc::c_int;
    let output_destination = output_alias(state, guest_fd);
    let captured_output = output.is_some() && output_destination.is_some();
    // Synthetic procfs descriptors have backend-owned content and must not be
    // forwarded to the supervisor's procfs.
    if state.proc_files.contains_key(&guest_fd) {
        return negative_errno(libc::ENOSYS);
    }
    let descriptor = (!captured_output)
        .then(|| host_fd(state, guest_fd))
        .flatten();
    if !captured_output && descriptor.is_none() {
        return negative_errno(libc::EBADF);
    }

    let current_position = !positioned
        || matches!(number, libc::SYS_preadv2 | libc::SYS_pwritev2) && args[3] as i64 == -1;
    if !current_position {
        if captured_output {
            return negative_errno(libc::ESPIPE);
        }
        let host_fd = descriptor.expect("validated guest descriptor disappeared");
        // A zero-vector call has no data or position side effect, but lets the
        // host descriptor apply Linux's seekability ordering before guest
        // memory is imported. In particular, pipes return ESPIPE here.
        // SAFETY: the iovec count is zero, so the null pointer is not read.
        let preflight = unsafe {
            libc::syscall(
                number,
                host_fd as libc::c_long,
                std::ptr::null::<libc::iovec>(),
                0usize,
                args[3] as libc::c_ulong,
                args[4] as libc::c_ulong,
                args[5] as libc::c_ulong,
            )
        };
        if preflight < 0 {
            return io_error(std::io::Error::last_os_error());
        }
    }

    let virtual_signalfd = signalfd_mask(state, guest_fd).is_some();
    if virtual_signalfd && current_position && !reading {
        // Linux rejects writev/pwritev2 on signalfd before importing the
        // iovec array. Its KVM backing eventfd is deliberately not exposed.
        return negative_errno(libc::EINVAL);
    }

    // Access-mode checks follow offset and seekability checks but still
    // precede iovec import, matching Linux's ordering.
    let access = if reading && is_open_standard(state, guest_fd) && guest_fd != libc::STDIN_FILENO {
        // Keep scalar read's policy for original stdout/stderr, even when the
        // supervisor's backing descriptor is O_RDWR. Guest-owned replacements
        // and dup aliases retain their separate descriptor/capture routing.
        Err(negative_errno(libc::EBADF))
    } else if captured_output {
        if reading {
            Err(negative_errno(libc::EBADF))
        } else {
            Ok(())
        }
    } else if let Some(host_fd) = descriptor {
        if reading {
            ensure_readable_fd(host_fd)
        } else {
            ensure_writable_fd(host_fd)
        }
    } else {
        Err(negative_errno(libc::EBADF))
    };
    if let Err(error) = access {
        return error;
    }

    // Linux's import_iovec takes the vector count as an unsigned int, so the
    // raw register's upper 32 bits are ignored for every vectored read and
    // write.
    let count = u64::from(args[2] as u32);
    let (guest_iovecs, total, kernel_total) = match decode_guest_iovecs(memory, args[1], count) {
        Ok(decoded) => decoded,
        Err(error) => return error,
    };
    // Linux validates preadv2 and pwritev2 flags (kiocb_set_rw_flags) after
    // importing the vectors and verifying the extent (rw_verify_area), and
    // before any byte is copied. The host call below comes only after the
    // executor has staged the payload, which reads guest memory, so the
    // refusal of unknown or conflicting flags is given here, after the same
    // extent check: a write whose source the guest cannot read (a truncated
    // shared file page, for example) is still refused for its flags.
    if positioned && total != 0 && matches!(number, libc::SYS_preadv2 | libc::SYS_pwritev2) {
        if !current_position
            && !virtual_signalfd
            && !captured_output
            && (args[3] as i64).checked_add(total as i64).is_none()
        {
            return negative_errno(libc::EINVAL);
        }
        if let Err(error) = validate_positioned_vectored_flags(number, args, total) {
            return error;
        }
    }
    if virtual_signalfd {
        debug_assert!(reading && current_position);
        // These flags require capabilities that signalfd does not provide.
        // Import and validate the vectors first, and preserve Linux's zero-byte
        // success without consuming a signal or changing the destination.
        if number == libc::SYS_preadv2
            && total != 0
            && args[5] as libc::c_int & (libc::RWF_ATOMIC | libc::RWF_DONTCACHE) != 0
        {
            return negative_errno(libc::EOPNOTSUPP);
        }
        return signalfd_read_stream(
            memory,
            state,
            guest_fd,
            &guest_iovecs,
            true,
            number == libc::SYS_preadv2 && args[5] as libc::c_int & libc::RWF_NOWAIT != 0,
        )
        .expect("signalfd mask disappeared without descriptor mutation");
    }
    if captured_output {
        if positioned {
            let flags = args[5] as libc::c_int;
            if number == libc::SYS_pwritev2
                && total != 0
                && flags & (libc::RWF_ATOMIC | libc::RWF_DONTCACHE) != 0
            {
                return negative_errno(libc::EOPNOTSUPP);
            }
        }
        debug_assert!(!reading, "captured output is not readable");
        return capture_vectored_write(
            memory,
            &guest_iovecs,
            output_destination.expect("captured output has no destination"),
            output.expect("captured output disappeared"),
        );
    }
    let host_fd = descriptor.expect("validated guest descriptor disappeared");
    if kernel_total > total {
        let flags = match fd_status_flags(host_fd) {
            Ok(flags) => flags,
            Err(error) => return error,
        };
        if flags & libc::O_DIRECT != 0 {
            // The private staging cap must not turn an originally unaligned
            // length or trailing vector into a valid direct-I/O request. Larger
            // O_DIRECT operations are unsupported until the full kernel-sized
            // vector shape can be preserved. Refuse before any data transfer.
            return negative_errno(libc::EOPNOTSUPP);
        }
    }
    staged_vectored_transfer(
        &mut ProviderMemory(memory),
        state,
        number,
        host_fd,
        &guest_iovecs,
        args,
        reading,
    )
}

fn staged_vectored_transfer<M: GuestMemoryAccess<Error = crate::Error> + AddressSpace>(
    memory: &mut M,
    state: &LoadedStaticElf,
    number: libc::c_long,
    host_fd: RawFd,
    guest_iovecs: &[GuestIoVec],
    args: &[u64; 6],
    reading: bool,
) -> i64 {
    let inotify = if reading {
        match host_fd_is_inotify(host_fd) {
            Ok(inotify) => inotify,
            Err(error) => return error,
        }
    } else {
        false
    };
    if inotify && let Err(error) = ensure_inotify_nonblocking(host_fd) {
        return error;
    }
    let staging_alignment = direct_io_memory_alignment(host_fd);

    // Give the host one iovec for every bounded guest iovec, with the same
    // length, order, and low address bits. Each nonempty vector has its own
    // anonymous arena, so a protected suffix cannot hide or protect a later
    // vector. A partially accessible vector remains one host vector: its live
    // prefix ends exactly at a page boundary and its remaining pages are
    // PROT_NONE. This lets one host syscall apply endpoint-specific EFAULT,
    // atomicity, packet-consumption, and eventfd-consumption rules without ever
    // exposing the supervisor's guest-memory mapping.
    let mut staged_vectors = Vec::with_capacity(guest_iovecs.len());
    for vector in guest_iovecs {
        let prefix = if reading {
            memory.accessible_prefix(vector.base, vector.length, Access::Write)
        } else {
            memory.accessible_prefix(vector.base, vector.length, Access::Read)
        }
        .unwrap_or(0);
        let mut staged = match StagedIoVector::new(*vector, prefix, staging_alignment) {
            Ok(staged) => staged,
            Err(error) => return error,
        };
        if prefix != 0
            && memory
                .read_exact(vector.base, staged.accessible_slice_mut(prefix))
                .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
        staged_vectors.push(staged);
    }

    // Inotify cookie virtualization restores an EFAULT read's partly written
    // cookie from the first nonempty vector's prior contents.
    let inotify_original = if inotify {
        staged_vectors
            .iter()
            .find(|vector| vector.guest.length != 0)
            .map(|vector| vector.accessible_slice(vector.accessible_length).to_vec())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut host_iovecs = staged_host_iovecs(&mut staged_vectors);
    if !reading {
        let (written, sigpipe) =
            invoke_vectored_write_reporting(number, host_fd, &mut host_iovecs, args);
        return with_guest_sigpipe(state, written, sigpipe);
    }

    let result = invoke_vectored_read(number, host_fd, &mut host_iovecs, args);
    if inotify {
        virtualize_staged_inotify_cookies(&mut staged_vectors, result, &inotify_original, state);
    }
    if result >= 0 {
        let mut remaining = result as usize;
        for vector in &staged_vectors {
            let transferred = remaining.min(vector.guest.length);
            let copied = transferred.min(vector.accessible_length);
            if copied != 0
                && memory
                    .write_exact(vector.guest.base, vector.accessible_slice(copied))
                    .is_err()
            {
                return negative_errno(libc::EFAULT);
            }
            remaining -= transferred;
            if remaining == 0 {
                break;
            }
        }
        debug_assert_eq!(remaining, 0, "host returned more bytes than requested");
    } else if result == negative_errno(libc::EFAULT) {
        // Linux may modify an accessible prefix before reporting EFAULT. In
        // particular eventfd consumes its counter and datagram sockets discard
        // their packet, while pipe/stream data remains queued; all four copy
        // bytes into the live prefix. The staging buffers were prefilled from
        // guest memory, so copying the accessible portions through the first
        // fault preserves both changed and untouched bytes safely.
        for vector in &staged_vectors {
            if vector.accessible_length != 0
                && memory
                    .write_exact(
                        vector.guest.base,
                        vector.accessible_slice(vector.accessible_length),
                    )
                    .is_err()
            {
                return negative_errno(libc::EFAULT);
            }
            if vector.accessible_length < vector.guest.length {
                break;
            }
        }
    }
    result
}

/// A host file backs a regular (or memfd) object when its mode is `S_IFREG`.
///
/// `sendfile(2)` requires a regular/memfd input that supports positioned reads;
/// sockets (`S_IFSOCK`) and pipes (`S_IFIFO`) are rejected so callers fall back
/// to the mediated `read()`/`write()` path. This mirrors Detcore's
/// `FdType::Regular | FdType::Memfd` gate in `handle_sendfile` (memfd objects are
/// themselves `S_IFREG`).
fn is_regular_host_file(file: &std::fs::File) -> Result<bool, i64> {
    Ok(file_mode(file)? & libc::S_IFMT == libc::S_IFREG)
}

fn resolve_sendfile_input(
    state: &LoadedStaticElf,
    in_fd: libc::c_int,
) -> Result<&std::fs::File, i64> {
    // A live unsupported endpoint takes the mediated fallback. A descriptor
    // absent from the guest model is EBADF, as in detcore::handle_sendfile.
    let Some(in_file) = state.files.get(&in_fd) else {
        return Err(if is_open_standard(state, in_fd) {
            negative_errno(libc::ENOSYS)
        } else {
            negative_errno(libc::EBADF)
        });
    };
    // Procfs can look regular, but forwarding it would bypass its deterministic
    // snapshot. Refuse it before the regular/memfd gate, as before. A seq
    // description's empty backing memfd is not its content.
    if state.fdinfo_files.contains_key(&in_fd) || ensure_fd_not_procfs(in_file.as_raw_fd()).is_err()
    {
        return Err(negative_errno(libc::ENOSYS));
    }
    if !is_regular_host_file(in_file)? {
        return Err(negative_errno(libc::ENOSYS));
    }
    ensure_readable(in_file)?;
    Ok(in_file)
}

fn read_sendfile_offset(memory: &GuestMemory, offset_ptr: u64) -> Result<libc::off_t, i64> {
    if !range_is_valid(&ProviderMemory(memory), offset_ptr, 8) {
        return Err(negative_errno(libc::EFAULT));
    }
    let mut raw = [0u8; 8];
    memory
        .user()
        .read(offset_ptr, &mut raw)
        .map_err(|_| negative_errno(libc::EFAULT))?;
    Ok(i64::from_ne_bytes(raw))
}

fn validate_sendfile_range(offset: libc::off_t, count: u64) -> Result<(), i64> {
    let count = i64::try_from(count).map_err(|_| negative_errno(libc::EINVAL))?;
    if offset < 0 || offset.checked_add(count).is_none() {
        return Err(negative_errno(libc::EINVAL));
    }
    Ok(())
}

// An unusable output still follows input access, explicit-offset seekability,
// and range errors on Linux. Check only these rejection conditions; unsupported
// inputs never reach a host transfer, and procfs keeps its mediated boundary.
fn validate_sendfile_rejected_input(
    state: &LoadedStaticElf,
    in_fd: libc::c_int,
    offset: Option<libc::off_t>,
    count: u64,
) -> Result<(), i64> {
    let Some(file) = state.files.get(&in_fd).or_else(|| {
        // Stdin has a separate modeled backing until it is closed or rebound.
        // Check that backing, never the executor's own host descriptor zero.
        if in_fd == libc::STDIN_FILENO && is_open_standard(state, in_fd) {
            state.stdin.as_ref()
        } else {
            None
        }
    }) else {
        return Ok(());
    };
    if ensure_fd_not_procfs(file.as_raw_fd()).is_err() {
        return Ok(());
    }
    // In particular, a pipe write end and O_PATH must fail access before the
    // explicit-offset check. Directories need access, not ensure_readable's
    // scalar-read EISDIR rejection, before validating their signed range.
    ensure_read_access(file)?;
    match file_mode(file)? & libc::S_IFMT {
        libc::S_IFIFO | libc::S_IFSOCK => {
            if offset.is_some() {
                return Err(negative_errno(libc::ESPIPE));
            }
            // These streams have no advancing file position. Linux still
            // validates the original signed count before rejecting the output;
            // querying lseek instead would incorrectly reject null offsets.
            validate_sendfile_range(0, count)
        }
        libc::S_IFDIR | libc::S_IFREG => {
            let offset = match offset {
                Some(offset) => offset,
                None => {
                    // SAFETY: file is a live readable regular file or directory.
                    // A zero SEEK_CUR query observes its cursor without changing it.
                    let offset = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) };
                    if offset < 0 {
                        return Err(io_error(std::io::Error::last_os_error()));
                    }
                    offset
                }
            };
            validate_sendfile_range(offset, count)
        }
        _ => Ok(()),
    }
}

// TODO-HUMAN-REVIEW(#322): Review sendfile forward-to-host semantics, the
// procfs-input refusal, the regular/memfd endpoint gate, and the guest offset
// read-back. After preceding pointer, access, offset and output errors, procfs
// and non-regular/non-memfd inputs retain the ENOSYS mediated fallback rather
// than forwarding an unsupported transfer to the host.
pub(super) fn sendfile(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    output: Option<&mut CapturedOutput>,
) -> i64 {
    // Linux syscall `int` arguments consume only the low descriptor word.
    let out_fd = args[0] as libc::c_int;
    // Remember output errors before unsupported-input routing, but preserve
    // input pointer, access, seekability and range errors before returning them.
    let (out_file, output_error) = if out_fd < 0 {
        (None, Some(negative_errno(libc::EBADF)))
    } else {
        match state.files.get(&out_fd) {
            Some(file) => (Some(file), ensure_writable(file).err()),
            None if is_open_standard(state, out_fd) => {
                let error = if out_fd == libc::STDIN_FILENO {
                    let stdin = state
                        .stdin
                        .as_ref()
                        .expect("open standard input disappeared");
                    ensure_writable(stdin).err()
                } else {
                    None
                };
                (None, error)
            }
            None => (None, Some(negative_errno(libc::EBADF))),
        }
    };
    let in_fd = args[1] as libc::c_int;
    let in_file = match resolve_sendfile_input(state, in_fd) {
        Ok(file) => file,
        Err(error) => {
            // Linux copies a nonnull offset before resolving either descriptor,
            // including zero-count calls. Do not validate its value before
            // input access: a readable negative offset with a bad input is EBADF.
            let offset = if args[2] != 0 {
                match read_sendfile_offset(memory, args[2]) {
                    Ok(offset) => Some(offset),
                    Err(error) => return error,
                }
            } else {
                None
            };
            if output_error.is_some()
                && let Err(error) = validate_sendfile_rejected_input(state, in_fd, offset, args[3])
            {
                return error;
            }
            return output_error.unwrap_or(error);
        }
    };
    let in_host = in_file.as_raw_fd();
    let Ok(count) = usize::try_from(args[3]) else {
        return negative_errno(libc::EINVAL);
    };
    let offset_ptr = args[2];
    if let Some(error) = output_error {
        // Copying the explicit offset and verifying its signed input range
        // precede output access rejection on Linux. Preserve those errors for
        // supported readable inputs without probing or consuming any bytes.
        // Linux validates the original guest count before either transfer cap.
        // A null offset uses the input cursor, which this query leaves intact.
        let offset = if offset_ptr != 0 {
            match read_sendfile_offset(memory, offset_ptr) {
                Ok(offset) => offset,
                Err(error) => return error,
            }
        } else {
            // SAFETY: in_host is a live readable regular-file descriptor. This
            // queries its current position without changing it or reading bytes.
            let offset = unsafe { libc::lseek(in_host, 0, libc::SEEK_CUR) };
            if offset < 0 {
                return io_error(std::io::Error::last_os_error());
            }
            offset
        };
        if let Err(error) = validate_sendfile_range(offset, args[3]) {
            return error;
        }
        return error;
    }
    let count = count.min(MAX_HOST_IO);

    // Fast path: a regular/memfd output that lives in the guest file table can be
    // copied with the host's zero-copy sendfile directly, preserving kernel
    // offset semantics.
    if let Some(out_file) = out_file {
        match is_regular_host_file(out_file) {
            Ok(true) => {}
            // A known-but-non-regular output (pipe/socket the guest opened) takes
            // the mediated fallback, exactly like detcore.
            Ok(false) => return negative_errno(libc::ENOSYS),
            Err(error) => return error,
        }
        let out_host = out_file.as_raw_fd();
        if offset_ptr == 0 {
            // SAFETY: both are live host descriptors; a null offset advances
            // in_fd's own file position exactly as the guest requested.
            let copied = unsafe { libc::sendfile(out_host, in_host, std::ptr::null_mut(), count) };
            return if copied < 0 {
                io_error(std::io::Error::last_os_error())
            } else {
                copied as i64
            };
        }
        // The guest supplied an explicit input offset; forward through a host
        // off_t and write the kernel-advanced value back so the guest observes
        // faithful sendfile semantics. off_t is i64 on x86_64.
        let mut host_offset = match read_sendfile_offset(memory, offset_ptr) {
            Ok(offset) => offset,
            Err(error) => return error,
        };
        // SAFETY: both descriptors are live and host_offset is a valid writable
        // off_t that the kernel updates in place with the new input offset.
        let copied = unsafe { libc::sendfile(out_host, in_host, &mut host_offset, count) };
        if copied < 0 {
            return io_error(std::io::Error::last_os_error());
        }
        if memory
            .user()
            .write(offset_ptr, &host_offset.to_ne_bytes())
            .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
        return copied as i64;
    }

    // The output is a standard stream outside the guest file table. Route
    // stdout/stderr through capture and stdin through its modeled descriptor,
    // as write(2) does. Read the input and re-emit through that mediated path.
    // Anything that is neither a modeled fd nor a standard stream is EBADF.
    if !is_open_standard(state, out_fd) {
        return negative_errno(libc::EBADF);
    }
    if count == 0 {
        return 0;
    }
    let mut bytes = vec![0u8; count];
    let read = if offset_ptr == 0 {
        // SAFETY: in_host is live and bytes is a writable host buffer of `count`.
        unsafe { libc::read(in_host, bytes.as_mut_ptr().cast::<libc::c_void>(), count) }
    } else {
        let host_offset = match read_sendfile_offset(memory, offset_ptr) {
            Ok(offset) => offset,
            Err(error) => return error,
        };
        // SAFETY: in_host is live, bytes is a writable host buffer of `count`,
        // and pread does not disturb in_fd's own file position.
        unsafe {
            libc::pread(
                in_host,
                bytes.as_mut_ptr().cast::<libc::c_void>(),
                count,
                host_offset,
            )
        }
    };
    if read < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let read = read as usize;
    bytes.truncate(read);
    if read == 0 {
        return 0;
    }

    // Route the copied bytes to the standard stream exactly as write(2) does.
    let written = match output_alias(state, out_fd) {
        Some(alias) => {
            if let Some(output) = output {
                if !output.append(matches!(alias, OutputAlias::Stderr), &bytes) {
                    return negative_errno(libc::EFBIG);
                }
                bytes.len() as i64
            } else {
                host_write(out_fd, &bytes)
            }
        }
        None => {
            let mut stdin = state
                .stdin
                .as_ref()
                .expect("open standard input disappeared");
            stdin
                .write(&bytes)
                .map_or_else(io_error, |count| count as i64)
        }
    };
    if written < 0 {
        return written;
    }
    // sendfile advances the explicit input offset by the number of bytes moved
    // to the output; write it back so the guest observes faithful semantics.
    if offset_ptr != 0 {
        let advanced = match read_sendfile_offset(memory, offset_ptr) {
            Ok(offset) => offset.saturating_add(written),
            Err(error) => return error,
        };
        if memory
            .user()
            .write(offset_ptr, &advanced.to_ne_bytes())
            .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
    }
    written
}
