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

/// Reads the executable at `path` for an exec. Every host resource this
/// process spends doing so is its own: the descriptors that open the file,
/// and the buffer the image is read into, which is as large as the file. One
/// that the host refuses (EMFILE, ENFILE, ENOMEM, or a buffer this process
/// cannot allocate) is answered ENOMEM, with `refusal` recording the typed
/// refusal that names it, so that the exec is refused by name rather than
/// answered with an errno Linux would give for the guest's own reasons. Every
/// other failure is the errno Linux gives the guest, except an exact fd-link
/// spelling of a descriptor the guest holds, which Linux would follow and run:
/// that is refused with ELOOP, below. As Linux's do_open_execat (fs/exec.c)
/// does, a file that is not regular is EACCES, and so is one the caller may
/// not execute; a FIFO is never opened and a device never read. Known
/// differences from Linux: a program the caller may execute but not read is
/// EACCES (it is read through a descriptor opened for reading); a spelling
/// through a descriptor link, `/proc/self/exe`, `/proc/self/root` or
/// `/proc/self/cwd` that this resolution does not recognize is refused
/// (ELOOP, ENOENT or EACCES); a path through a symlink into /proc (such as
/// /dev/stdin), or through /proc entries other than the recognized
/// descriptor and exe links, is resolved against this process's /proc rather
/// than answered from the guest's view, so it is refused or may not match
/// Linux; a program whose own path is longer than a page is ENOEXEC (its
/// load names it by that path); a program open for writing is not refused
/// with ETXTBSY (the image is read, not executed by the host); and the
/// execute check is this process's (`check_executable_regular_file`).
pub(super) fn read_executable_file(
    state: &LoadedStaticElf,
    path: &std::path::Path,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<ResolvedExecutable, i64> {
    const OPENING: &str = "opening the new program";
    let lookup = exec_lookup(state, path.as_os_str().as_bytes())
        .map_err(|errno| exec_open_errno(errno, OPENING, refusal))?;
    read_executable_lookup(state, path, lookup, refusal)
}

/// [`read_executable_file`] for a `path` whose lookup is already known.
fn read_executable_lookup(
    state: &LoadedStaticElf,
    path: &std::path::Path,
    lookup: ExecLookup,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<ResolvedExecutable, i64> {
    const OPENING: &str = "opening the new program";
    let pinned = open_exec_lookup(state, lookup, OPENING, refusal)?;
    check_executable_regular_file(&pinned)?;
    let (image, file) = read_opened_exec_file(
        &pinned,
        None,
        OPENING,
        "the new program's image",
        "reading the new program's image",
        refusal,
    )?;
    Ok(ResolvedExecutable {
        path: path.to_owned(),
        file: Some(Arc::new(file)),
        image,
    })
}

/// What an exec path is looked up below (`exec_lookup`).
enum ExecBase {
    /// The root, for an absolute name.
    Root,
    /// The working-directory handle, for a relative name.
    Cwd,
    /// The directory that a run of `..` components led to.
    Directory(std::fs::File),
    /// The file a descriptor the guest holds names: this process's
    /// descriptor for it.
    GuestDescriptor(RawFd),
}

impl ExecBase {
    /// The descriptor a lookup below this base starts from; `None` for the
    /// root, which a lookup reaches by an absolute path.
    fn host_dirfd(&self, state: &LoadedStaticElf) -> Option<RawFd> {
        match self {
            Self::Root => None,
            Self::Cwd => Some(state.fs_context.cwd_fd.as_raw_fd()),
            Self::Directory(directory) => Some(directory.as_raw_fd()),
            Self::GuestDescriptor(host_fd) => Some(*host_fd),
        }
    }
}

/// An exec path, looked up as far as `exec_lookup` goes.
struct ExecLookup {
    base: ExecBase,
    /// The part still to look up below `base`, with no `..` component and
    /// no leading `/`.
    rest: Vec<u8>,
    /// The spelling from the root of `rest` below `base`, where the base's
    /// path is known: an fd link or the caller's own exe link is recognized
    /// by it.
    spelling: Option<Vec<u8>>,
}

/// How Linux would walk the exec path `path`, without a lexical step.
///
/// The walk starts at the root for an absolute name, else at the
/// working-directory handle, and goes one segment at a time: the components
/// before the next `..`, then the run of `..` after them. A `..` is the
/// parent of the directory the walk has reached, which neither the spelling
/// nor the recorded working-directory path can tell, so each segment and its
/// `..` run are looked up physically below the directory reached, without
/// following a magic link (`open_host_metadata_path`); a failure there is that
/// walk's errno. Before that, the segment's spelling from the root (the
/// current path of the directory reached, as /proc/self/fd reads it, and the
/// segment) is classified: an fd-link spelling of a descriptor the guest
/// holds continues the walk below the file that descriptor names, as Linux
/// follows the magic link; one it does not hold, or another task's, is
/// ENOENT. The last segment, with no `..` after it, is classified the same
/// way when it is opened (`open_exec_lookup`).
///
/// The classification only chooses between those routes. It reads the
/// directory's path after the directory is pinned, so a rename in between
/// can only make a segment take the guest-view route where it would not, or
/// not take it where it would; either way the walk below the pinned
/// directory is the physical one, which follows no magic link and refuses a
/// /proc object at the end of each segment, so neither route opens a file
/// outside the guest's view. A directory that has been removed, or whose
/// path is too long to read, has no path to classify by, so a segment below
/// it is only looked up physically.
///
/// The root is this process's: the guest's absolute paths are this process's
/// (`host_dirfd_and_path`), and a `..` at the root stays there (fs/namei.c
/// follow_dotdot). That holds while the guest's root is this process's root;
/// an emulated chroot or pivot_root would have to make these lookups with
/// RESOLVE_IN_ROOT from the guest's root.
fn exec_lookup(state: &LoadedStaticElf, path: &[u8]) -> Result<ExecLookup, i64> {
    let (mut base, mut rest) = if path.starts_with(b"/") {
        (ExecBase::Root, exec_strip_leading_slashes(path).to_vec())
    } else {
        (ExecBase::Cwd, path.to_vec())
    };
    loop {
        let base_path = exec_base_path(state, &base)?;
        let Some((segment_end, climb_end)) = exec_next_climb(&rest) else {
            let spelling = base_path.map(|base_path| exec_join(&base_path, &rest));
            return Ok(ExecLookup {
                base,
                rest,
                spelling,
            });
        };
        // The segment ends at the `/` before its `..`, which is not part of
        // the name a link would be.
        let segment = &rest[..segment_end];
        let segment = segment.strip_suffix(b"/").unwrap_or(segment);
        let spelling = base_path.map(|base_path| exec_join(&base_path, segment));
        let link = spelling
            .as_deref()
            .and_then(|spelling| reverie_procfs::parse_fd_link(spelling, state.pid, state.tid));
        if let Some(link) = link {
            let after = exec_strip_leading_slashes(&rest[segment_end..]).to_vec();
            let (guest_fd, below) = match link {
                reverie_procfs::FdLinkPath::Exact(guest_fd) => (guest_fd, Vec::new()),
                reverie_procfs::FdLinkPath::Below { fd, rest } => (fd, rest.to_vec()),
                reverie_procfs::FdLinkPath::OtherTask => return Err(negative_errno(libc::ENOENT)),
            };
            if state.proc_files.contains_key(&guest_fd)
                || state.fdinfo_files.contains_key(&guest_fd)
            {
                // Synthetic carriers are regular-file descriptions: below one
                // is ENOTDIR, as below any regular file.
                return Err(negative_errno(libc::ENOTDIR));
            }
            let Some(host_fd) = host_fd(state, guest_fd) else {
                return Err(negative_errno(libc::ENOENT));
            };
            base = ExecBase::GuestDescriptor(host_fd);
            rest = if below.is_empty() {
                after
            } else {
                [&below[..], b"/", &after[..]].concat()
            };
            continue;
        }
        let directory = open_exec_component(state, &base, &rest[..climb_end])?;
        rest = exec_strip_leading_slashes(&rest[climb_end..]).to_vec();
        base = ExecBase::Directory(directory);
    }
}

/// The byte offsets in `path` (relative) of the end of the components before
/// its first `..` component, and of the end of the run of `..`, `.` and
/// empty components from there; `None` if it has no `..` component.
fn exec_next_climb(path: &[u8]) -> Option<(usize, usize)> {
    let mut offset = 0;
    let mut segment_end = None;
    let mut climb_end = 0;
    for component in path.split(|byte| *byte == b'/') {
        let end = offset + component.len();
        match (segment_end, component) {
            (None, b"..") => {
                segment_end = Some(offset);
                climb_end = end;
            }
            (Some(_), b".." | b"." | b"") => climb_end = end,
            (Some(_), _) => break,
            (None, _) => {}
        }
        offset = end + 1;
    }
    segment_end.map(|segment_end| (segment_end, climb_end))
}

/// `path` without its leading `/` characters.
fn exec_strip_leading_slashes(path: &[u8]) -> &[u8] {
    &path[path
        .iter()
        .position(|byte| *byte != b'/')
        .unwrap_or(path.len())..]
}

/// The spelling of `rest` (relative, with no `..` component) below the
/// directory at `base_path`. Empty and `.` components name nothing, so they
/// are dropped, as Linux skips them; with no `..` left this is exact. A
/// trailing `/` or `/.` is kept as a trailing `/`: it asks for a directory,
/// so `/proc/self/exe/` is not the exe link, and `/proc/self/fd/<n>/` is the
/// directory below descriptor <n>, as Linux reads them.
fn exec_join(base_path: &[u8], rest: &[u8]) -> Vec<u8> {
    let base_path = base_path.strip_suffix(b"/").unwrap_or(base_path);
    let mut components = rest
        .split(|byte| *byte == b'/')
        .filter(|component| !matches!(*component, b"" | b"."))
        .peekable();
    if components.peek().is_none() {
        return if base_path.is_empty() {
            b"/".to_vec()
        } else {
            base_path.to_vec()
        };
    }
    let mut spelling = base_path.to_vec();
    for component in components {
        spelling.push(b'/');
        spelling.extend_from_slice(component);
    }
    if rest.ends_with(b"/") || rest.ends_with(b"/.") {
        spelling.push(b'/');
    }
    spelling
}

/// The current path of the directory `base` is, as /proc/self/fd reads it:
/// `None` for one that has been removed, or whose path is too long to read
/// (ENAMETOOLONG). Neither can spell an fd link or the exe link, so a segment
/// below either is only looked up physically.
fn exec_base_path(state: &LoadedStaticElf, base: &ExecBase) -> Result<Option<Vec<u8>>, i64> {
    let Some(host_dirfd) = base.host_dirfd(state) else {
        return Ok(Some(b"/".to_vec()));
    };
    let path = match std::fs::read_link(format!("/proc/self/fd/{host_dirfd}")) {
        Ok(path) => path,
        Err(error) if error.raw_os_error() == Some(libc::ENAMETOOLONG) => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let path = path.into_os_string().into_vec();
    if !path.starts_with(b"/") || path.ends_with(b" (deleted)") {
        return Ok(None);
    }
    Ok(Some(path))
}

/// An O_PATH handle on `path` below `base`, looked up without following a
/// magic link and checked as every guest lookup is (`open_host_metadata_path`).
fn open_exec_component(
    state: &LoadedStaticElf,
    base: &ExecBase,
    path: &[u8],
) -> Result<std::fs::File, i64> {
    let (host_dirfd, path) = match base.host_dirfd(state) {
        None => (libc::AT_FDCWD, [&b"/"[..], path].concat()),
        Some(host_dirfd) if path.is_empty() => (host_dirfd, b".".to_vec()),
        Some(host_dirfd) => (host_dirfd, path.to_vec()),
    };
    let path = std::ffi::CString::new(path).map_err(|_| negative_errno(libc::EINVAL))?;
    open_host_metadata_path(state, host_dirfd, &path, false)
}

/// Opens `path` for an exec in the guest's view, as [`read_executable_file`]
/// describes, and returns the O_PATH handle that pins the file found.
fn open_exec_path(
    state: &LoadedStaticElf,
    path: &std::path::Path,
    opening: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<std::fs::File, i64> {
    let lookup = exec_lookup(state, path.as_os_str().as_bytes())
        .map_err(|errno| exec_open_errno(errno, opening, refusal))?;
    open_exec_lookup(state, lookup, opening, refusal)
}

/// Opens the file `lookup` names for an exec ([`open_exec_path`]), once:
/// the handle returned is the file the exec checks and reads.
fn open_exec_lookup(
    state: &LoadedStaticElf,
    lookup: ExecLookup,
    opening: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<std::fs::File, i64> {
    // This executor opens an exec path without following magic links, so an
    // exact fd-link spelling of a descriptor the guest holds is refused with
    // the errno Linux gives a magic link it will not follow, ELOOP
    // (fs/namei.c nd_jump_link under LOOKUP_NO_MAGICLINKS). Any other fd-link
    // spelling is answered from the guest's descriptor table
    // (`host_dirfd_and_path`): ENOENT for a descriptor the guest does not
    // hold, as Linux answers for an fd that is not open (fs/proc/fd.c
    // proc_lookupfd_common), and below a descriptor it holds, the file there.
    let opened = match lookup.spelling.as_deref().and_then(|spelling| {
        Some((
            spelling,
            reverie_procfs::parse_fd_link(spelling, state.pid, state.tid)?,
        ))
    }) {
        Some((_, reverie_procfs::FdLinkPath::Exact(guest_fd)))
            if host_fd(state, guest_fd).is_some() =>
        {
            return Err(negative_errno(libc::ELOOP));
        }
        Some((spelling, _)) => open_metadata_path(state, libc::AT_FDCWD, spelling, false),
        None => open_exec_component(state, &lookup.base, &lookup.rest),
    };
    opened.map_err(|errno| exec_open_errno(errno, opening, refusal))
}

/// The answer to an exec whose path lookup failed with `errno`. A host that
/// refuses the openat2 call the lookup is made with (ENOSYS or EPERM from a
/// kernel or sandbox without it, E2BIG or EINVAL for its arguments) leaves
/// no lookup this executor trusts: the exec is refused by name, with
/// `refusal` recording it, and never resolved another way. Otherwise it is
/// [`exec_step_errno`].
fn exec_open_errno(
    errno: i64,
    opening: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> i64 {
    if [libc::ENOSYS, libc::EPERM, libc::E2BIG, libc::EINVAL]
        .iter()
        .any(|unavailable| errno == negative_errno(*unavailable))
    {
        *refusal = Some(exec_path_lookup_refusal());
        return negative_errno(libc::EOPNOTSUPP);
    }
    exec_step_errno(errno, opening, refusal)
}

/// Refuses, with EACCES, an exec of a file `pinned` holds unless it is a
/// regular file the caller may execute, as Linux's do_open_execat does
/// (fs/exec.c; may_open refuses any other type under MAY_EXEC, fs/namei.c).
/// The checks are on the O_PATH handle, so a FIFO is never opened. The
/// execute check is faccessat2 with AT_EACCESS, so it judges this process's
/// credentials, as every guest open does; a host that refuses faccessat2
/// (ENOSYS or EPERM) gives the exec that errno.
fn check_executable_regular_file(pinned: &std::fs::File) -> Result<(), i64> {
    if file_mode(pinned)? & libc::S_IFMT != libc::S_IFREG {
        return Err(negative_errno(libc::EACCES));
    }
    // SAFETY: the empty path is NUL-terminated and pinned's descriptor is live.
    let access = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            pinned.as_raw_fd(),
            c"".as_ptr(),
            libc::X_OK,
            libc::AT_EMPTY_PATH | libc::AT_EACCESS,
        )
    };
    if access != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Reads the file `pinned` holds, through a descriptor of its own that is
/// returned with the image. With a `cap`, a file larger than `cap` bytes is
/// refused with ENOEXEC before any of it is read, and again if it grew past
/// `cap` while it was read.
fn read_opened_exec_file(
    pinned: &std::fs::File,
    cap: Option<u64>,
    opening: &str,
    what: &str,
    reading: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<(Vec<u8>, std::fs::File), i64> {
    use std::io::Read;
    let mut file = std::fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|error| exec_step_io_error(error, opening, refusal))?;
    let length = file.metadata().ok().map(|metadata| metadata.len());
    if let (Some(cap), Some(length)) = (cap, length)
        && length > cap
    {
        return Err(negative_errno(libc::ENOEXEC));
    }
    let mut image = Vec::new();
    // Reserved whole and up front, so that a buffer this process cannot
    // allocate is refused naming the request. read_to_end's own growth, for a
    // file that grew since, is fallible too: it reports OutOfMemory.
    if let Some(length) = length.and_then(|length| usize::try_from(length).ok())
        && image.try_reserve_exact(length).is_err()
    {
        *refusal = Some(exec_allocation_refusal(length, what));
        return Err(negative_errno(libc::ENOMEM));
    }
    match cap {
        Some(cap) => {
            (&mut file)
                .take(cap.saturating_add(1))
                .read_to_end(&mut image)
                .map_err(|error| exec_step_io_error(error, reading, refusal))?;
            if image.len() as u64 > cap {
                return Err(negative_errno(libc::ENOEXEC));
            }
        }
        None => {
            file.read_to_end(&mut image)
                .map_err(|error| exec_step_io_error(error, reading, refusal))?;
        }
    }
    Ok((image, file))
}

/// Resolves and reads the program interpreter at `path`, an exec's new image
/// names it (`PT_INTERP`), in the guest's view as [`read_executable_file`]
/// opens a program, so that a load maps the interpreter the guest names and
/// never opens the path itself. Linux opens an interpreter as it opens a
/// program (fs/binfmt_elf.c `load_elf_binary` calls `open_exec`): a
/// non-regular file, or one the caller may not execute, is EACCES
/// (fs/exec.c `do_open_execat`). A file of more than
/// [`crate::elf::MAX_INTERPRETER_BYTES`] is this loader's own limit, refused
/// with ENOEXEC as an unloadable interpreter. Known differences from Linux:
/// an interpreter the caller may execute but not read is EACCES (it is read
/// through a descriptor opened for reading); a spelling through a descriptor
/// link, `/proc/self/exe`, `/proc/self/root` or `/proc/self/cwd` that this
/// resolution does not recognize is refused (ELOOP, ENOENT or EACCES).
pub(super) fn read_exec_interpreter(
    state: &LoadedStaticElf,
    path: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<crate::elf::ExecInterpreter, i64> {
    const OPENING: &str = "opening the program interpreter";
    let pinned = open_exec_path(state, std::path::Path::new(path), OPENING, refusal)?;
    check_executable_regular_file(&pinned)?;
    let (image, file) = read_opened_exec_file(
        &pinned,
        Some(crate::elf::MAX_INTERPRETER_BYTES),
        OPENING,
        "the program interpreter's image",
        "reading the program interpreter's image",
        refusal,
    )?;
    Ok(crate::elf::ExecInterpreter::new(
        path.to_owned(),
        image,
        Arc::new(file),
    ))
}

/// Resolves and reads the image an exec of the guest's `path` runs, as
/// [`read_executable_file`] reads it; `refusal` records the typed refusal of
/// a host resource this process ran out of. An exec of the caller's own
/// `/proc/self/exe` runs the image the caller was loaded from, which this
/// copies into a buffer allocated fallibly: it is as large as that image.
pub(super) fn resolve_guest_exec_image(
    state: &LoadedStaticElf,
    path: Vec<u8>,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> Result<ResolvedExecutable, i64> {
    const OPENING: &str = "opening the new program";
    // The caller's own exe link is recognized by its spelling from the root
    // (`exec_lookup`), as an fd-link spelling is.
    let lookup =
        exec_lookup(state, &path).map_err(|errno| exec_open_errno(errno, OPENING, refusal))?;
    let exe_link = lookup.spelling.as_deref().and_then(|spelling| {
        reverie_procfs::classify_exe_path(spelling, &|tid| live_thread_in_process(state, tid))
    });
    match exe_link {
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
            let mut image = Vec::new();
            if image
                .try_reserve_exact(state.executable_image.len())
                .is_err()
            {
                *refusal = Some(exec_allocation_refusal(
                    state.executable_image.len(),
                    "a copy of the running program's image (/proc/self/exe)",
                ));
                return Err(negative_errno(libc::ENOMEM));
            }
            image.extend_from_slice(&state.executable_image);
            return Ok(ResolvedExecutable {
                path: std::path::PathBuf::from(std::ffi::OsString::from_vec(path)),
                file: Some(file.clone()),
                image,
            });
        }
        Some(false) => return Err(negative_errno(libc::ENOENT)),
        None => {}
    }
    // Linux resolves an exec's filename as it resolves any path (fs/exec.c
    // do_open_execat): an absolute one from the root, any other, with or
    // without a slash, from the working directory. execve never searches
    // PATH: execvp(3), posix_spawnp(3) and shells search it themselves and
    // pass the path they found.
    let executable_path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&path));
    read_executable_lookup(state, &executable_path, lookup, refusal)
}

/// Maximum `#!` interpreter indirection levels, matching the Linux kernel's
/// `BINPRM_MAX_RECURSION` limit for chained script interpreters.
pub(super) const MAX_SHEBANG_DEPTH: usize = 4;

/// Resolve `#!` interpreter scripts for in-guest `execve(2)`, as the kernel's
/// script loader does (`load_script`, fs/binfmt_script.c).
///
/// The reverie-kvm ELF loader can only map ELF images, so a guest that execs a
/// `#!`-script (for example a `sh` wrapper that execs another wrapper) must have
/// its interpreter resolved here. Each line is read as Linux reads it
/// ([`crate::elf::parse_script_line`]): only its first 256 bytes, the
/// interpreter, then at most one optional argument, the rest of the line,
/// never split on its spaces. On success the returned image is the
/// interpreter's file contents and `argv` is rewritten in kernel order:
/// `[interp, optional argument, script_path, <original argv[1..]>]`. Each
/// level therefore replaces `argv[0]` with at most two entries made from at
/// most 253 bytes of the line each, and the script's path, and there are at
/// most [`MAX_SHEBANG_DEPTH`] levels. Errors are returned as negative errnos.
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
        let Some(line) =
            crate::elf::parse_script_line(&image).map_err(|()| negative_errno(libc::ENOEXEC))?
        else {
            unreachable!("the image starts with #!");
        };
        let interpreter = std::path::PathBuf::from(std::ffi::OsString::from_vec(line.interpreter));
        // The guest's argv was read under the executor's limits (4096 entries,
        // 128 KiB in all); this level replaces argv[0] with at most two entries
        // made from at most 253 bytes of the line each, and the script's path,
        // and moves the rest. Allocated fallibly all the same: one this process
        // cannot allocate is ENOMEM, which an exec refuses as this backend's
        // own (`exec_host_memory_refusal`). An empty argv still gets all three.
        let mut rewritten = Vec::new();
        rewritten
            .try_reserve_exact(argv.len().max(1) + 2)
            .map_err(exec_out_of_memory)?;
        rewritten.push(
            try_lossy_string(interpreter.as_os_str().as_bytes()).map_err(exec_out_of_memory)?,
        );
        if let Some(argument) = line.argument {
            rewritten.push(try_lossy_string(&argument).map_err(exec_out_of_memory)?);
        }
        rewritten.push(try_lossy_string(path.as_os_str().as_bytes()).map_err(exec_out_of_memory)?);
        if argv.len() > 1 {
            rewritten.extend(argv.drain(1..));
        }
        argv = rewritten;

        path = interpreter;
        image = read_interpreter(&path)?;
    }
    Ok((path, image, argv))
}

/// The answer of an exec preparation to an allocation this process could not
/// make.
fn exec_out_of_memory(_: std::collections::TryReserveError) -> i64 {
    negative_errno(libc::ENOMEM)
}

/// `bytes` as UTF-8 with each invalid sequence replaced, exactly as
/// `String::from_utf8_lossy` replaces it, in a buffer allocated fallibly.
fn try_lossy_string(bytes: &[u8]) -> Result<String, std::collections::TryReserveError> {
    let mut text = String::new();
    for chunk in bytes.utf8_chunks() {
        let replacement = if chunk.invalid().is_empty() {
            ""
        } else {
            "\u{FFFD}"
        };
        text.try_reserve(chunk.valid().len() + replacement.len())?;
        text.push_str(chunk.valid());
        text.push_str(replacement);
    }
    Ok(text)
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
        state.stdin_copy()
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
        // A zero-length write to a datagram or seqpacket socket sends an empty
        // record (unix_dgram_sendmsg queues an skb of no bytes), which the
        // peer receives as a 0-byte message; one to a stream socket sends
        // nothing. An owned socket therefore takes even a zero count to the
        // host, which decides as it does for a nonzero one. Every other
        // descriptor keeps the early zero.
        if !standard
            && (output_destination.is_none() || output.is_none())
            && let Some(file) = state.files.get(&fd)
            && file_mode(file).is_ok_and(|mode| mode & libc::S_IFMT == libc::S_IFSOCK)
        {
            let host_fd = file.as_raw_fd();
            let (written, sigpipe) = suppress_host_sigpipe_reporting(None, || {
                // SAFETY: a zero count reads no byte from the dangling,
                // non-null pointer, and host_fd is a live backing descriptor.
                unsafe { libc::write(host_fd, std::ptr::dangling::<libc::c_void>(), 0) as i64 }
            });
            return with_guest_sigpipe(state, written, sigpipe);
        }
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
        .stdin_copy_mut()
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
    // Checked before the host read, so a datagram or seqpacket record whose
    // copy Linux would fault and free stays queued here
    // (https://github.com/rrnewton/reverie/issues/1235).
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

/// Whether the host's random pool is initialized, so that reading
/// /dev/random cannot wait: getrandom of zero bytes with GRND_NONBLOCK fails
/// with EAGAIN until then.
fn host_random_pool_ready() -> bool {
    // SAFETY: a zero-length request writes nothing.
    unsafe { libc::getrandom(std::ptr::null_mut(), 0, libc::GRND_NONBLOCK) == 0 }
}

/// The finite set of local filesystems whose regular files and directories
/// `admit_host_read_zero` admits under the backend's existing filesystem-I/O
/// contract. Pseudo, FUSE and network filesystems stay outside it.
pub(super) fn zero_read_local_filesystem(f_type: libc::c_long) -> bool {
    // Overlayfs adds no wait to that contract: ovl_read_iter returns 0 for an
    // empty iterator before it resolves or opens the real upper or lower file,
    // so a lower-only file is neither read nor copied up. Its directories use
    // generic_read_dir (EISDIR), as on the other three.
    // Linux v6.12 fs/overlayfs/file.c, ovl_read_iter:
    // https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/overlayfs/file.c#L278
    // https://github.com/rrnewton/reverie/issues/1354
    matches!(
        f_type,
        libc::TMPFS_MAGIC
            | libc::EXT4_SUPER_MAGIC
            | libc::BTRFS_SUPER_MAGIC
            | libc::OVERLAYFS_SUPER_MAGIC
    )
}

/// Refuse unsupported external waits before creating a reader or injecting a
/// host read. A zero-count read that waited in the host would hold the
/// executor's task there, out of the Tool's sight, where a Tool that keeps its
/// turn around the injection also keeps a guest peer from supplying data or
/// committing group exit: https://github.com/rrnewton/hermit/issues/3498.
///
/// This checks the owned endpoint selected by the shared-table snapshot, not
/// its guest fd number or modeled stdin type. O_NONBLOCK is deliberately not an
/// admission proof: another alias of the same open-file description can change
/// it after F_GETFL. Even a currently nonblocking inotify is therefore
/// outside this supported surface, including every instance this executor
/// created nonblocking (inotify.rs): the executor never clears O_NONBLOCK on
/// one, but an alias outside the guest, to which the guest sent it, can. Known
/// local regular files retain the backend's existing filesystem-I/O contract;
/// arbitrary pseudo/FUSE files and unknown drivers are not assumed to have
/// regular-file zero-read semantics.
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
        && zero_read_local_filesystem(filesystem.f_type)
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

/// [`host_read`] for a guest's read of host descriptor `fd`, which may be a
/// socket if `socket`. A Unix socket's read receives the rights of the
/// message it consumes, which Linux discards, to release them
/// (`receive_discarding_rights`), whatever is in flight when it starts: a
/// read can wait for a message that another process sends meanwhile
/// (`is_unix_socket`).
fn guest_host_read(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    fd: RawFd,
    address: u64,
    length: usize,
    socket: bool,
) -> i64 {
    if !(socket && is_unix_socket(fd)) {
        return host_read(memory, fd, address, length);
    }
    let mut bytes = match prepare_host_read(&ProviderMemory(memory), address, length) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    match receive_discarding_rights(state, fd, std::slice::from_mut(&mut iov), 0, None, false) {
        Ok(0) => 0,
        // The bytes were accessible when the read began (`prepare_host_read`).
        Ok(count) => match memory.user().write(address, &bytes[..count]) {
            Ok(()) => count as i64,
            Err(_) => end_run_for_late_receive_fault("read", address),
        },
        Err(error) => io_error(error),
    }
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
    pub(super) files: &'a mut PrivateFiles,
    pub(super) fd: i32,
    pub(super) endpoint: Option<std::fs::File>,
    /// The lent copy's host descriptor, which stays the reader's when it
    /// keeps the File (`PrivateFiles::mark_foreign`).
    host: RawFd,
}

impl<'a> ReadEndpoint<'a> {
    pub(super) fn take(files: &'a mut PrivateFiles, fd: i32) -> Self {
        let endpoint = files
            .remove(&fd)
            .expect("prechecked read descriptor disappeared");
        let host = endpoint.as_raw_fd();
        Self {
            files,
            fd,
            endpoint: Some(endpoint),
            host,
        }
    }
}

impl Drop for ReadEndpoint<'_> {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            // The exclusive map borrow prevents a competing local insertion.
            self.files.insert(self.fd, endpoint);
        } else {
            // None means the registry still owns the actual File because
            // physical retirement was not proven. Never duplicate, close, or
            // replace it: nor may another thread's retirement.
            self.files.mark_foreign(self.host);
        }
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
        let Some(stdin) = state.stdin_copy() else {
            return Ok(negative_errno(libc::EBADF));
        };
        if requested_length == 0 {
            admit_host_read_zero(stdin, fd, args[1])?;
            if let Some((context, identity)) = terminal_read {
                let host = stdin.as_raw_fd();
                // Preserve the owned C reader's cancellation and join protocol.
                // Adapt only its host operand; retain the original request and
                // let the kernel enforce descriptor-before-address ordering.
                let returned = context.read(
                    &mut state.stdin,
                    identity,
                    *request,
                    zero_read_host_address(args[1]),
                    0,
                );
                if state.stdin.is_none() {
                    // The reader kept the copy, as for a lent descriptor
                    // (`ReadEndpoint`).
                    state.files.mark_foreign(host);
                }
                let returned = returned?;
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
        return Ok(guest_host_read(
            memory,
            state,
            stdin.as_raw_fd(),
            args[1],
            length,
            true,
        ));
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
        // count, so the staged readv path applies scalar read semantics. An
        // instance that is blocking on the host is refused first: its read
        // would wait there (inotify.rs).
        Ok(true) => {
            refuse_blocking_inotify_read(host_fd, fd)?;
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
    Ok(guest_host_read(
        memory,
        state,
        host_fd,
        args[1],
        length,
        mode & libc::S_IFMT == libc::S_IFSOCK,
    ))
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
    // R2 slice 6: positioned read through the description when the entry
    // has one (a dup sharing the open description; read_at moves no
    // offset). The direct file path remains the fallback.
    let read = match host_description(state, fd) {
        Some(description) => {
            super::vfs_file::FileDescription::read_at(&description, &mut bytes, args[3])
        }
        None => file.read_at(&mut bytes, args[3]),
    };
    match read {
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
    state: &LoadedStaticElf,
    number: libc::c_long,
    host_fd: RawFd,
    host_iovecs: &mut [libc::iovec],
    args: &[u64; 6],
    socket: bool,
    unwritable: bool,
) -> i64 {
    // As for read: a readv of a Unix socket, or a preadv2 at its current
    // position, receives the rights it consumes (`guest_host_read`). Linux
    // returns 0 for a read of no byte before it reaches the socket
    // (`sock_read_iter`), and refuses RWF_ATOMIC and RWF_DONTCACHE for a
    // socket before reading (`kiocb_set_rw_flags`); the host call below gives
    // both.
    let flags = if number == libc::SYS_preadv2 {
        args[5] as libc::c_int
    } else {
        0
    };
    if (number == libc::SYS_readv || number == libc::SYS_preadv2 && args[3] as i64 == -1)
        && host_iovecs.iter().any(|vector| vector.iov_len != 0)
        && flags & (libc::RWF_ATOMIC | libc::RWF_DONTCACHE) == 0
        && socket
        && is_unix_socket(host_fd)
    {
        let receive = if flags & libc::RWF_NOWAIT != 0 {
            libc::MSG_DONTWAIT
        } else {
            0
        };
        return match receive_discarding_rights(
            state,
            host_fd,
            host_iovecs,
            receive,
            None,
            unwritable,
        ) {
            Ok(count) => count as i64,
            Err(error) => io_error(error),
        };
    }
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
    let (inotify, socket) = if reading {
        let mode = match fd_mode(host_fd) {
            Ok(mode) => mode,
            Err(error) => return error,
        };
        match host_fd_mode_is_inotify(host_fd, mode) {
            Ok(inotify) => (inotify, mode & libc::S_IFMT == libc::S_IFSOCK),
            Err(error) => return error,
        }
    } else {
        (false, false)
    };
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

    let mut host_iovecs = staged_host_iovecs(&mut staged_vectors);
    if !reading {
        let (written, sigpipe) =
            invoke_vectored_write_reporting(number, host_fd, &mut host_iovecs, args);
        return with_guest_sigpipe(state, written, sigpipe);
    }

    // A vectored inotify read can leave bytes past its count: see
    // vector_faulted_after_count. The host instance's count of queued bytes
    // before and after the read says whether it did.
    let inotify_queued = if inotify
        && staged_vectors
            .iter()
            .filter(|vector| vector.guest.length != 0)
            .count()
            > 1
    {
        host_inotify_queued(host_fd).ok()
    } else {
        None
    };
    // A receive from a Unix datagram or seqpacket socket into a buffer that
    // is not all writable may be refused (`refuse_unwritable_record_buffer`).
    let unwritable = socket
        && receives_records(host_fd)
        && staged_vectors
            .iter()
            .any(|vector| vector.accessible_length < vector.guest.length);
    let result = invoke_vectored_read(
        state,
        number,
        host_fd,
        &mut host_iovecs,
        args,
        socket,
        unwritable,
    );
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
                // The prefix was accessible when the read began; a read of a
                // Unix socket has received (`invoke_vectored_read`).
                return if socket && is_unix_socket(host_fd) {
                    end_run_for_late_receive_fault(
                        if number == libc::SYS_readv {
                            "readv"
                        } else {
                            "preadv2"
                        },
                        vector.guest.base,
                    )
                } else {
                    negative_errno(libc::EFAULT)
                };
            }
            remaining -= transferred;
            if remaining == 0 {
                break;
            }
        }
        debug_assert_eq!(remaining, 0, "host returned more bytes than requested");
        // The read took events past its count only when the read of the
        // vector after it copied them before a fault: inotify_read dequeues an
        // event before it copies it. Those events stay in that vector, as on
        // Linux; publish its accessible prefix, all of which the kernel wrote
        // (it copies events from the vector's start up to the first byte it
        // cannot write, the end of that prefix).
        //
        // The two counts measure this read alone only while no other task
        // reads the same instance between them. A guest that reads one
        // instance from two threads at once (possible only where the Tool lets
        // guest threads run concurrently) can raise the measured loss; the
        // vector is then published as it was staged before the read, which
        // can overwrite bytes an overlapping earlier vector received. A rename
        // in a watched directory by a process outside the guest can only lower
        // the measured loss, which withholds a publication but never causes a
        // wrong one.
        if let Some(before) = inotify_queued
            && let Some(vector) = vector_faulted_after_count(&staged_vectors, result as usize)
            && host_inotify_queued(host_fd)
                .is_ok_and(|after| i64::from(before) - i64::from(after) > result)
            && memory
                .write_exact(
                    vector.guest.base,
                    vector.accessible_slice(vector.accessible_length),
                )
                .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
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

/// The staged vector into which a successful vectored read of `count` bytes
/// from a file without `read_iter`, such as an inotify instance, may have
/// copied bytes past its count: the nonempty vector after the ones the count
/// fills, when the count ends exactly at its start and the vector has an
/// accessible prefix followed by an inaccessible suffix.
///
/// Linux reads such a file one iovec at a time (`do_loop_readv_writev`,
/// <https://github.com/torvalds/linux/blob/v6.17/fs/read_write.c#L835-L866>,
/// chosen at
/// <https://github.com/torvalds/linux/blob/v6.17/fs/read_write.c#L1017-L1020>).
/// When the read of an iovec fails after an earlier one succeeded, it returns
/// the earlier iovecs' count and drops the error, and whatever the failed read
/// copied stays in that iovec. `inotify_read`
/// (<https://github.com/torvalds/linux/blob/v6.17/fs/notify/inotify/inotify_user.c#L249-L299>)
/// copies whole events from the start of its buffer and fails with EFAULT at
/// the event whose copy faults, having dequeued it first (`get_one_event`,
/// <https://github.com/torvalds/linux/blob/v6.17/fs/notify/inotify/inotify_user.c#L170-L191>).
/// Only a vector with an inaccessible suffix can fault, and one whose
/// accessible prefix is empty faults at its first byte, copying nothing.
fn vector_faulted_after_count(
    staged_vectors: &[StagedIoVector],
    count: usize,
) -> Option<&StagedIoVector> {
    if count == 0 {
        return None;
    }
    let mut filled = 0usize;
    for vector in staged_vectors {
        if vector.guest.length == 0 {
            continue;
        }
        if filled == count {
            return (vector.accessible_length != 0
                && vector.accessible_length < vector.guest.length)
                .then_some(vector);
        }
        filled = filled.checked_add(vector.guest.length)?;
        if filled > count {
            return None;
        }
    }
    None
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
            state.stdin_copy()
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
                    let stdin = state.stdin_copy().expect("open standard input disappeared");
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
            let mut stdin = state.stdin_copy().expect("open standard input disappeared");
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
