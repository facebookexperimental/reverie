/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Synthetic /proc files and fdinfo (gVisor: pkg/sentry/fsimpl/proc).

use super::*;

pub(super) fn host_file_key(fd: RawFd) -> Result<(libc::dev_t, libc::ino_t), i64> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and fd is live.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstat initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_dev, stat.st_ino))
}

/// Bounds the process proc rights in flight across the namespace. Linux bounds
/// a user's in-flight rights by RLIMIT_NOFILE and fails the send with
/// ETOOMANYREFS; here each tracked description also pins a host descriptor, and
/// a right the host discards unreceived is never released, so the bound is small.
pub(super) const PROC_TRANSFER_LIMIT: usize = 1024;

/// Records one in-flight right for the process proc description at `guest_fd`.
pub(super) fn register_proc_transfer(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
    host_fd: RawFd,
) -> Result<(libc::dev_t, libc::ino_t), i64> {
    let description = &state.fdinfo_files[&guest_fd];
    let proc_inode = *state
        .proc_files
        .get(&guest_fd)
        .ok_or_else(|| negative_errno(libc::ENOSYS))?;
    let key = host_file_key(host_fd)?;
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let in_flight: usize = table
        .proc_transfers
        .values()
        .map(|transfer| transfer.in_flight)
        .sum();
    if in_flight >= PROC_TRANSFER_LIMIT {
        return Err(negative_errno(libc::ETOOMANYREFS));
    }
    match table.proc_transfers.entry(key) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            // The pin makes a different description at this identity impossible.
            if !Arc::ptr_eq(&entry.get().description, description) {
                return Err(negative_errno(libc::ENOSYS));
            }
            entry.get_mut().in_flight += 1;
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            // SAFETY: host_fd is live; success returns a new owned descriptor.
            let pin = unsafe { libc::fcntl(host_fd, libc::F_DUPFD_CLOEXEC, 0) };
            if pin < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            entry.insert(ProcTransfer {
                description: description.clone(),
                proc_inode,
                nofollow: state.synthetic_proc_nofollow_fds.contains(&guest_fd),
                // SAFETY: successful F_DUPFD_CLOEXEC transfers ownership.
                _pin: unsafe { std::fs::File::from_raw_fd(pin) },
                in_flight: 1,
            });
        }
    }
    Ok(key)
}

/// Finds the process proc description sent with a received backing memfd. A
/// peek leaves the right queued, so only a consuming receive takes it.
pub(super) fn received_proc_transfer(
    state: &LoadedStaticElf,
    file: &std::fs::File,
    peek: bool,
) -> Result<Option<(Arc<FdinfoDescription>, u64, bool)>, i64> {
    let key = host_file_key(file.as_raw_fd())?;
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if peek {
        return Ok(table.proc_transfers.get(&key).map(|transfer| {
            (
                transfer.description.clone(),
                transfer.proc_inode,
                transfer.nofollow,
            )
        }));
    }
    Ok(take_proc_transfer(&mut table, key))
}

/// Undoes registrations whose rights the host never queued.
pub(super) fn release_proc_transfers(state: &LoadedStaticElf, keys: &[(libc::dev_t, libc::ino_t)]) {
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for key in keys {
        take_proc_transfer(&mut table, *key);
    }
}

/// Undoes registrations whose rights the host dequeued but the guest will never
/// receive. A peek left them queued, so they stay in flight.
pub(super) fn release_dropped_proc_transfers<'a>(
    state: &LoadedStaticElf,
    files: impl IntoIterator<Item = &'a std::fs::File>,
    peek: bool,
) {
    if peek {
        return;
    }
    let keys: Vec<_> = files
        .into_iter()
        .filter_map(|file| host_file_key(file.as_raw_fd()).ok())
        .collect();
    release_proc_transfers(state, &keys);
}

/// Consumes one in-flight right, returning its description state.
fn take_proc_transfer(
    table: &mut crate::elf::GuestFileIdentityTable,
    key: (libc::dev_t, libc::ino_t),
) -> Option<(Arc<FdinfoDescription>, u64, bool)> {
    let std::collections::btree_map::Entry::Occupied(mut entry) = table.proc_transfers.entry(key)
    else {
        return None;
    };
    let transfer = entry.get_mut();
    let received = (
        transfer.description.clone(),
        transfer.proc_inode,
        transfer.nofollow,
    );
    transfer.in_flight -= 1;
    if transfer.in_flight == 0 {
        entry.remove();
    }
    Some(received)
}

#[derive(Debug)]
pub(super) enum SeqProcSource {
    Fdinfo(FdinfoTarget),
    Process {
        file: ProcessProcFile,
        view: ProcessProcView,
    },
}

/// A proc fdinfo entry refers to one task incarnation and descriptor number.
/// Each observation resolves the current entry in the original task's table.
#[derive(Debug)]
pub(super) struct FdinfoTarget {
    pub(super) target_tid: i32,
    pub(super) target_generation: u64,
    pub(super) target_fd: i32,
    pub(super) table: std::sync::Weak<Mutex<FileTableState>>,
    pub(super) lifecycle: Arc<Mutex<crate::elf::TaskLifecycleTable>>,
    pub(super) capture_output: bool,
}

/// The per-process `/proc/<pid>` files whose content Linux generates on read
/// and that the executor still renders: `status` only. `stat` followed
/// Detcore (package K slice D4c-1), which renders every spelling of a
/// process's own `/proc/<pid>/stat` from its own process table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessProcFile {
    Status,
}

impl ProcessProcFile {
    pub(super) fn from_normalized_path(path: &[u8]) -> Option<Self> {
        match path {
            b"/proc/self/status" => Some(Self::Status),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
        }
    }
}

/// The process cells rendered into `/proc/<pid>/status`. The parent
/// cell and the leader's name are shared with the live process, so a
/// description opened before reparenting or `PR_SET_NAME` renders the value
/// current at read time, as Linux does. The umask is sampled at open because
/// it is not a shared process cell here.
#[derive(Clone, Debug)]
pub(super) struct ProcessProcView {
    pub(super) pid: i32,
    pub(super) ppid: i32,
    pub(super) orphan_reaper_pid: Arc<AtomicI32>,
    pub(super) leader_name: Arc<Mutex<[u8; TASK_COMM_LEN]>>,
    pub(super) umask: libc::mode_t,
}

impl ProcessProcView {
    fn of(state: &LoadedStaticElf) -> Self {
        Self {
            pid: state.pid,
            ppid: state.ppid,
            orphan_reaper_pid: state.orphan_reaper_pid.clone(),
            leader_name: state.thread_group_leader_name.clone(),
            umask: state.umask,
        }
    }

    /// Same rule as [`LoadedStaticElf::guest_parent_pid`].
    fn parent_pid(&self) -> i32 {
        match self.orphan_reaper_pid.load(Ordering::SeqCst) {
            0 => self.ppid,
            reaper => reaper,
        }
    }

    /// The thread-group leader's `comm`, without its terminating NUL byte.
    fn comm(&self) -> Vec<u8> {
        let name = self
            .leader_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let length = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(TASK_COMM_LEN);
        name[..length].to_vec()
    }

    fn render(&self, file: ProcessProcFile) -> Vec<u8> {
        match file {
            ProcessProcFile::Status => self.status(),
        }
    }

    fn status(&self) -> Vec<u8> {
        let mut content = b"Name:\t".to_vec();
        // Linux renders newline and backslash as two-byte escape sequences in
        // the `Name` field; `stat` keeps the raw bytes.
        for byte in self.comm() {
            match byte {
                b'\n' => content.extend_from_slice(b"\\n"),
                b'\\' => content.extend_from_slice(b"\\\\"),
                _ => content.push(byte),
            }
        }
        content.push(b'\n');
        content.extend_from_slice(
            format!(
                "Umask:\t{umask:04o}\n\
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
                umask = self.umask,
                pid = self.pid,
                ppid = self.parent_pid(),
            )
            .as_bytes(),
        );
        content
    }
}

impl FdinfoDescription {
    fn observe(&self) -> Result<Vec<u8>, i64> {
        match &self.source {
            SeqProcSource::Fdinfo(target) => target.observe(),
            SeqProcSource::Process { file, view } => Ok(view.render(*file)),
        }
    }
}

impl FdinfoTarget {
    fn observe(&self) -> Result<Vec<u8>, i64> {
        let table = self
            .table
            .upgrade()
            .ok_or_else(|| negative_errno(libc::ENOENT))?;
        let (file, flags) = {
            // Order: description seq -> ONE file table -> lifecycle. Mutation
            // paths only propagate/drop description Arcs; they never lock seq.
            let table = table.lock().expect("KVM file-table lock poisoned");
            let lifecycle = self.lifecycle.lock().expect("KVM lifecycle lock poisoned");
            if !lifecycle
                .get(self.target_tid)
                .is_some_and(|task| task.generation == self.target_generation)
            {
                return Err(negative_errno(libc::ENOENT));
            }
            if table.proc_files.contains_key(&self.target_fd)
                || table.signalfd_fds.contains(&self.target_fd)
                || (self.capture_output
                    && (table.stdout_alias_fds.contains(&self.target_fd)
                        || table.stderr_alias_fds.contains(&self.target_fd)
                        || ((self.target_fd == 1 || self.target_fd == 2)
                            && !table.files.contains_key(&self.target_fd)
                            && !table.closed_standard_fds.contains(&self.target_fd))))
            {
                return Err(negative_errno(libc::ENOSYS));
            }
            let host = table
                .files
                .get(&self.target_fd)
                .map(AsRawFd::as_raw_fd)
                .or_else(|| {
                    if table.closed_standard_fds.contains(&self.target_fd) {
                        return None;
                    }
                    match self.target_fd {
                        0 => table.stdin.as_ref().map(AsRawFd::as_raw_fd),
                        1 | 2 => Some(self.target_fd),
                        _ => None,
                    }
                })
                .ok_or_else(|| negative_errno(libc::ENOENT))?;
            // F_GETFL and the descriptor's guest CLOEXEC belong to the same
            // table observation as F_SETFD/F_SETFL. Internal dup CLOEXEC is not
            // a guest flag. Pin the OFD before releasing its table.
            let flags = fd_status_flags(host)?
                | if table.cloexec_fds.contains(&self.target_fd) {
                    libc::O_CLOEXEC
                } else {
                    0
                };
            // SAFETY: the table owns host (or it is an open inherited standard
            // descriptor); fcntl validates the fd and returns a new owned fd.
            let pinned = unsafe { libc::fcntl(host, libc::F_DUPFD_CLOEXEC, 0) };
            if pinned < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            // SAFETY: successful F_DUPFD_CLOEXEC transfers ownership.
            (unsafe { std::fs::File::from_raw_fd(pinned) }, flags)
        };
        // Neither table nor lifecycle is held across procfs I/O. Private
        // anonymous carriers (epoll/inotify/eventfd/timerfd/pidfd, etc.) have no
        // ordinary file type and must not expose their supervisor identities.
        ensure_fdinfo_object(file.as_raw_fd())?;
        let bytes = read_owned_fdinfo(&file)?;
        replace_fdinfo_flags(&bytes, flags)
    }
}

impl FdinfoDescription {
    pub(super) fn read<M: GuestMemoryAccess<Error = crate::Error>>(
        &self,
        memory: &mut M,
        args: &[u64; 6],
        positioned: bool,
    ) -> i64 {
        let Ok(count) = usize::try_from(args[2]) else {
            return negative_errno(libc::EINVAL);
        };
        if positioned && (args[3] as i64) < 0 {
            return negative_errno(libc::EINVAL);
        }
        // vfs_read admits the original userspace interval before limiting the
        // transfer or entering seq_read. This is architecture admission only;
        // permission faults still occur during the counted copy, after show.
        if let Err(error) = validate_guest_iovec_address(args[1], count) {
            return error;
        }
        let mut sequence = self
            .sequence
            .lock()
            .expect("KVM fdinfo sequence lock poisoned");
        sequence.read(
            positioned.then_some(args[3]),
            count.min(MAX_HOST_IO),
            || self.observe(),
            |bytes| {
                memory
                    .copy_to_user_prefix(args[1], bytes)
                    .map_err(|_| negative_errno(libc::EFAULT))
            },
        )
    }

    pub(super) fn seek(&self, args: &[u64; 6]) -> i64 {
        self.sequence
            .lock()
            .expect("KVM fdinfo sequence lock poisoned")
            .seek(args[1] as i64, args[2] as libc::c_int, || self.observe())
    }
}

pub(super) fn fdinfo_private_carrier_error(
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> Option<i64> {
    let is_fdinfo = |raw: u64| state.fdinfo_files.contains_key(&(raw as libc::c_int));
    // Process stat/status backings are empty sealed synthetic proc files, the
    // same metadata carrier they had before read-time rendering; only their
    // content paths (read, seek, mmap, sendfile input) must avoid it.
    let is_fdinfo_entry = |raw: u64| {
        state
            .fdinfo_files
            .get(&(raw as libc::c_int))
            .is_some_and(|description| matches!(description.source, SeqProcSource::Fdinfo(_)))
    };
    // The backing memfd is never a readable payload for kernel transfer or
    // mmap operations. Scalar read/pread/lseek use seq; vectors retain the
    // existing proc-file ENOSYS boundary in vectored_io. A sendfile input is
    // refused by resolve_sendfile_input, after output errors are recorded.
    if (number == libc::SYS_sendfile as u64 && is_fdinfo(args[0]))
        || (number == libc::SYS_mmap as u64
            && args[3] & libc::MAP_ANONYMOUS as u64 == 0
            && is_fdinfo(args[4]))
        || (matches!(number, n if n == libc::SYS_ioctl as u64
            || n == libc::SYS_fstatfs as u64 || n == libc::SYS_fsync as u64
            || n == libc::SYS_fdatasync as u64 || n == libc::SYS_readahead as u64
            || n == libc::SYS_sync_file_range as u64 || n == libc::SYS_fchmod as u64
            || n == libc::SYS_fchown as u64)
            && is_fdinfo_entry(args[0]))
    {
        return Some(negative_errno(libc::ENOSYS));
    }
    if number == libc::SYS_fcntl as u64
        && is_fdinfo_entry(args[0])
        && !matches!(
            args[1] as libc::c_int,
            libc::F_DUPFD
                | libc::F_DUPFD_CLOEXEC
                | libc::F_GETFD
                | libc::F_SETFD
                | libc::F_GETFL
                | libc::F_SETFL
        )
    {
        return Some(negative_errno(libc::ENOSYS));
    }
    None
}

fn ensure_fdinfo_object(host_fd: RawFd) -> Result<(), i64> {
    if !matches!(
        fd_mode(host_fd)? & libc::S_IFMT,
        libc::S_IFREG
            | libc::S_IFDIR
            | libc::S_IFCHR
            | libc::S_IFBLK
            | libc::S_IFIFO
            | libc::S_IFSOCK
    ) {
        return Err(negative_errno(libc::ENOSYS));
    }
    Ok(())
}

fn read_owned_fdinfo(file: &std::fs::File) -> Result<Vec<u8>, i64> {
    // Explicit capacity for one raw record, not a truncated success. The owned
    // source remains live for the whole read, so its number cannot be reused.
    const LIMIT: u64 = 1024 * 1024;
    let source =
        std::fs::File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).map_err(io_error)?;
    read_fdinfo_bytes(source, LIMIT)
}

pub(super) fn read_fdinfo_bytes(source: impl std::io::Read, limit: u64) -> Result<Vec<u8>, i64> {
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(source, limit + 1);
    std::io::Read::read_to_end(&mut bounded, &mut bytes).map_err(io_error)?;
    if bytes.len() as u64 > limit {
        return Err(negative_errno(libc::EOVERFLOW));
    }
    Ok(bytes)
}

pub(super) fn replace_fdinfo_flags(bytes: &[u8], flags: libc::c_int) -> Result<Vec<u8>, i64> {
    let mut result = Vec::with_capacity(bytes.len());
    let mut found = false;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"flags:") {
            if found || !line.ends_with(b"\n") {
                return Err(negative_errno(libc::EIO));
            }
            let value = std::str::from_utf8(&line[b"flags:".len()..])
                .map_err(|_| negative_errno(libc::EIO))?
                .trim();
            u64::from_str_radix(value, 8).map_err(|_| negative_errno(libc::EIO))?;
            result.extend_from_slice(format!("flags:\t0{flags:o}\n").as_bytes());
            found = true;
        } else {
            result.extend_from_slice(line);
        }
    }
    if !found {
        return Err(negative_errno(libc::EIO));
    }
    Ok(result)
}

/// Recognize only current-process spellings. The selected task is retained;
/// /proc/self is the leader even when a live worker opens the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FdinfoPathTarget {
    Target { tid: i32, fd: i32 },
    MissingFinal { tid: i32 },
    EmptyFinal { tid: i32 },
    InvalidTask,
}

pub(super) fn fdinfo_path_target(state: &LoadedStaticElf, path: &[u8]) -> Option<FdinfoPathTarget> {
    let rest = path.strip_prefix(b"/proc/")?;
    let slash = rest.iter().position(|byte| *byte == b'/')?;
    let suffix = rest[slash + 1..].strip_prefix(b"fdinfo/")?;
    let task = &rest[..slash];
    let target = if task == b"self" {
        state.pid
    } else if task == b"thread-self" {
        state.tid
    } else {
        match std::str::from_utf8(task)
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
        {
            Some(tid)
                if (tid == state.pid || tid == state.tid) && tid.to_string().as_bytes() == task =>
            {
                tid
            }
            _ => return Some(FdinfoPathTarget::InvalidTask),
        }
    };
    if suffix.is_empty() {
        return Some(FdinfoPathTarget::EmptyFinal { tid: target });
    }
    let fd = match std::str::from_utf8(suffix)
        .ok()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<i32>().ok())
    {
        Some(fd) if fd < GUEST_NOFILE_LIMIT && fd.to_string().as_bytes() == suffix => fd,
        // Linux v6.3 fs/proc/fd.c returns ENOENT directly when its fd lookup
        // cannot resolve the final component. That precedes lookup_open's
        // create-error fallback even with O_CREAT|O_DIRECTORY|O_EXCL.
        _ => return Some(FdinfoPathTarget::MissingFinal { tid: target }),
    };
    Some(FdinfoPathTarget::Target { tid: target, fd })
}

/// Establish pathname existence only: the task incarnation and guest fd must
/// both be live. Content eligibility is deliberately a later open-only check,
/// so metadata and path/type errors do not depend on the private carrier kind.
pub(super) fn fdinfo_target_generation(
    state: &LoadedStaticElf,
    tid: i32,
    fd: i32,
) -> Result<u64, i64> {
    let generation = fdinfo_task_generation(state, tid)?;
    host_fd(state, fd).ok_or_else(|| negative_errno(libc::ENOENT))?;
    Ok(generation)
}

pub(super) fn fdinfo_task_generation(state: &LoadedStaticElf, tid: i32) -> Result<u64, i64> {
    state
        .task_lifecycle
        .lock()
        .expect("KVM lifecycle lock poisoned")
        .get(tid)
        .map(|task| task.generation)
        .ok_or_else(|| negative_errno(libc::ENOENT))
}

fn ensure_fdinfo_content_supported(
    state: &LoadedStaticElf,
    fd: i32,
    capture_output: bool,
) -> Result<(), i64> {
    // open_file has exclusive access to state. Do not lock fdinfo_table here:
    // successful description reads retain the established seq -> table ->
    // lifecycle order, while refused opens allocate no description/seq state.
    let host = host_fd(state, fd).ok_or_else(|| negative_errno(libc::ENOENT))?;
    if state.proc_files.contains_key(&fd)
        || signalfd_mask(state, fd).is_some()
        || (capture_output && output_alias(state, fd).is_some())
    {
        return Err(negative_errno(libc::ENOSYS));
    }
    ensure_fdinfo_object(host)
}

pub(super) fn open_fdinfo(
    state: &mut LoadedStaticElf,
    target: (i32, i32),
    flags: u64,
    capture_output: bool,
) -> i64 {
    let generation = match fdinfo_target_generation(state, target.0, target.1) {
        Ok(generation) => generation,
        Err(error) => return error,
    };
    let path_only = flags & libc::O_PATH as u64 != 0;
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
    if flags
        & (libc::O_PATH
            | libc::O_CREAT
            | libc::O_TRUNC
            | libc::O_DIRECT
            | libc::O_NOATIME
            | libc::O_ASYNC) as u64
        != 0
    {
        return negative_errno(libc::ENOSYS);
    }
    if flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64 {
        return negative_errno(libc::EACCES);
    }
    if let Err(error) = ensure_fdinfo_content_supported(state, target.1, capture_output) {
        return error;
    }
    if state.fdinfo_table.upgrade().is_none() {
        return negative_errno(libc::ENOSYS);
    }
    let path = format!("/proc/{}/fdinfo/{}", target.0, target.1).into_bytes();
    let description = Arc::new(FdinfoDescription {
        source: SeqProcSource::Fdinfo(FdinfoTarget {
            target_tid: target.0,
            target_generation: generation,
            target_fd: target.1,
            table: state.fdinfo_table.clone(),
            lifecycle: state.task_lifecycle.clone(),
            capture_output,
        }),
        path: path.clone(),
        nofollow_status: flags & libc::O_NOFOLLOW as u64 != 0,
        sequence: Mutex::default(),
    });
    // The empty, read-only backing file supplies descriptor ownership and
    // synthetic proc metadata only. Reads/seeks must use the description.
    let result = open_synthetic_proc(
        state,
        &path,
        b"",
        flags & libc::O_CLOEXEC as u64 != 0,
        false,
        0,
    );
    if result >= 0 {
        let fd = result as i32;
        let host = state.files[&fd].as_raw_fd();
        // Opening the owned carrier creates the new readonly OFD and keeps
        // supported Linux open status flags (including O_SYNC/O_DSYNC). The
        // internal proc magic link must be followed; guest O_NOFOLLOW refers
        // to the regular fdinfo entry, so retain that one status bit separately.
        use std::os::unix::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags((flags as libc::c_int & !libc::O_NOFOLLOW) | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{host}"))
        {
            Ok(file) => file,
            Err(error) => {
                close(state, result as u64);
                return io_error(error);
            }
        };
        let retired = state.insert_file(fd, file);
        state.file_retirement.retire(retired);
        state.fdinfo_files.insert(fd, description);
    }
    result
}

/// Open `/proc/<pid>/status` as a seq description over this
/// process's live cells. Access and flag checks precede this call.
pub(super) fn open_process_proc(
    state: &mut LoadedStaticElf,
    normalized_path: &[u8],
    file: ProcessProcFile,
    flags: u64,
    close_on_exec: bool,
) -> i64 {
    let description = Arc::new(FdinfoDescription {
        source: SeqProcSource::Process {
            file,
            view: ProcessProcView::of(state),
        },
        path: format!("/proc/{}/{}", state.pid, file.name()).into_bytes(),
        // open_synthetic_proc records guest O_NOFOLLOW for this descriptor.
        nofollow_status: false,
        sequence: Mutex::default(),
    });
    // The empty, read-only backing file supplies descriptor ownership and the
    // synthetic proc metadata only; reads and seeks use the description.
    let result = open_synthetic_proc(
        state,
        normalized_path,
        b"",
        close_on_exec,
        false,
        flags as libc::c_int,
    );
    if result >= 0 {
        state.fdinfo_files.insert(result as i32, description);
    }
    result
}

/// `/proc/self/fd/<fd>` as a C string on the stack: the bytes of
/// `format!("/proc/self/fd/{fd}")`, sign included, with a terminating NUL and
/// no allocation. A decimal descriptor never contains a NUL.
pub(super) struct ProcSelfFdPath {
    pub(super) bytes: [u8; PROC_SELF_FD_PATH_CAPACITY],
    /// The path's length, without the NUL at `bytes[len]`.
    pub(super) len: usize,
}

pub(super) const PROC_SELF_FD_PREFIX: &[u8] = b"/proc/self/fd/";

/// The prefix, the longest descriptor (`-2147483648`, eleven bytes) and the NUL.
pub(super) const PROC_SELF_FD_PATH_CAPACITY: usize = PROC_SELF_FD_PREFIX.len() + 11 + 1;

impl ProcSelfFdPath {
    pub(super) fn new(fd: RawFd) -> Self {
        let mut bytes = [0u8; PROC_SELF_FD_PATH_CAPACITY];
        bytes[..PROC_SELF_FD_PREFIX.len()].copy_from_slice(PROC_SELF_FD_PREFIX);
        let mut len = PROC_SELF_FD_PREFIX.len();
        if fd < 0 {
            bytes[len] = b'-';
            len += 1;
        }
        // Least significant digit first, then reversed into place.
        let mut digits = [0u8; 10];
        let mut count = 0;
        let mut magnitude = fd.unsigned_abs();
        loop {
            digits[count] = b'0' + (magnitude % 10) as u8;
            count += 1;
            magnitude /= 10;
            if magnitude == 0 {
                break;
            }
        }
        for &digit in digits[..count].iter().rev() {
            bytes[len] = digit;
            len += 1;
        }
        Self { bytes, len }
    }

    pub(super) fn as_c_str(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.bytes[..=self.len])
            .expect("a /proc/self/fd path has one NUL, at its end")
    }
}

// ===== Synthetic /proc surface =====
//
// TODO-HUMAN-REVIEW(reverie-kvm): Review synthetic /proc content and determinism.
//
// Real procfs is refused (see `ensure_not_procfs`) because its contents are
// host-specific and would break `--verify`. To still support programs that read
// a few well-known /proc files (diagnostics, self-inspection), a small
// allowlist uses backend-owned storage. Most contents are fixed; mount files
// retain the actual namespace snapshot for Tool normalization, and fdinfo uses
// its own observation/seq state. Fixed files retain ordinary memfd I/O. `fstat`,
// `newfstatat`, and `statx` on such a descriptor report synthesized, run-stable
// metadata, because the backing memfd's own inode varies per run and would
// otherwise perturb determinism. `/proc` itself is not served: it is refused
// as the rest of procfs is. The Tool serves `/proc` and its listing.
pub(super) const SYNTHETIC_DEV_MAJOR: u32 = 0;
pub(super) const SYNTHETIC_PROC_DEV_MINOR: u32 = 0xff01;
pub(super) const SYNTHETIC_GUEST_FD_DEV_MINOR: u32 = 0xff02;
// Provenance of removed renderings: /proc/version, /proc/filesystems,
// /proc/meminfo, /proc/vmstat and /proc/sys/kernel/osrelease are rendered by
// Detcore on every backend (https://github.com/rrnewton/hermit/issues/4213).
// The KVM copies removed here were marked AUTONOMOUS-BOT-IMPLEMENTED and
// carried TODO-HUMAN-REVIEW(PR-231) (meminfo parity with Hermit's memory
// persona) and TODO-HUMAN-REVIEW(PR-224) (the vmstat and osrelease surfaces
// and their regression test); those reviews now apply to Detcore's
// renderings. /proc/loadavg followed, once Detcore rendered it as a fixed
// file; its KVM copy carried no marker. /proc/uptime followed, once Detcore
// rendered it with its snapshot taken at the first read; its KVM copies (this
// table's entry and a dead open-path special case) carried no marker.
// /proc/stat followed, once Detcore rendered it from a fixed template plus
// virtual time; its KVM copy (this table's entry) carried no marker.
// /proc/cpuinfo followed, once Detcore rendered it from its virtual CPUID
// table wherever CPUID is virtualized and the backend can deliver the guest's
// CPUID instruction to the Tool, as KVM always can; its KVM copy (this table's
// entry, a fixed "reverie-kvm virtual CPU" block) carried no marker.
// /proc/mounts, /proc/self/mounts and /proc/self/mountinfo followed, once
// Detcore rendered every process's mount files from a container mount table
// that every run has (package K slice K3). Their KVM copy was the backend's
// own capture of its namespace's tables at image load (proc_mounts.rs), served
// with its length as st_size, plus a /proc/mounts O_NOFOLLOW special case; its
// regression test carried AUTONOMOUS-BOT-IMPLEMENTED and
// TODO-HUMAN-REVIEW(PR-225) (the mountinfo surface added for df), a review
// that now applies to Detcore's rendering.
// /proc/self/cmdline followed, once Detcore rendered every process's own
// command line from its memory by Linux's get_mm_cmdline rule, at the
// argument area it reads from each image's initial stack (package K slice
// D4b). Its KVM copy (this table's entry, argv[0] and a NUL from the loader's
// argv0, and the positioned-write EBADF that a read-only open of a plain
// procfs file gives) carried no marker.
// /proc/self/stat followed, once Detcore rendered every spelling of a
// process's own stat (self, thread-self, its pid, task/<tid>) from its process
// table and its own record of each thread's comm, in Linux's 52 fields
// (package K slice D4c-1). Its KVM copy (this table's entry, a 53-field line
// of pid, the leader's name, state R and the parent followed by zeros, its
// reopen refusal and its zero path size) carried no marker.
pub(super) const SYNTHETIC_REGULAR_PROC_PATHS: &[&[u8]] =
    &[b"/proc/locks", b"/proc/self/status", b"/proc/self/maps"];

pub(super) fn synthetic_dev(minor: u32) -> libc::dev_t {
    libc::makedev(SYNTHETIC_DEV_MAJOR, minor)
}

/// Deterministic inode for a normalized synthetic /proc path (FNV-1a). Stable
/// across runs so `--verify` sees identical `stat` results.
pub(super) fn synthetic_proc_inode(path: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Keep clear of low, conventionally-reserved inode numbers.
    hash | 0x1000
}

// TODO-HUMAN-REVIEW(PR-136): Review synthetic procfd link reconstruction.
pub(super) fn synthetic_proc_path_for_inode(inode: u64) -> Option<&'static [u8]> {
    SYNTHETIC_REGULAR_PROC_PATHS
        .iter()
        .copied()
        .find(|path| synthetic_proc_inode(path) == inode)
}

fn parse_proc_id(component: &[u8]) -> Option<i32> {
    if component.is_empty() || !component.iter().all(u8::is_ascii_digit) {
        return None;
    }
    component.iter().try_fold(0_i32, |value, digit| {
        value.checked_mul(10)?.checked_add(i32::from(*digit - b'0'))
    })
}

fn live_thread_in_process(state: &LoadedStaticElf, tid: i32) -> bool {
    state
        .task_lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(tid)
        .is_some_and(|task| task.tgid == state.pid)
}

/// Classify a procfs executable-link spelling. `Some(false)` is a syntactically
/// valid guest proc link naming a task outside the current process; callers
/// must refuse it rather than accidentally opening the supervisor's procfs.
pub(super) fn guest_proc_exe_path(state: &LoadedStaticElf, path: &[u8]) -> Option<bool> {
    if path == b"/proc/self/exe" || path == b"/proc/thread-self/exe" {
        return Some(true);
    }
    let components = path
        .strip_prefix(b"/proc/")?
        .split(|byte| *byte == b'/')
        .collect::<Vec<_>>();
    match components.as_slice() {
        [task, b"exe"] => parse_proc_id(task).map(|tid| live_thread_in_process(state, tid)),
        [b"self", b"task", task, b"exe"] => {
            parse_proc_id(task).map(|tid| live_thread_in_process(state, tid))
        }
        [group, b"task", task, b"exe"] => {
            let group = parse_proc_id(group)?;
            let task = parse_proc_id(task)?;
            Some(live_thread_in_process(state, group) && live_thread_in_process(state, task))
        }
        _ => None,
    }
}

/// Rewrite a `/proc/<pid>` path (for this guest's own pid) to the canonical
/// `/proc/self` form so both spellings resolve to the same synthetic content.
pub(super) fn normalize_proc_path(state: &LoadedStaticElf, path: &[u8]) -> Option<Vec<u8>> {
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
pub(super) fn synthetic_proc_content(state: &LoadedStaticElf, path: &[u8]) -> Option<Vec<u8>> {
    let normalized = normalize_proc_path(state, path)?;
    let content = match normalized.as_slice() {
        b"/proc/locks" => proc_locks_content(state),
        b"/proc/self/status" => proc_self_status_content(state),
        b"/proc/self/maps" => proc_self_maps_content(state),
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

/// The thread-group leader's `comm`, without its terminating NUL byte.
#[cfg(test)]
pub(super) fn proc_comm(state: &LoadedStaticElf) -> Vec<u8> {
    ProcessProcView::of(state).comm()
}

// AUTONOMOUS-BOT-IMPLEMENTED: Expose only the deterministic guest stack map.
// TODO-HUMAN-REVIEW(PR-223): Review the minimal synthetic process map surface.
pub(super) fn proc_self_maps_content(_state: &LoadedStaticElf) -> Vec<u8> {
    // The ELF loader places the stack in the window at the top of the user
    // address space, below Linux's TASK_SIZE.
    let stack_start = crate::memory::USER_ADDRESS_END - STACK_LIMIT;
    let stack_end = crate::memory::USER_STACK_TOP;
    format!("{stack_start:012x}-{stack_end:012x} rw-p 00000000 00:00 0 [stack]\n").into_bytes()
}

/// The size a path stat reports. Read-time files report zero, as Linux does
/// and as their descriptors' empty backing does.
pub(super) fn synthetic_proc_path_size(normalized: &[u8], content: &[u8]) -> usize {
    if ProcessProcFile::from_normalized_path(normalized).is_some() {
        0
    } else {
        content.len()
    }
}

pub(super) fn proc_self_status_content(state: &LoadedStaticElf) -> Vec<u8> {
    ProcessProcView::of(state).status()
}

pub(super) fn supported_synthetic_proc_seals(seals: libc::c_int) -> bool {
    seals == SYNTHETIC_PROC_REQUIRED_SEALS
        || seals == (SYNTHETIC_PROC_REQUIRED_SEALS | LINUX_F_SEAL_EXEC)
}

/// Back a synthesized /proc file with a memfd holding `content` and record it in
/// `proc_files` so `fstat`/`statx` report deterministic metadata.
pub(super) fn open_synthetic_proc(
    state: &mut LoadedStaticElf,
    normalized_path: &[u8],
    content: &[u8],
    close_on_exec: bool,
    path_only: bool,
    guest_status_flags: libc::c_int,
) -> i64 {
    // SAFETY: the name is a valid NUL-terminated C string.
    let raw = unsafe {
        libc::memfd_create(
            c"reverie-kvm-proc".as_ptr(),
            (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as libc::c_uint,
        )
    };
    if raw < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new owned descriptor on success.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw as RawFd) };
    if let Err(error) = file.write_all(content) {
        return io_error(error);
    }
    // Match the read-only mode exposed by the synthesized proc metadata. This
    // also makes a writable proc-fd reopen fail before the private carrier can
    // enter the guest table.
    // SAFETY: file owns a live descriptor and the mode contains permission bits only.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // Seal the populated snapshot before publishing any guest-visible handle.
    // In particular, F_SEAL_SEAL makes this exact immutable set permanent.
    // SAFETY: file owns a live sealable memfd and the seal mask is valid.
    if unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_ADD_SEALS,
            SYNTHETIC_PROC_REQUIRED_SEALS,
        )
    } != 0
    {
        return io_error(std::io::Error::last_os_error());
    }
    // A host may implicitly add F_SEAL_EXEC under vm.memfd_noexec policy. No
    // other missing or extra seal is an accepted carrier shape.
    // SAFETY: file owns a live descriptor and F_GET_SEALS has no third argument.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    if !supported_synthetic_proc_seals(seals) {
        return negative_errno(libc::EOPNOTSUPP);
    }
    let proc_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .expect("host fd path has no NUL");
    let host_flags = if path_only {
        libc::O_PATH | libc::O_CLOEXEC
    } else {
        libc::O_RDONLY
            | libc::O_CLOEXEC
            | (guest_status_flags & SYNTHETIC_PROC_PRESERVED_STATUS_FLAGS)
    };
    // Follow the supervisor's private proc magic link to expose the immutable
    // memfd itself, never an O_PATH handle to that magic link's procfs inode.
    // SAFETY: proc_path is NUL-terminated and the source descriptor is live.
    let descriptor = unsafe { libc::open(proc_path.as_ptr(), host_flags) };
    if descriptor < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: open returned a new descriptor owned by this call.
    let exposed = unsafe { std::fs::File::from_raw_fd(descriptor) };
    // The writable construction handle never enters the guest table. Opening
    // the proc-fd link creates a fresh O_RDONLY or O_PATH description at offset
    // zero without sharing the construction description.
    drop(file);
    let inode = synthetic_proc_inode(normalized_path);
    // The snapshot class lets a receiver of this descriptor, which has no
    // `proc_files` entry, keep timestamp 0.
    let guest_fd = insert_file_with_identity(
        state,
        exposed,
        close_on_exec,
        None,
        IdentityTimestamps::ProcSnapshot,
    );
    if guest_fd >= 0 {
        let guest_fd = guest_fd as libc::c_int;
        state.proc_files.insert(guest_fd, inode);
        if guest_status_flags & libc::O_NOFOLLOW != 0 {
            state.synthetic_proc_nofollow_fds.insert(guest_fd);
        } else {
            state.synthetic_proc_nofollow_fds.remove(&guest_fd);
        }
    }
    guest_fd
}

/// Overwrite the nondeterministic fields of a memfd `stat` with the stable
/// synthetic identity of a /proc file, keeping the (deterministic) size.
pub(super) fn sanitize_proc_stat(stat: &mut libc::stat, inode: u64) {
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
pub(super) fn synthetic_proc_stat(inode: u64, size: usize) -> libc::stat {
    // SAFETY: libc::stat is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_size = size as libc::off_t;
    sanitize_proc_stat(&mut stat, inode);
    stat
}

/// A synthetic `statx` mirroring [`synthetic_proc_stat`].
pub(super) fn synthetic_proc_statx(inode: u64, size: u64) -> libc::statx {
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
    stx.stx_blocks = (stx.stx_size + 511) >> 9;
    stx.stx_dev_major = SYNTHETIC_DEV_MAJOR;
    stx.stx_dev_minor = SYNTHETIC_PROC_DEV_MINOR;
    stx
}

// TODO-HUMAN-REVIEW(PR-92): Review deterministic guest-fd alias metadata.
pub(super) fn synthetic_guest_fd_inode(guest_fd: libc::c_int, symlink: bool) -> u64 {
    0x2000_0000 + (guest_fd as u64 * 2) + u64::from(symlink)
}

// TODO-HUMAN-REVIEW(PR-136): Review deterministic open-file object grouping.
pub(super) fn guest_fd_object_identity(
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
                timestamps: IdentityTimestamps::Host,
            })
        })
}

#[cfg(test)]
pub(super) fn synthetic_guest_fd_object_inode(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
) -> u64 {
    guest_fd_object_identity(state, guest_fd).inode
}

pub(super) fn sanitize_guest_fd_stat(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
    stat: &mut libc::stat,
) {
    if let Some(&inode) = state.proc_files.get(&guest_fd) {
        sanitize_proc_stat(stat, inode);
        return;
    }
    if let Some(seconds) = synthetic_descriptor_seconds(state, guest_fd) {
        set_stat_timestamps(stat, seconds);
    }
}

pub(super) fn sanitize_guest_fd_statx(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
    stat: &mut libc::statx,
) {
    if let Some(&inode) = state.proc_files.get(&guest_fd) {
        *stat = synthetic_proc_statx(inode, stat.stx_size);
        return;
    }
    if let Some(seconds) = synthetic_descriptor_seconds(state, guest_fd) {
        set_statx_timestamps(stat, seconds);
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/933):
// Review the fixed-timestamp classes of backend-made carriers.
/// The fixed timestamp that `guest_fd` reports in a run that reports host
/// metadata timestamps, because its host times are those of a carrier the
/// backend made rather than of any guest-visible object. `None` means a real
/// host object, or a run with that setting off, and the descriptor reports
/// the kernel's timestamps.
///
/// A `/proc` snapshot is classified by its identity, which every alias
/// shares. The virtual signalfd's private eventfd and the
/// self-pidfd proxy are classified by the descriptor instead: on a kernel
/// without pidfs, every anonymous-inode descriptor shares one host inode, so
/// their identity is shared with native descriptors and cannot carry a class.
/// A pidfd counts only when it names the supervisor process, see
/// [`is_self_pidfd`].
fn synthetic_descriptor_seconds(
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
) -> Option<libc::time_t> {
    if !state.host_metadata_timestamps {
        return None;
    }
    match state
        .fd_object_inodes
        .get(&guest_fd)
        .map(|identity| identity.timestamps)
    {
        Some(IdentityTimestamps::ProcSnapshot) => return Some(0),
        Some(IdentityTimestamps::Host) | None => {}
    }
    if signalfd_mask(state, guest_fd).is_some() || is_self_pidfd(state, guest_fd) {
        return Some(DETERMINISTIC_METADATA_SECONDS);
    }
    None
}
