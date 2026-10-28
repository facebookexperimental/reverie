/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The file descriptor table (gVisor: pkg/sentry/kernel/fd_table.go).

use super::*;

#[derive(Debug, Default)]
pub struct FileTableState {
    pub(super) stdin: Option<std::fs::File>,
    pub(super) stdin_entry_id: Arc<()>,
    pub(super) files: std::collections::BTreeMap<i32, std::fs::File>,
    pub(super) fd_entry_ids: std::collections::BTreeMap<i32, Arc<crate::elf::FdEntry>>,
    pub(super) epoll_domain: Arc<Mutex<EpollDomain>>,
    pub(super) poll_table_id: Arc<NativePollTable>,
    pub(super) native_poll_fds: std::collections::BTreeMap<i32, Arc<NativePollBinding>>,
    pub(super) pipe_owners: std::collections::BTreeMap<i32, Arc<pipe_owner::PipeOwner>>,
    pub(super) stdout_alias_fds: std::collections::BTreeSet<i32>,
    pub(super) stderr_alias_fds: std::collections::BTreeSet<i32>,
    pub(super) cloexec_fds: std::collections::BTreeSet<i32>,
    pub(super) closed_standard_fds: std::collections::BTreeSet<i32>,
    pub(super) proc_files: std::collections::BTreeMap<i32, u64>,
    pub(super) synthetic_proc_nofollow_fds: std::collections::BTreeSet<i32>,
    pub(super) fdinfo_files: std::collections::BTreeMap<i32, Arc<FdinfoDescription>>,
    pub(super) signalfd_fds: std::collections::BTreeSet<i32>,
    pub(super) fd_object_inodes: std::collections::BTreeMap<i32, Arc<GuestFileIdentity>>,
}

/// A seq_file-backed synthetic proc open description. Its content is rendered
/// when the sequence is (re)started, never when the file is opened, and never
/// from a supervisor fd. Aliases share seq state.
#[derive(Debug)]
pub struct FdinfoDescription {
    pub(super) source: SeqProcSource,
    pub(super) path: Vec<u8>,
    pub(super) nofollow_status: bool,
    pub(super) sequence: Mutex<crate::fdinfo::FdinfoSequence>,
}

/// A `/proc/<pid>/stat` or `status` description carried by SCM_RIGHTS. The host
/// passes only the empty backing memfd, so the receiver finds the description
/// by that memfd's identity. The pin keeps the inode from being reused while a
/// message may still carry it; `in_flight` counts rights sent and not yet
/// received.
#[derive(Debug)]
pub struct ProcTransfer {
    pub(super) description: Arc<FdinfoDescription>,
    pub(super) proc_inode: u64,
    pub(super) nofollow: bool,
    pub(super) _pin: std::fs::File,
    pub(super) in_flight: usize,
}

impl FileTableState {
    fn retire(self, retirement: &crate::elf::FileRetirement) {
        retirement.retire(self.stdin.into_iter().chain(self.files.into_values()));
    }

    pub(super) fn try_from_elf(state: &LoadedStaticElf) -> std::io::Result<Self> {
        Self::prepare_from_elf(state, false, None)
    }

    fn same_stdin_entry(&self, state: &LoadedStaticElf) -> bool {
        self.stdin.is_some() == state.stdin.is_some()
            && Arc::ptr_eq(&self.stdin_entry_id, &state.stdin_entry_id)
    }

    pub(super) fn update_from_elf(&mut self, state: &LoadedStaticElf) -> std::io::Result<()> {
        let same_stdin = self.same_stdin_entry(state);
        // Stage every required clone before taking an authoritative handle.
        // A failed clone leaves the entire previous table intact. An entry
        // unchanged since the last publication keeps the clone already
        // published for it, as install keeps a thread's own host fd: the same
        // entry identity is the same open description, so a fresh clone would
        // only add a dup now and a close when the old one retires.
        let mut next = Self::prepare_from_elf(state, same_stdin, Some(self))?;
        if same_stdin {
            next.stdin = self.stdin.take();
        }
        for &fd in state.files.keys() {
            next.files.entry(fd).or_insert_with(|| {
                self.files
                    .remove(&fd)
                    .expect("an unchanged entry has its published clone")
            });
        }
        let retired = std::mem::replace(self, next);
        retired.retire(&state.file_retirement);
        Ok(())
    }

    /// The table for `state`. With `published`, entries whose identity
    /// matches its own are left out of `files` for the caller to move over.
    fn prepare_from_elf(
        state: &LoadedStaticElf,
        preserve_stdin: bool,
        published: Option<&Self>,
    ) -> std::io::Result<Self> {
        let stdin = if preserve_stdin {
            None
        } else {
            state
                .stdin
                .as_ref()
                .map(|file| state.file_retirement.stage_clone(file))
                .transpose()?
        };
        let files = state
            .files
            .iter()
            .filter(|&(fd, _)| {
                !published.is_some_and(|published| {
                    published.files.contains_key(fd)
                        && state
                            .fd_entry_ids
                            .get(fd)
                            .zip(published.fd_entry_ids.get(fd))
                            .is_some_and(|(current, previous)| Arc::ptr_eq(current, previous))
                })
            })
            .map(|(&fd, file)| Ok((fd, state.file_retirement.stage_clone(file)?)))
            .collect::<std::io::Result<std::collections::BTreeMap<_, _>>>()?;
        Ok(Self {
            stdin: stdin.map(crate::elf::StagedFile::into_file),
            stdin_entry_id: state.stdin_entry_id.clone(),
            files: files
                .into_iter()
                .map(|(fd, file)| (fd, file.into_file()))
                .collect(),
            fd_entry_ids: state.fd_entry_ids.clone(),
            epoll_domain: state.epoll_domain.clone(),
            poll_table_id: state.poll_table_id.clone(),
            native_poll_fds: state.native_poll_fds.clone(),
            pipe_owners: state.pipe_owners.clone(),
            stdout_alias_fds: state.stdout_alias_fds.clone(),
            stderr_alias_fds: state.stderr_alias_fds.clone(),
            cloexec_fds: state.cloexec_fds.clone(),
            closed_standard_fds: state.closed_standard_fds.clone(),
            proc_files: state.proc_files.clone(),
            synthetic_proc_nofollow_fds: state.synthetic_proc_nofollow_fds.clone(),
            fdinfo_files: state.fdinfo_files.clone(),
            signalfd_fds: state
                .process_signals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .signalfd_masks
                .keys()
                .copied()
                .collect(),
            fd_object_inodes: state.fd_object_inodes.clone(),
        })
    }

    /// Whether `install` would leave `state`'s descriptor fields exactly as
    /// they are: the same entries by identity (so every host fd is kept) and
    /// the same descriptor facts. Reads only; allocates nothing.
    pub(super) fn installed_matches(&self, state: &LoadedStaticElf) -> bool {
        fn same_arcs<K: Ord, V>(
            a: &std::collections::BTreeMap<K, Arc<V>>,
            b: &std::collections::BTreeMap<K, Arc<V>>,
        ) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((ka, va), (kb, vb))| ka == kb && Arc::ptr_eq(va, vb))
        }
        // Destructured without `..`, so a field added to the table fails to
        // compile here until it is either compared or shown not to be
        // installed.
        let Self {
            stdin: _,
            stdin_entry_id: _,
            files,
            fd_entry_ids,
            epoll_domain,
            poll_table_id,
            native_poll_fds,
            pipe_owners,
            stdout_alias_fds,
            stderr_alias_fds,
            cloexec_fds,
            closed_standard_fds,
            proc_files,
            synthetic_proc_nofollow_fds,
            fdinfo_files,
            // install never writes the task's signalfd set.
            signalfd_fds: _,
            fd_object_inodes,
        } = self;
        // same_stdin_entry compares stdin and stdin_entry_id.
        self.same_stdin_entry(state)
            && files.keys().eq(state.files.keys())
            && same_arcs(fd_entry_ids, &state.fd_entry_ids)
            // install keeps a task's file only when both sides carry the same
            // entry identity; a file without one is always reinstalled.
            && files.keys().all(|fd| fd_entry_ids.contains_key(fd))
            && Arc::ptr_eq(epoll_domain, &state.epoll_domain)
            && Arc::ptr_eq(poll_table_id, &state.poll_table_id)
            && same_arcs(native_poll_fds, &state.native_poll_fds)
            && same_arcs(pipe_owners, &state.pipe_owners)
            && *stdout_alias_fds == state.stdout_alias_fds
            && *stderr_alias_fds == state.stderr_alias_fds
            && *cloexec_fds == state.cloexec_fds
            && *closed_standard_fds == state.closed_standard_fds
            && *proc_files == state.proc_files
            && *synthetic_proc_nofollow_fds == state.synthetic_proc_nofollow_fds
            && same_arcs(fdinfo_files, &state.fdinfo_files)
            && same_arcs(fd_object_inodes, &state.fd_object_inodes)
    }

    // TODO-HUMAN-REVIEW(PR-235): Review stable host-fd preservation during table sync.
    pub(super) fn install(&self, state: &mut LoadedStaticElf) -> std::io::Result<()> {
        // Every guest syscall installs the shared table, and it almost never
        // changed. Installing over an equal state rebuilds every collection
        // to the same contents, keeps every host fd, and retires no file; its
        // only other effect is the retirement flush below, kept here.
        if self.installed_matches(state) {
            state.file_retirement.retire(std::iter::empty());
            return Ok(());
        }
        // Finish every required fallible clone before replacing state.
        // An unchanged entry keeps its actual host fd for epoll MOD/DEL. Inode
        // equality cannot prove this: closing and reopening a linked file keeps
        // its filesystem identity but installs a different open description.
        let same_stdin = self.same_stdin_entry(state);
        let stdin = if same_stdin {
            None
        } else {
            self.stdin
                .as_ref()
                .map(|file| state.file_retirement.stage_clone(file))
                .transpose()?
        };
        let mut installed_files = std::collections::BTreeMap::new();
        for (&fd, shared_file) in &self.files {
            let same_entry = state.files.contains_key(&fd)
                && state
                    .fd_entry_ids
                    .get(&fd)
                    .zip(self.fd_entry_ids.get(&fd))
                    .is_some_and(|(previous, shared)| Arc::ptr_eq(previous, shared));
            if !same_entry {
                installed_files.insert(fd, state.file_retirement.stage_clone(shared_file)?);
            }
        }
        let mut installed_files: std::collections::BTreeMap<_, _> = installed_files
            .into_iter()
            .map(|(fd, file)| (fd, file.into_file()))
            .collect();
        let mut previous_files = std::mem::take(&mut state.files);
        for &fd in self.files.keys() {
            installed_files.entry(fd).or_insert_with(|| {
                previous_files
                    .remove(&fd)
                    .expect("unchanged descriptor entry has its original host fd")
            });
        }
        let retired_stdin = if same_stdin {
            None
        } else {
            std::mem::replace(
                &mut state.stdin,
                stdin.map(crate::elf::StagedFile::into_file),
            )
        };
        state.stdin_entry_id.clone_from(&self.stdin_entry_id);
        state.files = installed_files;
        state.file_retirement.retire(
            retired_stdin
                .into_iter()
                .chain(previous_files.into_values()),
        );
        state.fd_entry_ids.clone_from(&self.fd_entry_ids);
        state.epoll_domain.clone_from(&self.epoll_domain);
        state.poll_table_id.clone_from(&self.poll_table_id);
        state.native_poll_fds.clone_from(&self.native_poll_fds);
        state.pipe_owners.clone_from(&self.pipe_owners);
        state.stdout_alias_fds.clone_from(&self.stdout_alias_fds);
        state.stderr_alias_fds.clone_from(&self.stderr_alias_fds);
        state.cloexec_fds.clone_from(&self.cloexec_fds);
        state
            .closed_standard_fds
            .clone_from(&self.closed_standard_fds);
        state.proc_files.clone_from(&self.proc_files);
        state
            .synthetic_proc_nofollow_fds
            .clone_from(&self.synthetic_proc_nofollow_fds);
        state.fdinfo_files.clone_from(&self.fdinfo_files);
        state.fd_object_inodes.clone_from(&self.fd_object_inodes);
        Ok(())
    }
}

pub(super) fn mutates_file_table(number: u64) -> bool {
    matches!(
        number,
        number if number == libc::SYS_pipe as u64
            || number == libc::SYS_pipe2 as u64
            || number == libc::SYS_epoll_create1 as u64
            || number == libc::SYS_eventfd as u64
            || number == libc::SYS_eventfd2 as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-235): Review signalfd descriptor-table serialization.
            || number == libc::SYS_signalfd as u64
            || number == libc::SYS_signalfd4 as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-235): Review timerfd descriptor-table serialization.
            || number == libc::SYS_timerfd_create as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-1015): Review inotify descriptor-table serialization.
            || number == libc::SYS_inotify_init as u64
            || number == libc::SYS_inotify_init1 as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-235): Review pidfd descriptor-table serialization.
            || number == libc::SYS_pidfd_open as u64
            || number == libc::SYS_socket as u64
            || number == libc::SYS_socketpair as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-385): Review serialized SCM_RIGHTS insertion.
            // recvmsg can install descriptors in the guest table. Hold the
            // CLONE_FILES lock from fd selection through table publication so
            // sibling threads cannot choose the same deterministic guest fd.
            || number == libc::SYS_recvmsg as u64
            || number == libc::SYS_recvmmsg as u64
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
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(#322): memfd_create allocates a new guest
            // descriptor, so its insertion must be written back to the shared
            // file table; otherwise the follow-up injected fstat (and any later
            // read/write/close) cannot resolve the fresh fd and fails EBADF.
            || number == libc::SYS_memfd_create as u64
            || number == libc::SYS_close as u64
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(#340): close_range removes a span of
            // descriptors, so its effect must be written back to the shared file
            // table; otherwise a CLONE_FILES sibling would still resolve the
            // just-closed fds and the guest's own follow-up probe would wrongly
            // find them open.
            || number == libc::SYS_close_range as u64
    )
}

pub(super) fn accept_flags(request: &SyscallRequest) -> Option<Result<libc::c_int, i64>> {
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

// AUTONOMOUS-BOT-IMPLEMENTED: Preserve captured stdio identity across descriptor duplication.
// TODO-HUMAN-REVIEW(#91): Review output alias lifecycle across dup, close, fork, and exec.
#[derive(Clone, Copy)]
pub(super) enum OutputAlias {
    Stdout,
    Stderr,
}

pub(super) fn output_alias(state: &LoadedStaticElf, fd: libc::c_int) -> Option<OutputAlias> {
    output_alias_from_sets(
        fd,
        &state.stdout_alias_fds,
        &state.stderr_alias_fds,
        is_open_standard(state, fd),
    )
}

pub(super) fn output_alias_from_sets(
    fd: libc::c_int,
    stdout: &std::collections::BTreeSet<i32>,
    stderr: &std::collections::BTreeSet<i32>,
    standard: bool,
) -> Option<OutputAlias> {
    if stdout.contains(&fd) || (fd == libc::STDOUT_FILENO && standard) {
        Some(OutputAlias::Stdout)
    } else if stderr.contains(&fd) || (fd == libc::STDERR_FILENO && standard) {
        Some(OutputAlias::Stderr)
    } else {
        None
    }
}

pub(super) fn set_output_alias(
    state: &mut LoadedStaticElf,
    fd: libc::c_int,
    alias: Option<OutputAlias>,
) {
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
pub(super) fn cleanup_fd_object_inodes(state: &LoadedStaticElf) {
    let mut table = state
        .file_identity_table
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    table.objects.retain(|_, entry| entry.is_live());
}

// TODO-HUMAN-REVIEW(PR-136): Review link-removal identity lifecycle tracking.
pub(super) fn file_identity_stat(file: &std::fs::File) -> Option<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and file owns a live descriptor.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstat initialized stat on success.
    Some(unsafe { stat.assume_init() })
}

pub(super) fn downgrade_file_identity(state: &LoadedStaticElf, key: (libc::dev_t, libc::ino_t)) {
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

/// Finds or allocates the identity of a host object the backend just made or
/// opened. `timestamps` classifies a new identity.
fn allocate_fd_object_inode(
    state: &LoadedStaticElf,
    file: &std::fs::File,
    timestamps: IdentityTimestamps,
) -> Result<Arc<GuestFileIdentity>, i64> {
    allocate_fd_object_identity(state, file, timestamps, false)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/issues/933):
// Review the fixed-timestamp classes of backend-made carriers.
/// Finds or allocates the identity of a host object received in an SCM_RIGHTS
/// message. A live identity is the sender's and is shared as is, so every alias
/// keeps reporting the same timestamps. `timestamps`, recognized from the
/// carrier itself, classifies a new identity.
pub(super) fn allocate_received_fd_object_inode(
    state: &LoadedStaticElf,
    file: &std::fs::File,
    timestamps: IdentityTimestamps,
) -> Result<Arc<GuestFileIdentity>, i64> {
    allocate_fd_object_identity(state, file, timestamps, true)
}

fn allocate_fd_object_identity(
    state: &LoadedStaticElf,
    file: &std::fs::File,
    timestamps: IdentityTimestamps,
    received: bool,
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
        // A backend-made carrier is created just before its insertion, so no
        // live identity can already name it. Refuse rather than report the
        // carrier's timestamps through an identity of another class.
        if !received && timestamps != IdentityTimestamps::Host && identity.timestamps != timestamps
        {
            return Err(negative_errno(libc::EIO));
        }
        return Ok(identity);
    }

    let inode = table.next_inode;
    table.next_inode = inode
        .checked_add(1)
        .ok_or_else(|| negative_errno(libc::EOVERFLOW))?;
    let identity = Arc::new(GuestFileIdentity { inode, timestamps });
    // Linked filesystem objects keep Linux inode identity across close/reopen.
    // Anonymous or deleted objects cannot be reopened by path, so retain them
    // only while a descriptor in any forked state holds a strong identity. A
    // carrier's class must end with the carrier, so that a later object at a
    // reused host inode never inherits it.
    let entry = if persistent && timestamps == IdentityTimestamps::Host {
        GuestFileIdentityEntry::Persistent(identity.clone())
    } else {
        GuestFileIdentityEntry::Ephemeral(Arc::downgrade(&identity))
    };
    table.objects.insert(key, entry);
    Ok(identity)
}

// TODO-HUMAN-REVIEW(PR-136): Review descriptor insertion and identity allocation.
pub(super) fn insert_file_with_flags(
    state: &mut LoadedStaticElf,
    file: std::fs::File,
    close_on_exec: bool,
    output_alias: Option<OutputAlias>,
) -> i64 {
    insert_file_with_identity(
        state,
        file,
        close_on_exec,
        output_alias,
        IdentityTimestamps::Host,
    )
}

pub(super) fn insert_file_with_identity(
    state: &mut LoadedStaticElf,
    file: std::fs::File,
    close_on_exec: bool,
    output_alias: Option<OutputAlias>,
    timestamps: IdentityTimestamps,
) -> i64 {
    let Some(fd) = (0..GUEST_NOFILE_LIMIT)
        .find(|fd| !is_open_standard(state, *fd) && !state.files.contains_key(fd))
    else {
        state.file_retirement.retire([file]);
        return negative_errno(libc::EMFILE);
    };
    let object_inode = match allocate_fd_object_inode(state, &file, timestamps) {
        Ok(inode) => inode,
        Err(error) => {
            state.file_retirement.retire([file]);
            return error;
        }
    };
    // The selected slot is vacant; this cannot retire a description,
    // including when the caller holds signal_transaction.
    let retired = state.insert_file(fd, file);
    state.file_retirement.retire(retired);
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
pub(super) struct DuplicateFdSource {
    pub(super) output_alias: Option<OutputAlias>,
    pub(super) proc_inode: Option<u64>,
    pub(super) synthetic_proc_nofollow: bool,
    pub(super) fdinfo: Option<Arc<FdinfoDescription>>,
    pub(super) object_inode: Arc<GuestFileIdentity>,
    pub(super) signalfd_mask: Option<Arc<KernelSigset>>,
    pub(super) native_poll: Option<NativePollDescription>,
    pub(super) pipe_owner: Option<Arc<pipe_owner::PipeOwner>>,
}

/// Stops supported generic writes from reaching the eventfd that privately
/// backs a virtual signalfd. Linux signalfd descriptions are read-only.
/// Undispatched transfer syscalls remain ENOSYS without touching any host fd;
/// broad interception here would change their pointer and zero-work ordering.
pub(super) fn virtual_signalfd_write_error(
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> Option<i64> {
    let errno = match number {
        number if number == libc::SYS_write as u64 || number == libc::SYS_writev as u64 => {
            libc::EINVAL
        }
        number if number == libc::SYS_pwrite64 as u64 => {
            if (args[3] as i64) < 0 {
                libc::EINVAL
            } else {
                libc::ESPIPE
            }
        }
        number if number == libc::SYS_sendto as u64 || number == libc::SYS_sendmsg as u64 => {
            libc::ENOTSOCK
        }
        _ => return None,
    };
    let fd = if number == libc::SYS_write as u64 {
        // Match scalar write before it can reach the private eventfd carrier.
        args[0] as libc::c_int
    } else {
        libc::c_int::try_from(args[0]).ok()?
    };
    signalfd_mask(state, fd).map(|_| negative_errno(errno))
}

/// The readiness keeper of signalfd `fd`, which also holds its open file
/// description's guest-visible blocking mode.
pub(super) fn signalfd_carrier(
    state: &LoadedStaticElf,
    fd: libc::c_int,
) -> Option<crate::signal::SignalFdCarrier> {
    state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .signalfd_carriers
        .get(&fd)
        .cloned()
}

pub(super) fn signalfd_mask(state: &LoadedStaticElf, fd: libc::c_int) -> Option<Arc<KernelSigset>> {
    state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .signalfd_masks
        .get(&fd)
        .cloned()
}

pub(super) fn replace_signalfd_mask(
    state: &LoadedStaticElf,
    fd: libc::c_int,
    mask: Option<Arc<KernelSigset>>,
) {
    let mut process_signals = state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(mask) = mask {
        // Dup retains the same open description. Resolve its keeper while the
        // source alias is still live; no new host clone is needed for an alias.
        let carrier = process_signals
            .signalfd_masks
            .iter()
            .find_map(|(source, current)| {
                Arc::ptr_eq(current, &mask)
                    .then(|| process_signals.signalfd_carriers.get(source).cloned())
                    .flatten()
            })
            .expect("live signalfd source owns its readiness keeper");
        process_signals.signalfd_masks.insert(fd, mask);
        process_signals.signalfd_carriers.insert(fd, carrier);
    } else {
        process_signals.signalfd_masks.remove(&fd);
        process_signals.signalfd_carriers.remove(&fd);
    }
}

pub(super) fn duplicate_fd_at_or_above(
    state: &mut LoadedStaticElf,
    old_host_fd: RawFd,
    raw_minimum: u64,
    close_on_exec: bool,
    source: DuplicateFdSource,
) -> i64 {
    let _retirement = state.file_retirement.hold();
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
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
    let retired = state.insert_file(fd, file);
    if let Some(owner) = source.pipe_owner {
        state.pipe_owners.insert(fd, owner);
    }
    if let Some(description) = source.native_poll {
        install_native_poll_description(state, fd, description);
    }
    state.fd_object_inodes.insert(fd, source.object_inode);
    replace_signalfd_mask(state, fd, source.signalfd_mask);
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
    set_output_alias(state, fd, source.output_alias);
    if let Some(inode) = source.proc_inode {
        state.proc_files.insert(fd, inode);
    }
    if source.synthetic_proc_nofollow {
        state.synthetic_proc_nofollow_fds.insert(fd);
    } else {
        state.synthetic_proc_nofollow_fds.remove(&fd);
    }
    if let Some(description) = source.fdinfo {
        state.fdinfo_files.insert(fd, description);
    }
    drop(_transaction);
    state.file_retirement.retire(retired);
    i64::from(fd)
}

// TODO-HUMAN-REVIEW(PR-136): Review dup object-identity propagation.
pub(super) fn duplicate_fd(
    state: &mut LoadedStaticElf,
    raw_old_fd: u64,
    raw_new_fd: Option<u64>,
    raw_flags: u64,
    is_dup3: bool,
) -> i64 {
    let _retirement = state.file_retirement.hold();
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
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
    let source_synthetic_proc_nofollow = state.synthetic_proc_nofollow_fds.contains(&old_fd);
    let source_fdinfo = state.fdinfo_files.get(&old_fd).cloned();
    let source_native_poll = native_poll_description(state, old_fd);
    let source_signalfd_mask = signalfd_mask(state, old_fd);
    let source_pipe_owner = state.pipe_owners.get(&old_fd).cloned();
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
        let retired = state.insert_file(new_fd, file);
        if let Some(owner) = source_pipe_owner {
            state.pipe_owners.insert(new_fd, owner);
        }
        if let Some(description) = source_native_poll {
            install_native_poll_description(state, new_fd, description);
        }
        state.fd_object_inodes.insert(new_fd, source_object_inode);
        replace_signalfd_mask(state, new_fd, source_signalfd_mask);
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
        if let Some(description) = source_fdinfo {
            state.fdinfo_files.insert(new_fd, description);
        } else {
            state.fdinfo_files.remove(&new_fd);
        }
        set_output_alias(state, new_fd, source_alias);
        if let Some(inode) = source_proc_inode {
            state.proc_files.insert(new_fd, inode);
        } else {
            state.proc_files.remove(&new_fd);
        }
        if source_synthetic_proc_nofollow {
            state.synthetic_proc_nofollow_fds.insert(new_fd);
        } else {
            state.synthetic_proc_nofollow_fds.remove(&new_fd);
        }
        drop(_transaction);
        state.file_retirement.retire(retired);
        i64::from(new_fd)
    } else {
        let new_fd = insert_file_with_flags(state, file, close_on_exec, source_alias);
        if new_fd >= 0 {
            if let Some(owner) = source_pipe_owner {
                state.pipe_owners.insert(new_fd as i32, owner);
            }
            if let Some(description) = source_native_poll {
                install_native_poll_description(state, new_fd as i32, description);
            }
            state
                .fd_object_inodes
                .insert(new_fd as libc::c_int, source_object_inode);
            replace_signalfd_mask(state, new_fd as libc::c_int, source_signalfd_mask);
            if let Some(description) = source_fdinfo {
                state.fdinfo_files.insert(new_fd as i32, description);
            }
            if source_synthetic_proc_nofollow {
                state
                    .synthetic_proc_nofollow_fds
                    .insert(new_fd as libc::c_int);
            }
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
pub(super) fn pipe2(
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
    let creator = state.pipe_owner_process.clone();
    insert_file_pair(
        memory,
        state,
        address,
        [read_end, write_end],
        flags & libc::O_CLOEXEC != 0,
        Some(creator),
    )
}

// TODO-HUMAN-REVIEW(PR-205): Review paired guest-descriptor rollback and identity cleanup.
pub(super) fn insert_file_pair(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    address: u64,
    files: [std::fs::File; 2],
    close_on_exec: bool,
    pipe_creator: Option<Arc<()>>,
) -> i64 {
    let [first_file, second_file] = files.map(|file| state.file_retirement.stage(file));
    let first_fd = insert_file_with_flags(state, first_file.into_file(), close_on_exec, None);
    if first_fd < 0 {
        return first_fd;
    }
    let second_fd = insert_file_with_flags(state, second_file.into_file(), close_on_exec, None);
    if second_fd < 0 {
        remove_inserted_file(state, first_fd as libc::c_int);
        return second_fd;
    }

    let fds = [first_fd as libc::c_int, second_fd as libc::c_int];
    if let Some(creator) = pipe_creator {
        let pair_exported = Arc::new(AtomicBool::new(false));
        for fd in fds {
            state.pipe_owners.insert(
                fd,
                Arc::new(pipe_owner::PipeOwner::new(
                    creator.clone(),
                    pair_exported.clone(),
                )),
            );
        }
    }
    let mut bytes = [0; std::mem::size_of::<[libc::c_int; 2]>()];
    bytes[..std::mem::size_of::<libc::c_int>()].copy_from_slice(&fds[0].to_ne_bytes());
    bytes[std::mem::size_of::<libc::c_int>()..].copy_from_slice(&fds[1].to_ne_bytes());
    if memory.user().write(address, &bytes).is_err() {
        for fd in fds {
            remove_inserted_file(state, fd);
        }
        return negative_errno(libc::EFAULT);
    }
    0
}

fn remove_inserted_file(state: &mut LoadedStaticElf, fd: libc::c_int) {
    let retired = state.remove_file(fd);
    state.file_retirement.retire(retired);
    state.fd_object_inodes.remove(&fd);
    state.cloexec_fds.remove(&fd);
    cleanup_fd_object_inodes(state);
}
