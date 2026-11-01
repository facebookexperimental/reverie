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
    /// The private copies of this table's entries that its tasks hold.
    pub(super) private_copies: PrivateCopies,
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
        // Open the placeholder now, while this process can spare a
        // descriptor: a retirement may run when it cannot.
        revoked_copy_placeholder()?;
        let mut table = Self::prepare_from_elf(state, false, None)?;
        // The state a table is made from is its first task.
        table.private_copies.register(state);
        Ok(table)
    }

    fn same_stdin_entry(&self, state: &LoadedStaticElf) -> bool {
        self.stdin.is_some() == state.stdin.is_some()
            && Arc::ptr_eq(&self.stdin_entry_id, &state.stdin_entry_id)
    }

    /// Publishes `state`'s descriptors as the table's, after a call of its
    /// task changed them. The change has already happened in the task, so a
    /// failure here cannot answer the guest: it is a run-ending refusal.
    pub(super) fn update_from_elf(&mut self, state: &LoadedStaticElf) -> crate::Result<()> {
        let same_stdin = self.same_stdin_entry(state);
        // Stage every required clone before taking an authoritative handle.
        // A failed clone leaves the entire previous table intact. An entry
        // unchanged since the last publication keeps the clone already
        // published for it, as install keeps a thread's own host fd: the same
        // entry identity is the same open description, so a fresh clone would
        // only add a dup now and a close when the old one retires.
        let mut next =
            Self::prepare_from_elf(state, same_stdin, Some(self)).map_err(publication_error)?;
        // What this publication retires: each published entry the guest
        // closed or replaced (one the task no longer has, or has anew in
        // `next`), and stdin when it changed. Every other task's copy of one
        // goes in this call, or at the end of the call of that task that holds
        // it (PrivateCopies).
        let retired: Vec<_> = self
            .files
            .keys()
            .filter(|&fd| !state.files.copies().contains_key(fd) || next.files.contains_key(fd))
            .map(|&fd| (fd, self.fd_entry_ids.get(&fd).cloned()))
            .collect();
        let retired_stdin =
            (!same_stdin && self.stdin.is_some()).then(|| self.stdin_entry_id.clone());
        // A copy that this process's descriptor limits would not let the
        // retirement replace ends the run before anything changes: the table,
        // every copy and every record stay as they were.
        if let Some(copy) =
            self.private_copies
                .first_unreplaceable(state.tid, &retired, retired_stdin.as_ref())
        {
            return Err(copy.into_error());
        }
        #[cfg(test)]
        run_one_shot_test_hook(&PUBLICATION_CHECKED_TEST_HOOK);
        if same_stdin {
            next.stdin = self.stdin.take();
        }
        for &fd in state.files.copies().keys() {
            next.files.entry(fd).or_insert_with(|| {
                self.files
                    .remove(&fd)
                    .expect("an unchanged entry has its published clone")
            });
        }
        next.private_copies = std::mem::take(&mut self.private_copies);
        let unreplaced = next
            .private_copies
            .revoke(state.tid, &retired, retired_stdin.as_ref());
        next.private_copies.register(state);
        // Past the check, the guest's change is published whatever the
        // copies' fate: it has happened, as it has on Linux. A copy that still
        // could not be replaced (the limits fell after the check) stays in its
        // task's record, and ends the run.
        let retired = std::mem::replace(self, next);
        retired.retire(&state.file_retirement);
        match unreplaced.into_iter().next() {
            None => Ok(()),
            Some(copy) => Err(copy.into_error()),
        }
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
            .copies()
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
            private_copies: PrivateCopies::default(),
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
            // A record of the task's copies, not a descriptor fact; install
            // keeps it current either way.
            private_copies: _,
        } = self;
        // same_stdin_entry compares stdin and stdin_entry_id.
        self.same_stdin_entry(state)
            && files.keys().eq(state.files.copies().keys())
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
    pub(super) fn install(&mut self, state: &mut LoadedStaticElf) -> std::io::Result<()> {
        // Every guest syscall installs the shared table, and it almost never
        // changed. Installing over an equal state rebuilds every collection
        // to the same contents, keeps every host fd, and retires no file; its
        // only other effects are the retirement flush below, kept here, and
        // registering the copies of a task whose state already matched, as a
        // new thread's does.
        // A copy another task's retirement replaced holds the placeholder,
        // whatever its entry: install replaces it as a changed entry, never
        // keeps it (`CopyLedger::revoked`).
        let revoked = state.private_copy_gate.revoked();
        if revoked.is_empty() && self.installed_matches(state) {
            self.private_copies.ensure_registered(state);
            state.private_copy_gate.installed(&revoked);
            state.file_retirement.retire(std::iter::empty());
            return Ok(());
        }
        // Finish every required fallible clone before replacing state.
        // An unchanged entry keeps its actual host fd for epoll MOD/DEL. Inode
        // equality cannot prove this: closing and reopening a linked file keeps
        // its filesystem identity but installs a different open description.
        let same_stdin = self.same_stdin_entry(state)
            && !state
                .stdin
                .as_ref()
                .is_some_and(|copy| revoked.contains(&copy.as_raw_fd()));
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
            let same_entry = state
                .files
                .copies()
                .get(&fd)
                .is_some_and(|copy| !revoked.contains(&copy.as_raw_fd()))
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
        let mut previous_files = state.files.take_map();
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
        state.files.replace_map(installed_files);
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
        self.private_copies.register(state);
        state.private_copy_gate.installed(&revoked);
        Ok(())
    }

    /// Whether task `tid`'s record of copies still names one of guest
    /// descriptor `fd` (`PrivateCopies`).
    #[cfg(test)]
    pub(super) fn records_copy(&self, tid: i32, fd: i32) -> bool {
        self.private_copies.records_copy(tid, fd)
    }

    /// This table's descriptors as they are now, for a fork child, which the
    /// caller makes under the table lock: the forking task's private copies
    /// are as of its last install, and a sibling's retirement since may have
    /// replaced some of them (`PrivateCopies`). The child gets what the table
    /// holds, as a Linux fork copies the descriptor table it finds.
    pub(super) fn fork_descriptors(
        &self,
        retirement: &crate::elf::FileRetirement,
    ) -> std::io::Result<ForkDescriptors> {
        ForkDescriptors::new(
            &self.files,
            self.stdin.as_ref(),
            self.stdin_entry_id.clone(),
            retirement,
            ForkFacts {
                fd_entry_ids: &self.fd_entry_ids,
                epoll_domain: &self.epoll_domain,
                poll_table_id: &self.poll_table_id,
                native_poll_fds: &self.native_poll_fds,
                pipe_owners: &self.pipe_owners,
                stdout_alias_fds: &self.stdout_alias_fds,
                stderr_alias_fds: &self.stderr_alias_fds,
                cloexec_fds: &self.cloexec_fds,
                closed_standard_fds: &self.closed_standard_fds,
                proc_files: &self.proc_files,
                synthetic_proc_nofollow_fds: &self.synthetic_proc_nofollow_fds,
                fdinfo_files: &self.fdinfo_files,
                fd_object_inodes: &self.fd_object_inodes,
            },
        )
    }
}

/// The descriptor facts a new task's state starts from (`ForkDescriptors`).
struct ForkFacts<'a> {
    fd_entry_ids: &'a std::collections::BTreeMap<i32, Arc<crate::elf::FdEntry>>,
    epoll_domain: &'a Arc<Mutex<EpollDomain>>,
    poll_table_id: &'a Arc<NativePollTable>,
    native_poll_fds: &'a std::collections::BTreeMap<i32, Arc<NativePollBinding>>,
    pipe_owners: &'a std::collections::BTreeMap<i32, Arc<pipe_owner::PipeOwner>>,
    stdout_alias_fds: &'a std::collections::BTreeSet<i32>,
    stderr_alias_fds: &'a std::collections::BTreeSet<i32>,
    cloexec_fds: &'a std::collections::BTreeSet<i32>,
    closed_standard_fds: &'a std::collections::BTreeSet<i32>,
    proc_files: &'a std::collections::BTreeMap<i32, u64>,
    synthetic_proc_nofollow_fds: &'a std::collections::BTreeSet<i32>,
    fdinfo_files: &'a std::collections::BTreeMap<i32, Arc<FdinfoDescription>>,
    fd_object_inodes: &'a std::collections::BTreeMap<i32, Arc<GuestFileIdentity>>,
}

/// The descriptors a new task's state starts with
/// (`LoadedStaticElf::try_clone_for_fork_locked`): a clone of every
/// description, the entries' identities and facts, and the per-process poll
/// identities a fork gives a child. A fork child takes them from its
/// parent's table (`FileTableState::fork_descriptors`); a thread takes its
/// creator's, then installs the table it shares (`Self::of_state`).
pub(crate) struct ForkDescriptors {
    pub(crate) files: std::collections::BTreeMap<i32, crate::elf::StagedFile>,
    pub(crate) stdin: Option<crate::elf::StagedFile>,
    pub(crate) stdin_entry_id: Arc<()>,
    pub(crate) fd_entry_ids: std::collections::BTreeMap<i32, Arc<crate::elf::FdEntry>>,
    pub(crate) epoll_domain: Arc<Mutex<EpollDomain>>,
    pub(crate) poll_table_id: Arc<NativePollTable>,
    pub(crate) native_poll_fds: std::collections::BTreeMap<i32, Arc<NativePollBinding>>,
    pub(crate) pipe_owners: std::collections::BTreeMap<i32, Arc<pipe_owner::PipeOwner>>,
    pub(crate) stdout_alias_fds: std::collections::BTreeSet<i32>,
    pub(crate) stderr_alias_fds: std::collections::BTreeSet<i32>,
    pub(crate) cloexec_fds: std::collections::BTreeSet<i32>,
    pub(crate) closed_standard_fds: std::collections::BTreeSet<i32>,
    pub(crate) proc_files: std::collections::BTreeMap<i32, u64>,
    pub(crate) synthetic_proc_nofollow_fds: std::collections::BTreeSet<i32>,
    pub(crate) fdinfo_files: std::collections::BTreeMap<i32, Arc<FdinfoDescription>>,
    pub(crate) fd_object_inodes: std::collections::BTreeMap<i32, Arc<GuestFileIdentity>>,
}

impl ForkDescriptors {
    fn new(
        files: &std::collections::BTreeMap<i32, std::fs::File>,
        stdin: Option<&std::fs::File>,
        stdin_entry_id: Arc<()>,
        retirement: &crate::elf::FileRetirement,
        facts: ForkFacts<'_>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            files: files
                .iter()
                .map(|(&fd, file)| Ok((fd, retirement.stage_clone(file)?)))
                .collect::<std::io::Result<_>>()?,
            stdin: stdin.map(|file| retirement.stage_clone(file)).transpose()?,
            stdin_entry_id,
            fd_entry_ids: facts.fd_entry_ids.clone(),
            epoll_domain: facts.epoll_domain.clone(),
            poll_table_id: facts.poll_table_id.fork_identity(),
            native_poll_fds: facts
                .native_poll_fds
                .iter()
                .map(|(&fd, binding)| (fd, binding.fork_binding()))
                .collect(),
            pipe_owners: facts.pipe_owners.clone(),
            stdout_alias_fds: facts.stdout_alias_fds.clone(),
            stderr_alias_fds: facts.stderr_alias_fds.clone(),
            cloexec_fds: facts.cloexec_fds.clone(),
            closed_standard_fds: facts.closed_standard_fds.clone(),
            proc_files: facts.proc_files.clone(),
            synthetic_proc_nofollow_fds: facts.synthetic_proc_nofollow_fds.clone(),
            fdinfo_files: facts.fdinfo_files.clone(),
            fd_object_inodes: facts.fd_object_inodes.clone(),
        })
    }

    /// `state`'s own descriptors, as of its last install, for a thread it
    /// makes: the thread installs the table they share before it runs.
    pub(crate) fn of_state(state: &LoadedStaticElf) -> std::io::Result<Self> {
        Self::new(
            state.files.copies(),
            state.stdin.as_ref(),
            state.stdin_entry_id.clone(),
            &state.file_retirement,
            ForkFacts {
                fd_entry_ids: &state.fd_entry_ids,
                epoll_domain: &state.epoll_domain,
                poll_table_id: &state.poll_table_id,
                native_poll_fds: &state.native_poll_fds,
                pipe_owners: &state.pipe_owners,
                stdout_alias_fds: &state.stdout_alias_fds,
                stderr_alias_fds: &state.stderr_alias_fds,
                cloexec_fds: &state.cloexec_fds,
                closed_standard_fds: &state.closed_standard_fds,
                proc_files: &state.proc_files,
                synthetic_proc_nofollow_fds: &state.synthetic_proc_nofollow_fds,
                fdinfo_files: &state.fdinfo_files,
                fd_object_inodes: &state.fd_object_inodes,
            },
        )
    }
}

/// The refusal for a publication that could not clone a changed entry: the
/// change has happened in the calling task, but no other task can see it.
fn publication_error(error: std::io::Error) -> crate::Error {
    match reverie_kvm_core::host_limits::HostResourceExhaustion::of(&error) {
        Some(exhaustion) => crate::Error::HostResources {
            resource: exhaustion.resource,
            diagnostic: format!(
                "KVM descriptor table: {} publishing a thread's descriptor change to its \
                 process's shared table ({error}) under {}; the change has happened in the \
                 thread, but no other thread can see it, so the run ends here",
                exhaustion.resource.ran_out(),
                exhaustion.limit,
            ),
        },
        None => crate::Error::HostIo(error),
    }
}

/// The private copies of a shared table's entries that its tasks hold.
///
/// Each task's executor state holds a host descriptor of its own for every
/// entry it has installed. A guest close, or a dup2 or dup3 over a
/// descriptor, retires the entry's published clone and the closing task's
/// copy, but each other task's copy holds the open file description until
/// that task's next call installs the table again. A task that makes no
/// call, as one parked in a futex wait, keeps it open for good: a pipe's
/// reader then never sees EOF, and its waiter never wakes.
///
/// So every publication that retires an entry deals with each other task's
/// copy of it before the call returns, in the retiring task's turn, under the
/// table lock (which every install and publication holds) and the copy
/// owner's [`CopyLedger`]:
/// - A copy the owner's current call has reached (`PrivateFiles::get` and
///   its siblings) is left to that call, which holds it as Linux's `fdget`
///   holds a file for the call that looked it up; the call's end replaces it
///   (`CallScope`). An in-flight read, poll or accept therefore finishes on
///   the description it started with, and its probes never see anything else.
/// - Any other copy gets the placeholder now: `dup3` puts an `O_PATH`
///   description of /dev/null on the copy's descriptor (`replace_copy`). The
///   descriptor stays its owner's, to close when its next install replaces
///   it, and until then the owner's lookups treat the descriptor as closed.
///
/// Before it changes anything, a retirement checks that this process's
/// descriptor limits let it replace every such copy
/// (`PrivateCopies::first_unreplaceable`); if one is at or above a lowered
/// hard `RLIMIT_NOFILE`, nothing is published or replaced, and the run ends.
///
/// The description is then released when the guest's last reference to it
/// goes, as on Linux. A retirement's cost is one lookup per task sharing the
/// table for each retired entry.
///
/// The record of a task is its descriptors as of its last install or
/// publication, the only times its copies change while its gate is open.
/// Tables split only at fork, which makes the child a table, and a record,
/// of its own; no copy of one table is ever replaced by a retirement in
/// another. LinuxEmu shares a table only between the threads of a process
/// (a thread without CLONE_FILES, or a process with it, is refused), and has
/// no unshare.
#[derive(Debug, Default)]
pub(super) struct PrivateCopies {
    tasks: std::collections::BTreeMap<i32, TaskCopies>,
}

/// One task's copies: its ledger, and for stdin and each descriptor, the
/// entry it copies and the host descriptor that holds the copy.
#[derive(Debug)]
struct TaskCopies {
    gate: std::sync::Weak<Mutex<CopyLedger>>,
    stdin: Option<(Arc<()>, RawFd)>,
    files: std::collections::BTreeMap<i32, (Option<Arc<crate::elf::FdEntry>>, RawFd)>,
}

/// A copy a retirement could not deal with: it stays in its task's record.
#[derive(Debug)]
pub(super) struct UnreplacedCopy {
    tid: i32,
    /// The guest descriptor, or `None` for stdin.
    fd: Option<i32>,
    host: RawFd,
    /// Why: the check before publication (`PrivateCopies::first_unreplaceable`),
    /// or the failed replacement itself.
    cause: UnreplacedCause,
}

#[derive(Debug)]
enum UnreplacedCause {
    /// At or above this process's hard `RLIMIT_NOFILE`, where `dup3` cannot
    /// put the placeholder; found before anything was published.
    AboveHardLimit,
    /// The replacement failed after the guest's change was published.
    Failed(std::io::Error),
}

impl UnreplacedCopy {
    /// The run-ending refusal for this copy: the guest's close has already
    /// happened in the closing thread, so no errno can answer it.
    fn into_error(self) -> crate::Error {
        let descriptor = self.fd.map_or_else(
            || "standard input".to_owned(),
            |fd| format!("guest descriptor {fd}"),
        );
        let limits = reverie_kvm_core::host_limits::descriptor_limit_text();
        let diagnostic = match self.cause {
            UnreplacedCause::AboveHardLimit => format!(
                "KVM descriptor retirement: thread {}'s copy of {descriptor} (host descriptor {}) \
                 is at or above this process's hard RLIMIT_NOFILE ({limits}), where it cannot be \
                 replaced, so another thread's close or replacement of that descriptor cannot \
                 take its copy's description away; the run ends here, before the change is \
                 published, with every copy as it was",
                self.tid, self.host,
            ),
            UnreplacedCause::Failed(error) => format!(
                "KVM descriptor retirement: thread {}'s copy of {descriptor} (host descriptor {}) \
                 could not be replaced after another thread closed or replaced it ({error}) under \
                 this process's RLIMIT_NOFILE ({limits}); the copy still holds the closed \
                 description, so the run ends here rather than leave a reader waiting for its EOF",
                self.tid, self.host,
            ),
        };
        crate::Error::HostResources {
            resource: reverie_kvm_core::host_limits::HostResource::Descriptors,
            diagnostic,
        }
    }
}

impl PrivateCopies {
    /// Records `state`'s copies as its task's, in place of any earlier
    /// record, and forgets the tasks whose state is gone.
    fn register(&mut self, state: &LoadedStaticElf) {
        self.tasks.retain(|_, task| task.gate.strong_count() > 0);
        self.tasks.insert(
            state.tid,
            TaskCopies {
                gate: Arc::downgrade(&state.private_copy_gate.0),
                stdin: state
                    .stdin
                    .as_ref()
                    .map(|file| (state.stdin_entry_id.clone(), file.as_raw_fd())),
                files: state
                    .files
                    .iter()
                    .map(|(&fd, file)| {
                        (fd, (state.fd_entry_ids.get(&fd).cloned(), file.as_raw_fd()))
                    })
                    .collect(),
            },
        );
    }

    /// Whether task `tid`'s record still names a copy of guest descriptor `fd`.
    #[cfg(test)]
    fn records_copy(&self, tid: i32, fd: i32) -> bool {
        self.tasks
            .get(&tid)
            .is_some_and(|task| task.files.contains_key(&fd))
    }

    /// Registers `state` unless its record is already this state's.
    fn ensure_registered(&mut self, state: &LoadedStaticElf) {
        let current = self.tasks.get(&state.tid).is_some_and(|task| {
            std::ptr::eq(task.gate.as_ptr(), Arc::as_ptr(&state.private_copy_gate.0))
        });
        if !current {
            self.register(state);
        }
    }

    /// `task`'s copies of the retired entries (`retired`, with stdin's old
    /// identity when it changed): by guest descriptor, then stdin's.
    fn targets(
        task: &TaskCopies,
        retired: &[(i32, Option<Arc<crate::elf::FdEntry>>)],
        retired_stdin: Option<&Arc<()>>,
    ) -> (Vec<(i32, RawFd)>, Option<RawFd>) {
        let files = retired
            .iter()
            .filter_map(|(fd, entry)| {
                task.files
                    .get(fd)
                    .filter(|(copy, _)| same_entry(copy.as_ref(), entry.as_ref()))
                    .map(|&(_, host)| (*fd, host))
            })
            .collect();
        let stdin = retired_stdin.and_then(|retired| {
            task.stdin
                .as_ref()
                .filter(|(copy, _)| Arc::ptr_eq(copy, retired))
                .map(|&(_, host)| host)
        });
        (files, stdin)
    }

    /// The first copy, in thread-id and descriptor order, that [`Self::revoke`]
    /// would deal with for this retirement (every copy of a retired entry
    /// that a task other than `publisher` holds, whether its call reached it
    /// or not) and could not replace under this process's descriptor limits
    /// as they are now: one at or above the hard `RLIMIT_NOFILE`, which `dup3`
    /// refuses even with the soft limit raised (`replace_copy`). Reads only,
    /// so a retirement can refuse before it changes anything.
    fn first_unreplaceable(
        &self,
        publisher: i32,
        retired: &[(i32, Option<Arc<crate::elf::FdEntry>>)],
        retired_stdin: Option<&Arc<()>>,
    ) -> Option<UnreplacedCopy> {
        if retired.is_empty() && retired_stdin.is_none() {
            return None;
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes only `limit`. Without a limit to read,
        // each replacement decides for itself.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return None;
        }
        for (&tid, task) in &self.tasks {
            if tid == publisher {
                continue;
            }
            let (files, stdin) = Self::targets(task, retired, retired_stdin);
            if files.is_empty() && stdin.is_none() {
                continue;
            }
            let Some(gate) = task.gate.upgrade() else {
                continue;
            };
            let ledger = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if !ledger.open {
                continue;
            }
            let copies = files
                .into_iter()
                .map(|(fd, host)| (Some(fd), host))
                .chain(stdin.map(|host| (None, host)));
            for (fd, host) in copies {
                // A copy lent out is not the task's: no retirement touches it.
                if !ledger.foreign.contains(&host) && host as libc::rlim_t >= limit.rlim_max {
                    return Some(UnreplacedCopy {
                        tid,
                        fd,
                        host,
                        cause: UnreplacedCause::AboveHardLimit,
                    });
                }
            }
        }
        None
    }

    /// Deals with each copy that a task other than `publisher` holds of a
    /// retired entry (`retired`, with stdin's old identity when it changed):
    /// leaves a reached one to its call, replaces any other
    /// ([`CopyLedger::retire_copy`]). A copy leaves its task's record only
    /// once that is done; one that could not be replaced stays, and is
    /// returned. A task whose gate is closed holds no copy and is forgotten.
    fn revoke(
        &mut self,
        publisher: i32,
        retired: &[(i32, Option<Arc<crate::elf::FdEntry>>)],
        retired_stdin: Option<&Arc<()>>,
    ) -> Vec<UnreplacedCopy> {
        let mut unreplaced = Vec::new();
        if retired.is_empty() && retired_stdin.is_none() {
            return unreplaced;
        }
        let mut gone = Vec::new();
        for (&tid, task) in &mut self.tasks {
            if tid == publisher {
                continue;
            }
            let (targets, stdin) = Self::targets(task, retired, retired_stdin);
            if targets.is_empty() && stdin.is_none() {
                continue;
            }
            let Some(gate) = task.gate.upgrade() else {
                gone.push(tid);
                continue;
            };
            let mut ledger = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if !ledger.open {
                gone.push(tid);
                continue;
            }
            for (fd, host) in targets {
                match ledger.retire_copy(host) {
                    Ok(()) => {
                        task.files.remove(&fd);
                    }
                    Err(error) => unreplaced.push(UnreplacedCopy {
                        tid,
                        fd: Some(fd),
                        host,
                        cause: UnreplacedCause::Failed(error),
                    }),
                }
            }
            if let Some(host) = stdin {
                match ledger.retire_copy(host) {
                    Ok(()) => task.stdin = None,
                    Err(error) => unreplaced.push(UnreplacedCopy {
                        tid,
                        fd: None,
                        host,
                        cause: UnreplacedCause::Failed(error),
                    }),
                }
            }
        }
        for tid in gone {
            self.tasks.remove(&tid);
        }
        unreplaced
    }
}

/// Whether two copies are of one entry. An entry without an identity is
/// matched by its descriptor alone, as install treats it.
fn same_entry(
    copy: Option<&Arc<crate::elf::FdEntry>>,
    retired: Option<&Arc<crate::elf::FdEntry>>,
) -> bool {
    match (copy, retired) {
        (Some(copy), Some(retired)) => Arc::ptr_eq(copy, retired),
        (None, None) => true,
        _ => false,
    }
}

/// What one task's private copies are doing, shared by the task's state
/// ([`PrivateCopyGate`], [`PrivateFiles`]) and its record in the table
/// (`TaskCopies`), which a retiring task reaches under the table lock. The
/// owner and a retiring task take it in turn. Copies are named by their host
/// descriptors.
#[derive(Debug)]
struct CopyLedger {
    /// False once the task's exit gave its copies up, or its state was
    /// dropped: a retirement then skips the task.
    open: bool,
    /// Whether the task is inside a call (`CallScope`). Only a call's
    /// lookups reach copies: a lookup outside any call, which no call end
    /// would release, reaches nothing.
    in_call: bool,
    /// The copies the task's current call has reached. A retirement leaves
    /// these to the call's end (`deferred`).
    reached: std::collections::BTreeSet<RawFd>,
    /// Reached copies whose entries a retirement retired: the call's end
    /// replaces them (`CallScope`).
    deferred: std::collections::BTreeSet<RawFd>,
    /// Copies a retirement replaced with the placeholder. The task treats
    /// each as closed until its next install replaces it.
    revoked: std::collections::BTreeSet<RawFd>,
    /// Descriptors the task's record may still name that are no longer its
    /// copies: a copy lent to the terminal reader that kept it
    /// (`PrivateFiles::mark_foreign`). Its owner closes it, so a retirement
    /// must never replace it.
    foreign: std::collections::BTreeSet<RawFd>,
}

impl Default for CopyLedger {
    fn default() -> Self {
        Self {
            open: true,
            in_call: false,
            reached: Default::default(),
            deferred: Default::default(),
            revoked: Default::default(),
            foreign: Default::default(),
        }
    }
}

impl CopyLedger {
    /// The owner's call reaches `host`: true, and the copy stays the owner's
    /// original until the call ends, unless a retirement already replaced it,
    /// when the call finds the descriptor closed (false).
    fn reach(&mut self, host: RawFd) -> bool {
        if self.revoked.contains(&host) || self.foreign.contains(&host) {
            return false;
        }
        if self.in_call {
            self.reached.insert(host);
        }
        true
    }

    /// A retirement's part for one copy: leaves a reached copy to its call,
    /// and otherwise replaces it now. A descriptor that is no longer the
    /// task's copy is left alone.
    fn retire_copy(&mut self, host: RawFd) -> std::io::Result<()> {
        if self.foreign.contains(&host) {
            return Ok(());
        }
        if self.reached.contains(&host) {
            self.deferred.insert(host);
            return Ok(());
        }
        replace_copy(host)?;
        self.revoked.insert(host);
        Ok(())
    }
}

/// Whether a task's private copies may still be replaced by another task's
/// retirement of their entries (`PrivateCopies`), and what its calls and
/// those retirements are doing to them (`CopyLedger`). A task's state
/// declares it before its descriptors, so dropping the state closes it
/// before any copy is closed, and a task's exit closes it, giving up its
/// copies' descriptions under it, before it closes the copies. A retirement
/// holds the ledger while it replaces a copy, so it never replaces one after
/// the copy's descriptor number could have been reused, and a closed gate
/// means the task holds no copy to replace. The one exception is an exit
/// through a terminal cleanup service, which reads each descriptor it is
/// given: there the copies keep their descriptions until the service closes
/// them.
#[derive(Debug)]
pub struct PrivateCopyGate(Arc<Mutex<CopyLedger>>);

impl Default for PrivateCopyGate {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(CopyLedger::default())))
    }
}

impl PrivateCopyGate {
    fn ledger(&self) -> std::sync::MutexGuard<'_, CopyLedger> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `files` as this task's copies, looked up through this gate's ledger.
    pub fn bind(&self, files: std::collections::BTreeMap<i32, std::fs::File>) -> PrivateFiles {
        PrivateFiles {
            files,
            ledger: self.0.clone(),
        }
    }

    /// Whether this task's call may use its copy `host` (`CopyLedger::reach`).
    pub(crate) fn reach(&self, host: RawFd) -> bool {
        self.ledger().reach(host)
    }

    /// The copies a retirement replaced since this task's last install, for
    /// the next install to replace (`FileTableState::install`).
    fn revoked(&self) -> std::collections::BTreeSet<RawFd> {
        self.ledger().revoked.clone()
    }

    /// An install of this task succeeded: the `replaced` copies are gone,
    /// and so is any reach of the call so far. A copy whose retirement was
    /// left to this call still holds its original description, so the
    /// install treated it as it treats any copy of a retired entry.
    fn installed(&self, replaced: &std::collections::BTreeSet<RawFd>) {
        let mut ledger = self.ledger();
        ledger.revoked.retain(|host| !replaced.contains(host));
        ledger.reached.clear();
        ledger.deferred.clear();
        // The record the install made names only the copies the task holds.
        ledger.foreign.clear();
    }

    /// The scope of one call of this task: when it ends, the copies the call
    /// reached become replaceable again, and those whose entries were retired
    /// meanwhile are replaced.
    pub(crate) fn call_scope(&self) -> CallScope {
        self.ledger().in_call = true;
        CallScope(self.0.clone())
    }

    /// Closes the gate and, under it, makes each of `copies` drop its
    /// description: its descriptor stays open, for its owner to close, on
    /// the placeholder. A retirement after this skips the task.
    pub(crate) fn close<'a>(&self, copies: impl IntoIterator<Item = &'a std::fs::File>) {
        let mut ledger = self.ledger();
        ledger.open = false;
        ledger.reached.clear();
        ledger.deferred.clear();
        // A copy that cannot be replaced keeps its description until its
        // owner closes it, later in this exit.
        for copy in copies {
            let _ = replace_copy(copy.as_raw_fd());
        }
    }
}

impl Drop for PrivateCopyGate {
    fn drop(&mut self) {
        self.ledger().open = false;
    }
}

/// One call of a task, from its start to its end (`PrivateCopyGate::call_scope`).
pub(crate) struct CallScope(Arc<Mutex<CopyLedger>>);

impl Drop for CallScope {
    fn drop(&mut self) {
        let mut ledger = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ledger.in_call = false;
        ledger.reached.clear();
        if !ledger.open {
            // The task's exit has given its copies up; one handed to a
            // cleanup service is no longer the task's to touch.
            ledger.deferred.clear();
            return;
        }
        for host in std::mem::take(&mut ledger.deferred) {
            match replace_copy(host) {
                Ok(()) => {
                    ledger.revoked.insert(host);
                }
                // Not replaced, which the retirement's check rules out unless
                // this process's hard limit fell below the copy since: the
                // copy keeps its description, the original, until the owner's
                // next install, at the start of its next call, retires it.
                Err(_) => {
                    ledger.deferred.insert(host);
                }
            }
        }
    }
}

/// A one-shot test hook: a closure a test installs on one thread.
#[cfg(test)]
pub(crate) type OneShotTestHook = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
std::thread_local! {
    /// Runs once on the calling thread right after a call that does not
    /// change the table releases the table lock, before the call reaches any
    /// copy: where another task's retirement can replace the caller's copies.
    pub(crate) static TABLE_RELEASED_TEST_HOOK: OneShotTestHook =
        const { std::cell::RefCell::new(None) };
    /// Runs once on the calling thread right after a lookup reaches a copy
    /// (`PrivateFiles::get` and its siblings): where another task's
    /// retirement finds the copy in use.
    pub(crate) static COPY_REACHED_TEST_HOOK: OneShotTestHook =
        const { std::cell::RefCell::new(None) };
    /// Runs once on the calling thread right after a publication found every
    /// copy it retires replaceable (`PrivateCopies::first_unreplaceable`),
    /// before it changes anything.
    pub(crate) static PUBLICATION_CHECKED_TEST_HOOK: OneShotTestHook =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` once, if this thread installed it.
#[cfg(test)]
pub(crate) fn run_one_shot_test_hook(hook: &'static std::thread::LocalKey<OneShotTestHook>) {
    if let Some(hook) = hook.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

/// A task's private copies of its table's entries, by guest descriptor.
///
/// A guest operation looks a copy up with [`Self::get`], [`Self::get_mut`],
/// [`Self::contains_key`] or indexing, which reach it for the rest of the
/// call (`CopyLedger`): a retirement by another task then leaves it to the
/// call's end, as Linux leaves a file to a call that holds it. A copy that a
/// retirement replaced before the call reached it is not found, as a closed
/// descriptor is not. The map's own methods (through `Deref`) are for the
/// table's bookkeeping, which runs under the table lock and reaches nothing.
#[derive(Debug)]
pub struct PrivateFiles {
    files: std::collections::BTreeMap<i32, std::fs::File>,
    ledger: Arc<Mutex<CopyLedger>>,
}

impl PrivateFiles {
    fn reach(&self, file: &std::fs::File) -> bool {
        let reached = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reach(file.as_raw_fd());
        #[cfg(test)]
        if reached {
            run_one_shot_test_hook(&COPY_REACHED_TEST_HOOK);
        }
        reached
    }

    /// The copy of guest descriptor `fd`, for this call's use.
    pub fn get(&self, fd: &i32) -> Option<&std::fs::File> {
        let file = self.files.get(fd)?;
        self.reach(file).then_some(file)
    }

    /// The copy of guest descriptor `fd`, for this call's use.
    pub fn get_mut(&mut self, fd: &i32) -> Option<&mut std::fs::File> {
        let reached = self.files.get(fd).is_some_and(|file| self.reach(file));
        if reached {
            self.files.get_mut(fd)
        } else {
            None
        }
    }

    /// Whether guest descriptor `fd` has a copy this call can use.
    pub fn contains_key(&self, fd: &i32) -> bool {
        self.get(fd).is_some()
    }

    /// Host descriptor `host`, a copy this task lent out of the map (to the
    /// terminal reader), stays with its borrower, which closes it: it is no
    /// longer this task's copy, so no retirement or call end of this task
    /// may replace it, although the task's record may name it until the
    /// next install.
    pub fn mark_foreign(&self, host: RawFd) {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ledger.reached.remove(&host);
        ledger.deferred.remove(&host);
        ledger.revoked.remove(&host);
        ledger.foreign.insert(host);
    }

    /// The copies, for the table's bookkeeping: reaches nothing, and includes
    /// copies a retirement replaced.
    pub fn copies(&self) -> &std::collections::BTreeMap<i32, std::fs::File> {
        &self.files
    }

    /// Takes every copy out, leaving none (and the same ledger).
    pub fn take_map(&mut self) -> std::collections::BTreeMap<i32, std::fs::File> {
        std::mem::take(&mut self.files)
    }

    /// Puts `files` in place of the copies, which are returned.
    pub fn replace_map(
        &mut self,
        files: std::collections::BTreeMap<i32, std::fs::File>,
    ) -> std::collections::BTreeMap<i32, std::fs::File> {
        std::mem::replace(&mut self.files, files)
    }

    /// The copies, given up.
    pub fn into_map(self) -> std::collections::BTreeMap<i32, std::fs::File> {
        self.files
    }
}

impl std::ops::Deref for PrivateFiles {
    type Target = std::collections::BTreeMap<i32, std::fs::File>;

    fn deref(&self) -> &Self::Target {
        &self.files
    }
}

impl std::ops::DerefMut for PrivateFiles {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.files
    }
}

impl std::ops::Index<&i32> for PrivateFiles {
    type Output = std::fs::File;

    fn index(&self, fd: &i32) -> &std::fs::File {
        self.get(fd)
            .expect("indexed guest descriptor has no usable private copy")
    }
}

/// The description a replaced copy is left on: `O_PATH` on /dev/null, which
/// reads, writes and path lookups all refuse. Opened by the first table this
/// process makes (`FileTableState::try_from_elf`), so that a retirement,
/// which may run when this process has no descriptor to spare, never opens
/// it.
fn revoked_copy_placeholder() -> std::io::Result<RawFd> {
    use std::os::unix::fs::OpenOptionsExt;
    static PLACEHOLDER: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
    if let Some(file) = PLACEHOLDER.get() {
        return Ok(file.as_raw_fd());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open("/dev/null")?;
    Ok(PLACEHOLDER.get_or_init(|| file).as_raw_fd())
}

/// Puts the placeholder's description on copy `host`, dropping `host`'s own.
///
/// `dup3` refuses a target at or above this process's soft `RLIMIT_NOFILE`
/// (EBADF), even an open one, while Linux closes such a descriptor at any
/// limit. A copy above a lowered soft limit is replaced with the soft limit
/// raised just past it for the one call, and restored, under
/// [`NOFILE_LIMIT_ADJUSTMENT`], which every read of the guest's descriptor
/// limit also takes (`guest_nofile_limit`), so no guest allocation sees the
/// raised value. A copy at or above the hard limit (lowered after the copy
/// was made) cannot be replaced; a retirement looks for one before it
/// changes anything (`PrivateCopies::first_unreplaceable`). Closing the copy
/// instead would leave its owner's `File` naming a number that is no longer
/// its own.
fn replace_copy(host: RawFd) -> std::io::Result<()> {
    let placeholder = revoked_copy_placeholder()?;
    match dup3_retrying(placeholder, host) {
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
            let _adjustment = NOFILE_LIMIT_ADJUSTMENT
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit writes only `limit`.
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
                return Err(error);
            }
            let needed = host as libc::rlim_t + 1;
            if needed <= limit.rlim_cur || needed > limit.rlim_max {
                return Err(error);
            }
            let raised = libc::rlimit {
                rlim_cur: needed,
                rlim_max: limit.rlim_max,
            };
            // SAFETY: setrlimit reads only `raised`, a soft limit within the
            // hard one, which this process may always set.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
                return Err(error);
            }
            let replaced = dup3_retrying(placeholder, host);
            // SAFETY: restores the soft limit read above; lowering a soft
            // limit is always allowed.
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
            replaced
        }
        other => other,
    }
}

fn dup3_retrying(placeholder: RawFd, host: RawFd) -> std::io::Result<()> {
    loop {
        // SAFETY: the placeholder is open for the life of the process, and
        // `host` is a copy owned by a task whose open ledger the caller
        // holds, or the caller's own, so the descriptor is still that copy's.
        if unsafe { libc::dup3(placeholder, host, libc::O_CLOEXEC) } >= 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
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
    // Allocation runs under the table lock, where no copy is replaced, so
    // the search reads the copies without reaching any.
    let Some(fd) = (0..guest_nofile_limit())
        .find(|fd| !is_open_standard(state, *fd) && !state.files.copies().contains_key(fd))
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
    let limit = guest_nofile_limit();
    if !(0..limit).contains(&minimum) {
        return negative_errno(libc::EINVAL);
    }
    // Under the table lock, as for insert_file_with_identity.
    let Some(fd) = (minimum..limit)
        .find(|fd| !is_open_standard(state, *fd) && !state.files.copies().contains_key(fd))
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
            // Linux tests oldfd == newfd before the allocation bound
            // (ksys_dup3 and dup2 in fs/file.c): dup2 to itself returns the
            // descriptor even at or above the current RLIMIT_NOFILE, and
            // dup3 to itself is EINVAL there.
            if new_fd == old_fd {
                return if is_dup3 {
                    negative_errno(libc::EINVAL)
                } else {
                    i64::from(new_fd)
                };
            }
            if !(0..guest_nofile_limit()).contains(&new_fd) {
                return negative_errno(libc::EBADF);
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
