/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! pidfds (gVisor: pkg/sentry/kernel/pidfd.go).

use super::*;

/// A pidfd for another guest process: the process it names, and its shadow
/// socket (`process_signal_publication::pidfd_shadow`), which shows the
/// pidfd's readiness. In the guest's table the descriptor itself is a pidfd
/// for the supervisor, which the kernel answers for as for any pidfd; every
/// alias of the descriptor, from dup or fork, shares this record.
#[derive(Debug)]
pub(crate) struct ForeignPidfd {
    target: reverie::SignalProcessId,
    shadow: Arc<std::fs::File>,
    /// A descriptor of the shadow for each guest descriptor number an epoll
    /// call has named the pidfd by. Linux keys an epoll
    /// registration by descriptor number and open file description, so each
    /// number needs a host descriptor of its own; these close with the pidfd
    /// (`epoll_host_fd`).
    epoll_keys: Mutex<std::collections::BTreeMap<libc::c_int, std::fs::File>>,
}

impl ForeignPidfd {
    /// The process the pidfd names.
    pub(crate) fn target(&self) -> reverie::SignalProcessId {
        self.target
    }

    /// The host descriptor that poll and select watch for the pidfd.
    pub(super) fn readiness_fd(&self) -> RawFd {
        self.shadow.as_raw_fd()
    }

    /// The host descriptor that stands for guest descriptor number `fd` of
    /// the pidfd in an epoll registration, made the first time it is named.
    fn epoll_key_fd(&self, fd: libc::c_int) -> Result<RawFd, i64> {
        let mut keys = self
            .epoll_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(key) = keys.get(&fd) {
            return Ok(key.as_raw_fd());
        }
        // SAFETY: shadow owns a live descriptor; F_DUPFD_CLOEXEC returns a new
        // one above the standard descriptors.
        let key = unsafe {
            libc::fcntl(
                self.shadow.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                libc::STDERR_FILENO + 1,
            )
        };
        if key < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        // SAFETY: fcntl returned a new descriptor that nothing else owns.
        keys.insert(fd, unsafe { std::fs::File::from_raw_fd(key) });
        Ok(key)
    }

    #[cfg(test)]
    pub(super) fn shadow(&self) -> std::sync::Weak<std::fs::File> {
        Arc::downgrade(&self.shadow)
    }
}

/// The pidfd record of guest descriptor `fd`, if it is a pidfd for another
/// guest process.
pub(super) fn foreign_pidfd(
    state: &LoadedStaticElf,
    fd: libc::c_int,
) -> Option<&Arc<ForeignPidfd>> {
    state.foreign_pidfds.get(&fd)
}

/// The inode number that `stat` reports for a pidfd for `target`, another
/// guest process. Linux gives every process one pidfs inode, which all its
/// pidfds share, and numbers them from 2 upward as pids are made
/// (`pidfs_add_pid`, fs/pidfs.c), so pidfds compare equal by inode number
/// exactly when they name the same process. The stand-in's own inode is the
/// supervisor's, the one a pidfd for the caller itself reports; this number
/// is one per guest process instead, with the top bit set, which no pidfs
/// inode number reaches.
pub(super) fn foreign_pidfd_inode(target: reverie::SignalProcessId) -> u64 {
    1 << 63 | target.generation
}

/// The host descriptor whose readiness is guest descriptor `fd`'s: the shadow
/// of a pidfd for another process, whose own host descriptor never becomes
/// readable while the run lasts, and otherwise the descriptor itself. A
/// caller asks a shadow only for [`FOREIGN_PIDFD_POLL_EVENTS`].
pub(super) fn readiness_host_fd(state: &LoadedStaticElf, fd: libc::c_int) -> Option<RawFd> {
    let host_fd = host_fd(state, fd)?;
    Some(foreign_pidfd(state, fd).map_or(host_fd, |pidfd| pidfd.readiness_fd()))
}

/// The host descriptor an epoll call names for guest descriptor `fd`: as
/// [`readiness_host_fd`], with a host descriptor of the shadow for each
/// guest descriptor number of a pidfd for another process
/// ([`ForeignPidfd::epoll_key_fd`]). `Ok(None)` when `fd` is not open.
pub(super) fn epoll_host_fd(
    state: &LoadedStaticElf,
    fd: libc::c_int,
) -> Result<Option<RawFd>, i64> {
    let Some(host_fd) = host_fd(state, fd) else {
        return Ok(None);
    };
    match foreign_pidfd(state, fd) {
        Some(pidfd) => pidfd.epoll_key_fd(fd).map(Some),
        None => Ok(Some(host_fd)),
    }
}

/// The events that poll and select ask a pidfd's shadow for: all that
/// Linux's `pidfd_poll` reports besides `POLLHUP`, which poll reports
/// unasked (fs/pidfs.c). The shadow is a socket, which also reports that it
/// is writable and, once hung up, `POLLRDHUP`; a pidfd reports neither.
pub(super) const FOREIGN_PIDFD_POLL_EVENTS: libc::c_short = libc::POLLIN | libc::POLLRDNORM;

/// The events of an epoll registration of a pidfd's shadow, for a guest's
/// registration of the pidfd with `events`: the same, without the readiness
/// a pidfd never reports and its shadow socket does (see
/// [`FOREIGN_PIDFD_POLL_EVENTS`]). With `EPOLLEXCLUSIVE`, Linux refuses
/// (EINVAL) any of those but `EPOLLOUT`, so only `EPOLLOUT` is taken then,
/// and the host refuses the rest as Linux does.
pub(super) fn foreign_pidfd_epoll_events(events: u32) -> u32 {
    let mut never = libc::EPOLLOUT as u32;
    if events & libc::EPOLLEXCLUSIVE as u32 == 0 {
        never |= (libc::EPOLLWRNORM | libc::EPOLLWRBAND | libc::EPOLLRDHUP) as u32;
    }
    events & !never
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-235): Review self-only virtual pidfd translation.
pub(super) fn pidfd_open(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let flags = args[1] as libc::c_uint;
    if flags & !(libc::O_NONBLOCK as libc::c_uint) != 0 {
        return negative_errno(libc::EINVAL);
    }
    // Linux refuses a pid that cannot name one process before it looks the
    // pid up (`pidfd_open`, kernel/pid.c).
    let pid = args[0] as libc::pid_t;
    if pid <= 0 {
        return negative_errno(libc::EINVAL);
    }
    if pid != state.pid {
        // AUTONOMOUS-BOT-IMPLEMENTED
        return foreign_pidfd_open(state, pid, flags);
    }

    // The supervisor remains alive for every guest executor, so its pidfd has
    // the same readiness contract as a pidfd for the live virtual process.
    let file = match supervisor_pidfd(flags) {
        Ok(file) => file,
        Err(error) => return error,
    };
    // The pidfd is a real kernel object for the supervisor process, and its
    // metadata is the kernel's, as for a pidfd a guest receives from outside
    // the run; nothing here classifies it for later stat calls.
    insert_file_with_flags(state, file, true, None)
}

/// A new pidfd for the supervisor process, with `flags`.
fn supervisor_pidfd(flags: libc::c_uint) -> Result<std::fs::File, i64> {
    // SAFETY: pidfd_open takes no pointers.
    let host_fd = unsafe {
        libc::syscall(libc::SYS_pidfd_open, libc::getpid(), flags as libc::c_uint) as libc::c_int
    };
    if host_fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(host_fd) })
}

/// `pidfd_open(pid, flags)` for a guest process other than the caller's:
/// a pidfd for the supervisor stands in for it in the guest's table, and a
/// shadow socket shows its readiness ([`ForeignPidfd`]). Like Linux, it opens
/// one for a process that has exited and has not been reaped, which is then
/// readable at once.
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/pull/1410): Review pidfds for other guest
// processes, their stand-ins and their shadow sockets.
fn foreign_pidfd_open(state: &mut LoadedStaticElf, pid: libc::pid_t, flags: libc::c_uint) -> i64 {
    let target = match foreign_pidfd_target(state, pid) {
        Ok(target) => target,
        Err(errno) => return negative_errno(errno),
    };
    let Some(registry) = state.children.registry() else {
        // A task outside any process family has no other process to name.
        return negative_errno(libc::ESRCH);
    };
    let shadow = match registry.open_pidfd_shadow(target) {
        Ok(shadow) => shadow,
        Err(errno) => return negative_errno(errno),
    };
    let file = match supervisor_pidfd(flags) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let fd = insert_file_with_flags(state, file, true, None);
    if fd >= 0 {
        state.foreign_pidfds.insert(
            fd as libc::c_int,
            Arc::new(ForeignPidfd {
                target,
                shadow,
                epoll_keys: Default::default(),
            }),
        );
    }
    fd
}

/// The process `pid` names for a pidfd, as Linux's `pidfd_open` finds it
/// (kernel/pid.c): a live process whose thread group id `pid` is, even once
/// its leader has exited, or a process that has exited and has not been
/// reaped. EINVAL for a live thread that leads no thread group
/// (`pidfd_create`), ESRCH for a pid that names no process.
fn foreign_pidfd_target(
    state: &LoadedStaticElf,
    pid: libc::pid_t,
) -> Result<reverie::SignalProcessId, libc::c_int> {
    let live = {
        let lifecycle = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match lifecycle.get(pid) {
            Some(task) if task.tgid != pid => return Err(libc::EINVAL),
            Some(task) => Some(task.process_generation),
            None => lifecycle.live_process_generation(pid),
        }
    };
    if let Some(generation) = live {
        return Ok(reverie::SignalProcessId {
            tgid: reverie::Pid::from_raw(pid),
            generation,
        });
    }
    state
        .children
        .registry()
        .and_then(|registry| registry.unreaped_exited_process(pid))
        .ok_or(libc::ESRCH)
}

/// Classifies a carrier received in an SCM_RIGHTS message from the carrier
/// itself, so that the class survives every sender descriptor closing before
/// the receive, with nothing to account for while the right is in flight. A
/// `/proc` snapshot carrier is a memfd with its own name and the full
/// synthetic seal set. A guest that makes such a memfd itself gets
/// only fixed timestamps for it. Anything else, including a failed probe, is a
/// real host object, except a probe that fails only because no descriptor or
/// memory was left to reopen an O_PATH right (see [`CarrierSealProbe`]): the
/// receive needs a descriptor number but no new open file, so it can succeed
/// when the probe cannot. Such an object already matches the carrier name, a
/// regular file and the shared-memory filesystem, and keeps the class of its
/// name: a fixed time on a guest memfd with that name is deterministic, a host
/// time on the backend's carrier is not.
pub(super) fn received_carrier_timestamps(
    state: &LoadedStaticElf,
    file: &std::fs::File,
) -> IdentityTimestamps {
    if !state.host_metadata_timestamps {
        return IdentityTimestamps::Host;
    }
    if !fd_link_target_is(file.as_raw_fd(), b"/memfd:reverie-kvm-proc (deleted)") {
        return IdentityTimestamps::Host;
    }
    let timestamps = IdentityTimestamps::ProcSnapshot;
    match carrier_seals(file) {
        CarrierSealProbe::Seals(seals) if supported_synthetic_proc_seals(seals) => timestamps,
        CarrierSealProbe::OutOfResources => timestamps,
        CarrierSealProbe::Seals(_) | CarrierSealProbe::Absent => IdentityTimestamps::Host,
    }
}

/// What the seal probe of a received object found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CarrierSealProbe {
    /// The object's seals.
    Seals(libc::c_int),
    /// A regular file on the shared-memory filesystem whose seals could not be
    /// read because reopening it failed with EMFILE, ENFILE or ENOMEM.
    OutOfResources,
    /// No seals: the object is not a sealable regular shared-memory file, or
    /// the probe failed for another reason.
    Absent,
}

/// The seals of a memfd. An O_PATH description cannot query them, so a fresh
/// read-only description of the same memfd answers for it. Only a regular file
/// on the shared-memory filesystem, where every memfd lives, is reopened, and
/// without blocking: a guest object whose link text merely matches a carrier
/// name, such as a FIFO or a device, could block that open or act on it.
pub(super) fn carrier_seals(file: &std::fs::File) -> CarrierSealProbe {
    use std::os::unix::fs::OpenOptionsExt;

    // SAFETY: file owns a live descriptor and F_GET_SEALS has no third argument.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals >= 0 {
        return CarrierSealProbe::Seals(seals);
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat is writable and file owns a live descriptor; fstat accepts O_PATH.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return CarrierSealProbe::Absent;
    }
    // SAFETY: fstat initialized stat on success.
    if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
        return CarrierSealProbe::Absent;
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem is writable and file owns a live descriptor; fstatfs accepts O_PATH.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return CarrierSealProbe::Absent;
    }
    // SAFETY: fstatfs initialized filesystem on success.
    if unsafe { filesystem.assume_init() }.f_type != libc::TMPFS_MAGIC {
        return CarrierSealProbe::Absent;
    }
    let reopened = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
    {
        Ok(reopened) => reopened,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM)
            ) =>
        {
            return CarrierSealProbe::OutOfResources;
        }
        Err(_) => return CarrierSealProbe::Absent,
    };
    // SAFETY: reopened owns a live descriptor and F_GET_SEALS has no third argument.
    let seals = unsafe { libc::fcntl(reopened.as_raw_fd(), libc::F_GET_SEALS) };
    if seals >= 0 {
        CarrierSealProbe::Seals(seals)
    } else {
        CarrierSealProbe::Absent
    }
}

pub(super) fn synthetic_guest_fd_symlink_stat(guest_fd: libc::c_int) -> libc::stat {
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

pub(super) fn synthetic_guest_fd_symlink_statx(guest_fd: libc::c_int) -> libc::statx {
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
