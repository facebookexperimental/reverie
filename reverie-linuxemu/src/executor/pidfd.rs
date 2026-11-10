/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! pidfds (gVisor: pkg/sentry/kernel/pidfd.go).

use super::*;

/// A pidfd for a guest process: the process it names, and its shadow socket
/// (`process_signal_publication::pidfd_shadow`), which shows the pidfd's
/// readiness. In the guest's table the descriptor itself is a pidfd for the
/// supervisor, which the kernel answers for as for any pidfd.
///
/// The record is the pidfd's open file description: every alias of the
/// descriptor, from dup or fork, shares it. The descriptor tables that hold
/// the pidfd hold the record (`FdSlot`), and a task only names it
/// (`LoadedStaticElf::guest_pidfds`), so the record goes with the pidfd's
/// last descriptor, as Linux releases the description, and so do its shadow
/// and every epoll registration of the pidfd, whatever any other thread of
/// the process is doing. A call that finds the descriptor holds the record
/// until the call ends, even if another thread closes the descriptor
/// meanwhile ([`guest_pidfd`]), as Linux's `fdget` holds the file.
#[derive(Debug)]
pub(crate) struct GuestPidfd {
    target: reverie::SignalProcessId,
    shadow: Arc<std::fs::File>,
    /// A host descriptor of the shadow for each guest descriptor number by
    /// which an epoll registration names the pidfd ([`Self::epoll_control`]).
    epoll_keys: Mutex<std::collections::BTreeMap<libc::c_int, EpollKey>>,
}

/// The host descriptor that stands for one guest descriptor number of a
/// pidfd in epoll registrations: Linux keys a registration by descriptor
/// number and open file description, so each number needs a descriptor of
/// its own. `epolls` holds the registrations that name it, one for each
/// epoll with one: a successful `EPOLL_CTL_ADD` of the number adds the
/// epoll's, and its successful `EPOLL_CTL_DEL` removes it, as does the end
/// of the epoll's open file description ([`EpollIdentity`]), as Linux frees
/// an eventpoll's registrations with it. The key closes with the last of
/// them, or with the pidfd.
#[derive(Debug)]
struct EpollKey {
    file: std::fs::File,
    epolls: Vec<KeyRegistration>,
}

/// One epoll's registration of an epoll key.
#[derive(Debug)]
struct KeyRegistration {
    /// The epoll's identity, which every descriptor of its open file
    /// description shares, received ones included, and whose end ends the
    /// registration.
    identity: std::sync::Weak<EpollIdentity>,
    /// A host descriptor of the epoll, through which the pidfd's end removes
    /// the registration (`GuestPidfd`'s `Drop`). It goes with the
    /// registration, so it keeps the epoll no longer than the registration
    /// lasts.
    epoll: std::fs::File,
}

impl EpollKey {
    /// Where `epolls` holds the registration in the epoll whose identity is
    /// `epoll`.
    fn position(&self, epoll: &EpollIdentity) -> Option<usize> {
        self.epolls
            .iter()
            .position(|held| std::ptr::eq(held.identity.as_ptr(), epoll))
    }
}

// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/pull/1410): Review pidfd ends.
/// Removes the pidfd's epoll registrations, as Linux's `eventpoll_release`
/// does when it releases the pidfd's open file description. The host would
/// remove them itself when the shadow's open file description goes, but a
/// copy of the shadow that a fork of the supervisor holds keeps that
/// description, and the registrations with it, past the pidfd's last close.
impl Drop for GuestPidfd {
    fn drop(&mut self) {
        let keys = self
            .epoll_keys
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for key in keys.values() {
            for epoll in key.epolls.iter().map(|held| &held.epoll) {
                // SAFETY: both descriptors are live, and a DEL reads no
                // event.
                unsafe {
                    libc::epoll_ctl(
                        epoll.as_raw_fd(),
                        libc::EPOLL_CTL_DEL,
                        key.file.as_raw_fd(),
                        std::ptr::null_mut(),
                    )
                };
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Makes this thread's next epoll copy fail, as a full descriptor table
    /// would.
    pub(super) static EPOLL_COPY_FAILS_TEST_HOOK: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// A new host descriptor of the epoll whose host descriptor is `epoll_fd`.
fn copy_epoll(epoll_fd: RawFd) -> Option<std::fs::File> {
    #[cfg(test)]
    if EPOLL_COPY_FAILS_TEST_HOOK.with(|fails| fails.replace(false)) {
        return None;
    }
    // SAFETY: epoll_fd is the caller's live host descriptor of the epoll;
    // F_DUPFD_CLOEXEC returns a new one.
    let copy = unsafe { libc::fcntl(epoll_fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    (copy >= 0).then(|| unsafe { std::fs::File::from_raw_fd(copy) })
}

impl GuestPidfd {
    /// The process the pidfd names.
    pub(crate) fn target(&self) -> reverie::SignalProcessId {
        self.target
    }

    /// The host descriptor that poll and select watch for the pidfd.
    pub(super) fn readiness_fd(&self) -> RawFd {
        self.shadow.as_raw_fd()
    }

    /// `epoll_ctl` of `operation` in the epoll with host descriptor
    /// `epoll_fd` and identity `epoll`, for guest descriptor number `fd` of
    /// the pidfd, which `control` makes on the host descriptor it is given:
    /// the number's epoll key. An ADD makes the key if the number has none
    /// and closes it again if the ADD fails; it also keeps a host descriptor
    /// of the epoll, for the pidfd's end. An ADD that cannot make either
    /// fails as Linux fails an allocation, ENOMEM, before the host sees it. A
    /// MOD or DEL of a number without a key names the shadow itself, which no
    /// registration names, so the host answers it as Linux answers for a
    /// registration that does not exist: ENOENT, after its other checks. A
    /// DEL that succeeds removes the registration in the epoll it named,
    /// whichever descriptor of the epoll named it, and closes the key with
    /// its last registration. A successful ADD also tells the epoll, whose
    /// end ends the registration ([`Self::epoll_ended`]).
    pub(super) fn epoll_control(
        self: &Arc<Self>,
        fd: libc::c_int,
        operation: libc::c_int,
        epoll_fd: RawFd,
        epoll: &Arc<EpollIdentity>,
        control: impl FnOnce(RawFd) -> i64,
    ) -> i64 {
        let mut keys = self
            .epoll_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut made = None;
        let key = match keys.get(&fd) {
            Some(key) => key.file.as_raw_fd(),
            None if operation == libc::EPOLL_CTL_ADD => {
                // SAFETY: shadow owns a live descriptor; F_DUPFD_CLOEXEC
                // returns a new one above the standard descriptors.
                let key = unsafe {
                    libc::fcntl(
                        self.shadow.as_raw_fd(),
                        libc::F_DUPFD_CLOEXEC,
                        libc::STDERR_FILENO + 1,
                    )
                };
                if key < 0 {
                    return negative_errno(libc::ENOMEM);
                }
                // SAFETY: fcntl returned a new descriptor that nothing else
                // owns.
                made = Some(unsafe { std::fs::File::from_raw_fd(key) });
                key
            }
            None => self.shadow.as_raw_fd(),
        };
        // The host descriptor of the epoll that the registration keeps
        // (`KeyRegistration::epoll`).
        let mut epoll_copy = None;
        if operation == libc::EPOLL_CTL_ADD {
            match copy_epoll(epoll_fd) {
                Some(copy) => epoll_copy = Some(copy),
                None => return negative_errno(libc::ENOMEM),
            }
        }
        let result = control(key);
        match (operation, result) {
            (libc::EPOLL_CTL_ADD, 0) => {
                keys.entry(fd)
                    .or_insert_with(|| EpollKey {
                        file: made.take().expect("an ADD without a key made one"),
                        epolls: Vec::new(),
                    })
                    .epolls
                    .push(KeyRegistration {
                        identity: Arc::downgrade(epoll),
                        epoll: epoll_copy.take().expect("an ADD made its epoll copy"),
                    });
                epoll.register_pidfd(self, fd);
            }
            (libc::EPOLL_CTL_DEL, 0) => {
                if let std::collections::btree_map::Entry::Occupied(mut key) = keys.entry(fd) {
                    if let Some(held) = key.get().position(epoll) {
                        key.get_mut().epolls.swap_remove(held);
                    }
                    if key.get().epolls.is_empty() {
                        key.remove();
                    }
                }
                epoll.unregister_pidfd(self, fd);
            }
            _ => {}
        }
        result
    }

    /// Ends the registration of guest descriptor number `fd` of the pidfd
    /// in `epoll`, whose open file description has ended, and closes the
    /// number's key if it was the last. The host's registration goes too,
    /// with a DEL through the registration's host descriptor of the epoll:
    /// a host descriptor of the epoll that outlives its guest owners, as a
    /// fork of the supervisor or a retained descriptor table holds one, would
    /// otherwise keep watching the shadow, and report the exit to an epoll
    /// that watches it, after Linux has freed the registration
    /// (`eventpoll_release`).
    pub(super) fn epoll_ended(&self, fd: libc::c_int, epoll: &EpollIdentity) {
        let _ended;
        let mut keys = self
            .epoll_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let std::collections::btree_map::Entry::Occupied(mut key) = keys.entry(fd) {
            if let Some(held) = key.get().position(epoll) {
                let registration = key.get_mut().epolls.swap_remove(held);
                // SAFETY: both descriptors are live, and a DEL reads no
                // event.
                unsafe {
                    libc::epoll_ctl(
                        registration.epoll.as_raw_fd(),
                        libc::EPOLL_CTL_DEL,
                        key.get().file.as_raw_fd(),
                        std::ptr::null_mut(),
                    )
                };
            }
            if key.get().epolls.is_empty() {
                _ended = key.remove();
            }
        }
    }

    #[cfg(test)]
    pub(super) fn shadow(&self) -> std::sync::Weak<std::fs::File> {
        Arc::downgrade(&self.shadow)
    }

    /// How many epoll registrations name the pidfd, each with its host
    /// descriptor of the epoll.
    #[cfg(test)]
    pub(super) fn epoll_registrations(&self) -> usize {
        self.epoll_keys
            .lock()
            .unwrap()
            .values()
            .map(|key| key.epolls.len())
            .sum()
    }
}

/// The record of guest descriptor `fd`, if it is a pidfd for a guest process
/// that this call can use. It is found with the descriptor
/// (`LoadedStaticElf::guest_file`), so a call that finds the descriptor open
/// finds the record, and one that finds it closed finds none. The record
/// then lives until the call ends: the table holds it until a retirement of
/// the descriptor, and a retirement leaves it, with the descriptor's copy,
/// to a call that found the descriptor first (`CopyLedger::retire_copy`).
/// So a host descriptor of the record stays the record's for the whole call.
pub(super) fn guest_pidfd(state: &LoadedStaticElf, fd: libc::c_int) -> Option<Arc<GuestPidfd>> {
    let pidfd = state.guest_pidfds.get(&fd)?;
    state.guest_file(fd)?;
    pidfd.upgrade()
}

/// The inode number that `stat` reports for a pidfd for `target`, a guest
/// process. Linux gives every process one pidfs inode, which all its pidfds
/// share, whoever opened them, and numbers them from 2 upward as pids are
/// made (`pidfs_add_pid`, fs/pidfs.c), so pidfds compare equal by inode number
/// exactly when they name the same process. The stand-in's own inode is the
/// supervisor's; this number is one per guest process instead, with the top
/// bit set, which no pidfs inode number reaches.
pub(super) fn pidfd_inode(target: reverie::SignalProcessId) -> u64 {
    1 << 63 | target.generation
}

/// The host descriptor whose readiness is guest descriptor `fd`'s: the shadow
/// of a pidfd for a guest process, whose own host descriptor never becomes
/// readable while the run lasts, and otherwise the descriptor itself.
/// `None` when `fd` is not open. A caller asks a shadow only for
/// [`PIDFD_POLL_EVENTS`]; the shadow stays the pidfd's for the rest of the
/// call ([`guest_pidfd`]).
pub(super) fn readiness_host_fd(state: &LoadedStaticElf, fd: libc::c_int) -> Option<RawFd> {
    let pidfd = guest_pidfd(state, fd);
    let host_fd = host_fd(state, fd)?;
    Some(pidfd.map_or(host_fd, |pidfd| pidfd.readiness_fd()))
}

/// The events that poll and select ask a pidfd's shadow for: all that
/// Linux's `pidfd_poll` reports besides `POLLHUP`, which poll reports
/// unasked (fs/pidfs.c). The shadow is a socket, which also reports that it
/// is writable and, once hung up, `POLLRDHUP`; a pidfd reports neither.
pub(super) const PIDFD_POLL_EVENTS: libc::c_short = libc::POLLIN | libc::POLLRDNORM;

/// The events of an epoll registration of a pidfd's shadow, for a guest's
/// registration of the pidfd with `events`: the same, without the readiness
/// a pidfd never reports and its shadow socket does (see
/// [`PIDFD_POLL_EVENTS`]). With `EPOLLEXCLUSIVE`, Linux refuses
/// (EINVAL) any of those but `EPOLLOUT`, so only `EPOLLOUT` is taken then,
/// and the host refuses the rest as Linux does.
pub(super) fn pidfd_epoll_events(events: u32) -> u32 {
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
    // AUTONOMOUS-BOT-IMPLEMENTED
    guest_pidfd_open(state, pid, flags)
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

/// `pidfd_open(pid, flags)` for a guest process, the caller's own included:
/// a pidfd for the supervisor stands in for it in the guest's table, and a
/// shadow socket shows its readiness ([`GuestPidfd`]). Every pidfd for one
/// process, whoever opened it, so reports one inode ([`pidfd_inode`]). Like
/// Linux, it opens one for a process that has exited and has not been
/// reaped, which is then readable at once.
// TODO-HUMAN-REVIEW(https://github.com/rrnewton/reverie/pull/1410): Review pidfds for guest
// processes, their stand-ins and their shadow sockets.
fn guest_pidfd_open(state: &mut LoadedStaticElf, pid: libc::pid_t, flags: libc::c_uint) -> i64 {
    let target = match pidfd_target(state, pid) {
        Ok(target) => target,
        Err(errno) => return negative_errno(errno),
    };
    let Some(registry) = state.children.registry() else {
        // A task outside any process family has no other process to name,
        // and no record of its own process's life. The supervisor outlives
        // it, so the stand-in alone, never readable, is a pidfd for it, whose
        // metadata is the kernel's, as for a pidfd from outside the run.
        if pid != state.pid {
            return negative_errno(libc::ESRCH);
        }
        return match supervisor_pidfd(flags) {
            Ok(file) => insert_file_with_flags(state, file, true, None),
            Err(error) => error,
        };
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
        let pidfd = Arc::new(GuestPidfd {
            target,
            shadow,
            epoll_keys: Default::default(),
        });
        state
            .guest_pidfds
            .insert(fd as libc::c_int, Arc::downgrade(&pidfd));
        // The table holds the record once this call has published it.
        state.pidfd_holds.push(pidfd);
    }
    fd
}

/// The process `pid` names for a pidfd, as Linux's `pidfd_open` finds it
/// (kernel/pid.c): a live process whose thread group id `pid` is, even once
/// its leader has exited, or a process that has exited and has not been
/// reaped. ENOENT for a live thread that leads no thread group
/// (`pidfd_prepare`, [kernel/fork.c:1844] in v6.17), ESRCH for a pid that
/// names no process.
///
/// [kernel/fork.c:1844]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/fork.c?h=v6.17#n1844
fn pidfd_target(
    state: &LoadedStaticElf,
    pid: libc::pid_t,
) -> Result<reverie::SignalProcessId, libc::c_int> {
    let live = {
        let lifecycle = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match lifecycle.get(pid) {
            Some(task) if task.tgid != pid => return Err(libc::ENOENT),
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
