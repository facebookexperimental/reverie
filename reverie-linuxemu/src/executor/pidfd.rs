/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! pidfds (gVisor: pkg/sentry/kernel/pidfd.go).

use super::*;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-235): Review self-only virtual pidfd translation.
pub(super) fn pidfd_open(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let flags = args[1] as libc::c_uint;
    if flags & !(libc::O_NONBLOCK as libc::c_uint) != 0 {
        return negative_errno(libc::EINVAL);
    }
    if args[0] as libc::pid_t != state.pid {
        return negative_errno(libc::ESRCH);
    }

    // The supervisor remains alive for every guest executor, so its pidfd has
    // the same readiness contract as a pidfd for the live virtual process.
    // Cross-process pidfds remain unsupported until KVM can bind them to child
    // lifecycle state.
    let host_fd = unsafe {
        libc::syscall(libc::SYS_pidfd_open, libc::getpid(), flags as libc::c_uint) as libc::c_int
    };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    // A run that reports host metadata timestamps recognizes this pidfd later
    // by the recorded signature, see `is_self_pidfd`; without it, the pidfd
    // would report host times, so the call fails instead. A run with the
    // setting off never needs the signature.
    if let Err(error) = record_self_pidfd_signature(file.as_raw_fd())
        && state.host_metadata_timestamps
    {
        return error;
    }
    insert_file_with_flags(state, file, true, None)
}

/// pidfs's filesystem magic, from include/uapi/linux/magic.h.
pub(super) const PID_FS_MAGIC: libc::c_long = 0x5049_4446;

/// What identifies the process a pidfd names. With pidfs, every pidfd for a
/// process shares that process's inode, whose number is never reused. Without
/// pidfs, every pidfd shares the single anonymous inode, so the `Pid:` line of
/// the descriptor's fdinfo identifies the process instead, in the pid
/// namespace of the procfs that is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PidfdSignature {
    Pidfs(libc::dev_t, libc::ino_t),
    Fdinfo(libc::pid_t),
}

/// The signature of the supervisor process's own pidfd, with the process ID
/// it was recorded in, so that a forked process never uses its parent's.
/// `pidfd_open` records it when it first hands the guest a pidfd in this
/// process. Every guest process of every run in this process shares it.
pub(super) static SELF_PIDFD_SIGNATURE: Mutex<Option<(libc::pid_t, PidfdSignature)>> =
    Mutex::new(None);

/// Records the signature of `pidfd`, a pidfd for the supervisor process that
/// `pidfd_open` just made, unless this process has already recorded it. The
/// signature of a process never changes. Without pidfs this reads procfs,
/// which can fail when no descriptor is left.
fn record_self_pidfd_signature(pidfd: RawFd) -> Result<(), i64> {
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let mut recorded = SELF_PIDFD_SIGNATURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if recorded.is_some_and(|(owner, _)| owner == pid) {
        return Ok(());
    }
    *recorded = Some((pid, pidfd_signature(pidfd)?));
    Ok(())
}

/// The supervisor process's recorded pidfd signature, if `pidfd_open` has
/// made a pidfd in this process.
pub(super) fn recorded_self_pidfd_signature() -> Option<PidfdSignature> {
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    SELF_PIDFD_SIGNATURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .and_then(|(owner, signature)| (owner == pid).then_some(signature))
}

/// The signature of the process that `pidfd` names.
pub(super) fn pidfd_signature(pidfd: RawFd) -> Result<PidfdSignature, i64> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem is writable and pidfd is a live descriptor.
    if unsafe { libc::fstatfs(pidfd, filesystem.as_mut_ptr()) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: fstatfs initialized filesystem on success.
    if unsafe { filesystem.assume_init() }.f_type == PID_FS_MAGIC {
        return host_file_key(pidfd).map(|(dev, ino)| PidfdSignature::Pidfs(dev, ino));
    }
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}")).map_err(io_error)?;
    parse_pidfd_fdinfo_pid(&text)
        .map(PidfdSignature::Fdinfo)
        .ok_or(negative_errno(libc::EIO))
}

/// Whether `guest_fd` is a pidfd for the supervisor process. `pidfd_open`
/// hands out only that pidfd, for the guest's own process, and every guest
/// process of a run lives in the one supervisor process, so the class survives
/// dup, fork, exec and an SCM_RIGHTS transfer between guest processes. A pidfd
/// for any other process, such as one received over a socket from outside the
/// run, is a real host object and keeps its host timestamps. Linux names a
/// pidfd `anon_inode:[pidfd]` with and without pidfs.
///
/// Recognition allocates no descriptor with pidfs, so it holds when the
/// supervisor has none left, as after a guest's shared mappings pin every
/// descriptor number. Without pidfs it reads the pidfd's fdinfo, and a pidfd
/// whose fdinfo cannot be read then counts as the supervisor's: a fixed time
/// on a host pidfd is deterministic, a host time on the backend's is not.
pub(super) fn is_self_pidfd(state: &LoadedStaticElf, guest_fd: libc::c_int) -> bool {
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return false;
    };
    if !fd_link_target_is(host_fd, b"anon_inode:[pidfd]") {
        return false;
    }
    // Before pidfd_open has made the supervisor's pidfd in this process,
    // every pidfd came from outside the run.
    recorded_self_pidfd_signature()
        .is_some_and(|signature| pidfd_matches_signature(host_fd, signature))
}

/// Whether `pidfd` names the process with `signature`, a pidfd signature of
/// the supervisor process. A value that cannot be read counts as a match, see
/// [`is_self_pidfd`].
pub(super) fn pidfd_matches_signature(pidfd: RawFd, signature: PidfdSignature) -> bool {
    match signature {
        PidfdSignature::Pidfs(dev, ino) => {
            host_file_key(pidfd).map_or(true, |key| key == (dev, ino))
        }
        PidfdSignature::Fdinfo(pid) => pidfd_fdinfo_pid(pidfd).is_none_or(|named| named == pid),
    }
}

/// The `Pid:` field of a pidfd's fdinfo: the process it names, in the pid
/// namespace of the procfs that is read, or 0 or -1 when there is none there.
pub(super) fn pidfd_fdinfo_pid(fd: RawFd) -> Option<libc::pid_t> {
    parse_pidfd_fdinfo_pid(&std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?)
}

/// The `Pid:` field of a pidfd's fdinfo text.
fn parse_pidfd_fdinfo_pid(text: &str) -> Option<libc::pid_t> {
    text.lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|pid| pid.trim().parse().ok())
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
