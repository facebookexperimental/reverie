/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Credentials, capabilities, prctl and personality (gVisor: pkg/sentry/kernel/auth, syscalls/linux/sys_identity.go, sys_capability.go, sys_prctl.go).

use super::*;

/// The guest has its launcher's supplementary groups, as a process the
/// launcher spawned would, so the host kernel answers: EINVAL for a negative
/// size or one smaller than the group count, the count for size 0.
pub(super) fn getgroups<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    const NGROUPS_MAX: usize = 65_536;
    let size = args[0] as libc::c_int;
    if size < 0 {
        return negative_errno(libc::EINVAL);
    }
    let mut groups: Vec<libc::gid_t> = vec![0; (size as usize).min(NGROUPS_MAX)];
    // SAFETY: groups is writable for its length, which bounds the count.
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    if count < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    if size == 0 {
        return i64::from(count);
    }
    let bytes: Vec<u8> = groups[..count as usize]
        .iter()
        .flat_map(|group| group.to_ne_bytes())
        .collect();
    match memory.write_exact(args[1], &bytes) {
        Ok(()) => i64::from(count),
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
/// `flock(2)`: refused for every valid lock operation, before any host effect,
/// with ENOSYS and the typed refusal `UnsupportedOperation::Flock`.
///
/// This replaces a silent no-op that returned 0 without taking a lock, so two
/// guest processes could both "hold" LOCK_EX (https://github.com/rrnewton/reverie/issues/1069).
/// Forwarding to the host kernel is faithful only where the host open file
/// description has the guest description's exact identity and lifetime, and
/// in this backend it often does not:
///
/// - each thread of a guest process keeps private host copies of the shared
///   descriptor table, refreshed only at that thread's later table install,
///   so a guest's last close does not release the host lock until the
///   siblings catch up, at host-timed points when a sibling's syscall runs in
///   the background;
/// - a file mapping copies bytes and keeps no reference to the description,
///   so a lock Linux keeps through the mapping would be released early;
/// - descriptors passed through SCM_RIGHTS are held in flight by the host
///   kernel, invisible to the guest descriptor tables;
/// - captured stdio and synthetic carriers (procfs snapshots)
///   are not the guest's descriptions at all;
/// - on network and FUSE filesystems even LOCK_NB can wait on a server.
///
/// Forwarding may return later only behind a trait-level single-task semantic
/// and a regression test that a sibling thread's copy cannot delay release.
///
/// Validation that never touches a description still comes from the kernel:
/// a malformed operation (EINVAL), the ignored LOCK_MAND bit (0), and EBADF for
/// a descriptor the guest does not have. Those are answered by the host
/// `flock(-1, operation)`, which fails its descriptor lookup before any lock
/// code runs, so it has no lock effect on any description.
pub(super) fn flock(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // The kernel's flock takes `unsigned int fd, unsigned int cmd`.
    let operation = args[1] as u32;
    if host_fd(state, args[0] as libc::c_int).is_some() && flock_takes_effect(operation) {
        return negative_errno(libc::ENOSYS);
    }
    // SAFETY: flock takes no pointers, and fd -1 names no description.
    zero_or_errno(unsafe { libc::flock(-1, operation as libc::c_int) })
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn fchown(state: &LoadedStaticElf, raw_fd: u64) -> i64 {
    if host_fd(state, raw_fd as libc::c_int).is_some() {
        0
    } else {
        negative_errno(libc::EBADF)
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn fchownat(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_dirfd: libc::c_int,
    path_address: u64,
    flags: libc::c_int,
) -> i64 {
    let allowed = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
    if flags & !allowed != 0 {
        return negative_errno(libc::EINVAL);
    }
    let path = match read_c_string(&ProviderMemory(memory), path_address, 4096) {
        Ok(path) => path,
        Err(error) => return read_c_string_errno(error),
    };
    if path.is_empty() {
        if flags & libc::AT_EMPTY_PATH == 0 {
            return negative_errno(libc::ENOENT);
        }
        return fchown(state, guest_dirfd as u64);
    }
    match open_metadata_path(
        state,
        guest_dirfd,
        &path,
        flags & libc::AT_SYMLINK_NOFOLLOW != 0,
    ) {
        Ok(_) => 0,
        Err(error) => error,
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review the deterministic no-xattr KVM filesystem view.
// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn path_xattr_list(
    state: &LoadedStaticElf,
    memory: &mut GuestMemory,
    args: &[u64; 6],
    no_follow: bool,
) -> i64 {
    let path = match read_c_string(&ProviderMemory(memory), args[0], 4096) {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => return negative_errno(libc::ENOENT),
        Err(error) => return read_c_string_errno(error),
    };
    if synthetic_proc_content(state, &path).is_some() {
        return 0;
    }
    match open_metadata_path(state, libc::AT_FDCWD, &path, no_follow) {
        Ok(file) => xattr_list(memory, &XattrTarget::Path(file), args[1], args[2]),
        Err(error) => error,
    }
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn fd_xattr_list(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    match host_fd(state, args[0] as libc::c_int) {
        Some(fd) => xattr_list(memory, &XattrTarget::Fd(fd), args[1], args[2]),
        None => negative_errno(libc::EBADF),
    }
}

// TODO-HUMAN-REVIEW(PR-108): Review the prctl(2) subset for the KVM guest.
//
// Capability-control prctls use virtual guest state so privilege-dropping
// launchers can inspect and mutate their persona without touching supervisor
// credentials.
// TODO-HUMAN-REVIEW(PR-181): Review deterministic capability prctls.
pub(super) fn prctl<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    match args[0] {
        // TODO-HUMAN-REVIEW(PR-537): Review deterministic task-name state and lifecycle.
        option if option == libc::PR_SET_NAME as u64 => set_prctl_name(memory, state, args[1]),
        option if option == libc::PR_GET_NAME as u64 => memory
            .copy_to_user(args[1], &state.thread_name)
            .map_or_else(|_| negative_errno(libc::EFAULT), |_| 0),
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-925): https://github.com/rrnewton/reverie/issues/916.
        // prctl option is an int; its signal operand remains unsigned long.
        option if option as i32 == libc::PR_SET_PDEATHSIG => {
            // Width validation is Linux's first check, even for a stale caller.
            if args[1] > 64 {
                return negative_errno(libc::EINVAL);
            }
            let Ok(caller) = state.children.task_identity() else {
                return negative_errno(libc::ESRCH);
            };
            state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .set_parent_death_signal(caller, args[1])
                .map_or_else(|errno| negative_errno(errno.into_raw()), |_| 0)
        }
        option if option as i32 == libc::PR_GET_PDEATHSIG => {
            let Ok(caller) = state.children.task_identity() else {
                return negative_errno(libc::ESRCH);
            };
            let signal = state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .parent_death_signal(caller);
            match signal {
                Ok(signal) => memory
                    .put_user_i32(args[1], signal)
                    .map_or_else(|_| negative_errno(libc::EFAULT), |_| 0),
                Err(errno) => negative_errno(errno.into_raw()),
            }
        }
        // TODO-HUMAN-REVIEW(PR-537): Review deterministic transparent-hugepage state and lifecycle.
        option if option == libc::PR_SET_THP_DISABLE as u64 => {
            if args[3..5].iter().any(|argument| *argument != 0)
                || args[2] & !2 != 0
                || (args[1] == 0 && args[2] != 0)
            {
                negative_errno(libc::EINVAL)
            } else {
                let mode = if args[1] == 0 { 0 } else { 1 | args[2] as u8 };
                state.thp_disabled.store(mode, Ordering::SeqCst);
                0
            }
        }
        option if option == libc::PR_GET_THP_DISABLE as u64 => {
            if args[1..5].iter().any(|argument| *argument != 0) {
                negative_errno(libc::EINVAL)
            } else {
                i64::from(state.thp_disabled.load(Ordering::SeqCst))
            }
        }
        PR_CAPBSET_READ => {
            if args[1] <= crate::credentials::last_capability() {
                i64::from(state.capability_bounding & (1_u64 << args[1]) != 0)
            } else {
                negative_errno(libc::EINVAL)
            }
        }
        PR_CAPBSET_DROP => {
            if args[1] <= crate::credentials::last_capability() {
                state.capability_bounding &= !(1_u64 << args[1]);
                0
            } else {
                negative_errno(libc::EINVAL)
            }
        }
        option if option == libc::PR_SET_KEEPCAPS as u64 => match args[1] {
            0 => {
                state.keep_capabilities = false;
                0
            }
            1 => {
                state.keep_capabilities = true;
                0
            }
            _ => negative_errno(libc::EINVAL),
        },
        option if option == libc::PR_GET_KEEPCAPS as u64 => i64::from(state.keep_capabilities),
        // AUTONOMOUS-BOT-IMPLEMENTED
        option if option == libc::PR_SET_DUMPABLE as u64 => match args[1] {
            value @ (0 | 1) => {
                let dumpable = value == 1;
                // TODO-HUMAN-REVIEW(PR-235): Review virtual dumpability mutation.
                state.dumpable = dumpable;
                let updated = state
                    .task_lifecycle
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .set_dumpable(state.pid, dumpable);
                debug_assert!(updated, "current KVM process has no live task entry");
                0
            }
            _ => negative_errno(libc::EINVAL),
        },
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-235): Review virtual dumpability queries.
        option if option == libc::PR_GET_DUMPABLE as u64 => state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(state.tid)
            .map_or_else(
                || i64::from(state.dumpable),
                |task| i64::from(task.dumpable),
            ),
        option if option == libc::PR_CAP_AMBIENT as u64 => {
            prctl_cap_ambient(state, args[1], args[2])
        }
        // Other prctl operations are not modeled yet.
        _ => negative_errno(libc::ENOSYS),
    }
}

fn set_prctl_name<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    state: &mut LoadedStaticElf,
    address: u64,
) -> i64 {
    let mut name = [0; TASK_COMM_LEN];
    for (offset, slot) in name[..TASK_COMM_LEN - 1].iter_mut().enumerate() {
        let Some(address) = address.checked_add(offset as u64) else {
            return negative_errno(libc::EFAULT);
        };
        let mut byte = [0];
        if memory.read_exact(address, &mut byte).is_err() {
            return negative_errno(libc::EFAULT);
        }
        if byte[0] == 0 {
            break;
        }
        *slot = byte[0];
    }
    state.thread_name = name;
    if state.tid == state.pid {
        *state
            .thread_group_leader_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
    }
    0
}

pub(super) fn prctl_cap_ambient(
    state: &mut LoadedStaticElf,
    operation: u64,
    capability: u64,
) -> i64 {
    if operation == libc::PR_CAP_AMBIENT_CLEAR_ALL as u64 {
        state.capability_ambient = 0;
        return 0;
    }
    if capability > crate::credentials::last_capability() {
        return negative_errno(libc::EINVAL);
    }
    let bit = 1_u64 << capability;
    match operation {
        option if option == libc::PR_CAP_AMBIENT_IS_SET as u64 => {
            i64::from(state.capability_ambient & bit != 0)
        }
        option if option == libc::PR_CAP_AMBIENT_RAISE as u64 => {
            if state.capability_permitted & bit == 0 || state.capability_inheritable & bit == 0 {
                negative_errno(libc::EPERM)
            } else {
                state.capability_ambient |= bit;
                0
            }
        }
        option if option == libc::PR_CAP_AMBIENT_LOWER as u64 => {
            state.capability_ambient &= !bit;
            0
        }
        _ => negative_errno(libc::EINVAL),
    }
}

// TODO-HUMAN-REVIEW(PR-181): Review the virtual capability ABI and masks.
pub(super) fn capget<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    if args[0] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok((version, pid)) = read_capability_header(memory, args[0]) else {
        return negative_errno(libc::EFAULT);
    };
    if version != LINUX_CAPABILITY_VERSION_3 {
        if memory
            .write_exact(args[0], &LINUX_CAPABILITY_VERSION_3.to_ne_bytes())
            .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
        return if version == 0 && args[1] == 0 {
            0
        } else {
            negative_errno(libc::EINVAL)
        };
    }
    if !is_capability_self(pid, state) {
        return negative_errno(libc::ESRCH);
    }
    if args[1] == 0 {
        return 0;
    }
    let bytes = capability_data_bytes(
        state.capability_effective,
        state.capability_permitted,
        state.capability_inheritable,
    );
    match memory.write_exact(args[1], &bytes) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-181): Review deterministic capability mutation.
pub(super) fn capset<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    if args[0] == 0 || args[1] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok((version, pid)) = read_capability_header(memory, args[0]) else {
        return negative_errno(libc::EFAULT);
    };
    if version != LINUX_CAPABILITY_VERSION_3 {
        return negative_errno(libc::EINVAL);
    }
    if !is_capability_self(pid, state) {
        return negative_errno(libc::ESRCH);
    }
    let Ok((effective, permitted, inheritable)) = read_capability_data(memory, args[1]) else {
        return negative_errno(libc::EFAULT);
    };
    if effective & !permitted != 0
        || permitted & !state.capability_permitted != 0
        || inheritable & !state.capability_bounding != 0
    {
        return negative_errno(libc::EPERM);
    }
    let mask = crate::credentials::capability_mask();
    state.capability_effective = effective & mask;
    state.capability_permitted = permitted & mask;
    state.capability_inheritable = inheritable & mask;
    state.capability_ambient &= state.capability_permitted & state.capability_inheritable;
    0
}

fn read_capability_header<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    address: u64,
) -> Result<(u32, i32), ()> {
    let mut bytes = [0; 8];
    memory.read_exact(address, &mut bytes).map_err(|_| ())?;
    Ok((
        u32::from_ne_bytes(bytes[..4].try_into().expect("capability version size")),
        i32::from_ne_bytes(bytes[4..].try_into().expect("capability pid size")),
    ))
}

fn is_capability_self(pid: i32, state: &LoadedStaticElf) -> bool {
    pid == 0 || pid == state.pid || pid == state.tid
}

pub(super) fn capability_data_bytes(effective: u64, permitted: u64, inheritable: u64) -> [u8; 24] {
    let mut bytes = [0; 24];
    for (index, value) in [
        effective as u32,
        permitted as u32,
        inheritable as u32,
        (effective >> 32) as u32,
        (permitted >> 32) as u32,
        (inheritable >> 32) as u32,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}

fn read_capability_data<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    address: u64,
) -> Result<(u64, u64, u64), ()> {
    let mut bytes = [0; 24];
    memory.read_exact(address, &mut bytes).map_err(|_| ())?;
    let field = |index: usize| {
        u64::from(u32::from_ne_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("capability data field size"),
        ))
    };
    Ok((
        field(0) | field(3) << 32,
        field(1) | field(4) << 32,
        field(2) | field(5) << 32,
    ))
}

pub(super) const PERSONALITY_UNAME26: u32 = 0x0002_0000;

// TODO-HUMAN-REVIEW(PR-1013): Review the per-task fixed-layout personality profile.
pub(super) fn personality(state: &mut LoadedStaticElf, raw: u64) -> i64 {
    // Linux's syscall argument is unsigned int, including its query sentinel.
    let requested = raw as u32;
    let previous = state.linux_personality;
    if requested == u32::MAX {
        return i64::from(previous);
    }
    // Other execution domains or address-layout changes are not implemented.
    // Refuse before publishing state rather than reporting a flag with no effect.
    // UNAME26 is kept and reported: its one effect in Linux is the release
    // `uname` reports, which the Tool decides (Detcore replaces the release on
    // every backend, ptrace's included). A run without a Tool sees the host's
    // release unchanged, unlike Linux, which reports `2.6.<60 + minor>`.
    if requested & !PERSONALITY_UNAME26 != crate::elf::LINUX_FIXED_PERSONALITY {
        return negative_errno(libc::ENOSYS);
    }
    state.linux_personality = requested;
    i64::from(previous)
}

/// `uname(2)` from the host, whatever the guest's personality. Detcore
/// answers the kernel fields itself (`sysname`, `release` and `version`, so
/// a guest's UNAME26 personality never shows) and passes the rest
/// (`machine`, and `nodename` and `domainname` in a UTS namespace) through.
/// Without a Tool, a UNAME26 guest sees the host's release, where Linux
/// reports its `2.6.<60 + minor>` form.
///
/// In a Hermit run, every completed call's result is Detcore's. One failed
/// call is not: a `utsname` buffer spanning two writable MAP_SHARED pages
/// whose backing file was truncated so that the second page faults receives
/// the fields that fit in the first page (with the buffer 195 bytes before
/// the page end, `sysname`, `nodename` and `release`) before the fault. The
/// run then stops before Detcore sees the result, and those host values, the
/// host's release included, stay in the file. Before, a UNAME26 guest's
/// release there was this executor's compatibility form. A buffer that is
/// not accessible fails before anything is written.
pub(super) fn uname<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    address: u64,
) -> i64 {
    // SAFETY: zero is a valid utsname, and the pointer names a live one.
    let mut host = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut host) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    write_struct(memory, address, &host)
}
