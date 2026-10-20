/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Pipe-owner configuration without asynchronous signal delivery.
//!
//! A host PID must never stand in for a guest PID. Each pipe end has a shared
//! record, and only its creator process incarnation may configure/query it.
//! Fork retains the record (including permanent restrictions), but gives the
//! child a different process token. Threads and exec retain their token.
//!
//! Lock order is file table, then this description's leaf mutex. Never call
//! guest-memory APIs or callbacks while holding the leaf mutex. It serializes
//! owner admission, host F_SETFL, and pre-send escape marking across *all*
//! aliases, including aliases in different forked descriptor tables.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Managed,
    Escaped,
}

#[derive(Debug)]
struct Configuration {
    phase: Phase,
    // Linux initially reports F_OWNER_TID/0, including after F_SETSIG alone.
    // F_SETOWN(0), unlike that initial state, reports F_OWNER_PID/0.
    owner_type: i32,
    owner_pid: i32,
}

#[derive(Debug)]
pub(crate) struct PipeOwner {
    creator: Arc<()>,
    configuration: Mutex<Configuration>,
}

impl PipeOwner {
    #[cfg(test)]
    pub(super) fn configuration_available_for_test(&self) -> bool {
        self.configuration.try_lock().is_ok()
    }

    pub(super) fn new(creator: Arc<()>) -> Self {
        Self {
            creator,
            configuration: Mutex::new(Configuration {
                phase: Phase::Fresh,
                owner_type: 0, // F_OWNER_TID
                owner_pid: 0,
            }),
        }
    }

    pub(super) fn before_export(&self) -> Result<(), i64> {
        let mut configuration = self
            .configuration
            .lock()
            .map_err(|_| negative_errno(libc::ENOSYS))?;
        if configuration.phase == Phase::Managed {
            return Err(negative_errno(libc::ENOSYS));
        }
        // This is irreversible, even if a later element or host send fails.
        // The record is shared by every known alias; imported aliases never
        // acquire a new positive witness by inode or host-fd resemblance.
        configuration.phase = Phase::Escaped;
        Ok(())
    }

    pub(super) fn set_flags(&self, host_fd: RawFd, flags: i32) -> i64 {
        let Ok(configuration) = self.configuration.lock() else {
            return negative_errno(libc::ENOSYS);
        };
        if configuration.phase == Phase::Managed && flags & libc::O_ASYNC != 0 {
            return negative_errno(libc::ENOSYS);
        }
        // Keep the lock through the native mutation: otherwise a forked
        // sibling could enable fasync between owner admission and publication.
        // SAFETY: caller owns this host fd and the third argument is an int.
        zero_or_errno(unsafe { libc::fcntl(host_fd, libc::F_SETFL, flags) })
    }
}

fn owner_pointer_valid(address: u64) -> bool {
    address
        .checked_add(8)
        .is_some_and(|end| end <= X86_64_GUEST_USER_LIMIT)
}

/// Implements only known private-pipe configuration. Socket SIGURG, foreign
/// owner liveness, asynchronous delivery and descriptor export stay unsupported.
/// Linux source: fs/fcntl.c f_setown/f_{get,set}own_ex/f_owner_sig at
/// https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/fcntl.c
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-910): Review creator-incarnation and permanent shared pipe guards.
pub(super) fn fcntl(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_fd: i32,
    host_fd: RawFd,
    command: i32,
    argument: u64,
) -> i64 {
    // Descriptor existence is checked by the caller. Linux rejects O_PATH
    // before copying any owner structure, including on unsupported descriptors.
    let flags = match fd_status_flags(host_fd) {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    if flags & libc::O_PATH != 0 {
        return negative_errno(libc::EBADF);
    }
    let requested_owner = match command {
        libc::F_SETOWN => {
            let pid = argument as i32;
            if pid == i32::MIN {
                return negative_errno(libc::EINVAL);
            }
            Some((1, pid))
        }
        LINUX_F_SETOWN_EX => {
            let mut bytes = [0; 8];
            if !owner_pointer_valid(argument) || memory.user().read(argument, &mut bytes).is_err() {
                return negative_errno(libc::EFAULT);
            }
            let kind = i32::from_ne_bytes(bytes[..4].try_into().expect("owner type"));
            let pid = i32::from_ne_bytes(bytes[4..].try_into().expect("owner pid"));
            if !(0..=2).contains(&kind) {
                return negative_errno(libc::EINVAL);
            }
            if pid < 0 {
                // EX never uses a negative PID as process-group shorthand.
                // Linux find_vpid cannot resolve a negative namespace number.
                return negative_errno(libc::ESRCH);
            }
            Some((kind, pid))
        }
        _ => None,
    };
    let Some(owner) = state.pipe_owners.get(&guest_fd) else {
        return negative_errno(libc::ENOSYS);
    };
    if !Arc::ptr_eq(&owner.creator, &state.pipe_owner_process)
        || state.poll_table_id.unsafe_history.load(Ordering::SeqCst)
    {
        return negative_errno(libc::ENOSYS);
    }
    let Ok(mut configuration) = owner.configuration.lock() else {
        return negative_errno(libc::ENOSYS);
    };
    if configuration.phase == Phase::Escaped {
        return negative_errno(libc::ENOSYS);
    }
    // Re-read flags under the shared lock; another process's F_SETFL can
    // race the earlier O_PATH check, but cannot race this admission decision.
    match fd_status_flags(host_fd) {
        Ok(flags) if flags & libc::O_ASYNC == 0 => {}
        Ok(_) => return negative_errno(libc::ENOSYS),
        Err(error) => return error,
    }
    if let Some((kind, pid)) = requested_owner {
        if kind != 1 || (pid != 0 && pid != state.pid) {
            // No host namespace lookup, invented ESRCH, or process-group
            // success. Cross-incarnation queries also refuse above; a cached
            // PID must not pretend to model zombies, reaping or PID reuse.
            return negative_errno(libc::ENOSYS);
        }
        configuration.phase = Phase::Managed;
        configuration.owner_type = kind;
        configuration.owner_pid = pid;
        return 0;
    }
    match command {
        libc::F_GETOWN => i64::from(configuration.owner_pid),
        LINUX_F_GETOWN_EX => {
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&configuration.owner_type.to_ne_bytes());
            bytes[4..].copy_from_slice(&configuration.owner_pid.to_ne_bytes());
            drop(configuration);
            if !owner_pointer_valid(argument)
                || memory.user().copy_to_user(argument, &bytes).is_err()
            {
                negative_errno(libc::EFAULT)
            } else {
                0
            }
        }
        LINUX_F_SETSIG | LINUX_F_GETSIG => {
            // Linux v6.1 validates the whole unsigned-long SETSIG argument;
            // v6.18 first narrows to int. Retain the exact host ABI, with no
            // classifier/accept-set. This changes only the owned pipe's signal
            // number: host owner remains NULL and no fasync registration is
            // permitted after successful configuration. GETSIG ignores arg.
            // https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/fs/fcntl.c#L391
            // SAFETY: fd is held by the caller; both commands take no pointer.
            let result = unsafe { libc::syscall(libc::SYS_fcntl, host_fd, command, argument) };
            if result < 0 {
                io_error(std::io::Error::last_os_error())
            } else {
                if command == LINUX_F_SETSIG && result == 0 {
                    configuration.phase = Phase::Managed;
                }
                result
            }
        }
        _ => unreachable!("only pipe-owner commands reach this helper"),
    }
}
