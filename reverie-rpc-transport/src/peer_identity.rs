/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Identifying the process that opened a guest connection
//! ([`crate::RpcServer::require_connection_identity`]).

use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use reverie::ConnectionIdentity;

use crate::error::RpcError;

/// `PIDFD_INFO_PID` (Linux 6.13): the pid fields of a [`PidfdInfo`] are set.
/// The kernel always sets it for a process that has not been reaped.
const PIDFD_INFO_PID: u64 = 1 << 0;

/// The first published layout of `struct pidfd_info` (`PIDFD_INFO_SIZE_VER0`,
/// 64 bytes). The kernel accepts any size from this one up and fills what fits.
#[repr(C)]
#[derive(Default)]
struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    exit_code: i32,
}

const _: () = assert!(std::mem::size_of::<PidfdInfo>() == 64);

/// `PIDFD_GET_INFO` for the 64-byte layout: `_IOWR(0xFF, 11, 64 bytes)`.
const PIDFD_GET_INFO: libc::c_ulong = (3 << 30) | (64 << 16) | (0xFF << 8) | 11;

/// What `PIDFD_GET_INFO` says about the process `pidfd` names.
enum PeerState {
    /// Not reaped; its thread-group id in the caller's PID namespace.
    Live(i32),
    /// Reaped, or the kernel did not report its pid.
    Gone,
}

fn pidfd_get_info(pidfd: &impl AsRawFd) -> std::io::Result<PeerState> {
    let mut info = PidfdInfo::default();
    // SAFETY: `info` is a properly aligned, writable 64-byte struct, which is
    // what this ioctl number tells the kernel to fill.
    let rc = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_INFO, &mut info) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(PeerState::Gone),
            _ => Err(error),
        };
    }
    if info.mask & PIDFD_INFO_PID == 0 || info.tgid == 0 {
        return Ok(PeerState::Gone);
    }
    i32::try_from(info.tgid)
        .map(PeerState::Live)
        .map_err(|_| std::io::Error::other(format!("pidfd reported tgid {}", info.tgid)))
}

/// Fails, naming the kernel requirement, unless this kernel answers
/// `PIDFD_GET_INFO`, which per-connection identity needs.
pub(crate) fn check_kernel_support() -> Result<(), RpcError> {
    // SAFETY: pidfd_open on the calling process with no flags.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if raw < 0 {
        return Err(unsupported(&std::io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a descriptor pidfd_open has just returned to us.
    let own = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw as i32) };
    match pidfd_get_info(&own) {
        Ok(PeerState::Live(_)) => Ok(()),
        Ok(PeerState::Gone) => Err(unsupported(&std::io::Error::other(
            "PIDFD_GET_INFO reported no pid for the coordinator itself",
        ))),
        Err(error) => Err(unsupported(&error)),
    }
}

fn unsupported(error: &std::io::Error) -> RpcError {
    RpcError::Io(std::io::Error::other(format!(
        "per-connection identity needs SO_PEERPIDFD and PIDFD_GET_INFO (Linux 6.13): {error}"
    )))
}

/// The identity of the process that opened a connection, from the pidfd the
/// kernel recorded for it at `connect`. A connection from a process that has
/// already been reaped is refused: its pidfd can no longer report a pid.
pub(crate) fn identify(peer: OwnedFd) -> Result<ConnectionIdentity, RpcError> {
    match pidfd_get_info(&peer)? {
        PeerState::Live(tgid) => Ok(ConnectionIdentity::new(Arc::new(peer), tgid)),
        PeerState::Gone => Err(RpcError::Io(std::io::Error::other(
            "refusing a guest connection whose process was reaped before it was accepted",
        ))),
    }
}
