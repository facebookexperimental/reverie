/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This module provides groupings of closely related syscalls (i.e.,
//! "families"). These are useful when needing to handle families in very similar
//! ways.

use derive_more::From;

use super::Syscall;
use crate::args::ClockId;
use crate::args::CloneFlags;
use crate::args::StatPtr;
use crate::args::Timespec;
use crate::memory::Addr;
use crate::memory::AddrMut;
use crate::memory::MemoryAccess;

/// Represents the `[p]write{64,v,v2}` family of syscalls. All of these syscalls
/// have an associated file descriptor.
#[derive(From, Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum WriteFamily {
    Write(super::Write),
    Pwrite64(super::Pwrite64),
    Writev(super::Writev),
    Pwritev(super::Pwritev),
    Pwritev2(super::Pwritev2),
}

impl WriteFamily {
    /// Get the file descriptor associated with the write.
    pub fn fd(&self) -> i32 {
        match self {
            Self::Write(s) => s.fd(),
            Self::Pwrite64(s) => s.fd(),
            Self::Writev(s) => s.fd(),
            Self::Pwritev(s) => s.fd(),
            Self::Pwritev2(s) => s.fd(),
        }
    }
}

impl From<WriteFamily> for Syscall {
    fn from(family: WriteFamily) -> Syscall {
        match family {
            WriteFamily::Write(syscall) => Syscall::Write(syscall),
            WriteFamily::Pwrite64(syscall) => Syscall::Pwrite64(syscall),
            WriteFamily::Writev(syscall) => Syscall::Writev(syscall),
            WriteFamily::Pwritev(syscall) => Syscall::Pwritev(syscall),
            WriteFamily::Pwritev2(syscall) => Syscall::Pwritev2(syscall),
        }
    }
}

/// Represents the stat family of syscalls. All of these have an associated stat
/// buffer.
// Stat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
#[derive(From, Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum StatFamily {
    Stat(super::Stat),
    Fstat(super::Fstat),
    Lstat(super::Lstat),
    Newfstatat(super::Newfstatat),
}

// Stat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl StatFamily {
    /// Get address of the stat buffer. Returns `None` if a NULL pointer was
    /// specified.
    pub fn stat(&self) -> Option<StatPtr> {
        match self {
            Self::Stat(s) => s.stat(),
            Self::Fstat(s) => s.stat(),
            Self::Lstat(s) => s.stat(),
            Self::Newfstatat(s) => s.stat(),
        }
    }
}

// Stat not available in aarch64
#[cfg(not(target_arch = "aarch64"))]
impl From<StatFamily> for Syscall {
    fn from(family: StatFamily) -> Syscall {
        match family {
            StatFamily::Stat(syscall) => Syscall::Stat(syscall),
            StatFamily::Fstat(syscall) => Syscall::Fstat(syscall),
            StatFamily::Lstat(syscall) => Syscall::Lstat(syscall),
            StatFamily::Newfstatat(syscall) => Syscall::Newfstatat(syscall),
        }
    }
}

/// Represents the family of syscalls that get information about a socket. All of
/// these have some buffer and a length pointer.
#[derive(From, Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum SockOptFamily {
    Getsockopt(super::Getsockopt),
    Getpeername(super::Getpeername),
    Getsockname(super::Getsockname),
}

impl SockOptFamily {
    /// Get address of the value. Returns `None` if a NULL pointer was
    /// specified.
    pub fn value(&self) -> Option<AddrMut<u8>> {
        match self {
            Self::Getsockopt(s) => s.optval().map(AddrMut::cast),
            Self::Getpeername(s) => s.usockaddr().map(AddrMut::cast),
            Self::Getsockname(s) => s.usockaddr().map(AddrMut::cast),
        }
    }

    /// Get address of the buffer length. Returns `None` if a NULL pointer was
    /// specified.
    pub fn value_len(&self) -> Option<AddrMut<libc::socklen_t>> {
        match self {
            Self::Getsockopt(s) => s.optlen(),
            Self::Getpeername(s) => s.usockaddr_len(),
            Self::Getsockname(s) => s.usockaddr_len(),
        }
    }
}

impl From<SockOptFamily> for Syscall {
    fn from(family: SockOptFamily) -> Syscall {
        match family {
            SockOptFamily::Getsockopt(syscall) => Syscall::Getsockopt(syscall),
            SockOptFamily::Getpeername(syscall) => Syscall::Getpeername(syscall),
            SockOptFamily::Getsockname(syscall) => Syscall::Getsockname(syscall),
        }
    }
}

/// Represents the clone family of syscalls. All of these create a new process.
/// Generally, we only care about the flags used.
#[derive(From, Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum CloneFamily {
    // Fork not available in aarch64
    #[cfg(not(target_arch = "aarch64"))]
    Fork(super::Fork),
    // Vfork not available in aarch64
    #[cfg(not(target_arch = "aarch64"))]
    Vfork(super::Vfork),
    Clone(super::Clone),
    Clone3(super::Clone3),
}

impl CloneFamily {
    /// Returns the clone flags for the syscall. For `fork` and `vfork`, the
    /// flags are deduced based on the semantics of those syscalls. For the
    /// `clone` syscall, we simply return the flags passed as an argument to the
    /// syscall. For `clone3`, we have to read the flags from the pointer passed
    /// to the syscall. Thus, the `memory` parameter is not read unless this is
    /// a `clone3` syscall. If reading from memory fails for any reason, we
    /// return an empty set of clone flags (i.e., 0).
    pub fn flags<M: MemoryAccess>(&self, memory: &M) -> CloneFlags {
        match self {
            #[cfg(not(target_arch = "aarch64"))]
            Self::Fork(_) => CloneFlags::SIGCHLD,
            #[cfg(not(target_arch = "aarch64"))]
            Self::Vfork(_) => CloneFlags::CLONE_VFORK | CloneFlags::CLONE_VM | CloneFlags::SIGCHLD,
            Self::Clone(clone) => clone.flags().into(),
            Self::Clone3(clone) => {
                // sys_clone3 reads everything from a pointer.
                clone
                    .args()
                    .and_then(|ptr| memory.read_value(ptr).ok())
                    .map_or_else(CloneFlags::empty, |args| args.flags)
            }
        }
    }

    /// Returns the child tid for the syscall. For `fork` and `vfork`, this is
    /// always 0. For the `clone` syscall, we simply return the child tid
    /// passed as an argument to the syscall. For `clone3`, we have to read the
    /// child tid from the pointer passed to the syscall. Thus, the `memory`
    /// parameter is not read unless this is a `clone3` syscall. If reading
    /// from memory fails for any reason, we return 0.
    pub fn child_tid<M: MemoryAccess>(&self, memory: &M) -> usize {
        match self {
            #[cfg(not(target_arch = "aarch64"))]
            Self::Fork(_) => 0,
            #[cfg(not(target_arch = "aarch64"))]
            Self::Vfork(_) => 0,
            Self::Clone(clone) => clone.ctid().map_or(0, |ctid| ctid.as_raw()),
            Self::Clone3(clone) => {
                // sys_clone3 reads everything from a pointer.
                clone
                    .args()
                    .and_then(|ptr| memory.read_value(ptr).ok())
                    .map_or(0, |args| args.child_tid.try_into().unwrap())
            }
        }
    }
}

impl From<CloneFamily> for Syscall {
    fn from(family: CloneFamily) -> Syscall {
        match family {
            #[cfg(not(target_arch = "aarch64"))]
            CloneFamily::Fork(syscall) => Syscall::Fork(syscall),
            #[cfg(not(target_arch = "aarch64"))]
            CloneFamily::Vfork(syscall) => Syscall::Vfork(syscall),
            CloneFamily::Clone(syscall) => Syscall::Clone(syscall),
            CloneFamily::Clone3(syscall) => Syscall::Clone3(syscall),
        }
    }
}

/// Represents the nanosleep family of syscalls. These allow a thread to sleep
/// with nanosecond precision.
#[derive(From, Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum NanosleepFamily {
    Nanosleep(super::Nanosleep),
    ClockNanosleep(super::ClockNanosleep),
}

impl NanosleepFamily {
    /// Returns the clockid for the syscall. For `clock_nanosleep` this is
    /// the clockid passed as an argument to the syscall. For `nanosleep` the
    /// clockid is not specified as an argument, so return CLOCK_REALTIME which
    /// is semantically equivalent.
    pub fn clockid(&self) -> ClockId {
        match self {
            Self::Nanosleep(_) => ClockId::CLOCK_REALTIME,
            Self::ClockNanosleep(s) => s.clockid(),
        }
    }

    /// Returns the flags for the syscall. For `clock_nanosleep` these are
    /// the flags passed as an argument to the syscall. For `nanosleep`, the
    /// flags are not specified as an argument, so return 0 which is
    /// semantically equivalent (0 means relative time, i.e. *not* TIMER_ABSTIME).
    pub fn flags(&self) -> i32 {
        match self {
            Self::Nanosleep(_) => 0,
            Self::ClockNanosleep(s) => s.flags(),
        }
    }

    /// Get the request timespec pointer.
    pub fn req(&self) -> Option<Addr<Timespec>> {
        match self {
            Self::Nanosleep(s) => s.req(),
            Self::ClockNanosleep(s) => s.req(),
        }
    }

    /// Get the remain timespec pointer.
    pub fn rem(&self) -> Option<AddrMut<Timespec>> {
        match self {
            Self::Nanosleep(s) => s.rem(),
            Self::ClockNanosleep(s) => s.rem(),
        }
    }
}

impl From<NanosleepFamily> for Syscall {
    fn from(family: NanosleepFamily) -> Syscall {
        match family {
            NanosleepFamily::Nanosleep(syscall) => Syscall::Nanosleep(syscall),
            NanosleepFamily::ClockNanosleep(syscall) => Syscall::ClockNanosleep(syscall),
        }
    }
}
