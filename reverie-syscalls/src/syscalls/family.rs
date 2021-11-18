/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This module provides groupings of closely related syscalls (i.e.,
//! "families"). These are useful when needing to handle families in very similar
//! ways.

use super::Syscall;

use crate::args::StatPtr;
use crate::memory::AddrMut;

use derive_more::From;

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
#[derive(From, Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum StatFamily {
    Stat(super::Stat),
    Fstat(super::Fstat),
    Lstat(super::Lstat),
    Newfstatat(super::Newfstatat),
}

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
