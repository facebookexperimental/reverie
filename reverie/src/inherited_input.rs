/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A launcher-owned input pipe and its one-time initial-image identity.

use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use serde::Deserialize;
use serde::Serialize;

/// Host-private identity of a pipe the launcher created for a guest input.
///
/// These raw kernel values validate installation; they are neither virtualized
/// guest metadata nor canonical log payloads. This value alone is not authority:
/// a Tool accepts it only from the run's [`crate::GlobalTool::install_inherited_input`]
/// hook, while the corresponding [`InheritedInputLease`] remains alive.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InheritedInputIdentity {
    guest_fd: i32,
    dev: u64,
    inode: u64,
    rdev: u64,
    access_mode: i32,
}

impl fmt::Debug for InheritedInputIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Raw host identity must not enter guest-visible or compared logs.
        f.debug_struct("InheritedInputIdentity")
            .field("guest_fd", &self.guest_fd)
            .finish_non_exhaustive()
    }
}

impl InheritedInputIdentity {
    /// The descriptor slot into which the launcher installs the read end.
    pub fn guest_fd(&self) -> i32 {
        self.guest_fd
    }
    /// Raw device identity, for private installation validation only.
    pub fn dev(&self) -> u64 {
        self.dev
    }
    /// Raw inode identity, for private installation validation only.
    pub fn inode(&self) -> u64 {
        self.inode
    }
    /// Raw special-device identity, for private installation validation only.
    pub fn rdev(&self) -> u64 {
        self.rdev
    }
    /// The read end's immutable access mode (without mutable status flags).
    pub fn access_mode(&self) -> i32 {
        self.access_mode
    }

    /// Whether a live installed endpoint agrees with the held read end.
    ///
    /// This does not discover provenance. The caller must already possess this
    /// run's launch binding. In particular, another FIFO or fd 0 is not enough.
    pub fn matches(&self, stat: &libc::stat, status_flags: i32) -> bool {
        status_flags >= 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFIFO
            && (stat.st_dev, stat.st_ino, stat.st_rdev) == (self.dev, self.inode, self.rdev)
            && status_flags & libc::O_ACCMODE == self.access_mode
    }
}

/// An actual controller-created pipe, before its reader is installed in a guest.
///
/// The only constructor creates both endpoints. The launcher installs the reader
/// into `guest_fd`, and keeps the writer exclusively in its input pump. It offers
/// this object to the global Tool before any guest hook runs. Inherited or null
/// input, a descriptor number, and an observed FIFO do not create this authority.
pub struct InheritedInput {
    reader: OwnedFd,
    writer: OwnedFd,
    identity: InheritedInputIdentity,
}

impl InheritedInput {
    /// Create a blocking pipe whose original endpoints are close-on-exec.
    ///
    /// As with `Stdio::piped`, child stdio installation duplicates the reader
    /// into the destination slot without changing the open-file status flags.
    pub fn pipe(guest_fd: i32) -> io::Result<Self> {
        if guest_fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut fds = [-1; 2];
        // SAFETY: pipe2 writes two descriptors into this live array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 returned two new, exclusively owned descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes only into this live stat buffer.
        if unsafe { libc::fstat(reader.as_raw_fd(), &raw mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            reader,
            writer,
            identity: InheritedInputIdentity {
                guest_fd,
                dev: stat.st_dev,
                inode: stat.st_ino,
                rdev: stat.st_rdev,
                access_mode: flags & libc::O_ACCMODE,
            },
        })
    }

    /// The private identity of this actual pipe's read end.
    pub fn identity(&self) -> &InheritedInputIdentity {
        &self.identity
    }

    /// Hold the read end until the Tool's authenticated initial-image handoff.
    ///
    /// Release this lease when that handoff consumes the binding, or on startup
    /// failure. Keeping it for the entire run would change the writer's EPIPE;
    /// retaining an extra writer instead would prevent the guest from seeing EOF.
    pub fn lease(&self) -> io::Result<InheritedInputLease> {
        Ok(InheritedInputLease {
            reader: self.reader.try_clone()?,
            identity: self.identity.clone(),
        })
    }

    /// Transfer the reader to child stdio and the sole writer to its host pump.
    pub fn into_reader_and_writer(self) -> (OwnedFd, File) {
        (self.reader, File::from(self.writer))
    }
}

/// A temporary read-end lease; it never retains the controller's writer.
pub struct InheritedInputLease {
    reader: OwnedFd,
    identity: InheritedInputIdentity,
}

impl fmt::Debug for InheritedInputLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InheritedInputLease")
            .finish_non_exhaustive()
    }
}

impl InheritedInputLease {
    /// The identity whose endpoint this lease keeps alive.
    pub fn identity(&self) -> &InheritedInputIdentity {
        // Keep the ownership-bearing field explicit rather than treating the
        // copied identity as a substitute for the live endpoint.
        let _ = self.reader.as_raw_fd();
        &self.identity
    }
}

#[cfg(test)]
mod tests;
