/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use core::fmt;

use serde::{Deserialize, Serialize};
use syscalls::Errno;

/// Context associated with [`Error`]. Useful for knowing which particular part
/// of [`super::Command::spawn`] failed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Context {
    /// No context provided.
    Unknown,
    /// Setting CPU affinity failed.
    Affinity,
    /// The clone syscall failed.
    Clone,
    /// Setting up the tty failed.
    Tty,
    /// Setting up stdio failed.
    Stdio,
    /// Resetting signals failed.
    ResetSignals,
    /// Changing `/proc/{pid}/uid_map` failed.
    MapUid,
    /// Changing `/proc/{pid}/setgroups` or `/proc/{pid}/gid_map` failed.
    MapGid,
    /// Setting the hostname failed.
    Hostname,
    /// Setting the domainname failed.
    Domainname,
    /// Chroot failed.
    Chroot,
    /// Chdir failed.
    Chdir,
    /// Mounting failed.
    Mount,
    /// Network configuration failed.
    Network,
    /// The pre_exec callback(s) failed.
    PreExec,
    /// Setting the seccomp filter failed.
    Seccomp,
    /// Exec failed.
    Exec,
}

impl Context {
    /// Returns a string representation of the context.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown failure",
            Self::Affinity => "setting cpu affinity failed",
            Self::Clone => "clone failed",
            Self::Tty => "Setting the controlling tty failed",
            Self::Stdio => "Setting up stdio file descriptors failed",
            Self::ResetSignals => "Reseting signal handlers failed",
            Self::MapUid => "Setting UID map failed",
            Self::MapGid => "Setting GID map failed",
            Self::Hostname => "Setting hostname failed",
            Self::Domainname => "Setting domainname failed",
            Self::Chroot => "chroot failed",
            Self::Chdir => "chdir failed",
            Self::Mount => "mount failed",
            Self::Network => "network configuration failed",
            Self::PreExec => "pre_exec callback(s) failed",
            Self::Seccomp => "failed to install seccomp filter",
            Self::Exec => "execvp failed",
        }
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Write::write_str(f, self.as_str())
    }
}

/// An error from spawning a process. This is a thin wrapper around
/// [`crate::Errno`], but with more context about what went wrong.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Error {
    errno: Errno,
    context: Context,
}

impl Error {
    /// Creates a new `Error`.
    pub fn new(errno: Errno, context: Context) -> Self {
        Self { errno, context }
    }

    /// Converts a value `S` into an `Error`. Useful for turning `libc` function
    /// return types into a `Result`.
    pub fn result<S>(value: S, context: Context) -> Result<S, Self>
    where
        S: syscalls::ErrnoSentinel + PartialEq<S>,
    {
        Errno::result(value).map_err(|err| Self::new(err, context))
    }

    /// Gets the errno.
    pub fn errno(&self) -> Errno {
        self.errno
    }

    /// Gets the error context.
    pub fn context(&self) -> Context {
        self.context
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}: {}", self.context, self.errno)
    }
}

impl std::error::Error for Error {}

impl From<Errno> for Error {
    fn from(err: Errno) -> Self {
        Self::new(err, Context::Unknown)
    }
}

impl From<Error> for Errno {
    fn from(err: Error) -> Errno {
        err.errno
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        std::io::Error::from(err.errno)
    }
}

impl From<[u8; 8]> for Error {
    /// Deserializes an `Error` from bytes. Useful for receiving the error
    /// through a pipe from the child process.
    fn from(bytes: [u8; 8]) -> Self {
        debug_assert_eq!(core::mem::size_of::<Self>(), 8);
        unsafe { core::mem::transmute(bytes) }
    }
}

impl From<Error> for [u8; 8] {
    /// Serializes an `Error` into bytes. Useful for sending the error through a
    /// pipe to the parent process.
    fn from(error: Error) -> Self {
        debug_assert_eq!(core::mem::size_of::<Self>(), 8);
        unsafe { core::mem::transmute(error) }
    }
}

pub(super) trait AddContext<T> {
    fn context(self, context: Context) -> Result<T, Error>;
}

impl<T> AddContext<T> for Result<T, Errno> {
    fn context(self, context: Context) -> Result<T, Error> {
        self.map_err(move |errno| Error::new(errno, context))
    }
}

impl<T> AddContext<T> for Result<T, nix::errno::Errno> {
    fn context(self, context: Context) -> Result<T, Error> {
        self.map_err(move |errno| Error::new(Errno::new(errno as i32), context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bytes() {
        let bytes: [u8; 8] = Error::new(Errno::ENOENT, Context::Exec).into();
        assert_eq!(Error::from(bytes), Error::new(Errno::ENOENT, Context::Exec));
    }
}
