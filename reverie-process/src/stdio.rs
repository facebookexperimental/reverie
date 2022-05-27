/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use super::fd::{pipe, AsyncFd, Fd};

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

use syscalls::Errno;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Describes what to do with a standard I/O stream for a child process when
/// passed to the [`stdin`], [`stdout`], and [`stderr`] methods of [`Command`].
///
/// [`stdin`]: super::Command::stdin
/// [`stdout`]: super::Command::stdout
/// [`stderr`]: super::Command::stderr
/// [`Command`]: super::Command
#[derive(Debug)]
pub struct Stdio(InnerStdio);

/// A handle to a child process's standard input (stdin).
///
/// This struct is used in the [`stdin`] field on [`Child`].
///
/// When an instance of `ChildStdin` is [dropped], the `ChildStdin`'s underlying
/// file handle will be closed. If the child process was blocked on input prior
/// to being dropped, it will become unblocked after dropping.
///
/// [`stdin`]: super::Child::stdin
/// [`Child`]: super::Child
/// [dropped]: Drop
#[derive(Debug)]
pub struct ChildStdin(AsyncFd);

/// A handle to a child process's standard output (stdout).
///
/// This struct is used in the [`stdout`] field on [`Child`].
///
/// When an instance of `ChildStdout` is [dropped], the `ChildStdout`'s
/// underlying file handle will be closed.
///
/// [`stdout`]: super::Child::stdout
/// [`Child`]: super::Child
/// [dropped]: Drop
#[derive(Debug)]
pub struct ChildStdout(AsyncFd);

/// A handle to a child process's stderr.
///
/// This struct is used in the [`stderr`] field on [`Child`].
///
/// When an instance of `ChildStderr` is [dropped], the `ChildStderr`'s
/// underlying file handle will be closed.
///
/// [`stderr`]: super::Child::stderr
/// [`Child`]: super::Child
/// [dropped]: Drop
#[derive(Debug)]
pub struct ChildStderr(AsyncFd);

#[derive(Debug)]
enum InnerStdio {
    Inherit,
    Null,
    Piped,
    File(Fd),
}

impl Default for Stdio {
    fn default() -> Self {
        Self(InnerStdio::Inherit)
    }
}

impl Stdio {
    /// A new pipe should be arranged to connect the parent and child processes.
    pub fn piped() -> Self {
        Self(InnerStdio::Piped)
    }

    /// The child inherits from the corresponding parent descriptor. This is the default mode.
    pub fn inherit() -> Self {
        Self(InnerStdio::Inherit)
    }

    /// This stream will be ignored. This is the equivalent of attaching the
    /// stream to `/dev/null`.
    pub fn null() -> Self {
        Self(InnerStdio::Null)
    }

    /// Returns a pair of file descriptors, one for the parent and one for the
    /// child. If the child's file descriptor is `None`, then it shall be
    /// inherited from the parent. If the parent's file descriptor is `None`,
    /// then there is no link to the child and the child owns the other half of
    /// the file descriptor (if any). Both file descriptors will be `None` if
    /// stdio is being inherited.
    pub(super) fn pipes(&self, readable: bool) -> Result<(Option<Fd>, Option<Fd>), Errno> {
        match &self.0 {
            InnerStdio::Inherit => Ok((None, None)),
            InnerStdio::Null => Ok((None, Some(Fd::null(readable)?))),
            InnerStdio::Piped => {
                let (reader, writer) = pipe()?;
                let (parent, child) = if readable {
                    (writer, reader)
                } else {
                    (reader, writer)
                };
                Ok((Some(parent), Some(child)))
            }
            InnerStdio::File(file) => Ok((None, Some(file.dup()?))),
        }
    }
}

impl<T: IntoRawFd> From<T> for Stdio {
    fn from(f: T) -> Self {
        Self(InnerStdio::File(Fd::new(f.into_raw_fd())))
    }
}

impl From<Stdio> for std::process::Stdio {
    fn from(stdio: Stdio) -> Self {
        match stdio.0 {
            InnerStdio::Inherit => Self::inherit(),
            InnerStdio::Null => Self::null(),
            InnerStdio::Piped => Self::piped(),
            InnerStdio::File(fd) => Self::from(std::fs::File::from(fd)),
        }
    }
}

impl ChildStdin {
    pub(super) fn new(fd: Fd) -> Result<Self, Errno> {
        AsyncFd::writable(fd).map(Self)
    }
}

impl ChildStdout {
    pub(super) fn new(fd: Fd) -> Result<Self, Errno> {
        AsyncFd::readable(fd).map(Self)
    }
}

impl ChildStderr {
    pub(super) fn new(fd: Fd) -> Result<Self, Errno> {
        AsyncFd::readable(fd).map(Self)
    }
}

impl AsyncWrite for ChildStdin {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncRead for ChildStdout {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncRead for ChildStderr {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl FromRawFd for ChildStdin {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Self::new(Fd::new(fd)).unwrap()
    }
}

impl FromRawFd for ChildStdout {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Self::new(Fd::new(fd)).unwrap()
    }
}

impl FromRawFd for ChildStderr {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Self::new(Fd::new(fd)).unwrap()
    }
}

impl From<tokio::process::ChildStdin> for ChildStdin {
    fn from(io: tokio::process::ChildStdin) -> Self {
        let fd = io.as_raw_fd();
        let fd = unsafe { libc::dup(fd) };
        drop(io);
        unsafe { Self::from_raw_fd(fd) }
    }
}

impl From<tokio::process::ChildStdout> for ChildStdout {
    fn from(io: tokio::process::ChildStdout) -> Self {
        let fd = io.as_raw_fd();
        let fd = unsafe { libc::dup(fd) };
        drop(io);
        unsafe { Self::from_raw_fd(fd) }
    }
}

impl From<tokio::process::ChildStderr> for ChildStderr {
    fn from(io: tokio::process::ChildStderr) -> Self {
        let fd = io.as_raw_fd();
        let fd = unsafe { libc::dup(fd) };
        drop(io);
        unsafe { Self::from_raw_fd(fd) }
    }
}
