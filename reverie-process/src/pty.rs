/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;

use syscalls::Errno;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

use super::fd::AsyncFd;
use super::fd::Fd;

/// Represents a pseudo-TTY "master".
#[derive(Debug)]
pub struct Pty {
    fd: AsyncFd,
}

impl Pty {
    /// Opens a new pseudo-TTY master.
    ///
    /// NOTE: As long as there is a handle open to at least one child pty, reads
    /// will not reach EOF and will continue to return `EWOULDBLOCK`.
    pub fn open() -> Result<Self, Errno> {
        let fd = Fd::new(Errno::result(unsafe {
            libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY)
        })?);

        Errno::result(unsafe { libc::grantpt(fd.as_raw_fd()) })?;
        Errno::result(unsafe { libc::unlockpt(fd.as_raw_fd()) })?;

        let fd = AsyncFd::new(fd)?;

        Ok(Self { fd })
    }

    /// Opens a pseudo-TTY slave that is connected to this master.
    pub fn child(&self) -> Result<PtyChild, Errno> {
        const TIOCGPTPEER: libc::c_ulong = 0x5441;

        let parent = self.fd.as_raw_fd();

        let fd = Errno::result(unsafe {
            // NOTE: This ioctl isn't supported until Linux v4.13 (see
            // `ioctl_tty(2)`), so we may fallback to path-based slave fd
            // allocation.
            libc::ioctl(parent, TIOCGPTPEER, libc::O_RDWR | libc::O_NOCTTY)
        })
        .map(Fd::new)
        .or_else(|_err| {
            let mut path: [libc::c_char; libc::PATH_MAX as usize] = [0; libc::PATH_MAX as usize];

            Errno::result(unsafe { libc::ptsname_r(parent, path.as_mut_ptr(), path.len()) })?;

            Fd::open_c(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY)
        })?;

        Ok(PtyChild { fd })
    }
}

/// A pseudo-TTY child (or "slave" in TTY parlance). This is passed to child
/// processes.
#[derive(Debug)]
pub struct PtyChild {
    fd: Fd,
}

impl PtyChild {
    /// Sets the pseudo-TTY child as the controlling terminal for the current
    /// process.
    ///
    /// Specifically, this does several things:
    ///  1. Calls setsid to create a new session.
    ///  2. Makes this fd the controlling terminal of this process by running the
    ///     correct ioctl.
    ///  3. Calls `dup2` to set each stdio stream to redirect to this fd.
    ///  4. Closes the fd.
    pub fn login(self) -> Result<(), Errno> {
        Errno::result(unsafe { libc::login_tty(self.fd.into_raw_fd()) })?;
        Ok(())
    }

    /// Sets the window size in rows and columns.
    pub fn set_window_size(&self, rows: u16, cols: u16) -> Result<(), Errno> {
        let fd = self.fd.as_raw_fd();

        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        Errno::result(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize as *const _) })?;

        Ok(())
    }

    /// Returns the window size in terms of rows and columns.
    pub fn window_size(&self) -> Result<(u16, u16), Errno> {
        let fd = self.fd.as_raw_fd();

        let mut winsize = MaybeUninit::<libc::winsize>::uninit();

        Errno::result(unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, winsize.as_mut_ptr()) })?;

        let winsize = unsafe { winsize.assume_init() };

        Ok((winsize.ws_row, winsize.ws_col))
    }

    /// Sets the terminal parameters.
    pub fn set_terminal_params(&self, params: &libc::termios) -> Result<(), Errno> {
        let fd = self.fd.as_raw_fd();
        Errno::result(unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, params as *const _) })?;
        Ok(())
    }

    /// Gets the terminal parameters.
    pub fn terminal_params(&self) -> Result<libc::termios, Errno> {
        let fd = self.fd.as_raw_fd();

        let mut term = MaybeUninit::<libc::termios>::uninit();

        Errno::result(unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) })?;

        Ok(unsafe { term.assume_init() })
    }
}

impl AsRawFd for Pty {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsRawFd for PtyChild {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsyncWrite for Pty {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        Pin::new(&mut self.fd).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.fd).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.fd).poll_shutdown(cx)
    }
}

impl AsyncRead for Pty {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.fd).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open() {
        let pty = Pty::open().unwrap();

        let child1 = pty.child().unwrap();
        child1.set_window_size(20, 40).unwrap();
        assert_eq!(child1.window_size().unwrap(), (20, 40));

        let child2 = pty.child().unwrap();
        child2.set_window_size(40, 80).unwrap();

        assert_eq!(child2.window_size().unwrap(), (40, 80));

        // Since they're both connected to the same master, changing the window
        // size of one child affects both of them.
        assert_eq!(child1.window_size().unwrap(), (40, 80));
    }
}
