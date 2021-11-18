/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::util;

use core::pin::Pin;
use core::task::{Context, Poll};

use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::Path;

use syscalls::Errno;
use tokio::io::unix::AsyncFd as TokioAsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};

#[derive(Debug)]
// From `std/src/sys/unix/fd.rs`. Mark `-1` as an invalid file descriptor so it
// can be reused to in `Option<Fd>`.
#[rustc_layout_scalar_valid_range_start(0)]
#[rustc_layout_scalar_valid_range_end(0xFF_FF_FF_FE)]
pub struct Fd(i32);

/// An asynchronous file descriptor. The file descriptor is guaranteed to be in
/// non-blocking mode and implements `AsyncRead` and `AsyncWrite`.
#[derive(Debug)]
pub struct AsyncFd(TokioAsyncFd<Fd>);

impl Fd {
    pub fn new(fd: i32) -> Self {
        assert_ne!(fd, -1);
        unsafe { Self(fd) }
    }

    #[allow(dead_code)]
    pub fn open<P: AsRef<Path>>(path: P, flags: i32) -> Result<Self, Errno> {
        let path = util::to_cstring(path.as_ref());
        Self::open_c(path.as_ptr(), flags)
    }

    /// Opens a file from a NUL terminated string. This function does not
    /// allocate.
    pub fn open_c(path: *const libc::c_char, flags: i32) -> Result<Self, Errno> {
        let fd = Errno::result(unsafe { libc::open(path, flags) })?;
        Ok(unsafe { Self(fd) })
    }

    /// Creates a file from a NUL terminated string. This function does not allocate.
    pub fn create_c(
        path: *const libc::c_char,
        flags: i32,
        mode: libc::mode_t,
    ) -> Result<Self, Errno> {
        let fd = Errno::result(unsafe { libc::open(path, flags | libc::O_CREAT, mode) })?;
        Ok(unsafe { Self(fd) })
    }

    pub fn null(readable: bool) -> Result<Self, Errno> {
        let path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/null\0") };
        Self::open_c(
            path.as_ptr(),
            if readable {
                libc::O_RDONLY
            } else {
                libc::O_WRONLY
            },
        )
    }

    /// Creates an endpoint for communications and returns a file descriptor that
    /// refers to that endpoint.
    pub fn socket(domain: i32, ty: i32, protocol: i32) -> Result<Self, Errno> {
        Errno::result(unsafe { libc::socket(domain, ty, protocol) }).map(Self::new)
    }

    fn set_nonblocking(&self) -> Result<(), Errno> {
        let fd = self.as_raw_fd();
        let flags = Errno::result(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        Errno::result(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
        Ok(())
    }

    /// Returns true if the file descriptor is nonblocking.
    #[allow(unused)]
    pub fn is_nonblocking(&self) -> Result<bool, Errno> {
        let fd = self.as_raw_fd();
        let flags = Errno::result(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        Ok(flags & libc::O_NONBLOCK == libc::O_NONBLOCK)
    }

    pub fn dup(&self) -> Result<Fd, Errno> {
        let fd = Errno::result(unsafe { libc::dup(self.0) })?;
        Ok(unsafe { Fd(fd) })
    }

    pub fn dup2(&self, newfd: RawFd) -> Result<Fd, Errno> {
        let fd = Errno::result(unsafe { libc::dup2(self.0, newfd) })?;
        Ok(unsafe { Fd(fd) })
    }

    #[allow(unused)]
    pub fn close(self) -> Result<(), Errno> {
        let fd = self.0;
        core::mem::forget(self);
        Errno::result(unsafe { libc::close(fd) })?;
        Ok(())
    }

    /// Discards the file descriptor without closing it.
    pub fn leave_open(self) {
        core::mem::forget(self);
    }
}

impl IntoRawFd for Fd {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.as_raw_fd();
        core::mem::forget(self);
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.0) };
    }
}

impl Read for Fd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = Errno::result(unsafe {
            libc::read(
                self.0,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            )
        })?;

        Ok(res as usize)
    }
}

impl Write for Fd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let res = Errno::result(unsafe {
            libc::write(
                self.0,
                buf.as_ptr() as *const libc::c_void,
                buf.len() as libc::size_t,
            )
        })?;

        Ok(res as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for Fd {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Self::new(fd)
    }
}

impl From<Fd> for std::fs::File {
    fn from(fd: Fd) -> Self {
        unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) }
    }
}

impl AsyncFd {
    pub fn new(fd: Fd) -> Result<Self, Errno> {
        fd.set_nonblocking()?;
        Ok(Self(
            TokioAsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE).unwrap(),
        ))
    }

    pub fn readable(fd: Fd) -> Result<Self, Errno> {
        fd.set_nonblocking()?;
        Ok(Self(
            TokioAsyncFd::with_interest(fd, Interest::READABLE).unwrap(),
        ))
    }

    pub fn writable(fd: Fd) -> Result<Self, Errno> {
        fd.set_nonblocking()?;
        Ok(Self(
            TokioAsyncFd::with_interest(fd, Interest::WRITABLE).unwrap(),
        ))
    }
}

impl AsRawFd for AsyncFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsyncRead for AsyncFd {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = futures::ready!(self.0.poll_read_ready_mut(cx))?;

            match guard.try_io(|inner| {
                let n = inner.get_mut().read(buf.initialize_unfilled())?;
                buf.advance(n);

                Ok(())
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncFd {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = futures::ready!(self.0.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// Creates a unidirectional pipe. The writable end is second item and the
// readable end is the first item.
pub fn pipe() -> Result<(Fd, Fd), Errno> {
    let mut fds = [0; 2];

    // We use O_CLOEXEC because we don't want the pipe file descriptor to be
    // inherited by child processes directly. Instead, we use `dup2` to assign
    // it to one of the stdio file descriptors. Then, the duplicated file
    // descriptor won't be closed upon exec.
    Errno::result(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;

    Ok((unsafe { Fd(fds[0]) }, unsafe { Fd(fds[1]) }))
}

/// Writes bytes to a file. The file path must be null terminated.
pub fn write_bytes(path: &'static [u8], bytes: &[u8]) -> Result<(), Errno> {
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(path) };
    Fd::open_c(path.as_ptr(), libc::O_WRONLY)?
        .write_all(bytes)
        .map_err(|err| Errno::new(err.raw_os_error().unwrap()))
}

/// Creates a file if it does not exist.
pub fn touch(path: *const libc::c_char, mode: libc::mode_t) -> Result<(), Errno> {
    Fd::create_c(path, libc::O_CLOEXEC, mode).map(drop)
}

pub fn lstat(path: *const libc::c_char) -> Result<libc::stat64, Errno> {
    let mut buf: libc::stat64 = unsafe { core::mem::zeroed() };
    Errno::result(unsafe { libc::lstat64(path, &mut buf) })?;
    Ok(buf)
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct FileType(libc::mode_t);

impl FileType {
    pub fn new(path: *const libc::c_char) -> Result<Self, Errno> {
        Ok(Self::from(lstat(path)?))
    }

    pub fn is_dir(&self) -> bool {
        self.0 & libc::S_IFMT == libc::S_IFDIR
    }

    #[allow(unused)]
    pub fn is_file(&self) -> bool {
        self.0 & libc::S_IFMT == libc::S_IFREG
    }
}

impl From<libc::stat64> for FileType {
    fn from(stat: libc::stat64) -> Self {
        Self(stat.st_mode)
    }
}

/// Returns true if `path` is a directory. Returns `false` in all other cases.
///
/// NOTE: The `path` may exist and may be a directory, but this will still return
/// false if there is a permissions error. Use `FileType` to distinguish these
/// cases.
pub fn is_dir(path: *const libc::c_char) -> bool {
    match FileType::new(path) {
        Ok(ft) => ft.is_dir(),
        Err(_) => false,
    }
}

fn cstring_as_slice(s: &mut CString) -> &mut [libc::c_char] {
    let bytes = s.as_bytes_with_nul();
    unsafe {
        // This is safe because we are already provided a mutable `CString` and
        // we don't alias the two mutable references.
        core::slice::from_raw_parts_mut(bytes.as_ptr() as *mut libc::c_char, bytes.len())
    }
}

/// Creates every path component in `path` without allocating. This is done by
/// replacing each `/` with a NUL terminator as needed (and then changing the
/// `\0` back to `/` afterwards).
pub fn create_dir_all(path: &mut CString, mode: libc::mode_t) -> Result<(), Errno> {
    create_dir_all_(cstring_as_slice(path), mode)
}

/// Helper function. The last character in the path is always `\0`.
fn create_dir_all_(path: &mut [libc::c_char], mode: libc::mode_t) -> Result<(), Errno> {
    if path.len() == 1 {
        return Ok(());
    }

    // Try creating this directory
    match Errno::result(unsafe { libc::mkdir(path.as_ptr(), mode) }) {
        Ok(_) => return Ok(()),
        Err(Errno::ENOENT) => {}
        Err(_) if is_dir(path.as_ptr()) => return Ok(()),
        Err(e) => return Err(e),
    }

    // If it doesn't exist, try creating the parent directory.
    with_parent(path, |parent| {
        match parent {
            Some(p) => create_dir_all_(p, mode),
            None => {
                // Got all the way to the root without successfully creating any
                // child directories. Most likely a permissions error.
                Err(Errno::EPERM)
            }
        }
    })?;

    // Finally, try creating the directory again after the parent directories
    // now exist.
    match Errno::result(unsafe { libc::mkdir(path.as_ptr(), mode) }) {
        Ok(_) => Ok(()),
        Err(_) if is_dir(path.as_ptr()) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates an empty file at `path` without allocating.
pub fn touch_path(
    path: &mut CString,
    file_mode: libc::mode_t,
    dir_mode: libc::mode_t,
) -> Result<(), Errno> {
    touch_path_(cstring_as_slice(path), file_mode, dir_mode)
}

/// Helper function. The last character in the path is always `\0`.
fn touch_path_(
    path: &mut [libc::c_char],
    file_mode: libc::mode_t,
    dir_mode: libc::mode_t,
) -> Result<(), Errno> {
    // Try to create the file. This may fail if the parent directories do not exist.
    match touch(path.as_ptr(), file_mode) {
        Ok(_) => return Ok(()),
        Err(Errno::ENOENT) => {}
        Err(e) => return Err(e),
    }

    // Got ENOENT. Try to create the parent directories.
    with_parent(path, |parent| match parent {
        Some(p) => create_dir_all_(p, dir_mode),
        None => Err(Errno::ENOENT),
    })?;

    // Try creating the file again after the parent directories now exist.
    touch(path.as_ptr(), file_mode)
}

/// Helper function for chopping off the last path component, leaving only the
/// parent directory. To do this without allocating, the last path separator is
/// replaced with NUL before calling the closure. After the closure is done, the
/// NUL byte is replaced by the path component again. Thus, the path is only
/// mutated for the duration of the closure.
fn with_parent<F, T>(path: &mut [libc::c_char], mut f: F) -> T
where
    F: FnMut(Option<&mut [libc::c_char]>) -> T,
{
    // Find the index of one past the last path separator.
    if let Some(parent_index) = path
        .iter()
        .rev()
        .position(|c| *c == b'/' as i8)
        .map(|i| path.len() - i)
    {
        // NB: the index is guaranteed to be >0.
        path[parent_index - 1] = 0;

        let result = f(Some(&mut path[..parent_index]));

        // Restore the path to its former glory.
        path[parent_index - 1] = b'/' as i8;

        result
    } else {
        f(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use const_cstr::const_cstr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn test_is_dir() {
        assert!(is_dir(const_cstr!("/").as_ptr()));
        assert!(is_dir(const_cstr!("/dev").as_ptr()));
        assert!(!is_dir(const_cstr!("/dev/null").as_ptr()));
    }

    #[test]
    fn test_file_type() {
        assert!(FileType::new(const_cstr!("/").as_ptr()).unwrap().is_dir());
        assert!(
            FileType::new(const_cstr!("/dev").as_ptr())
                .unwrap()
                .is_dir()
        );
        assert!(
            !FileType::new(const_cstr!("/dev/null").as_ptr())
                .unwrap()
                .is_file()
        );
    }

    #[test]
    fn test_create_dir_all() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let mut path = CString::new(
            tempdir
                .path()
                .join("some/path/to/a/dir")
                .into_os_string()
                .as_bytes(),
        )
        .unwrap();
        let path2 = path.clone();

        create_dir_all(&mut path, 0o777).unwrap();

        assert_eq!(path, path2);

        assert!(is_dir(path.as_ptr()));
    }

    #[test]
    fn test_touch_path() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let mut path = CString::new(
            tempdir
                .path()
                .join("some/path/to/a/file")
                .into_os_string()
                .as_bytes(),
        )
        .unwrap();
        let path2 = path.clone();

        touch_path(&mut path, 0o666, 0o777).unwrap();

        assert_eq!(path, path2);

        assert!(FileType::new(path.as_ptr()).unwrap().is_file());
    }

    #[test]
    fn test_nonblocking() -> Result<(), Errno> {
        let (r, w) = pipe()?;

        assert!(!r.is_nonblocking()?);
        assert!(!w.is_nonblocking()?);

        let f = w.dup()?;

        assert!(!f.is_nonblocking()?);

        w.set_nonblocking()?;

        assert!(!r.is_nonblocking()?);
        assert!(w.is_nonblocking()?);
        assert!(f.is_nonblocking()?);

        Ok(())
    }
}
