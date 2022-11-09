/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Provides helpers for printing formatted messages to stdout/stderr without
//! relying on std.

use core::fmt;
use core::fmt::Write;

use syscalls::syscall3;
use syscalls::Errno;
use syscalls::Sysno;

#[inline(always)]
fn sys_write(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    unsafe { syscall3(Sysno::write, fd as usize, buf.as_ptr() as usize, buf.len()) }
}

fn sys_write_all(fd: i32, mut buf: &[u8]) -> Result<(), Errno> {
    while !buf.is_empty() {
        match sys_write(fd, buf) {
            Ok(n) => buf = &buf[n..],
            Err(Errno::EINTR) => continue,
            Err(errno) => return Err(errno),
        }
    }
    Ok(())
}

struct Stdio<const N: usize = 4096> {
    fd: i32,
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Stdio<N> {
    pub fn new(fd: i32) -> Self {
        Self {
            fd,
            buf: [0; N],
            len: 0,
        }
    }

    pub fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Errno> {
        while !buf.is_empty() {
            if self.buf[self.len..].is_empty() {
                self.flush()?;
            }
            let remaining = &mut self.buf[self.len..];
            let count = remaining.len().min(buf.len());
            remaining[0..count].copy_from_slice(&buf[0..count]);
            self.len += count;
            buf = &buf[count..];
        }

        Ok(())
    }

    /// Flushes the buffered writes to the file descriptor.
    pub fn flush(&mut self) -> Result<(), Errno> {
        sys_write_all(self.fd, &self.buf[0..self.len])?;
        self.len = 0;
        Ok(())
    }
}

impl<const N: usize> Drop for Stdio<N> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl fmt::Write for Stdio {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_all(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

fn _inner_print(fd: i32, args: fmt::Arguments<'_>, newline: bool) -> fmt::Result {
    let mut f = Stdio::new(fd);
    f.write_fmt(args)?;

    if newline {
        f.write_str("\n")?;
    }

    Ok(())
}

#[doc(hidden)]
pub fn _print(fd: i32, args: fmt::Arguments<'_>, newline: bool) {
    // Ignore the error.
    let _ = _inner_print(fd, args, newline);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(1, ::core::format_args!($($arg)*), false));
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::_print(2, ::core::format_args!($($arg)*), false));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ({
        // Purposefully avoiding format_args_nl because it requires a nightly
        // feature.
        $crate::_print(1, ::core::format_args!($($arg)*), true);
    })
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ({
        // Purposefully avoiding format_args_nl because it requires a nightly
        // feature.
        $crate::_print(2, ::core::format_args!($($arg)*), true);
    })
}
