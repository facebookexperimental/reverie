/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Collection of type-safe syscall arguments. These are shared among
//! potentially many syscalls.

use core::fmt;
use std::ffi::CString;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

mod clone;
mod fcntl;
mod io_uring;
pub mod ioctl;
mod poll;
mod stat;
mod sysinfo;
mod time;

pub use clone::*;
pub use fcntl::FcntlCmd;
pub use io_uring::*;
use nix::sys::stat::Mode;
use nix::sys::stat::SFlag;
use nix::unistd::Pid;
pub use poll::*;
use serde::Deserialize;
use serde::Serialize;
pub use stat::*;
pub use sysinfo::*;
pub use time::*;

use crate::Addr;
use crate::AddrMut;
use crate::Displayable;
use crate::Errno;
use crate::FromToRaw;
use crate::MemoryAccess;

/// Helper trait for reading a specific value from an address.
pub trait ReadAddr {
    /// The type of value returned by `read`.
    type Target: Sized;

    /// The error type returned by `read`.
    type Error;

    /// Reads the contents of the address and returns it.
    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error>;
}

impl<'a, T> ReadAddr for Addr<'a, T>
where
    T: Copy + Sized,
{
    type Target = T;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        memory.read_value(*self)
    }
}

impl<'a, T> ReadAddr for AddrMut<'a, T>
where
    T: Copy + Sized,
{
    type Target = T;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        memory.read_value(*self)
    }
}

/// An array of pointers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CArrayPtr<'a, T>(Addr<'a, Option<T>>);

impl<'a, T> ReadAddr for CArrayPtr<'a, T>
where
    T: Copy,
{
    type Target = Vec<T>;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        let mut v = Vec::new();

        let mut r = memory.reader(self.0);

        while let Some(addr) = r.read_value()? {
            v.push(addr);
        }

        Ok(v)
    }
}

impl<'a, T> FromToRaw for Option<CArrayPtr<'a, T>> {
    fn from_raw(raw: usize) -> Self {
        Option::<Addr<'a, Option<T>>>::from_raw(raw).map(CArrayPtr)
    }

    fn into_raw(self) -> usize {
        self.map(|p| p.0).into_raw()
    }
}

impl<'a, T> Displayable for Option<CArrayPtr<'a, T>>
where
    T: Copy + Displayable,
{
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => f.write_str("NULL"),
            Some(array) => match array.read(memory) {
                Ok(v) => {
                    write!(f, "{} -> [", array.0)?;

                    let mut count = 0;

                    let mut iter = v.into_iter();

                    if let Some(item) = iter.next() {
                        item.fmt(memory, outputs, f)?;
                        count += 1;
                    }

                    for item in iter {
                        f.write_str(", ")?;

                        // Only print the first 32 arguments like strace does.
                        if count > 32 {
                            f.write_str("...")?;
                            break;
                        }

                        item.fmt(memory, outputs, f)?;
                        count += 1;
                    }

                    f.write_str("]")
                }
                Err(e) => write!(f, "{} -> <{}>", array.0, e),
            },
        }
    }
}

/// A pointer to a `CString` that resides in the target address space.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CStrPtr<'a>(Addr<'a, u8>);

impl<'a> CStrPtr<'a> {
    /// Creates the `CStrPtr` from a raw pointer. Returns `None` if the given
    /// pointer is NULL.
    pub fn from_ptr(r: *const libc::c_char) -> Option<Self> {
        Addr::from_ptr(r as *const u8).map(CStrPtr)
    }
}

impl<'a> ReadAddr for CStrPtr<'a> {
    type Target = CString;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        memory.read_cstring(self.0)
    }
}

impl<'a> FromToRaw for Option<CStrPtr<'a>> {
    fn from_raw(raw: usize) -> Self {
        Option::<Addr<'a, u8>>::from_raw(raw).map(CStrPtr)
    }

    fn into_raw(self) -> usize {
        self.map(|p| p.0).into_raw()
    }
}

impl<'a> Displayable for CStrPtr<'a> {
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self.read(memory) {
            Ok(s) => {
                // Only display the first 64 bytes.
                if s.as_bytes().len() > 64 {
                    let mut bytes = s.into_bytes();
                    bytes.truncate(64);
                    let s = unsafe { CString::from_vec_unchecked(bytes) };
                    write!(f, "{} -> {:?}...", self.0, s)
                } else {
                    write!(f, "{} -> {:?}", self.0, s)
                }
            }
            Err(e) => write!(f, "{} -> <{}>", self.0, e),
        }
    }
}

impl<'a> Displayable for Option<CStrPtr<'a>> {
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => f.write_str("NULL"),
            Some(addr) => Displayable::fmt(addr, memory, outputs, f),
        }
    }
}

/// A pointer to a `Path` that resides in the target address space.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PathPtr<'a>(CStrPtr<'a>);

impl<'a> PathPtr<'a> {
    /// Creates the `PathPtr` from a raw pointer. Returns `None` if the given
    /// pointer is NULL.
    pub fn from_ptr(r: *const libc::c_char) -> Option<Self> {
        CStrPtr::from_ptr(r).map(PathPtr)
    }
}

impl<'a> ReadAddr for PathPtr<'a> {
    type Target = PathBuf;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        let path = PathBuf::from(OsString::from_vec(self.0.read(memory)?.into_bytes()));

        Ok(path)
    }
}

impl<'a> FromToRaw for Option<PathPtr<'a>> {
    fn from_raw(raw: usize) -> Self {
        Option::<CStrPtr<'a>>::from_raw(raw).map(PathPtr)
    }

    fn into_raw(self) -> usize {
        self.map(|p| p.0).into_raw()
    }
}

impl<'a> Displayable for Option<PathPtr<'a>> {
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => f.write_str("NULL"),
            Some(addr) => match addr.read(memory) {
                Ok(s) => write!(f, "{} -> {:?}", addr.0.0, s),
                Err(e) => write!(f, "{} -> <{}>", addr.0.0, e),
            },
        }
    }
}

/// A pointer to a `stat` buffer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StatPtr<'a>(pub AddrMut<'a, libc::stat>);

impl<'a> StatPtr<'a> {
    /// Creates the `StatPtr` from a raw pointer. Returns `None` if the given
    /// pointer is NULL.
    pub fn from_ptr(r: *const libc::stat) -> Option<Self> {
        AddrMut::from_ptr(r as *const libc::stat).map(StatPtr)
    }
}

impl<'a> ReadAddr for StatPtr<'a> {
    type Target = libc::stat;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        memory.read_value(self.0)
    }
}

impl<'a> FromToRaw for Option<StatPtr<'a>> {
    fn from_raw(raw: usize) -> Self {
        Option::<AddrMut<'a, libc::stat>>::from_raw(raw).map(StatPtr)
    }

    fn into_raw(self) -> usize {
        self.map(|p| p.0).into_raw()
    }
}

impl<'a> Displayable for Option<StatPtr<'a>> {
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => f.write_str("NULL"),
            Some(addr) => {
                if outputs {
                    match addr.read(memory) {
                        Ok(stat) => {
                            // Print st_mode the same way strace does.
                            let sflag = SFlag::from_bits_truncate(stat.st_mode);
                            let mode = Mode::from_bits_truncate(stat.st_mode);
                            write!(
                                f,
                                "{} -> {{st_mode={:?} | 0{:o}, st_size={}, ...}}",
                                addr.0, sflag, mode, stat.st_size
                            )
                        }
                        Err(e) => write!(f, "{} -> <{}>", addr.0, e),
                    }
                } else {
                    // Just print the address when not displaying outputs.
                    fmt::Display::fmt(&addr.0, f)
                }
            }
        }
    }
}

/// A pointer to a `statx` buffer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StatxPtr<'a>(pub AddrMut<'a, libc::statx>);

impl<'a> StatxPtr<'a> {
    /// Creates the `StatxPtr` from a raw pointer. Returns `None` if the given
    /// pointer is NULL.
    pub fn from_ptr(r: *const libc::statx) -> Option<Self> {
        AddrMut::from_ptr(r as *const libc::statx).map(StatxPtr)
    }
}

impl<'a> ReadAddr for StatxPtr<'a> {
    type Target = libc::statx;
    type Error = Errno;

    fn read<M: MemoryAccess>(&self, memory: &M) -> Result<Self::Target, Self::Error> {
        memory.read_value(self.0)
    }
}

impl<'a> FromToRaw for Option<StatxPtr<'a>> {
    fn from_raw(raw: usize) -> Self {
        Option::<AddrMut<'a, libc::statx>>::from_raw(raw).map(StatxPtr)
    }

    fn into_raw(self) -> usize {
        self.map(|p| p.0).into_raw()
    }
}

impl<'a> Displayable for Option<StatxPtr<'a>> {
    fn fmt<M: MemoryAccess>(
        &self,
        memory: &M,
        outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        match self {
            None => f.write_str("NULL"),
            Some(addr) => {
                if outputs {
                    match addr.read(memory) {
                        Ok(stat) => {
                            // Print mode the same way strace does.
                            let sflag = SFlag::from_bits_truncate(stat.stx_mode.into());
                            let mode = Mode::from_bits_truncate(stat.stx_mode.into());
                            write!(
                                f,
                                "{} -> {{st_mode={:?} | 0{:o}, st_size={}, ...}}",
                                addr.0, sflag, mode, stat.stx_size
                            )
                        }
                        Err(e) => write!(f, "{} -> <{}>", addr.0, e),
                    }
                } else {
                    // Just print the address when not displaying outputs.
                    fmt::Display::fmt(&addr.0, f)
                }
            }
        }
    }
}

bitflags::bitflags! {
    /// stx_mask from statx, see linux/stat.h
    #[derive(Serialize, Deserialize)]
    pub struct StatxMask: u32 {
        /// has stx_type
        const STATX_TYPE = 0x1;
        /// has stx_mode
        const STATX_MODE = 0x2;
        /// has stx_nlink
        const STATX_NLINK = 0x4;
        /// has stx_uid
        const STATX_UID = 0x8;
        /// has stx_gid
        const STATX_GID = 0x10;
        /// has stx_atime
        const STATX_ATIME = 0x20;
        /// has stx_mtime
        const STATX_MTIME = 0x40;
        /// has stx_ctime
        const STATX_CTIME = 0x80;
        /// has stx_ino
        const STATX_INO = 0x100;
        /// has stx_size
        const STATX_SIZE = 0x200;
        /// has stx_blocks
        const STATX_BLOCKS = 0x400;
        /// compatible with `stat'.
        const STATX_BASIC_STATS = 0x7ff;
        /// has stx_btime
        const STATX_BTIME = 0x800;
        /// has stx_mnt_id
        const STATX_MNT_ID = 0x1000;
        /// reserved
        const STATX_RESERVED = 0x80000000;
    }
}

impl Default for StatxMask {
    fn default() -> Self {
        StatxMask::STATX_BASIC_STATS
    }
}

impl FromToRaw for StatxMask {
    fn from_raw(raw: usize) -> Self {
        StatxMask::from_bits_truncate(raw as u32)
    }

    fn into_raw(self) -> usize {
        self.bits() as usize
    }
}

impl Displayable for StatxMask {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        fmt::Display::fmt(&self.bits(), f)
    }
}

pub(crate) fn fmt_nullable_ptr<T, E, M, P>(
    f: &mut std::fmt::Formatter<'_>,
    value: &Option<P>,
    memory: &M,
    outputs: bool,
) -> std::fmt::Result
where
    T: Displayable,
    E: std::fmt::Display,
    P: ReadAddr<Target = T, Error = E> + std::fmt::Display,
    M: MemoryAccess,
{
    match value {
        None => f.write_str("NULL"),
        Some(addr) => fmt_ptr(f, addr, memory, outputs),
    }
}

pub(crate) fn fmt_ptr<T, E, M, P>(
    f: &mut std::fmt::Formatter<'_>,
    addr: &P,
    memory: &M,
    outputs: bool,
) -> std::fmt::Result
where
    T: Displayable,
    E: std::fmt::Display,
    P: ReadAddr<Target = T, Error = E> + std::fmt::Display,
    M: MemoryAccess,
{
    if !outputs {
        write!(f, "{}", addr)
    } else {
        match addr.read(memory) {
            Ok(s) => write!(f, "{} -> {}", addr, s.display_with_outputs(memory)),
            Err(e) => write!(f, "{} -> <{}>", addr, e),
        }
    }
}

command_enum! {
    /// The argument pairs of `arch_prctl(2)`.
    #[allow(missing_docs)]
    pub enum ArchPrctlCmd<'a>: libc::c_int {
        ARCH_SET_GS(u64) = 0x1001,
        ARCH_SET_FS(u64) = 0x1002,
        ARCH_GET_FS(Option<Addr<'a, libc::c_ulong>>) = 0x1003,
        ARCH_GET_GS(Option<Addr<'a, libc::c_ulong>>) = 0x1004,

        ARCH_GET_CPUID(Option<Addr<'a, libc::c_ulong>>) = 0x1011,
        ARCH_SET_CPUID(u64) = 0x1012,
    }
}

const_enum! {
    /// Directives that tell `lseek` and `lseek64` what the offset is relative
    /// to.
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum Whence: i32 {
        /// Specifies an offset relative to the start of the file.
        SEEK_SET,

        /// Specifies an offset relative to the current file location.
        SEEK_CUR,

        /// Specifies an offset relative to the end of the file.
        SEEK_END,

        /// Specifies an offset relative to the next location in the file
        /// greater than or equal to offset that contains some data. If offset
        /// points to some data, then the file offset is set to offset.
        SEEK_DATA,

        /// Specify an offset relative to the next hole in the file greater than
        /// or equal to offset. If offset points into the middle of a hole, then
        /// the file offset should be set to offset. If there is no hole past
        /// offset, then the file offset should be adjusted to the end of the
        /// file (i.e., there is an implicit hole at the end of any file).
        SEEK_HOLE,
    }
}

const_enum! {
    /// A clock ID. See the definitions in `kernel/include/uapi/linux/time.h`.
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum ClockId: i32 {
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID,
        CLOCK_MONOTONIC_RAW,
        CLOCK_REALTIME_COARSE,
        CLOCK_MONOTONIC_COARSE,
        CLOCK_BOOTTIME,
        CLOCK_REALTIME_ALARM,
        CLOCK_BOOTTIME_ALARM,
    }
}
