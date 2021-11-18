/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSDstyle license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;
use std::os::unix::ffi::OsStringExt;
use std::{ffi::OsString, path::PathBuf};

use nix::sys::stat::FileStat;

use reverie::Pid;

use crate::gdbstub::{commands::*, hex::*};

/// struct stat defined by gdb host i/o packet. This is *not* the same as
/// libc::stat or nix's FileStat (which is just libc::stat).
// NB: packed is needed to force size_of::<HostioStat> == 0x40. Otherwise
// gdb (client) would complain.
#[repr(packed(4))]
pub struct HostioStat {
    st_dev: u32,
    st_ino: u32,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u32,
    st_size: u64,
    st_blksize: u64,
    st_blocks: u64,
    st_atime: u32,
    st_mtime: u32,
    st_ctime: u32,
}

impl From<FileStat> for HostioStat {
    fn from(stat: FileStat) -> HostioStat {
        HostioStat {
            st_dev: stat.st_dev as u32,
            st_ino: stat.st_ino as u32,
            st_nlink: stat.st_nlink as u32,
            st_mode: stat.st_mode as u32,
            st_uid: stat.st_uid,
            st_gid: stat.st_gid,
            st_rdev: stat.st_rdev as u32,
            st_size: stat.st_size as u64,
            st_blksize: stat.st_blksize as u64,
            st_blocks: stat.st_blocks as u64,
            st_atime: stat.st_atime as u32,
            st_mtime: stat.st_mtime as u32,
            st_ctime: stat.st_ctime as u32,
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum vFile {
    Setfs(Option<i32>),
    Open(PathBuf, i32, u32),
    Close(i32),
    Pread(i32, isize, isize),
    Pwrite(i32, isize, Vec<u8>),
    Fstat(i32),
    Unlink(PathBuf),
    Readlink(PathBuf),
}

impl ParseCommand for vFile {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        if bytes.starts_with(b":setfs:") {
            let pid: i32 = decode_hex(&bytes[b":setfs:".len()..]).ok()?;
            Some(vFile::Setfs(if pid == 0 { None } else { Some(pid) }))
        } else if bytes.starts_with(b":open:") {
            let mut iter = bytes[b":open:".len()..].split_mut(|c| *c == b',');
            let fname = iter.next().and_then(|s| decode_hex_string(s).ok())?;
            let fname = PathBuf::from(OsString::from_vec(fname));
            let flags = iter.next().and_then(|s| decode_hex(s).ok())?;
            let mode = iter.next().and_then(|s| decode_hex(s).ok())?;
            Some(vFile::Open(fname, flags, mode))
        } else if bytes.starts_with(b":close:") {
            let fd: i32 = decode_hex(&bytes[b":close:".len()..]).ok()?;
            Some(vFile::Close(fd))
        } else if bytes.starts_with(b":pread:") {
            let mut iter = bytes[b":pread:".len()..].split_mut(|c| *c == b',');
            let fd = iter.next().and_then(|s| decode_hex(s).ok())?;
            let count = iter.next().and_then(|s| decode_hex(s).ok())?;
            let offset = iter.next().and_then(|s| decode_hex(s).ok())?;
            Some(vFile::Pread(fd, count, offset))
        } else if bytes.starts_with(b":pwrite:") {
            let mut iter = bytes[b":pwrite:".len()..].split_mut(|c| *c == b',');
            let fd = iter.next().and_then(|s| decode_hex(s).ok())?;
            let offset = iter.next().and_then(|s| decode_hex(s).ok())?;
            let bytes = iter.next().and_then(|s| decode_binary_string(s).ok())?;
            Some(vFile::Pwrite(fd, offset, bytes))
        } else if bytes.starts_with(b":fstat:") {
            let fd: i32 = decode_hex(&bytes[b":fstat:".len()..]).ok()?;
            Some(vFile::Fstat(fd))
        } else if bytes.starts_with(b":unlink:") {
            let fname = bytes.split_off(b":unlink:".len());
            let fname = decode_hex_string(&fname).ok()?;
            let fname = PathBuf::from(OsString::from_vec(fname));
            Some(vFile::Unlink(fname))
        } else if bytes.starts_with(b":readlink:") {
            let fname = bytes.split_off(b":readlink:".len());
            let fname = decode_hex_string(&fname).ok()?;
            let fname = PathBuf::from(OsString::from_vec(fname));
            Some(vFile::Readlink(fname))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem;

    #[test]
    fn hostio_stat_size_check() {
        assert_eq!(mem::size_of::<HostioStat>(), 0x40);
    }

    #[test]
    fn hostio_sanity() {
        // NB: `vFile` prefix is stripped prior.
        assert_eq!(
            vFile::parse(BytesMut::from(&b":open:6a7573742070726f62696e67,0,1c0"[..])),
            Some(vFile::Open(PathBuf::from("just probing"), 0x0, 0x1c0))
        );
        assert_eq!(
            vFile::parse(BytesMut::from(&b":pread:b,1000,0"[..])),
            Some(vFile::Pread(0xb, 0x1000, 0x0))
        );
        assert_eq!(
            vFile::parse(BytesMut::from(&b":unlink:6a7573742070726f62696e67"[..])),
            Some(vFile::Unlink(PathBuf::from("just probing")))
        );
        assert_eq!(
            vFile::parse(BytesMut::from(&b":readlink:6a7573742070726f62696e67"[..])),
            Some(vFile::Readlink(PathBuf::from("just probing")))
        );
    }
}
