/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Serialization support for stat structs.

use serde::Deserialize;
use serde::Serialize;

/// A serializable version of `libc::stat`.
#[cfg(target_arch = "x86_64")]
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[serde(remote = "libc::stat")]
#[repr(C)]
#[allow(missing_docs)]
pub struct StatBuf {
    pub st_dev: libc::dev_t,
    pub st_ino: libc::ino64_t,
    pub st_nlink: libc::nlink_t,
    pub st_mode: libc::mode_t,
    pub st_uid: libc::uid_t,
    pub st_gid: libc::gid_t,
    #[serde(getter = "unused")]
    __pad0: libc::c_int,
    pub st_rdev: libc::dev_t,
    pub st_size: libc::off_t,
    pub st_blksize: libc::blksize_t,
    pub st_blocks: libc::blkcnt64_t,
    pub st_atime: libc::time_t,
    pub st_atime_nsec: i64,
    pub st_mtime: libc::time_t,
    pub st_mtime_nsec: i64,
    pub st_ctime: libc::time_t,
    pub st_ctime_nsec: i64,
    #[serde(getter = "unused")]
    __unused: [i64; 3],
}

/// A serializable version of `libc::stat`.
#[cfg(target_arch = "aarch64")]
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[serde(remote = "libc::stat")]
#[repr(C)]
#[allow(missing_docs)]
pub struct StatBuf {
    pub st_dev: libc::dev_t,
    pub st_ino: libc::ino_t,
    pub st_mode: libc::c_uint,
    pub st_nlink: libc::nlink_t,
    pub st_uid: libc::uid_t,
    pub st_gid: libc::gid_t,
    pub st_rdev: libc::dev_t,
    #[serde(getter = "unused")]
    __pad1: libc::c_ulong,
    pub st_size: libc::off64_t,
    pub st_blksize: libc::c_int,
    #[serde(getter = "unused")]
    __pad2: libc::c_int,
    pub st_blocks: libc::c_long,
    pub st_atime: libc::time_t,
    pub st_atime_nsec: libc::c_long,
    pub st_mtime: libc::time_t,
    pub st_mtime_nsec: libc::c_long,
    pub st_ctime: libc::time_t,
    pub st_ctime_nsec: libc::c_long,
    #[serde(getter = "unused")]
    __unused4: libc::c_uint,
    #[serde(getter = "unused")]
    __unused5: libc::c_uint,
}

fn unused<T: Default>(_stat: &libc::stat) -> T {
    T::default()
}

impl From<StatBuf> for libc::stat {
    #[cfg(not(target_arch = "aarch64"))]
    fn from(buf: StatBuf) -> libc::stat {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }

    // aarch64 cannot transmute
    #[cfg(target_arch = "aarch64")]
    fn from(buf: StatBuf) -> libc::stat {
        todo!("aarch64 implementation is incomplete");
    }
}

/// A serializable version of `libc::statx`.
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(C)]
#[allow(missing_docs)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    #[serde(skip)]
    __statx_timestamp_pad1: [i32; 1],
}

impl From<StatxTimestamp> for libc::statx_timestamp {
    fn from(buf: StatxTimestamp) -> libc::statx_timestamp {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }
}

impl From<libc::statx_timestamp> for StatxTimestamp {
    fn from(buf: libc::statx_timestamp) -> StatxTimestamp {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }
}

/// A serializable version of `libc::statx`.
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(C)]
#[allow(missing_docs)]
pub struct StatxBuf {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    #[serde(skip)]
    __statx_pad1: [u16; 1],
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    #[serde(skip)]
    __statx_pad2: u64,
    #[serde(skip)]
    __statx_pad3: [u64; 12],
}

impl From<StatxBuf> for libc::statx {
    fn from(buf: StatxBuf) -> libc::statx {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }
}

impl From<libc::statx> for StatxBuf {
    fn from(buf: libc::statx) -> StatxBuf {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::align_of;
    use core::mem::size_of;

    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size_of::<StatBuf>(), size_of::<libc::stat>());
        assert_eq!(size_of::<StatxBuf>(), size_of::<libc::statx>());
        assert_eq!(
            size_of::<StatxTimestamp>(),
            size_of::<libc::statx_timestamp>()
        );
    }

    #[test]
    fn alignment() {
        assert_eq!(align_of::<StatBuf>(), align_of::<libc::stat>());
        assert_eq!(align_of::<StatxBuf>(), align_of::<libc::statx>());
        assert_eq!(
            align_of::<StatxTimestamp>(),
            align_of::<libc::statx_timestamp>()
        );
    }
}
