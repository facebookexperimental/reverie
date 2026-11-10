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

    // libc's aarch64 `stat` keeps its padding fields private, so it cannot be
    // built field by field; start from zeroes, which Linux leaves in the
    // padding too, and copy every public field.
    #[cfg(target_arch = "aarch64")]
    fn from(buf: StatBuf) -> libc::stat {
        // SAFETY: `libc::stat` holds only integers, so all zeroes is a valid value.
        let mut stat: libc::stat = unsafe { core::mem::zeroed() };
        stat.st_dev = buf.st_dev;
        stat.st_ino = buf.st_ino;
        stat.st_mode = buf.st_mode;
        stat.st_nlink = buf.st_nlink;
        stat.st_uid = buf.st_uid;
        stat.st_gid = buf.st_gid;
        stat.st_rdev = buf.st_rdev;
        stat.st_size = buf.st_size;
        stat.st_blksize = buf.st_blksize;
        stat.st_blocks = buf.st_blocks;
        stat.st_atime = buf.st_atime;
        stat.st_atime_nsec = buf.st_atime_nsec;
        stat.st_mtime = buf.st_mtime;
        stat.st_mtime_nsec = buf.st_mtime_nsec;
        stat.st_ctime = buf.st_ctime;
        stat.st_ctime_nsec = buf.st_ctime_nsec;
        stat
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

#[cfg(not(target_env = "musl"))]
impl From<StatxTimestamp> for libc::statx_timestamp {
    fn from(buf: StatxTimestamp) -> libc::statx_timestamp {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }
}

#[cfg(not(target_env = "musl"))]
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

#[cfg(not(target_env = "musl"))]
impl From<StatxBuf> for libc::statx {
    fn from(buf: StatxBuf) -> libc::statx {
        // The layout and size is exactly the same, so this transmute is safe to
        // do.
        unsafe { core::mem::transmute(buf) }
    }
}

#[cfg(not(target_env = "musl"))]
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
        #[cfg(not(target_env = "musl"))]
        assert_eq!(size_of::<StatxBuf>(), size_of::<libc::statx>());
        #[cfg(not(target_env = "musl"))]
        assert_eq!(
            size_of::<StatxTimestamp>(),
            size_of::<libc::statx_timestamp>()
        );
    }

    /// Every public field survives the conversion to `libc::stat`, which
    /// deserializing a recorded `stat` result (`#[serde(with = "StatBuf")]`)
    /// performs. Each field gets a distinct value, so a swapped or dropped
    /// field fails.
    #[test]
    fn a_stat_buffer_converts_field_for_field() {
        #[cfg(target_arch = "x86_64")]
        let buf = StatBuf {
            st_dev: 1,
            st_ino: 2,
            st_nlink: 4,
            st_mode: 3,
            st_uid: 5,
            st_gid: 6,
            __pad0: 0,
            st_rdev: 7,
            st_size: 8,
            st_blksize: 9,
            st_blocks: 10,
            st_atime: 11,
            st_atime_nsec: 12,
            st_mtime: 13,
            st_mtime_nsec: 14,
            st_ctime: 15,
            st_ctime_nsec: 16,
            __unused: [0; 3],
        };
        #[cfg(target_arch = "aarch64")]
        let buf = StatBuf {
            st_dev: 1,
            st_ino: 2,
            st_mode: 3,
            st_nlink: 4,
            st_uid: 5,
            st_gid: 6,
            st_rdev: 7,
            __pad1: 0,
            st_size: 8,
            st_blksize: 9,
            __pad2: 0,
            st_blocks: 10,
            st_atime: 11,
            st_atime_nsec: 12,
            st_mtime: 13,
            st_mtime_nsec: 14,
            st_ctime: 15,
            st_ctime_nsec: 16,
            __unused4: 0,
            __unused5: 0,
        };
        let stat = libc::stat::from(buf);
        assert_eq!(
            (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_nlink),
            (1, 2, 3, 4)
        );
        assert_eq!((stat.st_uid, stat.st_gid, stat.st_rdev), (5, 6, 7));
        assert_eq!((stat.st_size, stat.st_blksize, stat.st_blocks), (8, 9, 10));
        assert_eq!(
            (
                stat.st_atime,
                stat.st_atime_nsec,
                stat.st_mtime,
                stat.st_mtime_nsec
            ),
            (11, 12, 13, 14)
        );
        assert_eq!((stat.st_ctime, stat.st_ctime_nsec), (15, 16));
    }

    #[test]
    fn alignment() {
        assert_eq!(align_of::<StatBuf>(), align_of::<libc::stat>());
        #[cfg(not(target_env = "musl"))]
        assert_eq!(align_of::<StatxBuf>(), align_of::<libc::statx>());
        #[cfg(not(target_env = "musl"))]
        assert_eq!(
            align_of::<StatxTimestamp>(),
            align_of::<libc::statx_timestamp>()
        );
    }
}

// The adapter deliberately preserves the entire 256-byte image, including newer
// kernel fields carried in its private reserved tail. Never rebuild this
// image field by field and silently discard those bytes.
const _: () = {
    assert!(
        core::mem::size_of::<StatxBuf>() == core::mem::size_of::<crate::linux_abi::KernelStatx>()
    );
    assert!(
        core::mem::align_of::<StatxBuf>() == core::mem::align_of::<crate::linux_abi::KernelStatx>()
    );
    assert!(
        core::mem::size_of::<StatxTimestamp>()
            == core::mem::size_of::<crate::linux_abi::KernelStatxTimestamp>()
    );
    assert!(
        core::mem::align_of::<StatxTimestamp>()
            == core::mem::align_of::<crate::linux_abi::KernelStatxTimestamp>()
    );
    assert!(
        core::mem::offset_of!(StatxTimestamp, tv_sec)
            == core::mem::offset_of!(crate::linux_abi::KernelStatxTimestamp, tv_sec)
    );
    assert!(
        core::mem::offset_of!(StatxTimestamp, tv_nsec)
            == core::mem::offset_of!(crate::linux_abi::KernelStatxTimestamp, tv_nsec)
    );
    assert!(
        core::mem::offset_of!(StatxTimestamp, __statx_timestamp_pad1)
            == core::mem::offset_of!(crate::linux_abi::KernelStatxTimestamp, __reserved)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_mask)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_mask)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_blksize)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_blksize)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_attributes)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_attributes)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_nlink)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_nlink)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_uid)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_uid)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_gid)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_gid)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_mode)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_mode)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_ino)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_ino)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_size)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_size)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_blocks)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_blocks)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_attributes_mask)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_attributes_mask)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_atime)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_atime)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_btime)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_btime)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_ctime)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_ctime)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_mtime)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_mtime)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_rdev_major)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_rdev_major)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_rdev_minor)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_rdev_minor)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_dev_major)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_dev_major)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_dev_minor)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_dev_minor)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, stx_mnt_id)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_mnt_id)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, __statx_pad1)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, __spare0)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, __statx_pad2)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_dio_mem_align)
    );
    assert!(
        core::mem::offset_of!(StatxBuf, __statx_pad3)
            == core::mem::offset_of!(crate::linux_abi::KernelStatx, stx_subvol)
    );
};

impl From<StatxBuf> for crate::linux_abi::KernelStatx {
    fn from(value: StatxBuf) -> Self {
        // SAFETY: integer-only representations; size, alignment and all named
        // field offsets are checked above. The reserved tail is copied intact.
        unsafe { core::mem::transmute(value) }
    }
}

impl From<crate::linux_abi::KernelStatx> for StatxBuf {
    fn from(value: crate::linux_abi::KernelStatx) -> Self {
        // SAFETY: the same integer-only layout checks apply in reverse.
        unsafe { core::mem::transmute(value) }
    }
}

#[cfg(test)]
mod kernel_abi_tests {
    use super::*;

    #[test]
    fn statx_all_bytes_round_trip_including_new_kernel_tail() {
        for fill in [0u8, 0x55, 0xaa, 0xff] {
            let bytes: [u8; 256] = core::array::from_fn(|i| fill ^ i as u8);
            // SAFETY: the generated UAPI consists entirely of integer fields;
            // every bit pattern is valid, and its size is checked above.
            let kernel: crate::linux_abi::KernelStatx = unsafe { core::mem::transmute(bytes) };
            let adapted = StatxBuf::from(kernel);
            let kernel = crate::linux_abi::KernelStatx::from(adapted);
            // SAFETY: same integer-only representation, without implicit holes.
            let actual: [u8; 256] = unsafe { core::mem::transmute(kernel) };
            assert_eq!(actual, bytes);
        }
    }
}
