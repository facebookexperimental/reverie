/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::collections::BTreeMap;
use std::fs;
use std::io;

use byteorder::NativeEndian;
use byteorder::ReadBytesExt;

use crate::syscalls::Addr;
use crate::Pid;

/// Represents the auxv table of a process.
///
/// NOTE: This is not necessarily the same table as the one used by
/// [`libc::getauxval`]. For dynamically linked programs, glibc will copy this
/// table early on in the start up of the program and may modify it. Thus, it is
/// really only safe to modify this immediately after `execve` runs.
pub struct Auxv {
    map: BTreeMap<libc::c_ulong, libc::c_ulong>,
}

impl Auxv {
    /// Reads the auxiliary values from `/proc/{pid}/auxv`.
    pub(crate) fn new(pid: Pid) -> io::Result<Self> {
        let mut map = BTreeMap::new();
        let buf = fs::read(format!("/proc/{}/auxv", pid))?;

        // The file size should be a multiple of `size_of::<u64>() * 2`.
        debug_assert_eq!(
            buf.len() % 16,
            0,
            "got invalid size of auxv file: {} bytes",
            buf.len()
        );

        let mut file = io::Cursor::new(buf);

        loop {
            let key = file.read_u64::<NativeEndian>()?;
            let value = file.read_u64::<NativeEndian>()?;

            if key == 0 && value == 0 {
                break;
            }

            map.insert(key, value);
        }

        Ok(Self { map })
    }

    /// The number of entries in the auxv table.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The address of sixteen bytes containing a random value.
    ///
    /// Returns `None` if the address is NULL or if `AT_RANDOM` does not exist in
    /// the auxv table.
    pub fn at_random(&self) -> Option<Addr<[u8; 16]>> {
        self.map
            .get(&libc::AT_RANDOM)
            .and_then(|val| Addr::from_raw(*val as usize))
    }

    /// The user ID of the thread.
    ///
    /// Returns `None` if the `AT_UID` does not exist in the auxv table.
    pub fn at_uid(&self) -> Option<libc::uid_t> {
        self.map.get(&libc::AT_UID).map(|val| *val as libc::uid_t)
    }

    /// The effective user ID of the thread.
    ///
    /// Returns `None` if the `AT_EUID` does not exist in the auxv table.
    pub fn at_euid(&self) -> Option<libc::uid_t> {
        self.map.get(&libc::AT_EUID).map(|val| *val as libc::uid_t)
    }

    /// The group ID of the process.
    ///
    /// Returns `None` if the `AT_GID` does not exist in the auxv table.
    pub fn at_gid(&self) -> Option<libc::gid_t> {
        self.map.get(&libc::AT_GID).map(|val| *val as libc::gid_t)
    }

    /// The effective group ID of the process.
    ///
    /// Returns `None` if the `AT_EGID` does not exist in the auxv table.
    pub fn at_egid(&self) -> Option<libc::gid_t> {
        self.map.get(&libc::AT_EGID).map(|val| *val as libc::gid_t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let map = Auxv::new(Pid::this()).unwrap();
        assert_eq!(map.is_empty(), false);
        assert_eq!(map.at_uid(), Some(unsafe { libc::getuid() }));
        assert_eq!(map.at_gid(), Some(unsafe { libc::getgid() }));
        assert!(map.at_random().is_some());
    }
}
