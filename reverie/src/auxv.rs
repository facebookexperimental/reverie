/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeMap;
use std::io;

use byteorder::NativeEndian;
use byteorder::ReadBytesExt;

use crate::Pid;
use crate::syscalls::Addr;

/// `AT_MINSIGSTKSZ`: the smallest signal stack the kernel can deliver on.
pub const AT_MINSIGSTKSZ: libc::c_ulong = 51;
/// `AT_RSEQ_FEATURE_SIZE`: the size of the rseq area features the kernel
/// supports. glibc registers rseq with it as the length.
pub const AT_RSEQ_FEATURE_SIZE: libc::c_ulong = 27;
/// `AT_RSEQ_ALIGN`: the alignment the kernel requires of the rseq area.
pub const AT_RSEQ_ALIGN: libc::c_ulong = 28;

/// The value every backend gives a guest for the auxiliary-vector entry
/// `key`, when the entry describes the CPU or the kernel rather than the
/// process, so that a guest starts up the same way on every host and under
/// every backend (<https://github.com/rrnewton/reverie/issues/947>,
/// <https://github.com/rrnewton/reverie/issues/449>). `None` for every other
/// entry.
///
/// - `AT_HWCAP` is CPUID leaf 1 EDX, and `AT_HWCAP2` the FSGSBASE bit of leaf
///   7 EBX, of the virtual CPU Detcore presents (hermit's
///   detcore/src/cpuid.rs, which a hermit test compares with these). Both
///   advertise a subset of what any supported host can do.
/// - `AT_MINSIGSTKSZ` must cover the largest signal frame any supported host
///   kernel writes, since under ptrace the host kernel writes them: 3,376
///   bytes on an AVX-512 host and about 11 KiB on an AMX host. 16 KiB covers
///   both.
/// - `AT_RSEQ_FEATURE_SIZE` and `AT_RSEQ_ALIGN` are Linux 6.3's, the first
///   release to report them.
pub const fn canonical_auxv_value(key: libc::c_ulong) -> Option<libc::c_ulong> {
    match key {
        libc::AT_HWCAP => Some(0x078b_fbfd),
        libc::AT_HWCAP2 => Some(0),
        AT_MINSIGSTKSZ => Some(16384),
        AT_RSEQ_FEATURE_SIZE => Some(28),
        AT_RSEQ_ALIGN => Some(32),
        _ => None,
    }
}

/// Refuses a host whose kernel reports an `AT_MINSIGSTKSZ` larger than the
/// canonical one: there a guest that sizes its alternate signal stack from
/// the canonical value could overflow it, since under ptrace the host kernel
/// writes the signal frames. `kernel_value` is what the host kernel put in an
/// auxiliary vector; 0 means it reported none.
pub fn check_host_minsigstksz(kernel_value: libc::c_ulong) -> Result<(), String> {
    let canonical = canonical_auxv_value(AT_MINSIGSTKSZ).unwrap_or(0);
    if kernel_value > canonical {
        return Err(format!(
            "this host's kernel reports AT_MINSIGSTKSZ {kernel_value}, larger than the \
             {canonical} bytes Reverie gives every guest; its signal frames would not \
             fit a guest's alternate signal stack"
        ));
    }
    Ok(())
}

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
    /// Builds an auxiliary vector from backend-provided key/value entries.
    ///
    /// Backends without a host process, such as a bare KVM guest, can use this
    /// to report the auxiliary vector they installed on the guest stack.
    pub fn from_entries(entries: impl IntoIterator<Item = (libc::c_ulong, libc::c_ulong)>) -> Self {
        Self {
            map: entries.into_iter().collect(),
        }
    }

    /// Reads the auxiliary values from `/proc/{pid}/auxv`.
    pub(crate) fn new(pid: Pid) -> io::Result<Self> {
        let mut map = BTreeMap::new();
        let buf = crate::process::launch_window::read(format!("/proc/{}/auxv", pid))?;

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
    pub fn at_random(&self) -> Option<Addr<'_, [u8; 16]>> {
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
    fn builds_from_backend_entries() {
        let map = Auxv::from_entries([
            (libc::AT_UID, 123),
            (libc::AT_GID, 456),
            (libc::AT_RANDOM, 0x1000),
        ]);

        assert_eq!(map.len(), 3);
        assert_eq!(map.at_uid(), Some(123));
        assert_eq!(map.at_gid(), Some(456));
        assert_eq!(
            map.at_random().map(|address| address.as_raw()),
            Some(0x1000),
        );
    }

    #[test]
    fn only_cpu_and_kernel_entries_have_canonical_values() {
        for key in [
            libc::AT_HWCAP,
            libc::AT_HWCAP2,
            AT_MINSIGSTKSZ,
            AT_RSEQ_FEATURE_SIZE,
            AT_RSEQ_ALIGN,
        ] {
            assert!(canonical_auxv_value(key).is_some(), "{key}");
        }
        for key in [
            libc::AT_PHDR,
            libc::AT_ENTRY,
            libc::AT_RANDOM,
            libc::AT_UID,
            libc::AT_SYSINFO_EHDR,
            libc::AT_EXECFN,
        ] {
            assert_eq!(canonical_auxv_value(key), None, "{key}");
        }
    }

    #[test]
    fn a_host_needing_larger_signal_stacks_is_refused() {
        assert_eq!(check_host_minsigstksz(0), Ok(()));
        assert_eq!(check_host_minsigstksz(3376), Ok(()));
        assert_eq!(check_host_minsigstksz(16384), Ok(()));
        let error = check_host_minsigstksz(16385).unwrap_err();
        assert!(error.contains("16385"), "{error}");
        assert!(error.contains("16384"), "{error}");
    }

    #[test]
    fn this_host_fits_the_canonical_signal_stack() {
        assert_eq!(
            check_host_minsigstksz(unsafe { libc::getauxval(AT_MINSIGSTKSZ) }),
            Ok(())
        );
    }

    #[test]
    fn smoke() {
        let map = Auxv::new(Pid::this()).unwrap();
        assert!(!map.is_empty());
        assert_eq!(map.at_uid(), Some(unsafe { libc::getuid() }));
        assert_eq!(map.at_gid(), Some(unsafe { libc::getgid() }));
        assert!(map.at_random().is_some());
    }
}
