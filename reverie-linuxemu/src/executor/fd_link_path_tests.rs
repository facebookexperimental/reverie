/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use super::*;

/// The descriptors the path builder must spell exactly as `format!` does:
/// one and two digits, every power-of-ten boundary near the ends, the
/// extremes and negative values (which name no descriptor, so `readlink`
/// fails on them as it did on the formatted path).
const DESCRIPTORS: &[RawFd] = &[
    0,
    1,
    9,
    10,
    11,
    99,
    100,
    999,
    1000,
    65535,
    1_000_000_000,
    i32::MAX - 1,
    i32::MAX,
    -1,
    -9,
    -10,
    -100,
    i32::MIN + 1,
    i32::MIN,
];

fn memfd(name: &CStr) -> OwnedFd {
    // SAFETY: name is NUL-terminated.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    // SAFETY: memfd_create returned a new descriptor that nothing else owns.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[test]
fn proc_self_fd_path_spells_each_descriptor_as_format_does() {
    for &fd in DESCRIPTORS {
        let path = ProcSelfFdPath::new(fd);
        let expected = format!("/proc/self/fd/{fd}");
        assert_eq!(&path.bytes[..path.len], expected.as_bytes(), "fd {fd}");
        assert_eq!(
            path.as_c_str(),
            CString::new(expected).unwrap().as_c_str(),
            "fd {fd}"
        );
    }
    // The longest descriptor fills the buffer exactly, NUL included.
    assert_eq!(
        ProcSelfFdPath::new(i32::MIN).len + 1,
        PROC_SELF_FD_PATH_CAPACITY
    );
}

#[test]
fn fd_link_reads_match_the_formatted_path_reads() {
    let file = memfd(c"fd-link-path");
    let fd = file.as_raw_fd();
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    assert_eq!(
        target.as_os_str().as_bytes(),
        b"/memfd:fd-link-path (deleted)"
    );
    assert_eq!(canonical_fd_path(fd), Ok(target));
    // A buffer shorter than the target holds its first bytes, as readlink
    // truncates.
    let mut short = [0u8; 8];
    assert_eq!(read_fd_link_into(fd, &mut short), Ok(8));
    assert_eq!(&short, b"/memfd:f");
    // Descriptors that name nothing fail the same way the formatted path
    // did: a negative one has no entry, and so does an unused one.
    for missing in [-1, i32::MIN, i32::MAX] {
        let formatted = std::fs::read_link(format!("/proc/self/fd/{missing}"))
            .unwrap_err()
            .raw_os_error()
            .unwrap();
        assert_eq!(
            canonical_fd_path(missing),
            Err(negative_errno(formatted)),
            "fd {missing}"
        );
        assert!(!fd_link_target_is(missing, b"anon_inode:[pidfd]"));
    }
}

#[test]
fn fd_link_target_is_requires_the_whole_target() {
    let file = memfd(c"x");
    let fd = file.as_raw_fd();
    assert!(fd_link_target_is(fd, b"/memfd:x (deleted)"));
    // A prefix, a longer string, and a same-length different string differ.
    assert!(!fd_link_target_is(fd, b"/memfd:x"));
    assert!(!fd_link_target_is(fd, b"/memfd:x (deleted)!"));
    assert!(!fd_link_target_is(fd, b"/memfd:y (deleted)"));

    // A target longer than the stack buffer reads as its first 64 bytes,
    // which never equal a shorter expected string, even one that is its
    // prefix.
    let long_name = c"fd-link-path-a-name-long-enough-to-fill-the-sixty-four-byte-buffer";
    let long = memfd(long_name);
    let target = canonical_fd_path(long.as_raw_fd()).unwrap();
    assert!(target.as_os_str().len() > 64);
    let prefix: [u8; 63] = target.as_os_str().as_bytes()[..63].try_into().unwrap();
    assert!(!fd_link_target_is(long.as_raw_fd(), &prefix));

    // The supervisor's own pidfd reads as Linux names it with and without
    // pidfs.
    // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    assert!(
        pidfd >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: pidfd_open returned a new descriptor that nothing else owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    assert!(fd_link_target_is(pidfd.as_raw_fd(), b"anon_inode:[pidfd]"));
    assert!(!fd_link_target_is(fd, b"anon_inode:[pidfd]"));
}
