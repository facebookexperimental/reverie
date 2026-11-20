/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Linux error numbers, as plain constants.
//!
//! This crate defines its own type rather than depending on a libc
//! or syscall crate: the values are architecture-independent Linux
//! ABI (`asm-generic/errno-base.h`, `asm-generic/errno.h`), and the
//! consumer translates [`Errno::code`] into whatever its syscall
//! layer returns.

/// A Linux `errno` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Errno(i32);

impl Errno {
    /// Wrap a raw Linux error number. Callers are expected to pass
    /// positive values from the constants below or from a failed
    /// syscall; the model never inspects the sign.
    pub const fn from_raw(code: i32) -> Self {
        Self(code)
    }

    /// The raw Linux error number.
    pub const fn code(self) -> i32 {
        self.0
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

/// Operation not permitted. `mount(2)`/`umount2(2)` give it to a
/// caller without `CAP_SYS_ADMIN` in the user namespace owning the
/// target mount namespace; the model also uses it for refusals by
/// name.
pub const EPERM: Errno = Errno(1);
/// No such file or directory (`mount(2)`, `umount2(2)` path
/// resolution).
pub const ENOENT: Errno = Errno(2);
/// Resource temporarily unavailable (`umount2(2)` with
/// `MNT_EXPIRE` on a mount that has not expired).
pub const EAGAIN: Errno = Errno(11);
/// Permission denied (`mount(2)`: a component of a path is not
/// searchable; resolution belongs to the performer).
pub const EACCES: Errno = Errno(13);
/// Device or resource busy (`umount2(2)`: the mount is busy).
pub const EBUSY: Errno = Errno(16);
/// No such device (`mount(2)`: the filesystem type is not
/// configured in the kernel).
pub const ENODEV: Errno = Errno(19);
/// Not a directory (`mount(2)` bind file/directory mismatch).
pub const ENOTDIR: Errno = Errno(20);
/// Invalid argument (`mount(2)`/`umount2(2)` flag validation;
/// `umount2(2)`: the target is not a mount point).
pub const EINVAL: Errno = Errno(22);
/// File name too long (path resolution; the performer reports it).
pub const ENAMETOOLONG: Errno = Errno(36);
/// Too many levels of symbolic links (path resolution; the
/// performer reports it).
pub const ELOOP: Errno = Errno(40);
