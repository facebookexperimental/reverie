/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Small identity and value types shared by the model and its
//! consumers. Every identifier the guest can observe is minted by
//! the consumer's [`crate::IdSource`]; these newtypes keep the
//! namespaces of IDs from being confused with each other or with
//! the kernel's own (host) mount identities, which appear only in
//! [`crate::IdentifiedPath`] and [`crate::ObservedMount`].

/// A mount's identity in the model (the value rendering shows and
/// `statx` would report as the mount ID). Minted through
/// [`IdKind::Mount`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MountId(pub u64);

/// A namespace's identity in the model, of any kind. Minted through
/// [`IdKind::Namespace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NsId(pub u64);

/// A superblock's identity in the model. Bind mounts share their
/// source's superblock, so device numbers follow the superblock
/// while mount IDs follow the mount. Assigned by the model in
/// seed order; the shown device minor and `f_fsid` come from the
/// consumer's source (see [`IdKind::DeviceMinor`] and
/// [`IdKind::FilesystemId`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SbId(pub u64);

/// A consumer-supplied task identity. The model records which
/// mount namespace each task belongs to; it neither mints nor
/// interprets task identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskKey(pub u64);

/// Which counter an [`crate::IdSource`] is asked to draw from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// Mount IDs (field 1 of a `mountinfo` row, `statx` mount ID).
    Mount,
    /// Propagation peer-group IDs (`shared:`, `master:` fields).
    PeerGroup,
    /// Device minor numbers (the shown `st_dev` of a superblock).
    DeviceMinor,
    /// Namespace identities (all namespace kinds).
    Namespace,
    /// `statfs` `f_fsid` values, one per superblock.
    FilesystemId,
}

/// A point in time as the consumer's clock reports it. The model
/// stores one per mount it creates (the mount point's mtime as
/// presented to the guest); normalization (`0 <= nsec < 1e9`) is the
/// clock's contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    /// Whole seconds.
    pub sec: i64,
    /// Nanoseconds within the second.
    pub nsec: i32,
}

/// The file type of an identified path operand, as one `statx`
/// reports it. Only the distinction Linux's bind rules check is
/// modeled (directory versus non-directory), plus symlinks for
/// no-follow decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    /// A directory.
    Directory,
    /// A regular file.
    RegularFile,
    /// A symbolic link (seen with [`crate::Follow::NoFollowFinal`]).
    Symlink,
    /// Anything else (device node, FIFO, socket, ...).
    Other,
}

impl FileType {
    /// Whether this type can be the target of a bind of `other`.
    /// Linux requires a directory to be bound onto a directory and
    /// a non-directory onto a non-directory; mixing them fails
    /// with `ENOTDIR` (`mount(2)` ERRORS, verified against the
    /// kernel).
    pub fn bind_compatible(self, other: FileType) -> bool {
        matches!(self, FileType::Directory) == matches!(other, FileType::Directory)
    }
}
