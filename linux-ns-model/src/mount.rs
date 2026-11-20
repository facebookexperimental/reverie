/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Mount-table records: one [`Mount`] per mount, one [`Superblock`]
//! per filesystem instance. A bind creates mounts that share the
//! source's superblock, so device numbers follow the superblock
//! and mount IDs follow the mount (as `st_dev` and the `statx`
//! mount ID do on Linux).

use alloc::vec::Vec;

use crate::injected::FsFacts;
use crate::types::MountId;
use crate::types::NsId;
use crate::types::SbId;
use crate::types::Timespec;

/// How mounts under this mount propagate, per
/// `mount_namespaces(7)` "Mount propagation" and the kernel's
/// `sharedsubtree.rst`. Group numbers are model identities drawn
/// from [`crate::IdKind::PeerGroup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Propagation {
    /// Mount and unmount events under this mount stay under it.
    Private,
    /// Events propagate neither way, and this mount cannot be the
    /// source of a bind (`EINVAL`, verified against the kernel).
    Unbindable,
    /// This mount is a member of the named peer group: events
    /// under any member appear under every member and under every
    /// slave of the group.
    Shared(u64),
    /// This mount receives events from the named peer group (its
    /// master) but propagates none back. `None` is a slave whose
    /// master group has no remaining member identity to name.
    Slave(Option<u64>),
    /// Both: member of `peer`, and a slave of `master`.
    SharedSlave {
        /// The peer group this mount belongs to.
        peer: u64,
        /// The peer group this mount receives from.
        master: Option<u64>,
    },
}

impl Propagation {
    /// The peer group this mount belongs to, if any.
    pub fn peer_group(self) -> Option<u64> {
        match self {
            Propagation::Shared(g) | Propagation::SharedSlave { peer: g, .. } => Some(g),
            _ => None,
        }
    }

    /// The peer group this mount receives events from, if any.
    pub fn master(self) -> Option<u64> {
        match self {
            Propagation::Slave(m) | Propagation::SharedSlave { master: m, .. } => m,
            _ => None,
        }
    }
}

/// One filesystem instance. Created when a namespace is seeded;
/// bind mounts reference the source mount's superblock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// Model identity.
    pub id: SbId,
    /// Shown device major (from the seeded facts).
    pub dev_major: u32,
    /// Shown device minor, drawn from [`crate::IdKind::DeviceMinor`].
    pub dev_minor: u32,
    /// Shown `statfs` `f_fsid`, drawn from
    /// [`crate::IdKind::FilesystemId`].
    pub fsid: u64,
    /// The identity facts (type, source, super options, magic).
    pub facts: FsFacts,
}

/// Whether a mount is attached in its namespace or lazily detached
/// (`umount2(2)` with `MNT_DETACH`): a detached mount vanishes from
/// path lookup and from `mountinfo`, but descriptors opened in it
/// beforehand still reach it, so its record stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountState {
    /// Attached and visible in its namespace.
    Visible,
    /// Lazily detached; reachable only through open descriptors.
    Detached,
}

/// One mount in one mount namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// Model identity (shown in `mountinfo` field 1).
    pub id: MountId,
    /// The kernel's unique mount ID for this mount, as reported by
    /// the performer. Facts and observations correlate through it;
    /// it is never shown to the guest.
    pub kernel_id: u64,
    /// The mount namespace this mount belongs to.
    pub ns: NsId,
    /// Parent mount (shown in `mountinfo` field 2). The root mount
    /// of a namespace is its own parent, as Linux reports it.
    pub parent: MountId,
    /// Path of the mount point below the parent mount's visible
    /// root, without a leading slash; empty when this mount is
    /// stacked on the parent's root (or is the namespace root).
    pub mountpoint_in_parent: Vec<u8>,
    /// Root of this mount within its filesystem (`mountinfo`
    /// field 4), an absolute in-filesystem path.
    pub root: Vec<u8>,
    /// The filesystem instance this mount belongs to.
    pub sb: SbId,
    /// Per-mount options, verbatim (`mountinfo` field 6). A bind
    /// inherits the source mount's string: the kernel ignores
    /// option flags given when a bind is created.
    pub mount_options: Vec<u8>,
    /// Propagation of events under this mount.
    pub propagation: Propagation,
    /// Attached or detached.
    pub state: MountState,
    /// When this mount point was created, by the consumer's clock.
    pub created: Timespec,
    /// Creation sequence within the model; rendering order follows
    /// it (a parent always precedes its children, as it was
    /// created first).
    pub seq: u64,
}

/// The `statfs` `f_flags` bits implied by option tokens. Linux
/// derives them from the mount and superblock flags; the model
/// keeps options verbatim and reads the flags back out of the
/// tokens (`statfs(2)` `f_flags`: `ST_RDONLY` etc.).
pub(crate) fn statfs_flags(mount_options: &[u8], super_options: &[u8]) -> u64 {
    let mut flags = 0u64;
    for token in mount_options
        .split(|b| *b == b',')
        .chain(super_options.split(|b| *b == b','))
    {
        flags |= match token {
            b"ro" => 1,            // ST_RDONLY
            b"nosuid" => 2,        // ST_NOSUID
            b"nodev" => 4,         // ST_NODEV
            b"noexec" => 8,        // ST_NOEXEC
            b"sync" => 16,         // ST_SYNCHRONOUS
            b"mand" => 64,         // ST_MANDLOCK
            b"noatime" => 1024,    // ST_NOATIME
            b"nodiratime" => 2048, // ST_NODIRATIME
            b"relatime" => 4096,   // ST_RELATIME
            _ => 0,
        };
    }
    flags
}
