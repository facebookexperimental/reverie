/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The consumer-injected traits: identity, time, presentation, and
//! host performance. Everything policy-shaped (which numbers, which
//! times, which presented capacities, how a host operation is
//! carried out) enters the model here; the model itself decides
//! only what Linux would do with those inputs.

use alloc::vec::Vec;

use crate::Errno;
use crate::request::CallerContext;
use crate::request::IdentifiedPath;
use crate::request::Observed;
use crate::request::Request;
use crate::types::IdKind;
use crate::types::Timespec;

/// Source of every identifier the guest can observe. Implementations
/// must never repeat a value within one [`IdKind`] for the life of
/// a model; whether the sequence is reproducible is the consumer's
/// choice, not the model's.
pub trait IdSource {
    /// Draw the next identifier of `kind`.
    fn next_id(&mut self, kind: IdKind) -> u64;
}

/// Source of the timestamps the model records for mount points it
/// creates.
pub trait Clock {
    /// The current time.
    fn now(&mut self) -> Timespec;
}

/// Facts about one filesystem (superblock) that rendering and
/// `statfs` need. For filesystems the model did not create (an
/// initial root, the source of a bind), the consumer seeds these;
/// they are facts about identity, while the *presented* capacity
/// numbers are policy and come from [`Presentation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsFacts {
    /// Filesystem type name (`tmpfs`, `ext4`, ...), as bytes.
    pub fs_type: Vec<u8>,
    /// Mount source (`none`, a device name, ...), as bytes.
    pub source: Vec<u8>,
    /// Superblock options, verbatim (the last `mountinfo` field).
    pub super_options: Vec<u8>,
    /// `statfs` `f_type` magic for this filesystem type.
    pub magic: u64,
    /// Device major number shown for this superblock. The minor is
    /// drawn from [`IdKind::DeviceMinor`] when the superblock is
    /// seeded.
    pub dev_major: u32,
    /// Fundamental block size (`f_bsize` and `f_frsize`) and the
    /// maximum filename length (`f_namelen`); identity facts the
    /// presentation function may keep or present differently.
    pub block_size: u64,
    /// Maximum filename length (`f_namelen`).
    pub name_max: u64,
}

/// The presented `statfs` view of one superblock. Field names
/// follow `statfs(2)`; the model overrides `magic`, `fsid`, and
/// `flags` from its own records (see [`crate::Model::statfs`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatfsView {
    /// `f_type`.
    pub magic: u64,
    /// `f_bsize`.
    pub block_size: u64,
    /// `f_blocks`.
    pub blocks: u64,
    /// `f_bfree`.
    pub blocks_free: u64,
    /// `f_bavail`.
    pub blocks_available: u64,
    /// `f_files`.
    pub files: u64,
    /// `f_ffree`.
    pub files_free: u64,
    /// `f_fsid` (model-authoritative; see [`crate::Model::statfs`]).
    pub fsid: u64,
    /// `f_namelen`.
    pub name_max: u64,
    /// `f_frsize`.
    pub fragment_size: u64,
    /// `f_flags` (`ST_*` bits, model-authoritative).
    pub flags: u64,
}

/// Values shown where Linux would show host-derived ones. A
/// consumer that wants host truth returns it; a consumer that wants
/// a presented machine returns that. The model never reads a host
/// fact except through here and through [`Performer`].
pub trait Presentation {
    /// The presented `statfs` view for a filesystem with `facts`.
    fn filesystem_view(&self, facts: &FsFacts) -> StatfsView;

    /// The memory size Linux's machine-derived filesystem defaults
    /// (for example an omitted tmpfs `size=`) are computed from.
    /// No bind or unmount decision reads it today; it is part of
    /// the injection contract so filesystem-creating mounts added
    /// later present through the same seam.
    fn memory_size(&self) -> u64;
}

/// Whether operand identification follows a final-component
/// symlink. Intermediate symlinks are always followed, as Linux
/// resolves them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Follow {
    /// Follow the final component if it is a symlink.
    FollowFinal,
    /// Identify the final component itself (`UMOUNT_NOFOLLOW`).
    NoFollowFinal,
}

/// Identifies targets and carries out admitted host operations.
/// Implementations carry no mount semantics: every decision about
/// what a request means belongs to the model, so two consumers
/// with different performers cannot diverge in meaning.
pub trait Performer {
    /// Resolve `path` (as the guest spelled it) from `caller`'s
    /// root and working directory and report the object found. On
    /// Linux this is one `statx`: the unique (kernel) mount ID,
    /// file type, and mount-root attribute, plus the object's path
    /// below that mount's visible root. Resolution errors are
    /// Linux's (`ENOENT`, `ENOTDIR`, `ELOOP`, ...) and reach the
    /// guest unchanged. No reference to the object is kept: the
    /// performed call re-resolves its original arguments, so the
    /// kernel's own rules (busy mounts, final symlinks) apply at
    /// the moment of the call.
    fn identify(
        &mut self,
        caller: &CallerContext,
        path: &[u8],
        follow: Follow,
    ) -> Result<IdentifiedPath, Errno>;

    /// Carry out the guest's call as made, in `caller`'s context,
    /// and report the kernel's outcome: the return value, and on
    /// success the mounts created (bind) or removed (unmount),
    /// read back by unique mount ID (`listmount(2)`/`statmount(2)`
    /// on Linux 6.8 and later). `effective_data` is the mount data
    /// to pass instead of the guest's when the model creates a
    /// filesystem and approved an effective option set; it is
    /// `None` for bind and unmount, which perform the guest's call
    /// byte for byte.
    fn perform(
        &mut self,
        caller: &CallerContext,
        call: &Request,
        effective_data: Option<&[u8]>,
    ) -> Observed;
}
