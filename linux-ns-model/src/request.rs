/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Requests, operand facts, decisions, and the pending-transition
//! handle. A consumer translates a guest call into a [`Request`],
//! identifies its path operands through its [`crate::Performer`],
//! and asks [`crate::Model::admit`] for a [`Decision`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::Errno;
use crate::injected::Clock;
use crate::injected::IdSource;
use crate::model::Model;
use crate::types::FileType;
use crate::types::MountId;
use crate::types::NsId;
use crate::types::TaskKey;

/// `mount(2)` flag: mount read-only. Ignored when a bind is created.
pub const MS_RDONLY: u64 = 1;
/// `mount(2)` flag: ignore setuid/setgid bits. Ignored on bind.
pub const MS_NOSUID: u64 = 2;
/// `mount(2)` flag: disallow device access. Ignored on bind.
pub const MS_NODEV: u64 = 4;
/// `mount(2)` flag: disallow program execution. Ignored on bind.
pub const MS_NOEXEC: u64 = 8;
/// `mount(2)` flag: synchronous writes. Ignored on bind.
pub const MS_SYNCHRONOUS: u64 = 16;
/// `mount(2)` flag: remount an existing mount.
pub const MS_REMOUNT: u64 = 32;
/// `mount(2)` flag: allow mandatory locks. Ignored on bind.
pub const MS_MANDLOCK: u64 = 64;
/// `mount(2)` flag: synchronous directory writes. Ignored on bind.
pub const MS_DIRSYNC: u64 = 128;
/// `mount(2)` flag: do not follow symlinks. Ignored on bind.
pub const MS_NOSYMFOLLOW: u64 = 256;
/// `mount(2)` flag: do not update access times. Ignored on bind.
pub const MS_NOATIME: u64 = 1024;
/// `mount(2)` flag: do not update directory access times.
pub const MS_NODIRATIME: u64 = 2048;
/// `mount(2)` flag: create a bind mount.
pub const MS_BIND: u64 = 4096;
/// `mount(2)` flag: move a mount.
pub const MS_MOVE: u64 = 8192;
/// `mount(2)` flag: recurse (with `MS_BIND`, copy submounts).
pub const MS_REC: u64 = 16384;
/// `mount(2)` flag: suppress kernel warnings. Ignored on bind.
pub const MS_SILENT: u64 = 32768;
/// `mount(2)` flag: POSIX ACLs. Ignored on bind.
pub const MS_POSIXACL: u64 = 65536;
/// `mount(2)` flag: mark unbindable (a propagation change).
pub const MS_UNBINDABLE: u64 = 131072;
/// `mount(2)` flag: mark private (a propagation change).
pub const MS_PRIVATE: u64 = 262144;
/// `mount(2)` flag: mark slave (a propagation change).
pub const MS_SLAVE: u64 = 524288;
/// `mount(2)` flag: mark shared (a propagation change).
pub const MS_SHARED: u64 = 1048576;
/// `mount(2)` flag: relative atime updates. Ignored on bind.
pub const MS_RELATIME: u64 = 2097152;
/// `mount(2)` flag: update the inode I_version field.
pub const MS_I_VERSION: u64 = 8388608;
/// `mount(2)` flag: always update access times. Ignored on bind.
pub const MS_STRICTATIME: u64 = 16777216;
/// `mount(2)` flag: lazy time updates. Ignored on bind.
pub const MS_LAZYTIME: u64 = 33554432;

/// `umount2(2)` flag: force unmount (meaningful for NFS; accepted
/// and without extra effect elsewhere, as on Linux).
pub const MNT_FORCE: u64 = 1;
/// `umount2(2)` flag: lazy unmount.
pub const MNT_DETACH: u64 = 2;
/// `umount2(2)` flag: mark expired / unmount if expired.
pub const MNT_EXPIRE: u64 = 4;
/// `umount2(2)` flag: do not dereference the target if it is a
/// symlink.
pub const UMOUNT_NOFOLLOW: u64 = 8;

/// Every `umount2(2)` flag bit (`umount2(2)` ERRORS: an unknown
/// flag fails with `EINVAL`).
pub(crate) const UMOUNT_KNOWN_MASK: u64 = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;

/// A location in a namespace's visible tree: a mount plus a path
/// below that mount's visible root (no leading slash; empty means
/// the mount root itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathInNs {
    /// The mount the location is on.
    pub mount: MountId,
    /// Path below the mount's visible root.
    pub below_root: Vec<u8>,
}

/// Who is making a request, in facts the consumer supplies from
/// its process model. The model interprets; it does not look up
/// credentials or working directories itself.
#[derive(Clone, Debug)]
pub struct CallerContext {
    /// The calling task.
    pub task: TaskKey,
    /// The caller's mount namespace.
    pub mount_ns: NsId,
    /// The caller's root directory.
    pub root: PathInNs,
    /// The caller's working directory.
    pub cwd: PathInNs,
    /// Whether the caller holds `CAP_SYS_ADMIN` in the user
    /// namespace that owns `mount_ns`. `mount(2)` and `umount2(2)`
    /// fail with `EPERM` without it. Which credentials confer the
    /// capability is consumer policy, evaluated before admission.
    pub cap_sys_admin_in_owner: bool,
}

/// A bind request, from `mount(2)` with `MS_BIND` in *mountflags*.
/// The `filesystemtype` and `data` arguments are ignored by Linux
/// for a bind, so they are not carried here.
#[derive(Clone, Debug)]
pub struct BindRequest {
    /// The *source* argument, as the guest spelled it.
    pub source: Vec<u8>,
    /// The *target* argument, as the guest spelled it.
    pub target: Vec<u8>,
    /// The full *mountflags* argument, as the guest passed it.
    pub flags: u64,
}

/// An unmount request, from `umount2(2)` (or `umount(2)`, whose
/// flags are zero).
#[derive(Clone, Debug)]
pub struct UmountRequest {
    /// The *target* argument, as the guest spelled it.
    pub target: Vec<u8>,
    /// The *flags* argument (`MNT_*`, `UMOUNT_NOFOLLOW`).
    pub flags: u64,
}

/// One guest call the model can admit. Operations added in later
/// versions arrive as new variants; a consumer refuses any other
/// mount-family call itself until then.
#[derive(Clone, Debug)]
pub enum Request {
    /// A bind mount (`mount(2)` with `MS_BIND`).
    Bind(BindRequest),
    /// An unmount (`umount2(2)`).
    Umount(UmountRequest),
}

/// What [`crate::Performer::identify`] reports about one operand:
/// the object a path resolved to, in terms of the mount that
/// contains it. The model correlates the kernel mount ID with its
/// own records; an ID the model has never seen means the facts and
/// the model disagree (a [`Divergence`]), never a guest error.
#[derive(Clone, Debug)]
pub struct IdentifiedPath {
    /// Unique (kernel) ID of the mount the path resolved on. For a
    /// path that ends at a mount point this is the topmost mount
    /// there, as `statx` reports it.
    pub kernel_mount_id: u64,
    /// Path of the object below that mount's visible root, without
    /// a leading slash; empty when the object is the mount root.
    pub below_mount_root: Vec<u8>,
    /// File type of the object.
    pub file_type: FileType,
    /// Whether the object is the root of its mount (the
    /// `STATX_ATTR_MOUNT_ROOT` attribute).
    pub is_mount_root: bool,
    /// Whether the final path component as spelled is a symlink.
    /// With [`crate::Follow::FollowFinal`] the remaining fields
    /// describe the link's target; this flag records that a
    /// no-follow form of the same call would have seen the link.
    pub final_is_symlink: bool,
}

/// One mount as the performer read it back after a performed call
/// (`statmount(2)` fields). *mount_point* is absolute from the
/// root of the mount namespace the mount belongs to — not from
/// the caller's (possibly narrower) root — so a performer whose
/// performing context is rooted below the namespace root converts
/// before reporting (its observation helper is not the guest's
/// chrooted thread).
#[derive(Clone, Debug)]
pub struct ObservedMount {
    /// Unique (kernel) mount ID of the new mount.
    pub kernel_mount_id: u64,
    /// Unique (kernel) mount ID of its parent mount.
    pub parent_kernel_mount_id: u64,
    /// Root of the mount within its filesystem. This is a deferred
    /// fact: only the call itself resolves it (a source path
    /// through a symlink can land anywhere on the source mount),
    /// and the model's prediction is a function of it.
    pub root: Vec<u8>,
    /// Mount point, absolute from the mount namespace's root.
    pub mount_point: Vec<u8>,
}

/// What [`crate::Performer::perform`] reports: the kernel's return
/// value and, on success, the affected mounts read back by unique
/// ID. A failure carries no effect (a failed `mount(2)` or
/// `umount2(2)` changes nothing).
#[derive(Clone, Debug)]
pub enum Observed {
    /// The call failed with this errno.
    Failed(Errno),
    /// A bind succeeded; these mounts were created (the primary
    /// mount plus any propagation copies).
    Bind {
        /// Every mount the call created.
        created: Vec<ObservedMount>,
    },
    /// An unmount succeeded; these kernel mount IDs are gone (or,
    /// with `MNT_DETACH`, detached).
    Umount {
        /// Kernel mount IDs removed by the call, including
        /// propagation counterparts and, for a detach, subtrees.
        removed_kernel_ids: Vec<u64>,
    },
}

/// Why a request was refused. Linux-rule variants carry Linux's
/// errno in [`Refusal::errno`]; [`RefuseReason::Unsupported`] is a
/// refusal by name of a request Linux would accept, always with
/// `EPERM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseReason {
    /// Unknown or contradictory flag bits (`EINVAL`).
    InvalidFlags,
    /// The caller lacks `CAP_SYS_ADMIN` in the owning user
    /// namespace (`EPERM`; `mount(2)`/`umount2(2)` ERRORS).
    NotCapable,
    /// Bind source and target types disagree on directory-ness
    /// (`ENOTDIR`).
    TypeMismatch,
    /// The bind source is on an unbindable mount (`EINVAL`).
    UnbindableSource,
    /// The unmount target is not a mount point (`EINVAL`).
    NotMountPoint,
    /// `UMOUNT_NOFOLLOW` and the final component is a symlink, so
    /// the target is the link itself, not a mount point
    /// (`EINVAL`).
    NoFollowFinalSymlink,
    /// The unmount target is the root mount of its namespace
    /// (`EINVAL`).
    NamespaceRoot,
    /// Linux would accept this request; the model does not cover
    /// it. The string names what is unmodeled, for the consumer's
    /// refusal report.
    Unsupported(&'static str),
}

impl RefuseReason {
    /// Whether this is a refusal by name of an otherwise valid
    /// request (as opposed to Linux's own error).
    pub fn is_unsupported(self) -> bool {
        matches!(self, RefuseReason::Unsupported(_))
    }

    /// A short stable name for consumer refusal reports.
    pub fn name(self) -> &'static str {
        match self {
            RefuseReason::InvalidFlags => "invalid-flags",
            RefuseReason::NotCapable => "not-capable",
            RefuseReason::TypeMismatch => "type-mismatch",
            RefuseReason::UnbindableSource => "unbindable-source",
            RefuseReason::NotMountPoint => "not-mount-point",
            RefuseReason::NoFollowFinalSymlink => "nofollow-final-symlink",
            RefuseReason::NamespaceRoot => "namespace-root",
            RefuseReason::Unsupported(what) => what,
        }
    }
}

/// A refused request: the errno the guest receives and the reason.
/// No host operation is performed for a refusal.
#[derive(Clone, Copy, Debug)]
pub struct Refusal {
    /// The errno returned to the guest.
    pub errno: Errno,
    /// Why the request was refused.
    pub reason: RefuseReason,
}

/// The performer's facts or observed effect disagree with the
/// model. This is never a guest-visible outcome: the consumer must
/// stop the affected run rather than pass an unmodeled result to
/// the guest. The model is left unchanged.
#[derive(Clone, Debug)]
pub struct Divergence {
    /// Human-readable detail naming the disagreement.
    pub detail: String,
}

impl core::fmt::Display for Divergence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "divergence: {}", self.detail)
    }
}

/// The result of a successful commit: what the guest call returns
/// and which model mounts the transition created or removed.
#[derive(Clone, Debug)]
pub struct Committed {
    /// The guest call's result. `Err(EBUSY)` for an unmount the
    /// kernel found busy — an outcome only the kernel can know,
    /// predicted as acceptable, with the model unchanged.
    pub guest: Result<(), Errno>,
    /// Mounts created, primary first.
    pub created: Vec<MountId>,
    /// Mounts removed from visibility (deleted, or detached under
    /// `MNT_DETACH`, whose records stay for descriptor lookups).
    pub removed: Vec<MountId>,
}

/// An admission decision.
pub enum Decision<'m> {
    /// Perform the request (at most one host operation), then
    /// commit the observed effect through the pending transition.
    Admit(Pending<'m>),
    /// Do not perform anything; return the refusal's errno.
    Refuse(Refusal),
}

/// The planned effect of an admitted request. Internal: consumers
/// only hold the [`Pending`] handle.
pub(crate) enum Plan {
    Bind(crate::bind::BindPlan),
    Umount(crate::umount::UmountPlan),
}

/// An admitted, uncommitted transition. It borrows the model
/// mutably, so no second transition can start until this one is
/// committed or dropped — one transition at a time per model is a
/// compile-time property, not a runtime check. Dropping a
/// `Pending` without committing aborts the transition; the model
/// was never changed.
pub struct Pending<'m> {
    pub(crate) model: &'m mut Model,
    pub(crate) plan: Plan,
}

impl Pending<'_> {
    /// Check `observed` against the prediction and, iff it
    /// matches, apply it. `ids` and `clock` are consulted only
    /// after the check passes, so a divergence consumes neither.
    pub fn commit(
        self,
        observed: Observed,
        ids: &mut dyn IdSource,
        clock: &mut dyn Clock,
    ) -> Result<Committed, Divergence> {
        match self.plan {
            Plan::Bind(plan) => crate::bind::commit_bind(self.model, plan, observed, ids, clock),
            Plan::Umount(plan) => crate::umount::commit_umount(self.model, plan, observed),
        }
    }

    /// Abort the transition explicitly (equivalent to dropping).
    pub fn abort(self) {}
}
