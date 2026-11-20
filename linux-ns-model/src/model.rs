/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The model state: the namespace tree, the mount table of each
//! mount namespace, superblocks, and task membership, plus the
//! admission entry point. Semantics of individual operations live
//! in the `bind` and `umount` modules; rendering in `render`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::injected::FsFacts;
use crate::injected::IdSource;
use crate::injected::Presentation;
use crate::injected::StatfsView;
use crate::mount::Mount;
use crate::mount::MountState;
use crate::mount::Propagation;
use crate::mount::Superblock;
use crate::mount::statfs_flags;
use crate::request::CallerContext;
use crate::request::Decision;
use crate::request::Divergence;
use crate::request::IdentifiedPath;
use crate::request::PathInNs;
use crate::request::Pending;
use crate::request::Request;
use crate::types::IdKind;
use crate::types::MountId;
use crate::types::NsId;
use crate::types::SbId;
use crate::types::TaskKey;
use crate::types::Timespec;

/// The kind of a namespace node. Mount namespaces carry a mount
/// table in this version; the other kinds exist as tree nodes so
/// ownership (a mount namespace is owned by a user namespace) and
/// later namespace operations have one home.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsKind {
    /// A mount namespace.
    Mount,
    /// A user namespace.
    User,
    /// A PID namespace.
    Pid,
    /// A network namespace.
    Net,
    /// An IPC namespace.
    Ipc,
    /// A UTS namespace.
    Uts,
    /// A cgroup namespace.
    Cgroup,
    /// A time namespace.
    Time,
}

/// One node of the namespace tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// Model identity.
    pub id: NsId,
    /// Which kind of namespace.
    pub kind: NsKind,
    /// Parent namespace of the same kind, if any.
    pub parent: Option<NsId>,
    /// The user namespace that owns this namespace, if applicable.
    pub owner_user_ns: Option<NsId>,
    /// For a mount namespace, its root mount once seeded.
    pub root_mount: Option<MountId>,
}

/// One mount of a namespace being seeded. The consumer reads its
/// initial kernel mount table (for example from `listmount(2)`)
/// and restates it in these terms; from then on the model is the
/// authority. Peer-group numbers and the `superblock` field are
/// opaque equality labels: mounts seeded with the same label
/// share a peer group (or superblock), and the model replaces
/// labels with [`IdSource`] values, preserving equality.
#[derive(Clone, Debug)]
pub struct SeedMount {
    /// The kernel's unique mount ID for this mount.
    pub kernel_mount_id: u64,
    /// The kernel mount ID of the parent mount, or `None` for the
    /// namespace root (exactly one per namespace).
    pub parent_kernel_mount_id: Option<u64>,
    /// Mount point below the parent mount's visible root (see
    /// [`Mount::mountpoint_in_parent`]); empty for the root.
    pub mountpoint_in_parent: Vec<u8>,
    /// Root of the mount within its filesystem.
    pub root: Vec<u8>,
    /// Per-mount options, verbatim.
    pub mount_options: Vec<u8>,
    /// Propagation, with peer-group numbers as equality labels.
    pub propagation: Propagation,
    /// Superblock equality label; mounts sharing a label must
    /// carry equal `fs` facts.
    pub superblock: u64,
    /// Identity facts of the superblock.
    pub fs: FsFacts,
    /// Creation time to record for the mount point.
    pub created: Timespec,
}

/// A defective seed (a consumer bug, never a guest outcome).
#[derive(Clone, Debug)]
pub struct SeedError {
    /// Human-readable detail.
    pub detail: String,
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "seed error: {}", self.detail)
    }
}

fn seed_err(detail: String) -> SeedError {
    SeedError { detail }
}

/// The whole modeled state. Pure data: clone it, snapshot it,
/// compare renderings of it — only [`Model::admit`] transitions
/// and seeding mutate it.
#[derive(Clone, Debug, Default)]
pub struct Model {
    pub(crate) namespaces: BTreeMap<NsId, Namespace>,
    pub(crate) mounts: BTreeMap<MountId, Mount>,
    pub(crate) superblocks: BTreeMap<SbId, Superblock>,
    pub(crate) by_kernel: BTreeMap<u64, MountId>,
    pub(crate) members: BTreeMap<TaskKey, NsId>,
    pub(crate) next_sb: u64,
    pub(crate) next_seq: u64,
}

/// Whether a propagation receiver is a peer of the event's parent
/// mount or a slave of its peer group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiverKind {
    Peer,
    Slave,
}

/// Join an absolute visible path (`/` or `/a/b`) with a path below
/// it (`` or `c/d`, no leading slash).
pub(crate) fn join_path(base: &[u8], below: &[u8]) -> Vec<u8> {
    if below.is_empty() {
        return base.to_vec();
    }
    let mut out = Vec::with_capacity(base.len() + 1 + below.len());
    out.extend_from_slice(base);
    if base != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(below);
    out
}

impl Model {
    /// An empty model, with no namespaces.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a namespace node. The ID is drawn from
    /// [`IdKind::Namespace`].
    pub fn add_namespace(
        &mut self,
        kind: NsKind,
        parent: Option<NsId>,
        owner_user_ns: Option<NsId>,
        ids: &mut dyn IdSource,
    ) -> NsId {
        let id = NsId(ids.next_id(IdKind::Namespace));
        self.namespaces.insert(
            id,
            Namespace {
                id,
                kind,
                parent,
                owner_user_ns,
                root_mount: None,
            },
        );
        id
    }

    /// Look up a namespace node.
    pub fn namespace(&self, id: NsId) -> Option<&Namespace> {
        self.namespaces.get(&id)
    }

    /// Look up a mount.
    pub fn mount(&self, id: MountId) -> Option<&Mount> {
        self.mounts.get(&id)
    }

    /// Look up a superblock.
    pub fn superblock(&self, id: SbId) -> Option<&Superblock> {
        self.superblocks.get(&id)
    }

    /// The model mount with this kernel (unique) mount ID, if the
    /// model has seen it.
    pub fn mount_by_kernel(&self, kernel_mount_id: u64) -> Option<MountId> {
        self.by_kernel.get(&kernel_mount_id).copied()
    }

    /// All mounts of a namespace (visible and detached), in
    /// creation order.
    pub fn mounts_in(&self, ns: NsId) -> Vec<&Mount> {
        let mut out: Vec<&Mount> = self.mounts.values().filter(|m| m.ns == ns).collect();
        out.sort_by_key(|m| m.seq);
        out
    }

    /// Visible children of a mount, in creation order.
    pub fn children(&self, mount: MountId) -> Vec<MountId> {
        let mut out: Vec<MountId> = self
            .mounts
            .values()
            .filter(|m| m.parent == mount && m.id != mount && m.state == MountState::Visible)
            .map(|m| m.id)
            .collect();
        out.sort_by_key(|id| self.mounts[id].seq);
        out
    }

    /// Record which mount namespace a task belongs to.
    pub fn register_task(&mut self, task: TaskKey, mount_ns: NsId) {
        self.members.insert(task, mount_ns);
    }

    /// A fork: the child starts in the parent's mount namespace
    /// (membership is otherwise moved only by the caller itself,
    /// and kept across exec — consumers record those moves with
    /// [`Model::register_task`]).
    pub fn fork_task(&mut self, child: TaskKey, parent: TaskKey) {
        if let Some(ns) = self.members.get(&parent).copied() {
            self.members.insert(child, ns);
        }
    }

    /// Forget a task (it exited).
    pub fn forget_task(&mut self, task: TaskKey) {
        self.members.remove(&task);
    }

    /// The mount namespace a task belongs to, if recorded.
    pub fn task_mount_ns(&self, task: TaskKey) -> Option<NsId> {
        self.members.get(&task).copied()
    }

    /// Seed the mount table of a mount namespace from the
    /// consumer's initial reading of the kernel. The namespace
    /// must exist, be of kind [`NsKind::Mount`], and have no
    /// mounts yet. Exactly one entry has no parent: the root.
    pub fn seed_mounts(
        &mut self,
        ns: NsId,
        seeds: &[SeedMount],
        ids: &mut dyn IdSource,
    ) -> Result<(), SeedError> {
        let node = self
            .namespaces
            .get(&ns)
            .ok_or_else(|| seed_err(format!("unknown namespace {ns:?}")))?;
        if node.kind != NsKind::Mount {
            return Err(seed_err(format!(
                "namespace {ns:?} is not a mount namespace"
            )));
        }
        if node.root_mount.is_some() {
            return Err(seed_err(format!("namespace {ns:?} is already seeded")));
        }
        // Validate everything against local maps first, so a
        // defective seed leaves the model unchanged.
        let mut seen: BTreeMap<u64, ()> = BTreeMap::new();
        let mut facts_of: BTreeMap<u64, &FsFacts> = BTreeMap::new();
        let mut root_count = 0usize;
        for seed in seeds {
            if self.by_kernel.contains_key(&seed.kernel_mount_id)
                || seen.insert(seed.kernel_mount_id, ()).is_some()
            {
                return Err(seed_err(format!(
                    "duplicate kernel mount id {}",
                    seed.kernel_mount_id
                )));
            }
            match facts_of.get(&seed.superblock) {
                Some(facts) if *facts != &seed.fs => {
                    return Err(seed_err(format!(
                        "superblock label {} seeded with unequal facts",
                        seed.superblock
                    )));
                }
                Some(_) => {}
                None => {
                    facts_of.insert(seed.superblock, &seed.fs);
                }
            }
            match seed.parent_kernel_mount_id {
                None => {
                    root_count += 1;
                    if !seed.mountpoint_in_parent.is_empty() {
                        return Err(seed_err("namespace root has a mount point path".into()));
                    }
                }
                Some(pk) if pk == seed.kernel_mount_id => {
                    return Err(seed_err(format!(
                        "mount {} is its own parent but not the root",
                        seed.kernel_mount_id
                    )));
                }
                Some(_) => {}
            }
        }
        for seed in seeds {
            if let Some(pk) = seed.parent_kernel_mount_id
                && !seen.contains_key(&pk)
            {
                return Err(seed_err(format!("unknown parent kernel mount id {pk}")));
            }
        }
        if root_count != 1 {
            return Err(seed_err(format!(
                "expected exactly one namespace root, got {root_count}"
            )));
        }
        // Validation passed: mint identities and superblocks.
        let mut id_of: BTreeMap<u64, MountId> = BTreeMap::new();
        let mut sb_of: BTreeMap<u64, SbId> = BTreeMap::new();
        let mut group_of: BTreeMap<u64, u64> = BTreeMap::new();
        for seed in seeds {
            id_of.insert(seed.kernel_mount_id, MountId(ids.next_id(IdKind::Mount)));
            if let alloc::collections::btree_map::Entry::Vacant(slot) = sb_of.entry(seed.superblock)
            {
                let sb = SbId(self.next_sb);
                self.next_sb += 1;
                let dev_minor = ids.next_id(IdKind::DeviceMinor) as u32;
                let fsid = ids.next_id(IdKind::FilesystemId);
                slot.insert(sb);
                self.superblocks.insert(
                    sb,
                    Superblock {
                        id: sb,
                        dev_major: seed.fs.dev_major,
                        dev_minor,
                        fsid,
                        facts: seed.fs.clone(),
                    },
                );
            }
        }
        let remap =
            |prop: Propagation, group_of: &mut BTreeMap<u64, u64>, ids: &mut dyn IdSource| {
                let mut g = |label: u64| {
                    *group_of
                        .entry(label)
                        .or_insert_with(|| ids.next_id(IdKind::PeerGroup))
                };
                match prop {
                    Propagation::Shared(label) => Propagation::Shared(g(label)),
                    Propagation::Slave(m) => Propagation::Slave(m.map(g)),
                    Propagation::SharedSlave { peer, master } => {
                        let peer = g(peer);
                        Propagation::SharedSlave {
                            peer,
                            master: master.map(g),
                        }
                    }
                    other => other,
                }
            };
        // Second pass: link the table.
        let mut roots: Vec<MountId> = Vec::new();
        for seed in seeds {
            let id = id_of[&seed.kernel_mount_id];
            let parent = match seed.parent_kernel_mount_id {
                None => {
                    roots.push(id);
                    if !seed.mountpoint_in_parent.is_empty() {
                        return Err(seed_err("namespace root has a mount point path".into()));
                    }
                    id
                }
                Some(pk) => *id_of
                    .get(&pk)
                    .ok_or_else(|| seed_err(format!("unknown parent kernel mount id {pk}")))?,
            };
            let seq = self.next_seq;
            self.next_seq += 1;
            self.mounts.insert(
                id,
                Mount {
                    id,
                    kernel_id: seed.kernel_mount_id,
                    ns,
                    parent,
                    mountpoint_in_parent: seed.mountpoint_in_parent.clone(),
                    root: seed.root.clone(),
                    sb: sb_of[&seed.superblock],
                    mount_options: seed.mount_options.clone(),
                    propagation: remap(seed.propagation, &mut group_of, ids),
                    state: MountState::Visible,
                    created: seed.created,
                    seq,
                },
            );
            self.by_kernel.insert(seed.kernel_mount_id, id);
        }
        if roots.len() != 1 {
            return Err(seed_err(format!(
                "expected exactly one namespace root, got {}",
                roots.len()
            )));
        }
        self.namespaces.get_mut(&ns).expect("checked").root_mount = Some(roots[0]);
        Ok(())
    }

    /// The namespace-absolute visible path of a mount (`/` for a
    /// namespace root), or `None` when the mount (or an ancestor)
    /// is detached or unknown.
    pub fn visible_path(&self, mount: MountId) -> Option<Vec<u8>> {
        let mut segments: Vec<&[u8]> = Vec::new();
        let mut cur = self.mounts.get(&mount)?;
        let mut steps = 0usize;
        loop {
            if cur.state != MountState::Visible {
                return None;
            }
            if cur.parent == cur.id {
                break;
            }
            if !cur.mountpoint_in_parent.is_empty() {
                segments.push(&cur.mountpoint_in_parent);
            }
            steps += 1;
            if steps > self.mounts.len() {
                return None;
            }
            cur = self.mounts.get(&cur.parent)?;
        }
        if segments.is_empty() {
            return Some(b"/".to_vec());
        }
        let mut out: Vec<u8> = Vec::new();
        for seg in segments.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(seg);
        }
        Some(out)
    }

    /// The namespace-absolute visible path of a location.
    pub fn path_visible(&self, path: &PathInNs) -> Option<Vec<u8>> {
        Some(join_path(&self.visible_path(path.mount)?, &path.below_root))
    }

    /// The topmost visible mount at an absolute path in `ns`, if
    /// one is mounted exactly there. Stacked mounts share a path;
    /// the topmost is the one no other candidate descends from.
    pub fn mount_at_path(&self, ns: NsId, path: &[u8]) -> Option<MountId> {
        let candidates: Vec<MountId> = self
            .mounts_in(ns)
            .into_iter()
            .filter(|m| m.state == MountState::Visible)
            .filter(|m| self.visible_path(m.id).as_deref() == Some(path))
            .map(|m| m.id)
            .collect();
        candidates.iter().copied().find(|cand| {
            !candidates.iter().any(|other| {
                other != cand && {
                    let mut cur = *other;
                    let mut found = false;
                    for _ in 0..=self.mounts.len() {
                        let m = &self.mounts[&cur];
                        if m.parent == cur {
                            break;
                        }
                        if m.parent == *cand {
                            found = true;
                            break;
                        }
                        cur = m.parent;
                    }
                    found
                }
            })
        })
    }

    /// The topmost visible mount stacked at (`parent`, `rel`):
    /// a child of `parent` at `rel`, followed through mounts
    /// stacked on its root.
    pub(crate) fn topmost_at(&self, parent: MountId, rel: &[u8]) -> Option<MountId> {
        let mut current = self
            .children(parent)
            .into_iter()
            .find(|id| self.mounts[id].mountpoint_in_parent == rel)?;
        loop {
            match self
                .children(current)
                .into_iter()
                .find(|id| self.mounts[id].mountpoint_in_parent.is_empty())
            {
                Some(next) => current = next,
                None => return Some(current),
            }
        }
    }

    /// Mounts that receive a mount/unmount event under `parent`
    /// (`sharedsubtree.rst`: every peer of the parent's group and
    /// every slave of that group, in any namespace). Ordered by
    /// visible path for a stable prediction.
    pub(crate) fn propagation_receivers(&self, parent: MountId) -> Vec<(MountId, ReceiverKind)> {
        let Some(group) = self
            .mounts
            .get(&parent)
            .and_then(|m| m.propagation.peer_group())
        else {
            return Vec::new();
        };
        let mut out: Vec<(MountId, ReceiverKind)> = self
            .mounts
            .values()
            .filter(|m| m.id != parent && m.state == MountState::Visible)
            .filter_map(|m| {
                if m.propagation.peer_group() == Some(group) {
                    Some((m.id, ReceiverKind::Peer))
                } else if m.propagation.master() == Some(group) {
                    Some((m.id, ReceiverKind::Slave))
                } else {
                    None
                }
            })
            .collect();
        out.sort_by_key(|a| self.visible_path(a.0));
        out
    }

    /// Decide a request. `facts` are the identified operands in
    /// request order (bind: source, then target; unmount: the
    /// target), obtained from the consumer's
    /// [`crate::Performer::identify`] with the request's follow
    /// rules. Facts that disagree with the model return a
    /// [`Divergence`], never a guest errno.
    pub fn admit(
        &mut self,
        caller: &CallerContext,
        request: &Request,
        facts: &[IdentifiedPath],
    ) -> Result<Decision<'_>, Divergence> {
        let planned = match request {
            Request::Bind(req) => crate::bind::plan_bind(self, caller, req, facts),
            Request::Umount(req) => crate::umount::plan_umount(self, caller, req, facts),
        }?;
        Ok(match planned {
            Ok(plan) => Decision::Admit(Pending { model: self, plan }),
            Err(refusal) => Decision::Refuse(refusal),
        })
    }

    /// The presented `statfs` view of the filesystem `mount`
    /// belongs to. The presentation supplies capacities; the model
    /// is authoritative for the type magic, the filesystem ID, and
    /// the `ST_*` flags implied by the mount's options.
    pub fn statfs(&self, mount: MountId, presentation: &dyn Presentation) -> Option<StatfsView> {
        let m = self.mounts.get(&mount)?;
        let sb = &self.superblocks[&m.sb];
        let mut view = presentation.filesystem_view(&sb.facts);
        view.magic = sb.facts.magic;
        view.fsid = sb.fsid;
        view.flags = statfs_flags(&m.mount_options, &sb.facts.super_options);
        Some(view)
    }

    /// The shown device numbers (`st_dev` major/minor) of a
    /// mount's filesystem.
    pub fn device_of(&self, mount: MountId) -> Option<(u32, u32)> {
        let m = self.mounts.get(&mount)?;
        let sb = &self.superblocks[&m.sb];
        Some((sb.dev_major, sb.dev_minor))
    }
}
