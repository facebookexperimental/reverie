/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bind mounts: admission and commit for `mount(2)` with `MS_BIND`.
//!
//! Rules applied here, each verified against the kernel:
//!
//! - flag bits 31 and above fail with `EINVAL` (bit 31 is the
//!   kernel-internal `MS_NOUSER`; the kernel rejects the whole
//!   upper half — verified with an untruncated 64-bit probe: an
//!   earlier probe through an untyped FFI binding truncated the
//!   flags to 32 bits and wrongly suggested they were ignored);
//!   unassigned bits below 31, and option and propagation bits
//!   given at bind creation, are ignored, and the new mount
//!   inherits the source mount's options;
//! - `MS_BIND|MS_REMOUNT` on distinct source and target objects
//!   fails with `EINVAL`; on the same object it is a remount, not
//!   modeled in this version and refused by name, as is `MS_REC`;
//! - the caller needs `CAP_SYS_ADMIN` in the owning user
//!   namespace (`EPERM`);
//! - a bind whose source is on an unbindable mount fails with
//!   `EINVAL`, whether the source is the mount root or below it;
//! - a directory binds only onto a directory and a non-directory
//!   only onto a non-directory (`ENOTDIR`);
//! - propagation of the new mount (`sharedsubtree.rst`): under a
//!   non-shared parent it inherits the source mount's propagation
//!   exactly. Under a shared parent the event also propagates to
//!   the parent's peers and slaves, and every created mount gets
//!   the source's peer group — or a new peer group, allocated for
//!   the set, when the source has none — preserving the source's
//!   master; copies under slave receivers become slaves of that
//!   peer group instead.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::errno;
use crate::injected::Clock;
use crate::injected::IdSource;
use crate::model::Model;
use crate::model::ReceiverKind;
use crate::model::join_path;
use crate::mount::Mount;
use crate::mount::MountState;
use crate::mount::Propagation;
use crate::request::BindRequest;
use crate::request::CallerContext;
use crate::request::Committed;
use crate::request::Divergence;
use crate::request::IdentifiedPath;
use crate::request::MS_BIND;
use crate::request::MS_REC;
use crate::request::MS_REMOUNT;
use crate::request::Observed;
use crate::request::Plan;
use crate::request::Refusal;
use crate::request::RefuseReason;
use crate::types::IdKind;
use crate::types::MountId;

pub(crate) struct CopySpec {
    parent: MountId,
    visible: Vec<u8>,
    kind: ReceiverKind,
}

/// Mountflag bits userspace may not pass: bit 31 (the
/// kernel-internal `MS_NOUSER`) and every bit above it. The
/// kernel rejects the whole upper half with `EINVAL` (verified
/// with a 64-bit probe sweep); unassigned bits below 31 are
/// ignored.
const MS_REJECTED_HIGH_BITS: u64 = !0x7FFF_FFFF;

pub(crate) struct BindPlan {
    parent: MountId,
    rel: Vec<u8>,
    target_visible: Vec<u8>,
    source_mount: MountId,
    copies: Vec<CopySpec>,
    parent_shared: bool,
    new_group_needed: bool,
}

fn refuse(errno: crate::Errno, reason: RefuseReason) -> Result<Plan, Refusal> {
    Err(Refusal { errno, reason })
}

fn divergence(detail: String) -> Divergence {
    Divergence { detail }
}

pub(crate) fn plan_bind(
    model: &Model,
    caller: &CallerContext,
    req: &BindRequest,
    facts: &[IdentifiedPath],
) -> Result<Result<Plan, Refusal>, Divergence> {
    if facts.len() != 2 {
        return Err(divergence(format!(
            "bind admission needs 2 identified operands, got {}",
            facts.len()
        )));
    }
    if req.flags & MS_REJECTED_HIGH_BITS != 0 {
        return Ok(refuse(errno::EINVAL, RefuseReason::InvalidFlags));
    }
    if req.flags & MS_BIND == 0 {
        return Ok(refuse(errno::EINVAL, RefuseReason::InvalidFlags));
    }
    if req.flags & MS_REMOUNT != 0 {
        let same_object = facts[0].kernel_mount_id == facts[1].kernel_mount_id
            && facts[0].below_mount_root == facts[1].below_mount_root;
        return Ok(if same_object {
            refuse(errno::EPERM, RefuseReason::Unsupported("remount-bind"))
        } else {
            refuse(errno::EINVAL, RefuseReason::InvalidFlags)
        });
    }
    if req.flags & MS_REC != 0 {
        return Ok(refuse(
            errno::EPERM,
            RefuseReason::Unsupported("recursive-bind"),
        ));
    }
    if !caller.cap_sys_admin_in_owner {
        return Ok(refuse(errno::EPERM, RefuseReason::NotCapable));
    }
    let (src_fact, tgt_fact) = (&facts[0], &facts[1]);
    let resolve = |fact: &IdentifiedPath, what: &str| -> Result<&Mount, Divergence> {
        let id = model.mount_by_kernel(fact.kernel_mount_id).ok_or_else(|| {
            divergence(format!(
                "{what} fact names unknown kernel mount id {}",
                fact.kernel_mount_id
            ))
        })?;
        let mount = &model.mounts[&id];
        if mount.ns != caller.mount_ns || mount.state != MountState::Visible {
            return Err(divergence(format!(
                "{what} fact resolved outside the caller's visible mount namespace"
            )));
        }
        Ok(mount)
    };
    let src_mount = resolve(src_fact, "source")?;
    let tgt_mount = resolve(tgt_fact, "target")?;
    if src_mount.propagation == Propagation::Unbindable {
        return Ok(refuse(errno::EINVAL, RefuseReason::UnbindableSource));
    }
    if !src_fact.file_type.bind_compatible(tgt_fact.file_type) {
        return Ok(refuse(errno::ENOTDIR, RefuseReason::TypeMismatch));
    }
    let parent = tgt_mount.id;
    let rel = tgt_fact.below_mount_root.clone();
    let target_visible = join_path(
        &model
            .visible_path(parent)
            .ok_or_else(|| divergence("target mount has no visible path".into()))?,
        &rel,
    );
    let copies: Vec<CopySpec> = model
        .propagation_receivers(parent)
        .into_iter()
        .map(|(recv, kind)| {
            let visible = join_path(
                &model.visible_path(recv).expect("receivers are visible"),
                &rel,
            );
            CopySpec {
                parent: recv,
                visible,
                kind,
            }
        })
        .collect();
    let parent_shared = tgt_mount.propagation.peer_group().is_some();
    Ok(Ok(Plan::Bind(BindPlan {
        parent,
        rel,
        target_visible,
        source_mount: src_mount.id,
        new_group_needed: parent_shared && src_mount.propagation.peer_group().is_none(),
        parent_shared,
        copies,
    })))
}

/// The propagation a created mount gets. `receiver` is `None`
/// for the primary mount. All cases observed directly on the
/// kernel: under a non-shared parent the source propagation is
/// inherited exactly; under a shared parent the mount takes the
/// source's peer group (a fresh one when the source has none —
/// even when no copy is propagated) and keeps the source's
/// master, while a copy under a slave receiver becomes a slave
/// of that peer group.
fn effective_propagation(
    source: Propagation,
    parent_shared: bool,
    receiver: Option<ReceiverKind>,
    new_group: Option<u64>,
) -> Propagation {
    if !parent_shared {
        return source;
    }
    let peer = source
        .peer_group()
        .or(new_group)
        .expect("shared parent with a peerless source allocates a group");
    if receiver == Some(ReceiverKind::Slave) {
        return Propagation::Slave(Some(peer));
    }
    match source.master() {
        Some(master) => Propagation::SharedSlave {
            peer,
            master: Some(master),
        },
        None => Propagation::Shared(peer),
    }
}

pub(crate) fn commit_bind(
    model: &mut Model,
    plan: BindPlan,
    observed: Observed,
    ids: &mut dyn IdSource,
    clock: &mut dyn Clock,
) -> Result<Committed, Divergence> {
    let created = match observed {
        Observed::Bind { created } => created,
        Observed::Failed(e) => {
            return Err(divergence(format!(
                "bind failed with {e} but admission predicted success"
            )));
        }
        Observed::Umount { .. } => {
            return Err(divergence(
                "bind transition observed an unmount outcome".into(),
            ));
        }
    };
    // Expected mounts: namespace-visible path -> parent model mount.
    let mut expected: Vec<(Vec<u8>, MountId, Option<ReceiverKind>)> =
        Vec::with_capacity(plan.copies.len() + 1);
    expected.push((plan.target_visible.clone(), plan.parent, None));
    for copy in &plan.copies {
        expected.push((copy.visible.clone(), copy.parent, Some(copy.kind)));
    }
    if created.len() != expected.len() {
        return Err(divergence(format!(
            "bind created {} mounts, model predicted {}",
            created.len(),
            expected.len()
        )));
    }
    // Validate the whole observed set before changing anything.
    let mut root: Option<Vec<u8>> = None;
    let mut matched: Vec<Option<usize>> = alloc::vec![None; created.len()];
    for (i, obs) in created.iter().enumerate() {
        if !obs.root.starts_with(b"/") {
            return Err(divergence("observed bind root is not absolute".into()));
        }
        match &root {
            None => root = Some(obs.root.clone()),
            Some(r) if *r != obs.root => {
                return Err(divergence(
                    "propagation copies disagree on the bind root".into(),
                ));
            }
            _ => {}
        }
        if model.by_kernel.contains_key(&obs.kernel_mount_id)
            || created[..i]
                .iter()
                .any(|o| o.kernel_mount_id == obs.kernel_mount_id)
        {
            return Err(divergence(format!(
                "observed mount reuses kernel mount id {}",
                obs.kernel_mount_id
            )));
        }
        if !obs.mount_point.starts_with(b"/") {
            return Err(divergence("observed mount point is not absolute".into()));
        }
        let visible = &obs.mount_point;
        let Some(idx) = expected
            .iter()
            .position(|(v, parent, _)| {
                v == visible && model.mounts[parent].kernel_id == obs.parent_kernel_mount_id
            })
            .filter(|idx| matched.iter().all(|m| *m != Some(*idx)))
        else {
            return Err(divergence(format!(
                "unexpected created mount at {}",
                String::from_utf8_lossy(visible)
            )));
        };
        matched[i] = Some(idx);
    }
    let root = root.unwrap_or_default();
    // Apply.
    let src = model.mounts[&plan.source_mount].clone();
    let new_group = plan
        .new_group_needed
        .then(|| ids.next_id(IdKind::PeerGroup));
    let created_at = clock.now();
    let mut created_ids: Vec<MountId> = Vec::new();
    let mut by_expected: Vec<Option<&crate::request::ObservedMount>> =
        alloc::vec![None; expected.len()];
    for (i, obs) in created.iter().enumerate() {
        by_expected[matched[i].expect("matched")] = Some(obs);
    }
    for (idx, (_, parent, kind)) in expected.iter().enumerate() {
        let obs = by_expected[idx].expect("every expected mount matched");
        let id = MountId(ids.next_id(IdKind::Mount));
        let seq = model.next_seq;
        model.next_seq += 1;
        model.mounts.insert(
            id,
            Mount {
                id,
                kernel_id: obs.kernel_mount_id,
                ns: model.mounts[parent].ns,
                parent: *parent,
                mountpoint_in_parent: plan.rel.clone(),
                root: root.clone(),
                sb: src.sb,
                mount_options: src.mount_options.clone(),
                propagation: effective_propagation(
                    src.propagation,
                    plan.parent_shared,
                    *kind,
                    new_group,
                ),
                state: MountState::Visible,
                created: created_at,
                seq,
            },
        );
        model.by_kernel.insert(obs.kernel_mount_id, id);
        created_ids.push(id);
    }
    Ok(Committed {
        guest: Ok(()),
        created: created_ids,
        removed: Vec::new(),
    })
}
