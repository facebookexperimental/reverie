/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Unmounts: admission and commit for `umount2(2)`.
//!
//! Rules applied here, each verified against the kernel:
//!
//! - unknown flag bits, and `MNT_EXPIRE` combined with
//!   `MNT_DETACH` or `MNT_FORCE`, fail with `EINVAL` (`umount2(2)`
//!   ERRORS); `MNT_EXPIRE` (with or without `UMOUNT_NOFOLLOW`) is
//!   valid Linux the model does not cover — it needs the kernel's
//!   expiry bookkeeping — so it is refused by name;
//! - the caller needs `CAP_SYS_ADMIN` in the owning user
//!   namespace (`EPERM`);
//! - with `UMOUNT_NOFOLLOW` a final symlink is the target itself,
//!   not a mount point (`EINVAL`); without it the link is
//!   followed, as every path resolution here is;
//! - a target that is not a mount root fails with `EINVAL`
//!   ("target is not a mount point"), as does the root mount of a
//!   namespace;
//! - a busy mount fails with `EBUSY`. Submounts make a
//!   non-detach unmount busy in a way the model can prove, so a
//!   reported success there is a divergence; open descriptors
//!   make it busy in a way only the kernel can know, so `EBUSY`
//!   is a predicted-acceptable outcome and the guest receives it
//!   with the model unchanged;
//! - under a shared parent the unmount propagates to the
//!   counterpart mounts under the parent's peers and slaves
//!   (`sharedsubtree.rst`); `MNT_DETACH` detaches each victim's
//!   whole subtree, whose records stay for descriptor lookups.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::vec::Vec;

use crate::errno;
use crate::model::Model;
use crate::mount::MountState;
use crate::request::CallerContext;
use crate::request::Committed;
use crate::request::Divergence;
use crate::request::IdentifiedPath;
use crate::request::MNT_DETACH;
use crate::request::MNT_EXPIRE;
use crate::request::Observed;
use crate::request::Plan;
use crate::request::Refusal;
use crate::request::RefuseReason;
use crate::request::UMOUNT_KNOWN_MASK;
use crate::request::UMOUNT_NOFOLLOW;
use crate::request::UmountRequest;
use crate::types::MountId;

pub(crate) struct UmountPlan {
    victims: Vec<MountId>,
    removed: Vec<MountId>,
    detach: bool,
    success_possible: bool,
}

fn refuse(errno: crate::Errno, reason: RefuseReason) -> Result<Plan, Refusal> {
    Err(Refusal { errno, reason })
}

fn divergence(detail: alloc::string::String) -> Divergence {
    Divergence { detail }
}

fn subtree(model: &Model, root: MountId, out: &mut Vec<MountId>) {
    out.push(root);
    for child in model.children(root) {
        subtree(model, child, out);
    }
}

pub(crate) fn plan_umount(
    model: &Model,
    caller: &CallerContext,
    req: &UmountRequest,
    facts: &[IdentifiedPath],
) -> Result<Result<Plan, Refusal>, Divergence> {
    if facts.len() != 1 {
        return Err(divergence(format!(
            "unmount admission needs 1 identified operand, got {}",
            facts.len()
        )));
    }
    if req.flags & !UMOUNT_KNOWN_MASK != 0 {
        return Ok(refuse(errno::EINVAL, RefuseReason::InvalidFlags));
    }
    if req.flags & MNT_EXPIRE != 0 {
        return Ok(
            if req.flags & (MNT_DETACH | crate::request::MNT_FORCE) != 0 {
                refuse(errno::EINVAL, RefuseReason::InvalidFlags)
            } else {
                refuse(errno::EPERM, RefuseReason::Unsupported("mnt-expire"))
            },
        );
    }
    if !caller.cap_sys_admin_in_owner {
        return Ok(refuse(errno::EPERM, RefuseReason::NotCapable));
    }
    let fact = &facts[0];
    let Some(victim_id) = model.mount_by_kernel(fact.kernel_mount_id) else {
        return Err(divergence(format!(
            "target fact names unknown kernel mount id {}",
            fact.kernel_mount_id
        )));
    };
    let victim = &model.mounts[&victim_id];
    if victim.ns != caller.mount_ns || victim.state != MountState::Visible {
        return Err(divergence(
            "target fact resolved outside the caller's visible mount namespace".into(),
        ));
    }
    if req.flags & UMOUNT_NOFOLLOW != 0 && fact.final_is_symlink {
        return Ok(refuse(errno::EINVAL, RefuseReason::NoFollowFinalSymlink));
    }
    if !fact.is_mount_root {
        return Ok(refuse(errno::EINVAL, RefuseReason::NotMountPoint));
    }
    if !fact.below_mount_root.is_empty() {
        return Err(divergence(
            "target fact claims a mount root below the mount root".into(),
        ));
    }
    if victim.parent == victim.id {
        return Ok(refuse(errno::EINVAL, RefuseReason::NamespaceRoot));
    }
    // Counterparts: the topmost mount at the same relative path
    // under each propagation receiver of the victim's parent,
    // when it is the same filesystem object (same superblock and
    // root) the propagation originally copied.
    let mut victims: Vec<MountId> = alloc::vec![victim_id];
    for (recv, _) in model.propagation_receivers(victim.parent) {
        if let Some(w) = model.topmost_at(recv, &victim.mountpoint_in_parent) {
            let wm = &model.mounts[&w];
            if w != victim_id && wm.sb == victim.sb && wm.root == victim.root {
                victims.push(w);
            }
        }
    }
    let detach = req.flags & MNT_DETACH != 0;
    let success_possible = detach || victims.iter().all(|v| model.children(*v).is_empty());
    let mut removed: Vec<MountId> = Vec::new();
    for v in &victims {
        if detach {
            subtree(model, *v, &mut removed);
        } else {
            removed.push(*v);
        }
    }
    Ok(Ok(Plan::Umount(UmountPlan {
        victims,
        removed,
        detach,
        success_possible,
    })))
}

pub(crate) fn commit_umount(
    model: &mut Model,
    plan: UmountPlan,
    observed: Observed,
) -> Result<Committed, Divergence> {
    let removed_kernel_ids = match observed {
        Observed::Failed(e) => {
            return if e == errno::EBUSY {
                Ok(Committed {
                    guest: Err(errno::EBUSY),
                    created: Vec::new(),
                    removed: Vec::new(),
                })
            } else {
                Err(divergence(format!(
                    "unmount failed with {e} but admission predicted success or EBUSY"
                )))
            };
        }
        Observed::Umount { removed_kernel_ids } => removed_kernel_ids,
        Observed::Bind { .. } => {
            return Err(divergence(
                "unmount transition observed a bind outcome".into(),
            ));
        }
    };
    if !plan.success_possible {
        return Err(divergence(
            "unmount reported success but the model proves a victim busy with submounts".into(),
        ));
    }
    let expected: BTreeSet<u64> = plan
        .removed
        .iter()
        .map(|id| model.mounts[id].kernel_id)
        .collect();
    let observed_set: BTreeSet<u64> = removed_kernel_ids.iter().copied().collect();
    if observed_set.len() != removed_kernel_ids.len() || observed_set != expected {
        return Err(divergence(format!(
            "unmount removed {removed_kernel_ids:?}, model predicted {:?}",
            expected.iter().collect::<Vec<_>>()
        )));
    }
    if plan.detach {
        for id in &plan.removed {
            model.mounts.get_mut(id).expect("planned").state = MountState::Detached;
        }
    } else {
        for id in &plan.removed {
            let mount = model.mounts.remove(id).expect("planned");
            model.by_kernel.remove(&mount.kernel_id);
        }
    }
    Ok(Committed {
        guest: Ok(()),
        created: Vec::new(),
        removed: plan.victims,
    })
}
