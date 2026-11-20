/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared fixtures: plain counter IDs (each kind in its own range,
//! so a kind mix-up in the model shows up as a wrong value, not a
//! plausible one), a fixed clock and presentation, and seeded
//! topologies the case tables drive.

#![expect(
    dead_code,
    reason = "shared fixtures are compiled into each test binary, and not every binary uses every helper"
)]

use linux_ns_model::*;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct CounterIds {
    pub mounts: u64,
    pub groups: u64,
    pub minors: u64,
    pub namespaces: u64,
    pub fsids: u64,
}

impl IdSource for CounterIds {
    fn next_id(&mut self, kind: IdKind) -> u64 {
        match kind {
            IdKind::Mount => {
                self.mounts += 1;
                100 + self.mounts
            }
            IdKind::PeerGroup => {
                self.groups += 1;
                7000 + self.groups
            }
            IdKind::DeviceMinor => {
                self.minors += 1;
                50 + self.minors
            }
            IdKind::Namespace => {
                self.namespaces += 1;
                9000 + self.namespaces
            }
            IdKind::FilesystemId => {
                self.fsids += 1;
                0xF51D_0000 + self.fsids
            }
        }
    }
}

pub struct FixedClock;
impl Clock for FixedClock {
    fn now(&mut self) -> Timespec {
        Timespec {
            sec: 1_800_000_000,
            nsec: 25,
        }
    }
}

pub struct FixedPresentation;
impl Presentation for FixedPresentation {
    fn filesystem_view(&self, facts: &FsFacts) -> StatfsView {
        StatfsView {
            magic: facts.magic,
            block_size: facts.block_size,
            blocks: 1_000_000,
            blocks_free: 900_000,
            blocks_available: 900_000,
            files: 500_000,
            files_free: 499_000,
            fsid: 0,
            name_max: facts.name_max,
            fragment_size: facts.block_size,
            flags: 0,
        }
    }
    fn memory_size(&self) -> u64 {
        1 << 30
    }
}

pub fn tmpfs_facts() -> FsFacts {
    FsFacts {
        fs_type: b"tmpfs".to_vec(),
        source: b"tmpfs".to_vec(),
        super_options: b"rw,relatime".to_vec(),
        magic: 0x0102_1994,
        dev_major: 0,
        block_size: 4096,
        name_max: 255,
    }
}

fn seed(
    kernel: u64,
    parent: Option<u64>,
    at: &[u8],
    root: &[u8],
    propagation: Propagation,
    superblock: u64,
) -> SeedMount {
    SeedMount {
        kernel_mount_id: kernel,
        parent_kernel_mount_id: parent,
        mountpoint_in_parent: at.to_vec(),
        root: root.to_vec(),
        mount_options: b"rw,relatime".to_vec(),
        propagation,
        superblock,
        fs: tmpfs_facts(),
        created: Timespec {
            sec: 1_800_000_000,
            nsec: 0,
        },
    }
}

/// Kernel IDs of the standard topology, deliberately far from the
/// model IDs `CounterIds` mints.
pub mod kid {
    /// `/` (private tmpfs, superblock 1).
    pub const ROOT: u64 = 10;
    /// `/shared` (shared tmpfs, superblock 2).
    pub const SHARED: u64 = 11;
    /// `/shared-peer` (peer of SHARED, same superblock).
    pub const SHARED_PEER: u64 = 12;
    /// `/unbindable` (only in the unbindable topology).
    pub const UNBINDABLE: u64 = 13;
}

/// Standard seeded model: root `/`, `/shared` and `/shared-peer`
/// peers on one tmpfs. Returns the model, the mount namespace,
/// and the ID source after seeding.
pub fn seeded_standard() -> (Model, NsId, CounterIds) {
    let mut model = Model::new();
    let mut ids = CounterIds::default();
    let user = model.add_namespace(NsKind::User, None, None, &mut ids);
    let ns = model.add_namespace(NsKind::Mount, None, Some(user), &mut ids);
    model
        .seed_mounts(
            ns,
            &[
                seed(kid::ROOT, None, b"", b"/", Propagation::Private, 1),
                seed(
                    kid::SHARED,
                    Some(kid::ROOT),
                    b"shared",
                    b"/",
                    Propagation::Shared(5),
                    2,
                ),
                seed(
                    kid::SHARED_PEER,
                    Some(kid::ROOT),
                    b"shared-peer",
                    b"/",
                    Propagation::Shared(5),
                    2,
                ),
            ],
            &mut ids,
        )
        .expect("seed");
    (model, ns, ids)
}

/// Standard topology plus an unbindable mount at `/unbindable`.
pub fn seeded_with_unbindable() -> (Model, NsId, CounterIds) {
    let mut model = Model::new();
    let mut ids = CounterIds::default();
    let user = model.add_namespace(NsKind::User, None, None, &mut ids);
    let ns = model.add_namespace(NsKind::Mount, None, Some(user), &mut ids);
    model
        .seed_mounts(
            ns,
            &[
                seed(kid::ROOT, None, b"", b"/", Propagation::Private, 1),
                seed(
                    kid::UNBINDABLE,
                    Some(kid::ROOT),
                    b"unbindable",
                    b"/",
                    Propagation::Unbindable,
                    3,
                ),
            ],
            &mut ids,
        )
        .expect("seed");
    (model, ns, ids)
}

/// A caller rooted at the namespace root mount with the capability
/// (or without it, for the EPERM rows).
pub fn caller(model: &Model, ns: NsId, cap: bool) -> CallerContext {
    let root = model.namespace(ns).expect("ns").root_mount.expect("seeded");
    CallerContext {
        task: TaskKey(1),
        mount_ns: ns,
        root: PathInNs {
            mount: root,
            below_root: Vec::new(),
        },
        cwd: PathInNs {
            mount: root,
            below_root: Vec::new(),
        },
        cap_sys_admin_in_owner: cap,
    }
}

/// Build an identified-operand fact.
pub fn fact(
    kernel_mount_id: u64,
    below_mount_root: &[u8],
    file_type: FileType,
    is_mount_root: bool,
) -> IdentifiedPath {
    IdentifiedPath {
        kernel_mount_id,
        below_mount_root: below_mount_root.to_vec(),
        file_type,
        is_mount_root,
        final_is_symlink: false,
    }
}

/// The rendered mountinfo for the whole namespace from its root.
/// These fixtures use ASCII paths only; the byte-exact rendering
/// of non-ASCII bytes is covered directly in bind_umount_cases.
pub fn mountinfo(model: &Model, ns: NsId) -> String {
    let root = model.namespace(ns).expect("ns").root_mount.expect("seeded");
    String::from_utf8(model.render_mountinfo(
        ns,
        &PathInNs {
            mount: root,
            below_root: Vec::new(),
        },
    ))
    .expect("fixture paths are UTF-8")
}
